#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <net/if.h>
#include <unistd.h>
#include <argp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sched.h>
#include <search.h>

#include <linux/lwtunnel.h>
#include <linux/seg6_iptunnel.h>
#include <linux/seg6_local.h>

#include "lib.h"
#include "tablesnoop.h"
#include "tablesnoop.skel.h"

// strlen($/proc/sys/kernel/pid_max + 1 (\0))
#define MAX_PIDLEN      8
#define NETNS_PATHLEN   256

const char *fmt_proc_netns = "/proc/%ld/ns/net";
const char *fmt_netns_dir = "/var/run/netns/%s";
const char *netns_dir = "/var/run/netns/";

static pid_t child_processes[256];
static int child_process_counter = 0;

static struct environment env = {
    .netns_cache = NULL,
    .v4only = false,
    .v6only = false,
    .global_netns = false,
    .exiting = false,
    .verbose = false,
    .show_lookup_fails = false,
    .separate_event_prints = false,
};

static void signal_handler(int signo)
{
    (void) signo;
	env.exiting = true;
}

/* By default Linux uses a fast-path when no custom ip rules
 * exist. This skip fib_rules_lookup call, which breaks
 * tablesnoop's IPv4 FIB lookup to netns association logic.
 * As a workaround, let's insert and immediately remove a dummy
 * ip rule, just to force fib_rules_lookup call before FIB lookup.
 * */
static bool force_rule_lookups(void)
{
#define BAIL(msg) perror(msg); return false;
    char ns_path[NETNS_PATHLEN];
    int ret = 0;
    int fd;

    for (size_t i = 0; i < array_get_size(env.netns_cache); i++) {
        const struct netns_item *ns = array_peek(env.netns_cache, i);
        snprintf(ns_path, NETNS_PATHLEN, fmt_proc_netns, ns->pid);

        fd = open(ns_path, O_RDONLY);
        if (fd < 0) {
            BAIL("open");
        }

        if (setns(fd, CLONE_NEWNET) < 0) {
            BAIL("setns");
        }

        ret += system("ip rule add protocol 255");
        ret += system("ip -6 rule add protocol 255");
        usleep(1000);
        ret += system("ip rule del protocol 255");
        ret += system("ip -6 rule del protocol 255");
        if (ret) {
            fprintf(stderr, RED "Failed to initialize tablesnoop, exiting...\n" RESET);
            BAIL("system");
        }

        if (setns(env.originl_netns_fd, CLONE_NEWNET) < 0) {
            BAIL("setns");
        }

        close(fd);
    }

    return true;
}

/* @returns: PID for the given netns inode number
 * or -1 if netns not in the cache */
static long get_pid_for_netns_inode(const struct array *netns_cache, unsigned int netns_inode)
{
    if (!netns_cache)
        return -1;

    size_t size = array_get_size(netns_cache);
    for (size_t i = 0; i < size; ++i) {
        const struct netns_item *item = array_peek(netns_cache, i);
        if (item->ino == netns_inode) {
            return item->pid;
        }
    }

    return -1;
}

/* @returns: PID for the given netns cookie ID
 * or -1 if netns not in the cache */
static long get_pid_for_netns(const struct array *netns_cache, unsigned long netns)
{
    if (!netns_cache)
        return -1;

    size_t size = array_get_size(netns_cache);
    for (size_t i = 0; i < size; ++i) {
        const struct netns_item *item = array_peek(netns_cache, i);
        if (item->cookie == netns) {
            return item->pid;
        }
    }

    return -1;
}

static void run_proc_in_netns(void)
{
    char netns_path[NETNS_PATHLEN];
    struct dirent *netns_entry;
    DIR *netnsfs;

    netnsfs = opendir(netns_dir);
    if (!netnsfs) {
        if (env.verbose) {
            fprintf(stderr, "Info: no iproute2 net namespaces at %s\n", netns_dir);
        }
        return;
    }

    while ((netns_entry = readdir(netnsfs)) != NULL) {

        if (*netns_entry->d_name == '.')
            continue;

        pid_t fpid = fork();
        if (fpid == 0) { // child process

            snprintf(netns_path, NETNS_PATHLEN - strlen(netns_entry->d_name), fmt_netns_dir, netns_entry->d_name);

            int ns_fd = open(netns_path, O_RDONLY);
            if (ns_fd < 0) {
                fprintf(stderr, "Unable to open %s\n", netns_path);
                goto error;
            }

            if (setns(ns_fd, CLONE_NEWNET) < 0) {
                close(ns_fd);
                perror("setns");
                goto error;
            }

            pause(); // wait for stopping...

error:
            closedir(netnsfs);
            close(ns_fd);
            env.exiting = true;
        } else {
            child_processes[child_process_counter++] = fpid;
        }
    }
    closedir(netnsfs);
}

/* Returns a cache with (netns_cookie, netns_inode, pid) tuples.
 * It scans through every PID in procfs and collect  from them.
 * Multiple processes can have the same netns, the
 * cache only stores every netns once with the smallest PID.
 * PID and inode required for enable global rule tracing,
 * for filtering we could use net_cookie only...
 * */
static struct array *create_netns_cache(void)
{
    char netns_path[NETNS_PATHLEN];
    struct array *cache = NULL;
    struct stat netns_stat;
    struct dirent *entry;
    DIR *procfs;
    int ret;

    run_proc_in_netns();
    procfs = opendir("/proc");
    if (!procfs) {
        perror("opendir");
        goto out_procfs;
    }

    cache = array_init(32, sizeof(struct netns_item));
    if (!cache) {
        perror("Failed to allocate netns cache");
        goto out_cache;
    }

    if (env.verbose)
        printf("Build cache for netns to pid association...\n");

    while ((entry = readdir(procfs)) != NULL) {
        errno = 0;
        if (entry->d_type != DT_DIR || !isdigit(entry->d_name[0]))
            continue;

        snprintf(netns_path, NETNS_PATHLEN, fmt_proc_netns, atol(entry->d_name));

        ret = stat(netns_path, &netns_stat);
        if (ret < 0)
            continue;

        ret = get_pid_for_netns_inode(cache, netns_stat.st_ino);
        if (ret > 0)
            continue;

        int ns_fd = open(netns_path, O_RDONLY);
        if (setns(ns_fd, CLONE_NEWNET) == -1) {
            perror("setns");
            close(ns_fd);
        }

        struct netns_item new_item = {
            .ino = netns_stat.st_ino,
            .pid = atol(entry->d_name),
            .cookie = get_netns_cookie()
        };

        if (!array_add(cache, &new_item))
            goto out_new_item;

        if(env.verbose)
            printf("netns: %u pid: %ld cookie: %ld\n", new_item.ino, new_item.pid, new_item.cookie);
    }

    if (errno && !entry) {
        perror("readdir");
    }

    closedir(procfs);
    return cache;

out_new_item:
    array_free(env.netns_cache);
out_cache:
    closedir(procfs);
out_procfs:
    return NULL;
}

/* Return netdevice name for interface index within a given
 * networ namespace (also store it in @ifnamebuf)
 *
 * Note #1: uses a simple cache, to store successfully
 * resolved (netns_cookie, netns_inode, PID) tuples, rebuild the cache if needed
 *
 * TODO: use caching for ifindex to name resolution as well
 * */
static char *if_netns_indextoname(char *ifnamebuf, unsigned long nsid, unsigned int if_index) {
    char ns_path[NETNS_PATHLEN];
    int fd;

    int pid = get_pid_for_netns(env.netns_cache, nsid);

    if (pid < 0) {
        if (env.netns_cache)
            array_free(env.netns_cache);

        env.netns_cache = create_netns_cache();
        pid = get_pid_for_netns(env.netns_cache, nsid);
        if (pid < 0) {
            perror("unable to find pid for netns\n");
            goto out_pid;
        }
    }

    snprintf(ns_path, NETNS_PATHLEN, fmt_proc_netns, pid);
    fd = open(ns_path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        goto out_pid;
    }

    if (setns(fd, CLONE_NEWNET) < 0) {
        perror("setns");
        goto out_setns;
    }

    if (if_indextoname(if_index, ifnamebuf) == NULL) {
        sprintf(ifnamebuf, "<%u>", if_index);
    }

    if (setns(env.originl_netns_fd, CLONE_NEWNET) < 0) {
        perror("setns");
        goto out_setns;
    }

    close(fd);

    return ifnamebuf;

out_setns:
    setns(env.originl_netns_fd, CLONE_NEWNET);
    close(fd);
out_pid:
    array_free(env.netns_cache);
    return NULL;
}

static const char *color_lookup_result(const struct tablesnoop_event *e)
{
    return e->success ? GRN : RED;
}

static int print_ip46(const char *name, int family, const union ip46addr *addr)
{
    char buf[INET6_ADDRSTRLEN] = {0};
    const char *col = RED;
    if (family == AF_INET) {
        inet_ntop(AF_INET, addr, buf, INET_ADDRSTRLEN);
        col = MAG;
    } else if (family == AF_INET6) {
        inet_ntop(AF_INET6, addr, buf, INET6_ADDRSTRLEN);
        col = BLU;
    } else {
        snprintf(buf, sizeof(buf), "unknown family %d", family);
    }
    return printf("%s %s%s" RESET, name, col, buf);
}

static inline const char *srv6_actid_to_name(int action_id)
{
    const char *action_names[SEG6_LOCAL_ACTION_MAX + 1] = {
        [SEG6_LOCAL_ACTION_UNSPEC] = "unspecified",
        [SEG6_LOCAL_ACTION_END] = "End",
        [SEG6_LOCAL_ACTION_END_X] = "End.X",
        [SEG6_LOCAL_ACTION_END_T] = "End.T",
        [SEG6_LOCAL_ACTION_END_DX2] = "End.DX2",
        [SEG6_LOCAL_ACTION_END_DX6] = "End.DX6",
        [SEG6_LOCAL_ACTION_END_DX4] = "End.DX4",
        [SEG6_LOCAL_ACTION_END_DT6] = "End.DT6",
        [SEG6_LOCAL_ACTION_END_DT4] = "End.DT4",
        [SEG6_LOCAL_ACTION_END_B6] = "End.B6",
        [SEG6_LOCAL_ACTION_END_B6_ENCAP] = "End.B6.Encap",
        [SEG6_LOCAL_ACTION_END_BM] = "End.BM",
        [SEG6_LOCAL_ACTION_END_S] = "End.S",
        [SEG6_LOCAL_ACTION_END_AS] = "End.AS",
        [SEG6_LOCAL_ACTION_END_AM] = "End.AM",
        [SEG6_LOCAL_ACTION_END_BPF] = "End.BPF",
        [SEG6_LOCAL_ACTION_END_DT46] = "End.DT46",
    };

    if (action_id > SEG6_LOCAL_ACTION_MAX)
        return "invalid";

    return action_names[action_id];
}

// copied from include/vdso/bits.h and include/uapi/linux/const.h
#define __AC(X,Y)               (X##Y)
#define _AC(X,Y)                __AC(X,Y)
#define UL(x)                   (_AC(x, UL))
#define BIT(nr)                 (UL(1) << (nr))
// copied from net/ipv6/seg6_local.c
// the enum containing SEG6_LOCAL_FLV_OP_PSP is in include/uapi/linux/seg6_local.h
#define SEG6_F_LOCAL_FLV_OP(flvname)    BIT(SEG6_LOCAL_FLV_OP_##flvname)
#define SEG6_F_LOCAL_FLV_NEXT_CSID      SEG6_F_LOCAL_FLV_OP(NEXT_CSID)
#define SEG6_F_LOCAL_FLV_PSP            SEG6_F_LOCAL_FLV_OP(PSP)

static void print_seg6local(unsigned long netns, int seg6action, const struct seg6local_data *s6l)
{
    printf(" action " YEL "%s" RESET, srv6_actid_to_name(seg6action));

    if (seg6action == SEG6_LOCAL_ACTION_END_T ||
            seg6action == SEG6_LOCAL_ACTION_END_DT6) {
        printf(" table " YEL "%d" RESET, s6l->table);
    }
    if (seg6action == SEG6_LOCAL_ACTION_END_DT4 ||
            seg6action == SEG6_LOCAL_ACTION_END_DT46) {
        printf(" vrf_table " YEL "%d" RESET, s6l->vrf_table);
    }
    if (seg6action == SEG6_LOCAL_ACTION_END_DX4) {
        print_ip46(" nh4", AF_INET, (void*)&s6l->nh4);
    }
    if (seg6action == SEG6_LOCAL_ACTION_END_DX6) {
        print_ip46(" nh6", AF_INET6, (void*)&s6l->nh6);
    }
    if (s6l->oif) {
        char oifstr[IFNAMSIZ];
        if_netns_indextoname(oifstr, netns, s6l->oif);
        printf(" oif " CYN "%s" RESET, oifstr);
    }

    if (s6l->flavor_ops & SEG6_F_LOCAL_FLV_PSP) {
        printf(" flavor " YEL "PSP" RESET);
    }
    if (s6l->flavor_ops & SEG6_F_LOCAL_FLV_NEXT_CSID) {
        printf(" flavor " YEL "NEXT-CSID" RESET " loc " YEL "%d" RESET " func " YEL "%d" RESET,
                s6l->csid_loc_bits, s6l->csid_func_bits);
    }
}

static void print_nexthop(unsigned long netns, const struct nexthop_data *nh)
{
    printf(" " BLD "-->" RESET);
    if (nh->gw_family != AF_UNSPEC)
        print_ip46(" gw", nh->gw_family, &nh->gw);
    printf(" dev " CYN "%s" RESET, nh->dev);

    if (nh->lwt_type == LWTUNNEL_ENCAP_NONE)
        return;

    const char *lwt_names[] = {
        "NONE", "MPLS", "IP", "ILA", "IP6", "SEG6", "BPF", "SEG6_LOCAL", "RPL", "IOAM6", "XFRM"
    };
    printf("\n    " BLD "%s" RESET, lwt_names[nh->lwt_type]);

    if (nh->lwt_type == LWTUNNEL_ENCAP_SEG6) {
        const char *seg6_mode = "unknown";
        switch (nh->lwt_seg6_mode) {
            case SEG6_IPTUN_MODE_INLINE: seg6_mode = "inline"; break;
            case SEG6_IPTUN_MODE_ENCAP: seg6_mode = "encap"; break;
            case SEG6_IPTUN_MODE_L2ENCAP: seg6_mode = "l2encap"; break;
            case SEG6_IPTUN_MODE_ENCAP_RED: seg6_mode = "encap.red"; break;
            case SEG6_IPTUN_MODE_L2ENCAP_RED: seg6_mode = "l2encap.red"; break;
        }

        printf(" mode " YEL "%s" RESET " segments_left " YEL "%u" RESET " first_segment " YEL "%u" RESET " [",
                seg6_mode, nh->lwt_seg6_hdr.segments_left, nh->lwt_seg6_hdr.first_segment);
        for (unsigned i=0; i<=nh->lwt_seg6_hdr.segments_left; i++) {
            print_ip46("", AF_INET6, (void*)&nh->lwt_seg6_hdr.segments[i]);
        }
        printf(" ]");
    }
    else if (nh->lwt_type == LWTUNNEL_ENCAP_SEG6_LOCAL) {
        print_seg6local(netns, nh->lwt_seg6_mode, &nh->lwt_seg6local_data);
    }
}

static void print_fib_event(const struct tablesnoop_event *e)
{
    if (env.filtered && !env.routes_only)
        return;

    char iifstr[IFNAMSIZ];
    char oifstr[IFNAMSIZ];

    if (!e->success && !env.show_lookup_fails)
        return;

    if (e->type == FIB_V4) {
        printf("%sfib4:" RESET " " ITA "packet" RESET, color_lookup_result(e));
        print_ip46(" src", AF_INET, &e->fib.packet_src);
        print_ip46(" dst", AF_INET, &e->fib.packet_dst);
        if (env.verbose) {
            if_netns_indextoname(iifstr, e->netns, e->fib.packet_iif);
            if_netns_indextoname(oifstr, e->netns, e->fib.packet_oif);
            printf(" iif " CYN "%s" RESET " oif " CYN "%s" RESET " dscp " YEL "%u" RESET,
                    iifstr, oifstr, e->fib.packet_dscp);
        }

        if (e->success) {
            print_ip46(" " ITA "fib" RESET " key", AF_INET, &e->fib.fib_dst);
            printf(MAG "/%u" RESET, e->fib.fib_prefixlen);
            if (env.verbose) {
                printf(" netns " YEL "%lu" RESET " table id " YEL "%u" RESET, e->netns, e->fib.fib_table_id);
            }
        }
    } else {
        printf("%sfib6:" RESET " " ITA "packet" RESET, color_lookup_result(e));
        print_ip46(" src", AF_INET6, &e->fib.packet_src);
        print_ip46(" dst", AF_INET6, &e->fib.packet_dst);
        if (env.verbose) {
            if_netns_indextoname(iifstr, e->netns, e->fib.packet_iif);
            if_netns_indextoname(oifstr, e->netns, e->fib.packet_oif);
            printf(" iif " CYN "%s" RESET " oif " CYN "%s" RESET " dscp " YEL "%u" RESET " flowlabel " YEL "%u" RESET,
                    iifstr, oifstr, e->fib.packet_dscp, e->fib.packet_flowlabel);
        }

        if (e->success) {
            print_ip46(" " ITA "fib" RESET " key", AF_INET6, &e->fib.fib_dst);
            printf(BLU "/%u" RESET, e->fib.fib_prefixlen);
            if (env.verbose) {
                printf(" netns " YEL "%lu" RESET " table id " YEL "%u" RESET, e->netns, e->fib.fib_table_id);
            }
        }
    }

    if (e->success)
        print_nexthop(e->netns, &e->fib.nh);
    printf("\n");
}

static void print_rule_event(const struct tablesnoop_event *e)
{
    if (env.filtered && !env.rules_only)
        return;

    if (!(e->rule.family == AF_INET || e->rule.family == AF_INET6)) {
        printf(RED "error: invalid rule family %d\n" RESET, e->rule.family);
        return;
    }

    if (!e->success && !env.show_lookup_fails)
        return;

    printf("%srule%d:" RESET " " ITA "packet" RESET, color_lookup_result(e),
            e->rule.family == AF_INET ? 4 : 6);
    print_ip46(" src", e->rule.family, &e->rule.packet_src);
    print_ip46(" dst", e->rule.family, &e->rule.packet_dst);

    if (e->success) {
        printf(" " ITA "rule" RESET " pref " YEL "%u" RESET " table " YEL "%u" RESET,
                e->rule.pref, e->rule.table);

        if (e->rule.src_len) {
            print_ip46(" src", e->rule.family, &e->rule.src);
            printf("%s/%u" RESET, e->rule.family == AF_INET ? MAG : BLU, e->rule.src_len);
        }
        if (e->rule.dst_len) {
            print_ip46(" dst", e->rule.family, &e->rule.dst);
            printf("%s/%u" RESET, e->rule.family == AF_INET ? MAG : BLU, e->rule.dst_len);
        }

        if (env.verbose) {
            printf(" netns " YEL "%lu" RESET, e->netns);
            if (e->rule.iifname[0])
                printf(" iif " CYN "%s" RESET, e->rule.iifname);
            if (e->rule.oifname[0])
                printf(" oif " CYN "%s" RESET, e->rule.oifname);
            if (e->rule.mark)
                printf(" mark " YEL "%u" RESET, e->rule.mark);
            if (e->rule.dscp)
                printf(" dscp " YEL "%u" RESET, e->rule.dscp);
            if (e->rule.l3mdev)
                printf(" l3mdev " YEL "%u" RESET, e->rule.l3mdev);
            if (e->rule.goto_target)
                printf(" goto " YEL "%u" RESET, e->rule.goto_target);
        }
    }

    printf("\n");
}

static int tablesnoop_event_cb(void *ctx __attribute_maybe_unused__, void *data, size_t data_sz)
{
    //TODO can this happen??
    if (data_sz != sizeof(struct tablesnoop_event)) {
        fprintf(stderr, RED "Error: malformed event from kernel. BPF objects out-of-date?\n" RESET);
        env.exiting = true;
    }

    const struct tablesnoop_event *e = data;

    switch (e->type) {
    case FIB_V4:
    case FIB_V6: print_fib_event(e);
        break;
    case RULE: print_rule_event(e);
        break;
    default: fprintf(stderr, RED "unknown event type %d\n" RESET, e->type);
    }

    return 0;
}

static int parse_opt(int key, char *arg, struct argp_state *state) {
    (void) arg; (void) state;

    switch (key) {
    case '4':
        env.v4only = true;
        break;
    case '6':
        env.v6only = true;
        break;
    case 'g':
        env.global_netns = true;
        break;
    case 'v':
        env.verbose = true;
        break;
    case 's':
        env.separate_event_prints = true;
        break;
    case 'x':
        env.show_lookup_fails = true;
        break;
    case OPT_ROUTES_ONLY:
        env.filtered = true;
        env.routes_only = true;
        break;
    case OPT_RULES_ONLY:
        env.filtered = true;
        env.rules_only = true;
        break;
    }

    if (env.v4only && env.v6only) {
        env.v4only = false;
        env.v6only = false;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    struct ring_buffer *rb = NULL;
    struct tablesnoop_bpf *obj = NULL;
    int ret = EXIT_SUCCESS;
    struct argp_option options[] =
    {
        { "v4", '4', 0, 0, "Use IPv4. By default, both IPv4 and IPv6 are logged.", 0},
        { "v6", '6', 0, 0, "Use IPv6. By default, both IPv4 and IPv6 are logged.", 0},
        { "global", 'g', 0, 0, "Collect events from all network namespace (global).", 0},
        { "verbose", 'v', 0, 0, "Enable detailed output.", 0},
        { "separate", 's', 0, 0, "Insert empty line after a timeout.", 0},
        { "show_failed", 'x', 0, 0, "Show failed lookup results", 0},
        { "route", OPT_ROUTES_ONLY, 0, 0, "Only display route lookups", 0},
        { "rule", OPT_RULES_ONLY, 0, 0, "Only display rule lookups", 0},
        { 0 }
    };

    struct argp argp = { options, parse_opt, 0, 0, 0, 0, 0 };
    argp_parse(&argp, argc, argv, 0, 0, 0);

    env.original_netns = get_netns_cookie();
    if (env.verbose)
        printf("Original netns: %lu\n", env.original_netns);

    env.originl_netns_fd = get_netns_fd();
    if (env.originl_netns_fd < 0)
        return EXIT_FAILURE;

    env.netns_cache = create_netns_cache();
    if (env.verbose)
        printf("Event size: %lu bytes\n", sizeof(struct tablesnoop_event));

    if (force_rule_lookups() == false) {
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    obj = tablesnoop_bpf__open_and_load();
    if (!obj) {
        perror("Failed to open and load BPF object\n");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    ret = tablesnoop_bpf__attach(obj);
    if (ret) {
        perror("Failed to attach BPF programs\n");
        ret = EXIT_FAILURE;
        goto cleanup;

    }

    // Share struct environment config options with the kernel
    obj->bss->env = env;

    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        perror("Unable to setup signal handler\n");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(obj->maps.rb), tablesnoop_event_cb, NULL, NULL);
	if (!rb) {
		ret = EXIT_FAILURE;
		perror("Failed to create ring buffer\n");
		goto cleanup;
	}

    bool print_separator = env.separate_event_prints;
    while (!env.exiting) {
        ret = ring_buffer__poll(rb, 500);
        if (ret == 0) {
            if (print_separator) {
                print_separator = false;
                printf("\n");
            }
        } else {
            print_separator = env.separate_event_prints;
        }
        if (ret == -EINTR)
            break;
        if (ret < 0) {
            perror("Error while polling ring buffer\n");
            break;
        }
    }

cleanup:
    printf(RESET"\n"); //disable custom colors
    close(env.originl_netns_fd);
    ring_buffer__free(rb);
    tablesnoop_bpf__destroy(obj);
    for (int i = 0; i < child_process_counter; ++i) {
        kill(child_processes[i], SIGTERM);
        waitpid(child_processes[i], NULL, 0);
    }
    return ret;
}
