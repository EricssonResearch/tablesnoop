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

static inline void stop(const char *err)
{
    perror(err);
    env.exiting = true;
}

/* By default Linux uses a fast-path when no custom ip rules
 * exitst. This skip fib_rules_lookup call, which breaks
 * tablesnoop's IPv4 FIB lookup to netns association logic.
 * As a workaround, lets insert and immediately remove a dummy
 * ip rule, just to force fib_rules_lookup call before FIB lookup.
 * */
static void force_rule_lookups(void)
{
    char ns_path[NETNS_PATHLEN];
    int ret = 0;
    int fd;

    for (size_t i = 0; i < array_get_size(env.netns_cache); i++) {
        const struct netns_item *ns = array_peek(env.netns_cache, i);
        snprintf(ns_path, NETNS_PATHLEN, fmt_proc_netns, ns->pid);

        fd = open(ns_path, O_RDONLY);
        if (fd < 0)
            stop("open");

        if (setns(fd, CLONE_NEWNET) < 0)
            stop("setns");

        ret += system("ip rule add protocol 255");
        ret += system("ip -6 rule add protocol 255");
        usleep(1000);
        ret += system("ip rule del protocol 255");
        ret += system("ip -6 rule del protocol 255");
        if (ret) {
            fprintf(stderr, RED "Failed to initialize tablesnoop, exiting...\n" RESET);
            stop("system");
        }

        if (setns(env.originl_netns_fd, CLONE_NEWNET) < 0)
            stop("setns");

        close(fd);
    }
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
    // char netns_path[NETNS_PATHLEN];
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

            char *netns_path = realpath(netns_entry->d_name, NULL);
            if (!netns_path)
                stop("realpath");

            int ns_fd = open(netns_path, O_RDONLY);
            if (ns_fd < 0) {
                free(netns_path);
                stop("open");
            }

            if (setns(ns_fd, CLONE_NEWNET) < 0) {
                free(netns_path);
                close(ns_fd);
                stop("setns");
            }

            free(netns_path);
            pause(); // wait for stopping...

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
 * It scan through every PID in procfs and collect  from them.
 * Multiple processes can have the same netns, the
 * cache only store every netns once with the smallest PID.
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

    errno = 0;
    while ((entry = readdir(procfs)) != NULL) {
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
        sprintf(ifnamebuf, "-");
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

static void color_lookup_result(const struct fib_event *e)
{
    if (env.show_lookup_fails) {
        if (e->success) {
            printf(GRN);
        } else {
            printf(RED);
        }
    }
}

static void print_nexthop(const struct nexthop_data *nh)
{
    const char *fmt_nh = MAG "--> " RESET "gw: " GRN "%s " RESET "egress: %s";
    char gw[INET6_ADDRSTRLEN] = { 0 };

    if (nh->family == AF_INET)
        inet_ntop(AF_INET, &nh->v4.gw, gw, INET_ADDRSTRLEN);
    else if (nh->family == AF_INET6)
        inet_ntop(AF_INET6, nh->v6.gw, gw, INET6_ADDRSTRLEN);
    printf(fmt_nh, gw, nh->egress);
}

static void print_fib_event(const struct fib_event *e)
{
    if (env.filtered && !env.routes_only)
        return;

    const char *fmt6_verbose = "netns: %lu iif: %s oif: %s table id: %d dscp: %u flowlabel: %x ";
    const char *fmt4_verbose = "netns: %lu iif: %s oif: %s table id: %d dscp: %u ";
    const char *fmt_fib = "v%d:" RESET " src: " BLU "%s " RESET " dst: " BLU "%s " RESET;
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];
    char iifstr[IFNAMSIZ];
    char oifstr[IFNAMSIZ];

    if (!e->success && !env.show_lookup_fails)
        return;

    if (env.verbose) {
        if_netns_indextoname(iifstr, e->netns, e->fib.iif);
        if_netns_indextoname(oifstr, e->netns, e->fib.oif);
        if (e->type == FIB_V4)
            printf(fmt4_verbose, e->netns, iifstr, oifstr, e->fib.table_id, e->fib.dscp, e->fib.nh.egress);
        else if (e->type == FIB_V6)
            printf(fmt6_verbose, e->netns, iifstr, oifstr, e->fib.table_id, e->fib.dscp, e->fib.v6.flowlabel, e->fib.nh.egress);
    }

    color_lookup_result(e);
    switch (e->type) {
    case FIB_V4:
        inet_ntop(AF_INET, &e->fib.v4.src, src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &e->fib.v4.dst, dst, INET_ADDRSTRLEN);
        printf(fmt_fib, 4, src, dst);
        break;
    case FIB_V6:
        inet_ntop(AF_INET6, e->fib.v6.src, src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, e->fib.v6.dst, dst, INET6_ADDRSTRLEN);
        printf(fmt_fib, 6, src, dst);
        break;
    default: break;
    }

    if (e->success)
        print_nexthop(&e->fib.nh);
    printf("\n");
}

static void print_rule_event(const struct fib_event *e)
{
    if (env.filtered && !env.rules_only)
        return;

    const char *fmt_rule = "rule%d:" RESET " pref: " YEL "%u" RESET " table: " YEL "%u " RESET;
    const struct rule_data *rule = &e->rule;
    char src[INET6_ADDRSTRLEN] = { 0 };
    char dst[INET6_ADDRSTRLEN] = { 0 };
    const void *psrc, *pdst;

    if (rule->invalid) {
        printf(RED "error: invalid ip rule\n" RESET);
        return;
    }

    if (!e->success && !env.show_lookup_fails)
        return;


    if (env.verbose) {
        printf("netns: %lu ", e->netns);
        color_lookup_result(e);
        printf(fmt_rule, e->type == RULE_V4 ? 4 : 6, rule->pref, rule->table);
        if (rule->has_iifname) printf("iif: %s ", rule->iifname);
        if (rule->has_oifname) printf("oif: %s ", rule->oifname);
        if (rule->has_mark) printf("mark: %u ", rule->mark);
        if (rule->has_l3mdev) printf("l3mdev: %u ", rule->l3mdev);
        if (rule->has_goto) printf("goto: %u ", rule->goto_target);
        if (rule->has_dscp) printf("dscp: %u ", rule->dscp);

        int addr_size = e->type == RULE_V4 ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        int addr_family = e->type == RULE_V4 ? AF_INET : AF_INET6;
        if (e->type == RULE_V4) psrc = &rule->v4.src; else psrc = rule->v6.src;
        if (e->type == RULE_V4) pdst = &rule->v4.dst; else pdst = rule->v6.dst;

        if (rule->has_dstaddr) {
            inet_ntop(addr_family, psrc, src, addr_size);
            printf("src: %s ", src);
        }
        if (rule->has_srcaddr) {
            inet_ntop(addr_family, pdst, dst, addr_size);
            printf("dst: %s", dst);
        }
    } else {
        color_lookup_result(e);
        printf(fmt_rule, e->type == RULE_V4 ? 4 : 6, rule->pref, rule->table);
    }

    printf("\n");
}

static int fib_event_cb(void *ctx __attribute_maybe_unused__, void *data, size_t data_sz)
{
    if (data_sz != sizeof(struct fib_event)) {
        fprintf(stderr, RED "Error: malformed event from kernel. BPF objects out-of-date?\n" RESET);
        env.exiting = true;
    }

    const struct fib_event *e = data;

    switch (e->type) {
    case FIB_V4:
    case FIB_V6: print_fib_event(e);
        break;
    case RULE_V4:
    case RULE_V6: print_rule_event(e);
        break;
    default: fprintf(stderr, RED "unknown event type\n" RESET);
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
    int ret;
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
        printf("Event size: %lu bytes\n", sizeof(struct fib_event));

    force_rule_lookups();

    struct ring_buffer *rb = NULL;
    struct tablesnoop_bpf *obj = tablesnoop_bpf__open_and_load();
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

    rb = ring_buffer__new(bpf_map__fd(obj->maps.rb), fib_event_cb, NULL, NULL);
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
