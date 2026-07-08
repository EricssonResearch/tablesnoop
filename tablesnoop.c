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
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sched.h>
#include <search.h>
#include <stdarg.h>

#include <linux/lwtunnel.h>
#include <linux/seg6_iptunnel.h>
#include <linux/seg6_local.h>

#include "common.h"
#include "tablesnoop.h"

static bool separate_on_timeout = false;
static bool show_lwt = false;
static bool verbose = false;
static bool exiting = false;

static struct environment env = {
    .filter_netns = true,
    .show_events = SHOW_EVERYTHING,
    .show_lookup_fails = false,
};

static void signal_handler(int signo)
{
    (void) signo;
	exiting = true;
}

// Load a feature, reusing the shared ring buffer map fd.
static void load_feature(struct bpf_feature *f, struct environment *e, int rb_fd)
{
    printf("Loading %-8s module...  ", f->name);
    fflush(stdout);

    f->obj = f->open();
    if (!f->obj) {
        printf("[" RED "FAIL" RESET "] open failed\n");
        return;
    }

    // Reuse the userspace-created ring buffer map
    struct bpf_map *map = f->get_rb_map(f->obj);
    if (bpf_map__reuse_fd(map, rb_fd) != 0) {
        printf("[" RED "FAIL" RESET "] ringbuf reuse failed\n");
        f->destroy(f->obj);
        f->obj = NULL;
        return;
    }

    if (f->load(f->obj) != 0) {
        printf("[" YEL "SKIP" RESET "] not available on this kernel\n");
        f->destroy(f->obj);
        f->obj = NULL;
        return;
    }

    f->set_env(f->obj, e);

    if (f->attach(f->obj) != 0) {
        printf("[" RED "FAIL" RESET "] attach failed\n");
        f->destroy(f->obj);
        f->obj = NULL;
        return;
    }

    f->loaded = true;
    printf("[" GRN " OK " RESET "]\n");
}

static void destroy_feature(struct bpf_feature *f)
{
    if (f->loaded) {
        f->destroy(f->obj);
        f->obj = NULL;
        f->loaded = false;
    }
}

unsigned long get_netns_cookie(void)
{
    int sk = socket(AF_INET, SOCK_STREAM, 0);
    if (sk < 0) {
        perror("socket");
        return sk;
    }

    unsigned long cookie = -1;
    socklen_t sz = sizeof(cookie);

    if (getsockopt(sk, SOL_SOCKET, SO_NETNS_COOKIE, &cookie, &sz) != 0) {
        perror("getsockopt");
    }

    close(sk);

    return cookie;
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

static inline const char *rule_fail_reason(int err)
{
    switch (err) {
    case -EAGAIN:       return "no route in table";
    case -ENETUNREACH:  return "unreachable";
    case -EACCES:       return "prohibit";
    case -EINVAL:       return "blackhole";
    default:            return strerror(-err);
    }
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

static void print_seg6local(int seg6action, const struct seg6local_data *s6l)
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
    if (*s6l->oif)
        printf(" oif " CYN "%s" RESET, s6l->oif);

    if (s6l->flavor_ops & SEG6_F_LOCAL_FLV_PSP) {
        printf(" flavor " YEL "PSP" RESET);
    }
    if (s6l->flavor_ops & SEG6_F_LOCAL_FLV_NEXT_CSID) {
        printf(" flavor " YEL "NEXT-CSID" RESET " loc " YEL "%d" RESET " func " YEL "%d" RESET,
                s6l->csid_loc_bits, s6l->csid_func_bits);
    }
}

static void print_nexthop(const struct nexthop_data *nh)
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
    printf(" " BLD "%s" RESET, lwt_names[nh->lwt_type]);
    if (!show_lwt)
        return;

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
        print_seg6local(nh->lwt_seg6_mode, &nh->lwt_seg6local_data);
    }
    else if (nh->lwt_type == LWTUNNEL_ENCAP_MPLS) {
        printf(" labels " YEL "%u" RESET, nh->lwt_mpls_data.labels);
        for (unsigned i=0; i<nh->lwt_mpls_data.labels; i++) {
            if (i >= MPLS_MAX_LABELS) {
                printf("/" YEL "..." RESET);
                break;
            }
            printf("%s" YEL "%u" RESET,
                    i==0 ? " stack " : "/",
                    nh->lwt_mpls_data.label[i]);
        }
    }
}

static void print_fib_event(const struct tablesnoop_event *e)
{
    if (!e->success && !env.show_lookup_fails)
        return;

    if (e->type == FIB_V4) {
        printf("%sfib4:" RESET " " ITA "packet" RESET, color_lookup_result(e));
        print_ip46(" src", AF_INET, &e->fib.packet_src);
        print_ip46(" dst", AF_INET, &e->fib.packet_dst);
        if (verbose) {
            printf(" iif " CYN "%s" RESET " oif " CYN "%s" RESET " dscp " YEL "%u" RESET
                   " netns " YEL "%lu" RESET " table id " YEL "%u" RESET,
                    e->fib.packet_iif, e->fib.packet_oif, e->fib.packet_dscp,
                    e->netns, e->fib.fib_table_id);
        }

        if (e->success) {
            print_ip46(" " ITA "fib" RESET " key", AF_INET, &e->fib.fib_dst);
            printf(MAG "/%u" RESET, e->fib.fib_prefixlen);
        }
    } else {
        printf("%sfib6:" RESET " " ITA "packet" RESET, color_lookup_result(e));
        print_ip46(" src", AF_INET6, &e->fib.packet_src);
        print_ip46(" dst", AF_INET6, &e->fib.packet_dst);
        if (verbose) {
            printf(" iif " CYN "%s" RESET " oif " CYN "%s" RESET " dscp " YEL "%u" RESET " flowlabel " YEL "%u" RESET
                   " netns " YEL "%lu" RESET " table id " YEL "%u" RESET,
                    e->fib.packet_iif, e->fib.packet_oif, e->fib.packet_dscp, e->fib.packet_flowlabel,
                    e->netns, e->fib.fib_table_id);
        }

        if (e->success) {
            print_ip46(" " ITA "fib" RESET " key", AF_INET6, &e->fib.fib_dst);
            printf(BLU "/%u" RESET, e->fib.fib_prefixlen);
        }
    }

    if (e->success)
        print_nexthop(&e->fib.nh);
    if (e->cached)
        printf(" " YEL "cached" RESET);
    printf("\n");
}

static void print_rule_event(const struct tablesnoop_event *e)
{
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

    if (verbose) {
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

    if (!e->success)
        printf(RED " -> %s" RESET, rule_fail_reason(e->rule.err));

    printf("\n");
}

static void print_mpls_event(const struct tablesnoop_event *e)
{
    if (!e->success && !env.show_lookup_fails)
        return;

    printf("%smpls:" RESET " " ITA "packet" RESET " label " YEL "%u" RESET " ttl " YEL "%u" RESET,
            color_lookup_result(e), e->mpls.packet_label.label, e->mpls.packet_label.ttl);

    if (e->success) {
        printf(" " ITA "route" RESET " paths " YEL "%u" RESET " labels " YEL "%u" RESET,
                e->mpls.multipath_count, e->mpls.label_count);

        for (unsigned i=0; i<e->mpls.label_count; i++) {
            if (i >= MPLS_MAX_LABELS) {
                printf("/" YEL "..." RESET);
                break;
            }
            printf("%s" YEL "%u" RESET,
                    i==0 ? " stack " : "/",
                    e->mpls.label_stack[i]);
        }
        //printf(" via len " YEL "%u" RESET, e->mpls.via_len);
        if (e->mpls.via_len > 0)
            print_ip46(" via", e->mpls.via_len==16 ? AF_INET6 : AF_INET, &e->mpls.via);

        if (e->mpls.dev[0])
            printf(" dev " CYN "%s" RESET, e->mpls.dev);
    }

    printf("\n");
}

#define NUD_INCOMPLETE  0x01
#define NUD_REACHABLE   0x02
#define NUD_STALE       0x04
#define NUD_DELAY       0x08
#define NUD_PROBE       0x10
#define NUD_FAILED      0x20
#define NUD_NOARP       0x40
#define NUD_PERMANENT   0x80

static inline const char *nud_state_str(unsigned char state)
{
    switch (state) {
    case NUD_INCOMPLETE: return "incomplete";
    case NUD_REACHABLE:  return "reachable";
    case NUD_STALE:      return "stale";
    case NUD_DELAY:      return "delay";
    case NUD_PROBE:      return "probe";
    case NUD_FAILED:     return "failed";
    case NUD_NOARP:      return "noarp";
    case NUD_PERMANENT:  return "permanent";
    default:             return "unknown";
    }
}

static inline const char *neigh_func(unsigned int func)
{
    switch (func) {
    case NEIGH_CREATE:   return "create";
    case NEIGH_UPDATE:   return "update";
    case NEIGH_DESTROY:  return "destroy";
    case NEIGH_LOOKUP:   return "lookup";
    default:             return "unknown";
    }
}

static void print_neigh_event(const struct tablesnoop_event *e)
{
    if (!e->success && !env.show_lookup_fails)
        return;

    if (e->neigh.family == AF_INET) {
        printf("%sarp:" RESET, color_lookup_result(e));
        printf(" " ITA "packet" RESET);
        print_ip46(" dst", AF_INET, &e->neigh.next_hop_addr);
    } else if (e->neigh.family == AF_INET6) {
        printf("%snd:" RESET, color_lookup_result(e));
        printf(" " ITA "packet" RESET);
        print_ip46(" dst", AF_INET6, &e->neigh.next_hop_addr);
    } else {
        printf(RED "error: invalid family %d\n" RESET, e->neigh.family);
        return;
    }

    printf(" dev " CYN "%s" RESET, e->neigh.dev);
    printf(" type " YEL "%s" RESET, neigh_func(e->neigh.event_type));
    printf(" " BLD "-->" RESET);

    const unsigned char *mac = e->neigh.mac;
    printf(" mac " MAG "%02x:%02x:%02x:%02x:%02x:%02x" RESET, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    if (verbose) {
        printf(" state " YEL "%s" RESET, nud_state_str(e->neigh.state));
        printf(" netns " YEL "%lu" RESET, e->netns);
    }

    printf("\n");
}

#define BR_NO_STP 0
#define BR_KERNEL_STP 1
#define BR_USER_STP 2

static inline const char *br_stp_state(unsigned int state)
{
    switch (state) {
    case BR_NO_STP:     return "off";
    case BR_KERNEL_STP: return "kernel";
    case BR_USER_STP:   return "user";
    default:            return "unknown";
    }
}

static void print_fdb_event(const struct tablesnoop_event *e)
{
    if (!e->success && !env.show_lookup_fails)
        return;
        
    printf("%sfdb:" RESET, color_lookup_result(e));
    printf(" " ITA "packet" RESET);
    
    const unsigned char *src = e->fdb.src_mac;
    const unsigned char *dst = e->fdb.dst_mac;
    printf(" src " MAG "%02x:%02x:%02x:%02x:%02x:%02x" RESET, src[0], src[1], src[2], src[3], src[4], src[5]);
    printf(" dst " MAG "%02x:%02x:%02x:%02x:%02x:%02x" RESET, dst[0], dst[1], dst[2], dst[3], dst[4], dst[5]);
    printf(" bridge " CYN "%s" RESET, e->fdb.bridge);

    if (verbose) {
        printf(" stp " YEL "%s" RESET, br_stp_state(e->fdb.stp));
    }

    printf(" vid " YEL "%u" RESET, e->fdb.vid);
    
    if (verbose) {
        printf(" origin " YEL "%s" RESET, e->fdb.origin ? "local" : "remote");
        printf(" netns " YEL "%lu" RESET, e->netns);
    }

    printf(" " BLD "-->" RESET);
    printf(" port " CYN "%s" RESET, e->fdb.port);

    printf("\n");
}

static int tablesnoop_event_cb(void *ctx __attribute_maybe_unused__, void *data, size_t data_sz)
{
    //TODO can this happen??
    if (data_sz != sizeof(struct tablesnoop_event)) {
        fprintf(stderr, RED "Error: malformed event from kernel. BPF objects out-of-date?\n" RESET);
        exiting = true;
    }

    const struct tablesnoop_event *e = data;

    switch (e->type) {
    case FIB_V4:
    case FIB_V6: print_fib_event(e);
        break;
    case RULE: print_rule_event(e);
        break;
    case MPLS: print_mpls_event(e);
        break;
    case NEIGH: print_neigh_event(e);
        break;
    case FDB: print_fdb_event(e);
        break;
    default: fprintf(stderr, RED "unknown event type %d\n" RESET, e->type);
    }

    return 0;
}

static int parse_opt(int key, char *arg, struct argp_state *state) {
    (void) arg; (void) state;

    switch (key) {
    case OPT_FIB4:
        if (env.show_events == SHOW_EVERYTHING)
            env.show_events = 0;
        env.show_events |= SHOW_FIB4;
        break;
    case OPT_FIB6:
        if (env.show_events == SHOW_EVERYTHING)
            env.show_events = 0;
        env.show_events |= SHOW_FIB6;
        break;
    case OPT_RULE4:
        if (env.show_events == SHOW_EVERYTHING)
            env.show_events = 0;
        env.show_events |= SHOW_RULE4;
        break;
    case OPT_RULE6:
        if (env.show_events == SHOW_EVERYTHING)
            env.show_events = 0;
        env.show_events |= SHOW_RULE6;
        break;
    case OPT_MPLS:
        if (env.show_events == SHOW_EVERYTHING)
            env.show_events = 0;
        env.show_events |= SHOW_MPLS;
        break;
    case OPT_SRV6:
        if (env.show_events == SHOW_EVERYTHING)
            env.show_events = 0;
        env.show_events |= SHOW_SRV6;
        break;
    case OPT_NEIGH:
        if (env.show_events == SHOW_EVERYTHING)
            env.show_events = 0;
        env.show_events |= SHOW_NEIGH;
        break;
    case OPT_FDB:
        if (env.show_events == SHOW_EVERYTHING)
            env.show_events = 0;
        env.show_events |= SHOW_FDB;
        break;
    case 'g':
        env.filter_netns = false;
        break;
    case 'l':
        show_lwt = true;
    case 'v':
        verbose = true;
        break;
    case 's':
        separate_on_timeout = true;
        break;
    case 'x':
        env.show_lookup_fails = true;
        break;
    }

    return 0;
}

bool module_loaded(const char *modname)
{
    unsigned modname_len = strlen(modname);
    char line[256];
    FILE *mods = fopen("/proc/modules", "r");
    if (!mods) return false;
    while (fgets(line, sizeof(line), mods)) {
        // the line also contains information about the module
        if (strncmp(line, modname, modname_len) == 0) {
            fclose(mods);
            return true;
        }
    }
    fclose(mods);
    return false;
}

static int ignore_print(enum libbpf_print_level level, const char *fmt, va_list ap)
{
    (void)level; (void)fmt; (void)ap;
    return 0;
}

int main(int argc, char *argv[])
{
    struct ring_buffer *rb = NULL;
    int rb_fd = -1;
    int ret = EXIT_SUCCESS;
    struct argp_option options[] =
    {
        { "fib4", OPT_FIB4, 0, 0, "Show IPv4 FIB lookups", 0},
        { "fib6", OPT_FIB6, 0, 0, "Show IPv6 FIB lookups", 0},
        { "rule4", OPT_RULE4, 0, 0, "Show IPv4 rule lookups", 0},
        { "rule6", OPT_RULE6, 0, 0, "Show IPv6 rule lookups", 0},
        { "mpls", OPT_MPLS, 0, 0, "Show MPLS lookups", 0},
        { "srv6", OPT_SRV6, 0, 0, "Show SRv6 lookups", 0},
        { "neigh", OPT_NEIGH, 0, 0, "Show neighbor lookups", 0},
        { "fdb", OPT_FDB, 0, 0, "Show forwarding database lookups", 0},
        { "global", 'g', 0, 0, "Collect events from all network namespaces", 0},
        { "lwt", 'l', 0, 0, "Show LightWeight Tunnel info (off by default)", 0},
        { "verbose", 'v', 0, 0, "Enable detailed output", 0},
        { "separator", 's', 0, 0, "Print separator line after a timeout", 0},
        { "show_failed", 'x', 0, 0, "Show failed lookup results", 0},
        { 0 }
    };

    struct argp argp = { options, parse_opt, 0, 0, 0, 0, 0 };
    argp_parse(&argp, argc, argv, 0, 0, 0);

    env.my_netns_cookie = get_netns_cookie();
    if (verbose)
        printf("Original netns: %lu\n", env.my_netns_cookie);

    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        perror("Unable to setup signal handler\n");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    // Suppress libbpf errors — we handle failures ourselves
    libbpf_set_print(ignore_print);

    struct bpf_map_create_opts rb_opts = { .sz = sizeof(struct bpf_map_create_opts) };
    rb_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "rb", 0, 0, 256 * 4096, &rb_opts);
    if (rb_fd < 0) {
        perror("Failed to create ring buffer map");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    for (int i = 0; i < FEATURE_COUNT; i++) {
        if (env.show_events & features[i].show_flag)
            load_feature(&features[i], &env, rb_fd);
    }

    rb = ring_buffer__new(rb_fd, tablesnoop_event_cb, NULL, NULL);
    if (!rb) {
        ret = EXIT_FAILURE;
        perror("Failed to create ring buffer\n");
        goto cleanup;
    }

    bool print_separator = false;
    while (!exiting) {
        ret = ring_buffer__poll(rb, 500);
        if (ret == 0) {
            if (print_separator) {
                print_separator = false;
                printf("----------------------------------------------------\n");
            }
        } else {
            print_separator = separate_on_timeout;
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
    for (int i = 0; i < FEATURE_COUNT; i++)
        destroy_feature(&features[i]);
    ring_buffer__free(rb);
    if (rb_fd >= 0)
        close(rb_fd);
    return ret;
}
