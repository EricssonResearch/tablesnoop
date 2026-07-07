#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/version.h>

#include "common.h"
#include "common.bpf.h"
#include "flavors.h"

extern int LINUX_KERNEL_VERSION __kconfig;
extern bool CONFIG_IP_MULTIPLE_TABLES __kconfig;
extern const void net_namespace_list __ksym;

struct {
    __uint (type, BPF_MAP_TYPE_RINGBUF);
    __uint (max_entries, 256 * 4096);
} rb SEC (".maps");

// Configuration set by userspace
volatile struct environment env;

/* SRv6 cached-route tracing.
 *
 * seg6_input_core()/seg6_output_core() try a per-CPU dst_cache before
 * falling back to a full FIB lookup. On a cache hit the kernel skips
 * fib6_table_lookup() path and we have no fib6 trace
 *
 * - cache_dst parameter is NULL on cache miss. We can return early,
 *   because a regular fib6 lookup will takes place (already traced)
 * - on cache hit (cache_dst != NULL) we read the data used for the
 *   lookup from the (post-encap) network header. This is equivalent
 *   with the uncached fib6 data.
 */
SEC("fexit/seg6_do_srh")
int BPF_PROG(fexit_seg6_do_srh, struct sk_buff *skb, struct dst_entry *cache_dst, int ret)
{
    if ((env.show_events & SHOW_FIB6) == 0)
        return BPF_OK;

    if (ret != 0 || cache_dst == NULL)
        return BPF_OK; // transform failed, or cache miss (fib6 probe covers it)

    const struct net *net = bpf_core_cast(BPF_CORE_READ(skb, dev, nd_net.net), struct net);
    if (env.filter_netns && env.my_netns_cookie != net->net_cookie)
        return BPF_OK;

    // cache_dst is the cached dst_entry, embedded as the first member of rt6_info
    struct rt6_info *rt6 = bpf_core_cast(cache_dst, struct rt6_info);
    struct fib6_info *f6i = BPF_CORE_READ(rt6, from);
    if (!f6i)
        return BPF_OK;

    struct tablesnoop_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct tablesnoop_event), 0);
    if (!e)
        return BPF_OK;
    __builtin_memset(e, 0, sizeof(*e));

    e->type = FIB_V6;
    e->netns = net->net_cookie;
    e->success = true;
    e->cached = true;

    // Post-transform outer IPv6 header == the key used for the cached lookup
    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 nhoff = BPF_CORE_READ(skb, network_header);
    struct ipv6hdr *ip6 = bpf_core_cast(head + nhoff, struct ipv6hdr);

    __be32 flowinfo = 0;
    bpf_probe_read_kernel(&flowinfo, sizeof(flowinfo), head + nhoff);
    flowinfo &= IPV6_FLOWINFO_MASK;

    // Resolve the first nexthop, handling both inline and nexthop-object routes
    struct fib6_nh *f6nh;
    struct nexthop *nh = BPF_CORE_READ(f6i, nh);
    if (nh) {
        struct nh_info *nhi = bpf_core_cast(BPF_CORE_READ(nh, nh_info), struct nh_info);
        f6nh = bpf_core_cast(&nhi->fib6_nh, struct fib6_nh);
    } else {
        f6nh = bpf_core_cast(&f6i->fib6_nh[0], struct fib6_nh);
    }
    struct fib6_table *table = bpf_core_cast(BPF_CORE_READ(f6i, fib6_table), struct fib6_table);

    construct_fib6_route(e, net, f6i, f6nh, table);
    construct_fib6_packet(e, net, BPF_CORE_READ(ip6, daddr), BPF_CORE_READ(ip6, saddr),
                          flowinfo, BPF_CORE_READ(skb, skb_iif), 0);

    bpf_ringbuf_submit(e, 0);
    return BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";