#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/version.h>

#include "common.h"
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

//////////// vvvvv mpls internal stuff copied from the kernel vvvvv ///////////////

#define MPLS_LS_LABEL_MASK      0xFFFFF000
#define MPLS_LS_LABEL_SHIFT     12
#define MPLS_LS_TC_MASK         0x00000E00
#define MPLS_LS_TC_SHIFT        9
#define MPLS_LS_S_MASK          0x00000100
#define MPLS_LS_S_SHIFT         8
#define MPLS_LS_TTL_MASK        0x000000FF
#define MPLS_LS_TTL_SHIFT       0

static inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
        return skb->head + skb->network_header;
}

static inline struct mpls_shim_hdr *mpls_hdr(const struct sk_buff *skb)
{
        return (struct mpls_shim_hdr *)skb_network_header(skb);
}

static inline struct mpls_entry_decoded mpls_entry_decode(struct mpls_shim_hdr *hdr)
{
        struct mpls_entry_decoded result;
        unsigned entry = bpf_ntohl(hdr->label_stack_entry);

        result.label = (entry & MPLS_LS_LABEL_MASK) >> MPLS_LS_LABEL_SHIFT;
        result.ttl = (entry & MPLS_LS_TTL_MASK) >> MPLS_LS_TTL_SHIFT;
        result.tc =  (entry & MPLS_LS_TC_MASK) >> MPLS_LS_TC_SHIFT;
        result.bos = (entry & MPLS_LS_S_MASK) >> MPLS_LS_S_SHIFT;

        return result;
}

static struct mpls_route *mpls_route_input_rcu(struct net *net, unsigned int index)
{
    struct mpls_route /*__rcu*/ **platform_label;

    if (index >= net->mpls.platform_labels)
        return NULL;

    platform_label = net->mpls.platform_label; //rcu_dereference(net->mpls.platform_label);
    return platform_label[index]; //rcu_dereference(platform_label[index]);
}

struct mpls_nh { /* next hop label forwarding entry */
        struct net_device       *nh_dev;
        netdevice_tracker       nh_dev_tracker;

        /* nh_flags is accessed under RCU in the packet path; it is
         * modified handling netdev events with rtnl lock held
         */
        unsigned int            nh_flags;
        u8                      nh_labels;
        u8                      nh_via_alen;
        u8                      nh_via_table;
        u8                      nh_reserved1;

        u32                     nh_label[0];
};

// see the comment about the memory layout of @rt_nh in net/mpls/internal.h
// linux/types.h: #define rcu_head callback_head
struct mpls_route { /* next hop label forwarding entry */
        struct callback_head/*rcu_head*/         rt_rcu; // this struct is 2 pointers
        u8                      rt_protocol;
        u8                      rt_payload_type;
        u8                      rt_max_alen;
        u8                      rt_ttl_propagate;
        u8                      rt_nhn;
        /* rt_nhn_alive is accessed under RCU in the packet path; it
         * is modified handling netdev events with rtnl lock held
         */
        u8                      rt_nhn_alive;
        u8                      rt_nh_size;
        u8                      rt_via_offset;
        u8                      rt_reserved1;
        struct mpls_nh          rt_nh[0];
};

//////////// ^^^^^ mpls internal stuff copied from the kernel ^^^^^ ///////////////

static bool construct_mpls_event(struct tablesnoop_event *e, struct net *net, struct sk_buff *skb)
{
    e->type = MPLS;
    e->netns = net->net_cookie;

    struct mpls_shim_hdr *hdr = mpls_hdr(skb);
    struct mpls_entry_decoded dec = mpls_entry_decode(hdr);

    e->mpls.packet_label = dec;

    struct mpls_route *rt = mpls_route_input_rcu(net, dec.label);
    if (rt == NULL) {
        return false;
    }

    // The mpls_route can have multiple nexthops with their own label stack and
    // via address, here we only extract the first nexthop.

    // We can't directly use @rt, because the eBPF verifier doesn't trust it to
    // be a valid pointer (it comes from an array of pointers, according to the
    // verifier it's a scalar). After using bpf_core_cast() on it we can use it
    // as a pointer, but struct mpls_route has no BTF information so we have to
    // cast it to a different struct. The struct rtnl_link_stats64 is 200 bytes
    // without holes, so after the cast that whole area becomes valid for the
    // verifier, and we can then freely re-cast it to struct mpls_route.
    struct rtnl_link_stats64 *rt_buf = bpf_core_cast(rt, struct rtnl_link_stats64);
    struct mpls_route *rt_rt = (struct mpls_route *)rt_buf;

    e->mpls.multipath_count = rt_rt->rt_nhn;
    e->mpls.label_count = rt_rt->rt_nh[0].nh_labels;
    e->mpls.via_len = rt_rt->rt_nh[0].nh_via_alen;

    // nh_label[i] are simply numbers
    for (unsigned i=0; i<MPLS_MAX_LABELS; i++) {
        if (i >= e->mpls.label_count)
            break;
        e->mpls.label_stack[i] = rt_rt->rt_nh[0].nh_label[i];
    }

    // The via address is after the nexthop structure, but not always directly.
    // They take the nexthop with the most labels, align the result to 8 bytes,
    // and that is the common via offset for all nexthops. The total size of
    // the nexthop+via is also padded to the longest via address in case there
    // are both v4 and v6 addresses. See the comment at the MPLS_NH_SIZE macro.
    // Fortunately we don't have to compute anything here, because we can use
    // rt->rt_via_offset.
    //
    // The via address is thus at rt_nh[0] + rt_via_offset

    unsigned nh_offset = offsetof(struct mpls_route, rt_nh);
    unsigned via_offset = rt_rt->rt_via_offset;
    struct in6_addr *rt_nh_via = bpf_core_cast((char*)rt + nh_offset + via_offset, struct in6_addr);
    e->mpls.via.ip6 = *rt_nh_via;

    if (rt_rt->rt_nh[0].nh_dev) {
        struct net_device *nh_dev = bpf_core_cast(rt_rt->rt_nh[0].nh_dev, struct net_device);
        __builtin_memcpy(e->mpls.dev, nh_dev->name, IFNAMSIZ);
    } else {
        e->mpls.dev[0] = 0;
    }

    return true;
}

SEC("fentry/mpls_forward")
int BPF_PROG(fentry_mpls_forward, struct sk_buff *skb, struct net_device *dev,
            struct packet_type *pt, struct net_device *orig_dev)
{
    struct net *net = dev->nd_net.net; //dev_net_rcu(dev);
    if (env.filter_netns && env.my_netns_cookie != net->net_cookie)
        return BPF_OK;

    struct tablesnoop_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct tablesnoop_event), 0);
    if (!e)
        return BPF_OK;
    __builtin_memset(e, 0, sizeof(*e));

    //TODO can we skip submitting on no success?
    e->success = construct_mpls_event(e, net, skb);
    bpf_ringbuf_submit(e, 0);

    return BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";