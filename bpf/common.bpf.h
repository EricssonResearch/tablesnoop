#ifndef _H_COMMON_BPF
#define _H_COMMON_BPF

#include "common.h"

#define IPV6_FLOWINFO_MASK              bpf_htonl(0x0FFFFFFF)
#define IPV6_FLOWLABEL_MASK             bpf_htonl(0x000FFFFF)
#define IPV6_TCLASS_SHIFT               20
#define IPV6_TCLASS_MASK (IPV6_FLOWINFO_MASK & ~IPV6_FLOWLABEL_MASK)
#define MAX_NETNS_COUNT                 1024
#define NETDEV_HASHENTRIES              256

//////////// vvvvv mpls internal stuff copied from the kernel vvvvv ///////////////

// this is in include/net/mpls_iptunnel.h
//  which we can't include because it's not uapi
//  and even if we could include it vmlinux.h would be in conflict with it
struct mpls_iptunnel_encap {
        u8      labels;
        u8      ttl_propagate;
        u8      default_ttl;
        u8      reserved1;
        u32     label[];
};

//////////// ^^^^^ mpls internal stuff copied from the kernel ^^^^^ ///////////////

/* Resolve ifindex to interface name within a netns*/
static inline void get_ifname_netns(const struct net *netns, const int ifindex,
                                    char ifnamebuf[IFNAMSIZ])
{
    if (!ifindex)
        return;

    const int dev_index = ifindex & (NETDEV_HASHENTRIES - 1);
    struct hlist_head *index_head = BPF_CORE_READ(netns, dev_index_head);
    struct hlist_node *iter = BPF_CORE_READ(&index_head[dev_index], first);

    bpf_repeat(NETDEV_HASHENTRIES) {
        if (!iter)
            break;
        void *dev_ptr = container_of(iter, struct net_device, index_hlist);
        const struct net_device *dev = bpf_core_cast(dev_ptr, struct net_device);
        if (BPF_CORE_READ(dev, ifindex) == ifindex) {
            __builtin_memcpy(ifnamebuf, dev->name, IFNAMSIZ);
            return;
        }
        iter = BPF_CORE_READ(iter, next);
    }
}

static void construct_seg6local_data(const struct net *net, struct seg6local_data *seg6l, const struct seg6_local_lwt *slwt)
{
    seg6l->table = slwt->table;
    seg6l->nh4 = slwt->nh4;
    seg6l->nh6 = slwt->nh6;
    get_ifname_netns(net, slwt->oif, seg6l->oif);
    seg6l->vrf_table = slwt->dt_info.vrf_table;
    seg6l->flavor_ops = slwt->flv_info.flv_ops;
    seg6l->csid_loc_bits = slwt->flv_info.lcblock_bits;
    seg6l->csid_func_bits = slwt->flv_info.lcnode_func_bits;
}

static void construct_nexthop_data(const struct net *net, struct nexthop_data *nhd, const struct fib_nh_common *nhc)
{
    struct in6_addr *in6 = NULL;
    struct in_addr *in4 = NULL;

    //TODO dev is the device the fib entry is bound to, egress is nhc->nhc_oif
    struct net_device *dev = nhc->nhc_dev;
    if (dev)
        __builtin_memcpy(&nhd->dev, dev->name, sizeof(nhd->dev));

    if (nhc->nhc_gw_family == AF_INET) {
        // bpf_printk("v4 gw: %pI4", &nhc->nhc_gw.ipv4);
        nhd->gw_family = AF_INET;
        __builtin_memcpy(&nhd->gw, &nhc->nhc_gw.ipv4, sizeof(struct in_addr));
    } else if (nhc->nhc_gw_family == AF_INET6) {
        // bpf_printk("v6 gw: %pI6", &nhc->nhc_gw.ipv6);
        nhd->gw_family = AF_INET6;
        __builtin_memcpy(&nhd->gw, &nhc->nhc_gw.ipv6, sizeof(struct in6_addr));
    } else {
        nhd->gw_family = AF_UNSPEC;
    }

    if (nhc->nhc_lwtstate) {
        nhd->lwt_type = nhc->nhc_lwtstate->type;
        if (nhc->nhc_lwtstate->type == LWTUNNEL_ENCAP_SEG6) {
            struct seg6_lwt *slwt = (struct seg6_lwt *)nhc->nhc_lwtstate->data;
            struct ipv6_sr_hdr *srh = slwt->tuninfo[0].srh;

            nhd->lwt_seg6_mode = slwt->tuninfo[0].mode;

            __builtin_memcpy(&nhd->lwt_seg6_hdr, srh, sizeof(struct ipv6_sr_hdr));
            for (unsigned i=0; i<SRH_MAX_HOPS; i++) {
                if (i > srh->segments_left) break;
                __builtin_memcpy(&nhd->lwt_seg6_hdr.segments[i], &srh->segments[i], sizeof(struct in6_addr));
            }
        }
        else if (nhc->nhc_lwtstate->type == LWTUNNEL_ENCAP_SEG6_LOCAL) {
            struct seg6_local_lwt *slwt = (struct seg6_local_lwt *)nhc->nhc_lwtstate->data;

            nhd->lwt_seg6_mode = slwt->action;
            construct_seg6local_data(net, &nhd->lwt_seg6local_data, slwt);
        }
        else if (nhc->nhc_lwtstate->type == LWTUNNEL_ENCAP_MPLS) {
            struct mpls_iptunnel_encap *mlwt = (struct mpls_iptunnel_encap *)nhc->nhc_lwtstate->data;
            nhd->lwt_mpls_data.labels = mlwt->labels;
            for (unsigned i=0; i<MPLS_MAX_LABELS; i++) {
                if (i > nhd->lwt_mpls_data.labels) break;
                nhd->lwt_mpls_data.label[i] = mlwt->label[i];
            }
        }
    } else {
        nhd->lwt_type = 0;
    }
}

/* Fill the route key, table id and nexthop of a FIB_V6 event from a fib6_info.
 * Shared by the live fib6 lookup probe and the SRv6 cached-route probe.
 * */
static void construct_fib6_route(struct tablesnoop_event *e, const struct net *net,
                                 struct fib6_info *f6i, const struct fib6_nh *nh,
                                 const struct fib6_table *table)
{
    e->fib.fib_dst.ip6 = BPF_CORE_READ(f6i, fib6_dst.addr);
    e->fib.fib_prefixlen = BPF_CORE_READ(f6i, fib6_dst.plen);
    e->fib.fib_table_id = BPF_CORE_READ(table, tb6_id);

    construct_nexthop_data(net, &e->fib.nh, &nh->nh_common);
}

/* Fill the per-packet fields of a FIB_V6 event. The lookup probe sources these
 * from the flowi6, the cached probe from the post-transform IPv6 header;
 * @flowinfo is the IPv6 flow-info word (tclass + flow label, version masked). */
static void construct_fib6_packet(struct tablesnoop_event *e, const struct net *net,
                                  struct in6_addr daddr, struct in6_addr saddr,
                                  __be32 flowinfo, int iif, int oif)
{
    e->fib.packet_dst.ip6 = daddr;
    e->fib.packet_src.ip6 = saddr;
    get_ifname_netns(net, oif, e->fib.packet_oif);
    get_ifname_netns(net, iif, e->fib.packet_iif);
    e->fib.packet_dscp = (unsigned char) (bpf_ntohl(flowinfo & IPV6_TCLASS_MASK) >> (IPV6_TCLASS_SHIFT + 2));
    e->fib.packet_flowlabel = bpf_ntohl(flowinfo & IPV6_FLOWLABEL_MASK);
}

#endif // _H_COMMON_BPF
