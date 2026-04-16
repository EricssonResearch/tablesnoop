#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/version.h>

#include "tablesnoop.h"
#include "flavors.h"

#ifndef bpf_core_cast
#error "bpf_core_cast not available in libbpf < 1.4.0"
#endif

extern int LINUX_KERNEL_VERSION __kconfig;
extern const void net_namespace_list __ksym;

#define IPV6_FLOWINFO_MASK              bpf_htonl(0x0FFFFFFF)
#define IPV6_FLOWLABEL_MASK             bpf_htonl(0x000FFFFF)
#define IPV6_TCLASS_SHIFT               20
#define IPV6_TCLASS_MASK (IPV6_FLOWINFO_MASK & ~IPV6_FLOWLABEL_MASK)

struct {
    __uint (type, BPF_MAP_TYPE_RINGBUF);
    __uint (max_entries, 256 * 4096);
} rb SEC (".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(uintptr_t));
    __uint(value_size, sizeof(unsigned long));
    __uint(max_entries, 10);
} hmap SEC(".maps");

// Configuration set by userspace
volatile struct environment env;

static void list_all_netns_native()
{
    struct list_head *nslist = bpf_core_cast(&net_namespace_list, struct list_head);
    struct list_head *iter = nslist->next;
    bpf_repeat(1024) {
        const struct net *net = bpf_core_cast(container_of(iter, struct net, list), struct net);
        // bpf_printk("net: %p inode: %u cookie: %lu", net, net->ns.inum, net->net_cookie);
        if (iter->next == nslist)
            break;
        iter = iter->next;
    }
}

static inline bool is_dscp_full_supported()
{
    if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(6, 12, 0))
        return true;
    return false;
}

static void construct_seg6local_data(struct seg6local_data *seg6l, const struct seg6_local_lwt *slwt)
{
    seg6l->table = slwt->table;
    seg6l->nh4 = slwt->nh4;
    seg6l->nh6 = slwt->nh6;
    seg6l->oif = slwt->oif;
    seg6l->vrf_table = slwt->dt_info.vrf_table;
    seg6l->flavor_ops = slwt->flv_info.flv_ops;
    seg6l->csid_loc_bits = slwt->flv_info.lcblock_bits;
    seg6l->csid_func_bits = slwt->flv_info.lcnode_func_bits;
}

static void construct_nexthop_data(struct nexthop_data *nhd, const struct fib_nh_common *nhc)
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
            construct_seg6local_data(&nhd->lwt_seg6local_data, slwt);
        }
    } else {
        nhd->lwt_type = 0;
    }
}

static void construct_fib4_event(struct tablesnoop_event *e, const struct fib_table *tb, const struct flowi4 *flp,
    const struct fib_result *res, int fib_flags, unsigned long netns, int ret)
{
    e->type = FIB_V4;
    e->netns = netns;

    e->fib.fib_dst.ip4.s_addr = res->prefix;
    e->fib.fib_prefixlen = res->prefixlen;
    e->fib.fib_table_id = tb->tb_id;

    e->fib.packet_dst.ip4.s_addr = flp->daddr;
    e->fib.packet_src.ip4.s_addr = flp->saddr;
    e->fib.packet_oif = flp->__fl_common.flowic_oif;
    e->fib.packet_iif = flp->__fl_common.flowic_iif;
    struct flowi_common___pre6_18 *flowic_pre6_18  = (void*)&flp->__fl_common;
    if (bpf_core_field_exists(flowic_pre6_18->flowic_tos)) {
        e->fib.packet_dscp = flowic_pre6_18->flowic_tos >> 2; // TODO: DSCP is not correct?
    } else {
        e->fib.packet_dscp = flp->__fl_common.flowic_dscp >> 2;
    }

    construct_nexthop_data(&e->fib.nh, res->nhc);
}


static void construct_fib6_event(struct tablesnoop_event *e, struct net *net, struct fib6_table *table, int oif,
                                 struct flowi6 *fl6, struct fib6_result *res, int strict, int ret)
{
    e->type = FIB_V6;
    e->netns = net->net_cookie;

    e->fib.fib_dst.ip6 = res->f6i->fib6_dst.addr;
    e->fib.fib_prefixlen = res->f6i->fib6_dst.plen;
    e->fib.fib_table_id = table->tb6_id;

    e->fib.packet_dst.ip6 = fl6->daddr;
    e->fib.packet_src.ip6 = fl6->saddr;
    e->fib.packet_oif = fl6->__fl_common.flowic_oif;
    e->fib.packet_iif = fl6->__fl_common.flowic_iif;
    e->fib.packet_dscp = (unsigned char) (bpf_ntohl(fl6->flowlabel & IPV6_TCLASS_MASK) >> (IPV6_TCLASS_SHIFT + 2));
    e->fib.packet_flowlabel = bpf_ntohl(fl6->flowlabel & IPV6_FLOWLABEL_MASK);

    construct_nexthop_data(&e->fib.nh, &res->nh->nh_common);
}


static void construct_fib_rule_event(struct tablesnoop_event *e, const struct flowi *fl,
        const struct fib_rule *rule, const struct fib_rules_ops *ops)
{
    e->type = RULE;
    e->netns = ops->fro_net->net_cookie;

    e->rule.family = ops->family;
    e->rule.table = rule ? rule->table : 0;

    if (ops->family == AF_INET) {
        const struct flowi4 *fl4 = bpf_core_cast(fl, struct flowi4);
        e->rule.packet_src.ip4.s_addr = fl4->saddr;
        e->rule.packet_dst.ip4.s_addr = fl4->daddr;
    } else if (ops->family == AF_INET6) {
        const struct flowi6 *fl6 = bpf_core_cast(fl, struct flowi6);
        e->rule.packet_src.ip6 = fl6->saddr;
        e->rule.packet_dst.ip6 = fl6->daddr;
    } else {
        return;
    }

    if (rule == NULL)
        return;

    __builtin_memcpy(e->rule.iifname, rule->iifname, IFNAMSIZ);
    __builtin_memcpy(e->rule.oifname, rule->oifname, IFNAMSIZ);
    e->rule.pref = rule->pref;
    e->rule.mark = rule->mark;
    e->rule.l3mdev = rule->l3mdev;
    e->rule.goto_target = rule->target;

    if (ops->family == AF_INET) {
        const struct fib4_rule *rule4 = bpf_core_cast(rule, struct fib4_rule);
        const struct fib4_rule___v6_12 *rule4_v6_12 = (void*)rule4;
        bool dscp_full4 = false;

        if (bpf_core_field_exists(rule4_v6_12->dscp_full)) {
            dscp_full4 = rule4_v6_12->dscp_full;
        }

        e->rule.dst.ip4.s_addr = rule4->dst;
        e->rule.src.ip4.s_addr = rule4->src;
        e->rule.dst_len = rule4->dst_len;
        e->rule.src_len = rule4->src_len;

        if (is_dscp_full_supported()) {
            if (dscp_full4)
                e->rule.dscp = rule4->dscp >> 2;
            else
                e->rule.dscp = rule4->dscp;
        } else {
            e->rule.dscp = rule4->dscp >> 2;
        }

    } else if (ops->family == AF_INET6) {
        struct fib6_rule *rule6 = bpf_core_cast(rule, struct fib6_rule);
        struct fib6_rule___v6_12 *rule6_v6_12 = (void*)rule6;
        bool dscp_full6 = false;

        if (bpf_core_field_exists(rule6_v6_12->dscp_full)) {
            dscp_full6 = rule6_v6_12->dscp_full;
        }

        e->rule.dst.ip6 = rule6->dst.addr;
        e->rule.src.ip6 = rule6->src.addr;
        e->rule.dst_len = rule6->dst.plen;
        e->rule.src_len = rule6->src.plen;

        if (is_dscp_full_supported()) {
            if (dscp_full6)
                e->rule.dscp = rule6->dscp >> 2;
            else
                e->rule.dscp = rule6->dscp;
        } else {
            e->rule.dscp = rule6->dscp >> 2;
        }
    }
}

SEC("fexit/fib_table_lookup")
int BPF_PROG(fexit_fib_table_lookup, struct fib_table *tb, const struct flowi4 *flp,
             struct fib_result *res, int fib_flags, int ret)
{
    uintptr_t key = (uintptr_t)tb;
    unsigned long *netns = bpf_map_lookup_elem(&hmap, &key);
    if (!netns)
        return BPF_OK;

    // bpf_printk("fexit: table: %p %u", key, *inum);
    if (!env.global_netns && env.original_netns != *netns)
        return BPF_OK;

    if (env.v6only)
        return BPF_OK;
    // bpf_printk("fib4 lookup %d", ret);

    struct tablesnoop_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct tablesnoop_event), 0);
    if (!e)
        return BPF_OK;

    construct_fib4_event(e, tb, flp, res, fib_flags, *netns, ret);
    e->success = (res->table != NULL);
    bpf_ringbuf_submit(e, 0);
    return BPF_OK;
}


SEC("fexit/fib6_table_lookup")
int BPF_PROG(fexit_fib6_table_lookup, struct net *net, struct fib6_table *table, int oif,
             struct flowi6 *fl6, struct fib6_result *res, int strict, int ret)
{
    if (!env.global_netns && env.original_netns != net->net_cookie)
        return BPF_OK;

    if (env.v4only)
        return BPF_OK;
    // bpf_printk("fib6 lookup %d", ret);

    struct tablesnoop_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct tablesnoop_event), 0);
    if (!e)
        return BPF_OK;

    construct_fib6_event(e, net, table, oif, fl6, res, strict, ret);
    e->success = (res->f6i != net->ipv6.fib6_null_entry);
    bpf_ringbuf_submit(e, 0);
    return BPF_OK;
}


SEC("fexit/fib_get_table")
int BPF_PROG(fexit_fib_get_table, struct net *net, u32 id, struct fib_table *ret)
{
    unsigned long netns = net->net_cookie;
    uintptr_t key = (uintptr_t)ret;
    bpf_map_update_elem(&hmap, &key, &netns, BPF_ANY);
    return BPF_OK;
}


SEC("fexit/fib_rules_lookup")
int BPF_PROG(fexit_fib_rules_lookup, struct fib_rules_ops *ops, struct flowi *fl,
             int flags, struct fib_lookup_arg *arg, int ret)
{
    if (!env.global_netns && env.original_netns != ops->fro_net->net_cookie)
        return BPF_OK;

    if ((env.v4only && ops->family != AF_INET) ||
        (env.v6only && ops->family != AF_INET6))
        return BPF_OK;

    struct tablesnoop_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct tablesnoop_event), 0);
    if (!e)
        return BPF_OK;

    // note: on success fib_rules_lookup() sets arg->rule to the found one
    construct_fib_rule_event(e, fl, arg->rule, ops);
    e->success = (ret == 0);// && (arg->rule != NULL);
    bpf_ringbuf_submit(e, 0);

    return BPF_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
