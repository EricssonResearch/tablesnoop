#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/version.h>
#include <endian.h>

#include "tablesnoop.h"

#ifndef bpf_core_cast
#error "bpf_core_cast not available in libbpf < 1.4.0"
#include <error_libbpf_too_old>
#endif

extern int LINUX_KERNEL_VERSION __kconfig;
extern const void net_namespace_list __ksym;

#define IPV6_FLOWINFO_MASK              htobe32(0x0FFFFFFF)
#define IPV6_FLOWLABEL_MASK             htobe32(0x000FFFFF)
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

static void construct_nexthop_data(struct nexthop_data *nhd, const void *result, enum event_type type)
{
    const struct fib_nh_common *nhc = NULL;
    const struct fib6_result *nh6 = NULL;
    const struct fib_result *nh4 = NULL;

    struct in6_addr *in6 = NULL;
    struct in_addr *in4 = NULL;
    void *gw = NULL;

    if (type == FIB_V4) {
        gw = &nhd->v4.gw;
        nh4 = bpf_core_cast(result, struct fib_result);
        nhc = nh4->nhc;
    }
    else if (type == FIB_V6) {
        gw = &nhd->v6.gw;
        nh6 = bpf_core_cast(result, struct fib6_result);
        nhc = &nh6->nh->nh_common;
    } else {
        nhd->invalid = true;
        return;
    }

    if (nhc) {
        struct net_device *dev = nhc->nhc_dev;
        if (dev)
            __builtin_memcpy(&nhd->egress, dev->name, sizeof(nhd->egress));

        if (nhc->nhc_gw_family == AF_INET) {
            // bpf_printk("v4 gw: %pI4", &nhc->nhc_gw.ipv4);
            nhd->family = AF_INET;
            __builtin_memcpy(gw, &nhc->nhc_gw.ipv4, sizeof(struct in_addr));
        } else if (type == FIB_V6 || nhc->nhc_gw_family == AF_INET6) {
            // bpf_printk("v6 gw: %pI6", &nhc->nhc_gw.ipv6);
            nhd->family = AF_INET6;
            __builtin_memcpy(gw, &nhc->nhc_gw.ipv6, sizeof(struct in6_addr));
        } else {
            nhd->invalid = true;
            return;
        }
    }
}


static void construct_fib4_event(struct fib_event *e, const struct fib_table *tb, const struct flowi4 *flp,
    const struct fib_result *res, int fib_flags, unsigned long netns, int ret)
{
    struct in_addr *in;
    e->type = FIB_V4;
    e->netns = netns;
    e->fib.table_id = tb->tb_id;
    e->fib.oif = flp->__fl_common.flowic_oif;
    e->fib.iif = flp->__fl_common.flowic_iif;
    e->fib.dscp = flp->__fl_common.flowic_tos >> 2; // TODO: DSCP is not correct

    if (flp->__fl_common.flowic_proto == IPPROTO_TCP || flp->__fl_common.flowic_proto == IPPROTO_UDP) {
        e->fib.dport = bpf_ntohs(flp->uli.ports.dport);
        e->fib.sport = bpf_ntohs(flp->uli.ports.sport);
    }

    in = (struct in_addr *) &e->fib.v4.dst;
    in->s_addr = flp->daddr;
    in = (struct in_addr *) &e->fib.v4.src;
    in->s_addr = flp->saddr;

    construct_nexthop_data(&e->fib.nh, res, e->type);
}


static void construct_fib6_event(struct fib_event *e, struct net *net, struct fib6_table *table, int oif,
                                 struct flowi6 *fl6, struct fib6_result *res, int strict, int ret)
{
    struct in6_addr *in6;
    e->type = FIB_V6;
    e->netns = net->net_cookie;
    e->fib.table_id = table->tb6_id;
    e->fib.oif = fl6->__fl_common.flowic_oif;
    e->fib.iif = fl6->__fl_common.flowic_iif;
    e->fib.dscp = (unsigned char) (bpf_ntohl(fl6->flowlabel & IPV6_TCLASS_MASK) >> (IPV6_TCLASS_SHIFT + 2));
    if (fl6->__fl_common.flowic_proto == IPPROTO_TCP ||
        fl6->__fl_common.flowic_proto == IPPROTO_UDP) {
        e->fib.dport = bpf_ntohs(fl6->uli.ports.dport);
        e->fib.sport = bpf_ntohs(fl6->uli.ports.sport);
    }

    in6 = (struct in6_addr *) &e->fib.v6.dst;
    *in6 = fl6->daddr;
    in6 = (struct in6_addr *) &e->fib.v6.src;
    *in6 = fl6->saddr;
    e->fib.v6.flowlabel = be32toh(fl6->flowlabel & IPV6_FLOWLABEL_MASK);

    construct_nexthop_data(&e->fib.nh, res, e->type);
}


static void construct_fib_rule_event(struct fib_event *e, const struct fib_rule *rule,
                                     const struct fib_rules_ops *ops)
{
    struct fib4_rule *rule4 = NULL;
    struct fib6_rule *rule6 = NULL;
    bool dscp_full4 = bpf_core_field_exists(rule4->dscp_full);
    bool dscp_full6 = bpf_core_field_exists(rule6->dscp_full);

    e->rule.table = rule->table;
    e->netns = ops->fro_net->net_cookie;

    if (rule->iifname[0] && (e->rule.has_iifname = true))
        __builtin_memcpy(e->rule.iifname, rule->iifname, IFNAMSIZ);
    if (rule->oifname[0] && (e->rule.has_oifname = true))
        __builtin_memcpy(e->rule.oifname, rule->oifname, IFNAMSIZ);

    if (rule->pref && (e->rule.has_pref = true))
        e->rule.pref = rule->pref;
    if (rule->mark && (e->rule.has_mark = true))
        e->rule.mark = rule->mark;
    if (rule->l3mdev && (e->rule.has_l3mdev = true))
        e->rule.l3mdev = rule->l3mdev;
    if (rule->target && (e->rule.has_goto = true))
        e->rule.goto_target = rule->target;

    if (ops->family == AF_INET ) {

        // rule4 = (struct fib4_rule *) rule;
        rule4 = bpf_core_cast(rule, struct fib4_rule);
        e->type = RULE_V4;

        if (rule4->dst_len && (e->rule.has_dstaddr = true))
            e->rule.v4.dst = rule4->dst;
        if (rule4->src_len && (e->rule.has_srcaddr = true))
            e->rule.v4.src = rule4->src;
        if (rule4->dscp && (e->rule.has_dscp = true)) {
            if (is_dscp_full_supported()) {
                if (dscp_full4)
                    e->rule.dscp = rule4->dscp >> 2;
                else
                    e->rule.dscp = rule4->dscp;
            } else {
                e->rule.dscp = rule4->dscp >> 2;
            }
        }

    } else if (ops->family == AF_INET6) {

        // rule6 = (struct fib6_rule *) rule;
        rule6 = bpf_core_cast(rule, struct fib6_rule);
        e->type = RULE_V6;
        // bpf_printk("table: %d", rule6->common.table);

        if (rule6->dst.plen && (e->rule.has_dstaddr = true))
            __builtin_memcpy(e->rule.v6.dst, &rule6->dst.addr, sizeof(struct in6_addr));
        if (rule6->src.plen && (e->rule.has_srcaddr = true))
            __builtin_memcpy(e->rule.v6.src, &rule6->src.addr, sizeof(struct in6_addr));
        if (rule6->dscp && (e->rule.has_dscp = true)) {
            if (is_dscp_full_supported()) {
                if (dscp_full6)
                    e->rule.dscp = rule6->dscp >> 2;
                else
                    e->rule.dscp = rule6->dscp;
            } else {
                e->rule.dscp = rule6->dscp >> 2;
            }
        }
    } else {
        e->rule.invalid = true;
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

    struct fib_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct fib_event), 0);
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

    struct fib_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct fib_event), 0);
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

    struct fib_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct fib_event), 0);
    if (!e)
        return BPF_OK;

    construct_fib_rule_event(e, arg->rule, ops);
    e->success = (ret == 0);
    bpf_ringbuf_submit(e, 0);

    return BPF_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
