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

/* (Per-CPU) temporary storage for fib events happening
 * between rule action fentry/fexits.
 * */
struct rule_ctx {
    bool in_rule_ctx;
    bool pending_fib;
    struct tablesnoop_event pending;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rule_ctx);
} rule_ctx_map SEC(".maps");

static __always_inline struct rule_ctx *get_rule_ctx(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&rule_ctx_map, &zero);
}

/* fib_table_lookup() do not have struct net argument, therefore
 * we have to find out the network namespace from the struct fib_table.
 * For that we reverted fib_get_table() and trace back the container struct net
 * from the routing table id. This is possible, since the hash bucket index
 * is table_id & (FIB_TABLE_HASHSZ - 1).
 *
 * Note: this only used for trace failed lookups. When the routing lookup
 * is successful, struct fib_result.table is valid and netns is there.
 * */
static const struct net *fib4_table_netns(const struct fib_table *table)
{
    const unsigned FIB_TABLE_HASHSZ = CONFIG_IP_MULTIPLE_TABLES ? 256 : 2;
    unsigned h = BPF_CORE_READ(table, tb_id) & (FIB_TABLE_HASHSZ - 1);

    struct list_head *netns_list =
        bpf_core_cast(&net_namespace_list, struct list_head);
    struct list_head *iter = netns_list->next;

    bpf_repeat(MAX_NETNS_COUNT) {

        void *net_ptr = container_of(iter, struct net, list);
        const struct net *net = bpf_core_cast(net_ptr, struct net);
        struct hlist_head *bucket = BPF_CORE_READ(net, ipv4.fib_table_hash);
        if (!bucket)
            return NULL;

        struct hlist_node *node = BPF_CORE_READ(bucket + h, first);
        bpf_repeat(FIB_TABLE_HASHSZ) {
            if (!node)
                break;
            if ((const void *) node == (const void *) table)
                return net;
            node = BPF_CORE_READ(node, next);
        }

        if (iter->next == netns_list) // circular
            break;
        iter = iter->next;
    }

    return 0;
}

static inline bool is_dscp_full_supported()
{
    if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(6, 12, 0))
        return true;
    return false;
}

static void construct_fib4_event(struct tablesnoop_event *e, const struct net *net,
                                 const struct fib_table *tb, const struct flowi4 *flp,
                                 const struct fib_result *res, int fib_flags, int ret)
{
    e->type = FIB_V4;
    e->netns = net->net_cookie;

    e->fib.fib_dst.ip4.s_addr = res->prefix;
    e->fib.fib_prefixlen = res->prefixlen;
    e->fib.fib_table_id = tb->tb_id;

    e->fib.packet_dst.ip4.s_addr = flp->daddr;
    e->fib.packet_src.ip4.s_addr = flp->saddr;
    get_ifname_netns(net, flp->__fl_common.flowic_oif, e->fib.packet_oif);
    get_ifname_netns(net, flp->__fl_common.flowic_iif, e->fib.packet_iif);
    struct flowi_common___pre6_18 *flowic_pre6_18  = (void*)&flp->__fl_common;
    struct flowi_common___post6_18 *flowic_post6_18 = (void*)&flp->__fl_common;
    if (bpf_core_field_exists(flowic_pre6_18->flowic_tos)) {
        e->fib.packet_dscp = flowic_pre6_18->flowic_tos >> 2; // TODO: DSCP is not correct?
    } else {
        e->fib.packet_dscp = flowic_post6_18->flowic_dscp >> 2;
    }

    construct_nexthop_data(net, &e->fib.nh, res->nhc);
}

static void construct_fib6_event(struct tablesnoop_event *e, const struct net *net,
                                 struct fib6_table *table, int oif, struct flowi6 *fl6,
                                 struct fib6_result *res, int strict, int ret)
{
    e->type = FIB_V6;
    e->netns = net->net_cookie;

    construct_fib6_route(e, net, res->f6i, res->nh, table);
    construct_fib6_packet(e, net, fl6->daddr, fl6->saddr, fl6->flowlabel,
                          fl6->__fl_common.flowic_iif, fl6->__fl_common.flowic_oif);
}

static void construct_fib_rule_event(struct tablesnoop_event *e, const struct flowi *fl,
        const struct fib_rule *rule, int family, const struct net *net)
{
    e->type = RULE;
    e->netns = net->net_cookie;

    e->rule.family = family;
    e->rule.table = rule ? rule->table : 0;

    if (family == AF_INET) {
        const struct flowi4 *fl4 = bpf_core_cast(fl, struct flowi4);
        e->rule.packet_src.ip4.s_addr = fl4->saddr;
        e->rule.packet_dst.ip4.s_addr = fl4->daddr;
    } else if (family == AF_INET6) {
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

    if (family == AF_INET) {
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

    } else if (family == AF_INET6) {
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

/* Called from fentry fib[46]_rule_action, to notify subseqeuent fib
 * table lookup call if called from the rule action context.
 * Uses a per-CPU flag to do that.
 */
static __always_inline void rule_action_enter(void)
{
    struct rule_ctx *ctx = get_rule_ctx();
    if (!ctx)
        return;
    ctx->in_rule_ctx = true;
    ctx->pending_fib = false;
}

/* Callend when fib[46]_rule_action returns.
* If there was a fib table lookup in between, we have a pending
* fib table event stored and it should be submitted to the ringbuf
* after the rule event. If has_pending=false there was no fib lookup
* and we only submit the rule event (if not filtered by the user)
*/
static __always_inline int rule_action_exit(struct fib_rule *rule, struct flowi *fl,
                                            int family, int ret)
{
    struct rule_ctx *ctx = get_rule_ctx();
    bool has_pending = false;

    if (ctx) {
        has_pending = ctx->pending_fib;
        ctx->in_rule_ctx = false;
        ctx->pending_fib = false;
    }

    struct net *net = rule->fr_net;
    // A flag, not an early return: even a filtered-out rule must still flush
    // the table event stashed below.
    bool show_rule = true;

    if (env.filter_netns && env.my_netns_cookie != net->net_cookie)
        show_rule = false;
    if (family == AF_INET && (env.show_events & SHOW_RULE4) == 0)
        show_rule = false;
    if (family == AF_INET6 && (env.show_events & SHOW_RULE6) == 0)
        show_rule = false;

    bool success = ret == 0;
    if (env.show_lookup_fails == false && success == false)
        show_rule = false;

    // Emit the rule event first, then the table lookup it triggered.
    if (show_rule) {
        struct tablesnoop_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct tablesnoop_event), 0);
        if (e) {
            __builtin_memset(e, 0, sizeof(*e));
            construct_fib_rule_event(e, fl, rule, family, net);
            e->success = success;
            e->rule.err = ret;
            bpf_ringbuf_submit(e, 0);
        }
    }

    // Stashed table event was already filtered, so emit it unconditionally.
    if (ctx && has_pending) {
        struct tablesnoop_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct tablesnoop_event), 0);
        if (e) {
            __builtin_memcpy(e, &ctx->pending, sizeof(*e));
            bpf_ringbuf_submit(e, 0);
        }
    }

    return BPF_OK;
}

SEC("fexit/fib_table_lookup")
int BPF_PROG(fexit_fib_table_lookup, struct fib_table *tb, const struct flowi4 *flp,
             struct fib_result *res, int fib_flags, int ret)
{
    if ((env.show_events & SHOW_FIB4) == 0)
        return BPF_OK;
    // bpf_printk("fib4 lookup %d", ret);

    bool success = res->table != NULL;
    if (env.show_lookup_fails == false && success == false)
        return BPF_OK;

    struct net *netns;
    if (success)
        netns = bpf_core_cast(BPF_CORE_READ(res, fi, fib_net), struct net);
    else
        netns = bpf_core_cast(fib4_table_netns(tb), struct net);

    if (env.filter_netns && env.my_netns_cookie != netns->net_cookie)
        return BPF_OK;

    // Called from rule action context, store the event without submitting
    struct rule_ctx *rctx = get_rule_ctx();
    if (rctx && rctx->in_rule_ctx) {
        __builtin_memset(&rctx->pending, 0, sizeof(rctx->pending));
        construct_fib4_event(&rctx->pending, netns, tb, flp, res, fib_flags, ret);
        rctx->pending.success = success;
        rctx->pending_fib = true;
        return BPF_OK;
    }

    struct tablesnoop_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct tablesnoop_event), 0);
    if (!e)
        return BPF_OK;
    __builtin_memset(e, 0, sizeof(*e));

    construct_fib4_event(e, netns, tb, flp, res, fib_flags, ret);
    e->success = success;
    bpf_ringbuf_submit(e, 0);
    return BPF_OK;
}


SEC("fexit/fib6_table_lookup")
int BPF_PROG(fexit_fib6_table_lookup, struct net *net, struct fib6_table *table, int oif,
             struct flowi6 *fl6, struct fib6_result *res, int strict, int ret)
{
    if (env.filter_netns && env.my_netns_cookie != net->net_cookie)
        return BPF_OK;

    if ((env.show_events & SHOW_FIB6) == 0)
        return BPF_OK;
    // bpf_printk("fib6 lookup %d", ret);

    bool success = res->f6i != net->ipv6.fib6_null_entry;
    if (env.show_lookup_fails == false && success == false)
        return BPF_OK;

    // Called from rule action context, store the event without submitting
    struct rule_ctx *rctx = get_rule_ctx();
    if (rctx && rctx->in_rule_ctx) {
        __builtin_memset(&rctx->pending, 0, sizeof(rctx->pending));
        construct_fib6_event(&rctx->pending, net, table, oif, fl6, res, strict, ret);
        rctx->pending.success = success;
        rctx->pending_fib = true;
        return BPF_OK;
    }

    struct tablesnoop_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct tablesnoop_event), 0);
    if (!e)
        return BPF_OK;
    __builtin_memset(e, 0, sizeof(*e));

    construct_fib6_event(e, net, table, oif, fl6, res, strict, ret);
    e->success = success;
    bpf_ringbuf_submit(e, 0);
    return BPF_OK;
}

SEC("fentry/fib4_rule_action")
int BPF_PROG(fentry_fib4_rule_action, struct fib_rule *rule, struct flowi *flp,
             int flags, struct fib_lookup_arg *arg)
{
    rule_action_enter();
    return BPF_OK;
}

SEC("fexit/fib4_rule_action")
int BPF_PROG(fexit_fib4_rule_action, struct fib_rule *rule, struct flowi *flp,
             int flags, struct fib_lookup_arg *arg, int ret)
{
    return rule_action_exit(rule, flp, AF_INET, ret);
}

SEC("fentry/fib6_rule_action")
int BPF_PROG(fentry_fib6_rule_action, struct fib_rule *rule, struct flowi *flp,
             int flags, struct fib_lookup_arg *arg)
{
    rule_action_enter();
    return BPF_OK;
}

SEC("fexit/fib6_rule_action")
int BPF_PROG(fexit_fib6_rule_action, struct fib_rule *rule, struct flowi *flp,
             int flags, struct fib_lookup_arg *arg, int ret)
{
    return rule_action_exit(rule, flp, AF_INET6, ret);
}

char LICENSE[] SEC("license") = "GPL";