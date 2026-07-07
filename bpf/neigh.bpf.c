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

static void construct_neigh_event(struct tablesnoop_event *e, struct net_device *dev, const void *pkey,
                                  int family, struct neighbour *neigh, enum neigh_event_type event_type,
                                  unsigned char state, bool success)
{
    struct net *net = dev->nd_net.net;
    e->netns = net->net_cookie;
    e->type = NEIGH;
    e->success = success;
    e->neigh.event_type = event_type;
    e->neigh.state = state;
    e->neigh.dev_type = dev->type;
    __builtin_memcpy(e->neigh.dev, dev->name, IFNAMSIZ);
    e->neigh.family = family;

    if (family == AF_INET) {
        bpf_probe_read_kernel(&e->neigh.next_hop_addr.ip4, 4, pkey);
    } else if (family == AF_INET6) {
        bpf_probe_read_kernel(&e->neigh.next_hop_addr.ip6, 16, pkey);
    }

    if (neigh) {
        bpf_probe_read_kernel(e->neigh.mac, 6, neigh->ha);
    }
}

SEC("fexit/neigh_lookup")
int BPF_PROG(fexit_neigh_lookup, struct neigh_table *tbl, const void *pkey,
             struct net_device *dev, struct neighbour *ret)
{
    if (env.filter_netns && env.my_netns_cookie != dev->nd_net.net->net_cookie)
        return BPF_OK;

    struct tablesnoop_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct tablesnoop_event), 0);
    if (!e)
        return BPF_OK;
    __builtin_memset(e, 0, sizeof(*e));

    construct_neigh_event(e, dev, pkey, tbl->family, ret, NEIGH_LOOKUP,
                          ret ? ret->nud_state : 0, ret != NULL);
    bpf_ringbuf_submit(e, 0);

    return BPF_OK;
}

SEC("fexit/__neigh_create")
int BPF_PROG(fexit_neigh_create, struct neigh_table *tbl, const void *pkey,
		    struct net_device *dev, bool want_ref, struct neighbour *ret)
{
    if (env.filter_netns && env.my_netns_cookie != dev->nd_net.net->net_cookie)
        return BPF_OK;
    
    struct tablesnoop_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct tablesnoop_event), 0);
    if (!e)
        return BPF_OK;
    __builtin_memset(e, 0, sizeof(*e));

    construct_neigh_event(e, dev, pkey, tbl->family, ret, NEIGH_CREATE,
                          ret ? ret->nud_state : 0, ret != NULL);
    bpf_ringbuf_submit(e, 0);

    return BPF_OK;
}

SEC("fexit/neigh_destroy")
int BPF_PROG(fexit_neigh_destroy, struct neighbour *neigh)
{
    struct net_device *dev = neigh->dev;
    if (env.filter_netns && env.my_netns_cookie != dev->nd_net.net->net_cookie)
        return BPF_OK;

    struct tablesnoop_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct tablesnoop_event), 0);
    if (!e)
        return BPF_OK;
    __builtin_memset(e, 0, sizeof(*e));

    construct_neigh_event(e, dev, neigh->primary_key, neigh->tbl->family,
                          neigh, NEIGH_DESTROY, neigh->nud_state, true);
    bpf_ringbuf_submit(e, 0);

    return BPF_OK;
}

SEC("fexit/neigh_update")
int BPF_PROG(fexit_neigh_update, struct neighbour *neigh, const u8 *lladdr, u8 new,
		     u32 flags, u32 nlmsg_pid, int ret)
{
    struct net_device *dev = neigh->dev;
    if (env.filter_netns && env.my_netns_cookie != dev->nd_net.net->net_cookie)
        return BPF_OK;

    struct tablesnoop_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct tablesnoop_event), 0);
    if (!e)
        return BPF_OK;
    __builtin_memset(e, 0, sizeof(*e));

    construct_neigh_event(e, dev, neigh->primary_key, neigh->tbl->family,
                          neigh, NEIGH_UPDATE, new, ret == 0);
    bpf_ringbuf_submit(e, 0);

    return BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";
