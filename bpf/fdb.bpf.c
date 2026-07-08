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

static void construct_fdb_event(struct tablesnoop_event *e, struct net_bridge *br, unsigned char *src_mac,
                                unsigned char *dst_mac, struct net_bridge_port *port, __u16 vid, bool origin,
                                bool success)
{
    e->type = FDB;
    e->netns = br->dev->nd_net.net->net_cookie;
    bpf_probe_read_kernel(e->fdb.src_mac, 6, src_mac);
    bpf_probe_read_kernel(e->fdb.dst_mac, 6, dst_mac);
    e->fdb.stp = br->stp_enabled;
    e->fdb.origin = origin;
    e->fdb.vid = vid;
    e->success = success;

    __builtin_memcpy(e->fdb.bridge, br->dev->name, IFNAMSIZ);
    if (port)
        __builtin_memcpy(e->fdb.port, port->dev->name, IFNAMSIZ);
}

SEC("fexit/__br_forward")
int BPF_PROG(fexit___br_forward, const struct net_bridge_port *to, struct sk_buff *skb, bool local_orig)
{
    struct net_bridge_port *port = (struct net_bridge_port *)to;
    struct net_bridge *br = port->br;
    if (env.filter_netns && env.my_netns_cookie != br->dev->nd_net.net->net_cookie)
        return BPF_OK;

    struct tablesnoop_event *e = bpf_ringbuf_reserve(&rb, sizeof(struct tablesnoop_event), 0);
    if (!e)
        return BPF_OK;
    __builtin_memset(e, 0, sizeof(*e));

    unsigned char src_mac[6];
    unsigned char dst_mac[6];
    struct ethhdr *eth = (struct ethhdr *)(skb->head + skb->mac_header);
    bpf_probe_read_kernel(src_mac, 6, eth->h_source);
    bpf_probe_read_kernel(dst_mac, 6, eth->h_dest);

    __u16 vid = skb->vlan_tci & 0x0FFF;

    construct_fdb_event(e, br, src_mac, dst_mac, port, vid, local_orig, true);

    bpf_ringbuf_submit(e, 0);
    return BPF_OK;
}

char LICENSE[] SEC("license") = "GPL";
