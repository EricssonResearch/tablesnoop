#ifndef _H_COMMON
#define _H_COMMON

#include <stdbool.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ    16
#endif

#ifndef AF_UNSPEC
#define AF_UNSPEC   0
#endif

#ifndef AF_INET
#define AF_INET     2   /* Internet IPv4 Protocol 	*/
#endif

#ifndef AF_INET6
#define AF_INET6    10  /* Internet IPv6 Protocol 	*/
#endif

#ifndef SKB_DST_PTRMASK
#define SKB_DST_NOREF   1UL
#define SKB_DST_PTRMASK ~(SKB_DST_NOREF)
#endif

// For console output coloring
// source: https://stackoverflow.com/a/23657072/3945980
#define BLD   "\x1B[1m"
#define ITA   "\x1B[3m"
#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

enum opts {
    OPT_FIB4 = 500,
    OPT_FIB6,
    OPT_RULE4,
    OPT_RULE6,
    OPT_NEIGH,
    OPT_FDB,
};

#define SHOW_RULE4 0x01u
#define SHOW_RULE6 0x02u
#define SHOW_FIB4  0x04u
#define SHOW_FIB6  0x08u
#define SHOW_NEIGH 0x10u
#define SHOW_FDB   0x20u
#define SHOW_EVERYTHING 0xffffffffu

struct environment {
    unsigned long my_netns_cookie;
    bool filter_netns;
    unsigned show_events; // bitfield of SHOW_XXX
    bool show_lookup_fails;
};

struct netns_item {
    unsigned int ino;
    unsigned long cookie;
    long pid;
};

enum event_type {
    FIB_V4,
    FIB_V6,
    RULE,
    MPLS,
    NEIGH,
    FDB,
};

union ip46addr {
    struct in_addr ip4;
    struct in6_addr ip6;
};

struct rule_data {
    union ip46addr packet_src; // version is family
    union ip46addr packet_dst; // version is family

    int family;
    unsigned table;
    int err; // fib rule action return value: 0 == success, <0 == failure reason

    unsigned mark;
    unsigned pref;
    unsigned goto_target; //TODO this should always be 0
    unsigned char l3mdev;
    unsigned char dscp;
    char iifname[IFNAMSIZ];
    char oifname[IFNAMSIZ];
    union ip46addr src; // version is family
    union ip46addr dst; // version is family
    unsigned char src_len;
    unsigned char dst_len;
};

#define SRH_MAX_HOPS 10
// we need this to be slightly different from ipv6_sr_hdr
struct my_ipv6_sr_hdr {
        __u8    nexthdr;
        __u8    hdrlen;
        __u8    type;
        __u8    segments_left;
        __u8    first_segment; /* Represents the last_entry field of SRH */
        __u8    flags;
        __u16   tag;

        struct in6_addr segments[SRH_MAX_HOPS]; // this is [] in the original
};

// we don't need most of the stuff in struct seg6_local_lwt
struct seg6local_data {
    int table; // End.T
    struct in_addr nh4; // End.DX4
    struct in6_addr nh6; // End.DX6
    char oif[IFNAMSIZ]; // End.X
    int vrf_table; // End.DT4 and End.DT46
    int flavor_ops; // PSP and CSID
    char csid_loc_bits;
    char csid_func_bits;
};

#define MPLS_MAX_LABELS 5

struct mpls_encap_data {
    unsigned char labels;
    unsigned label[MPLS_MAX_LABELS];
};

struct nexthop_data {
    char dev[IFNAMSIZ]; // normally egress, for lwt it can be ingress
    int gw_family;
    union ip46addr gw;

    unsigned short lwt_type;
    int lwt_seg6_mode; // SEG6_IPTUN_MODE_XXX or SEG6_LOCAL_ACTION_XXX
    union {
        struct my_ipv6_sr_hdr lwt_seg6_hdr;
        struct seg6local_data lwt_seg6local_data;
        struct mpls_encap_data lwt_mpls_data;
    };
};

struct fib_data {
    // version is from event_type
    union ip46addr packet_src;
    union ip46addr packet_dst;
    char packet_oif[IFNAMSIZ]; //TODO this is always 0
    char packet_iif[IFNAMSIZ];
    unsigned char packet_dscp;
    unsigned int packet_flowlabel; // only for v6

    // always the same version as the packet
    union ip46addr fib_dst;
    unsigned char fib_prefixlen;
    unsigned int fib_table_id;

    struct nexthop_data nh;
};

// from net/mpls/internal.h (why isn't this in vmlinux.h?)
struct mpls_entry_decoded {
        unsigned int label;
        unsigned char ttl;
        unsigned char tc;
        unsigned char bos;
};

struct mpls_data {
    struct mpls_entry_decoded packet_label;

    unsigned label_stack[MPLS_MAX_LABELS];
    unsigned char label_count;
    unsigned char multipath_count;
    unsigned char via_len;
    union ip46addr via;
    char dev[IFNAMSIZ];
};

enum neigh_event_type {
    NEIGH_CREATE,
    NEIGH_UPDATE,
    NEIGH_DESTROY,
    NEIGH_LOOKUP,
};

struct neigh_data {
    enum neigh_event_type event_type;
    union ip46addr next_hop_addr;
    char dev[IFNAMSIZ];
    unsigned short dev_type;
    unsigned char mac[6];
    unsigned char family;
    unsigned char state;
};

struct fdb_data {
    char bridge[IFNAMSIZ];
    char port[IFNAMSIZ];
    unsigned char src_mac[6];
    unsigned char dst_mac[6];
    unsigned char stp;
    unsigned short vid;
    bool origin;
};

// structure for kernelspace -> userspace messaging
// with BPF ringbuffer
struct tablesnoop_event {
    enum event_type type;
    unsigned long netns;
    union {
        struct fib_data fib;
        struct rule_data rule;
        struct mpls_data mpls;
        struct neigh_data neigh;
        struct fdb_data fdb;
    };
    bool success : 1;
    bool cached : 1; // route came from a per-CPU dst_cache hit (no FIB lookup)
};


#endif //_H_COMMON
