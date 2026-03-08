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
#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

enum opts {
    OPT_ROUTES_ONLY = 256,
    OPT_RULES_ONLY
};

struct environment {
    struct array *netns_cache; //to avoid iterating procs over and over
    unsigned long original_netns; //kernel's struct net::net_cookie
    long originl_netns_fd; // = open(/proc/self/ns/net)
    bool separate_event_prints;
    bool v4only;
    bool v6only;
    bool global_netns;
    bool exiting;
    bool verbose;
    bool show_lookup_fails;
    bool filtered;
    bool routes_only;
    bool rules_only;
};

struct netns_item {
    unsigned int ino;
    unsigned long cookie;
    long pid;
};

enum event_type {
    FIB_V4,
    FIB_V6,
    RULE_V4,
    RULE_V6,
    SRV6_END,
};

union ip46addr {
    struct in_addr ip4;
    struct in6_addr ip6;
};

struct rule_data {
    bool invalid : 1;
    bool has_pref : 1;
    bool has_mark : 1;
    bool has_target : 1;
    bool has_l3mdev : 1;
    bool has_iifname : 1;
    bool has_oifname : 1;
    bool has_dstaddr : 1;
    bool has_srcaddr : 1;
    bool has_dscp : 1;
    bool has_goto : 1;

    unsigned mark;
    unsigned table;
    unsigned pref;
    unsigned goto_target;
    unsigned char family;
    unsigned char l3mdev;
    unsigned char dscp;
    char iifname[IFNAMSIZ];
    char oifname[IFNAMSIZ];
    union ip46addr src; // version is from event_type
    union ip46addr dst; // version is from event_type
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
    int oif; // End.X
    int vrf_table; // End.DT4 and End.DT46
    int flavor_ops; // PSP and CSID
    char csid_loc_bits;
    char csid_func_bits;
};

struct nexthop_data {
    char egress[IFNAMSIZ];
    int gw_family;
    union ip46addr gw;

    unsigned short lwt_type;
    int lwt_seg6_mode; // SEG6_IPTUN_MODE_XXX or SEG6_LOCAL_ACTION_XXX
    union {
        struct my_ipv6_sr_hdr lwt_seg6_hdr;
        struct seg6local_data lwt_seg6local_data;
    };
};

struct fib_data {
    struct nexthop_data nh;
    unsigned int table_id;
    unsigned int oif;
    unsigned int iif;
    unsigned char dscp;
    unsigned int flowlabel; // only for v6
    union ip46addr src; // version is from event_type
    union ip46addr dst; // version is from event_type
};

struct srv6_data {
    int action;
    struct seg6local_data seg6local;
};

// structure for kernelspace -> userspace messaging
// with BPF ringbuffer
struct fib_event {
    enum event_type type;
    unsigned long netns;
    union {
        struct fib_data fib;
        struct rule_data rule;
        struct srv6_data srv6;
    };
    bool success : 1;
};


#endif //_H_COMMON
