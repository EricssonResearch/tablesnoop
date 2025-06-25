#ifndef _H_COMMON
#define _H_COMMON

#include <stdbool.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ    16
#endif

#ifndef AF_INET
#define AF_INET     2   /* Internet IPv4 Protocol 	*/
#endif

#ifndef AF_INET6
#define AF_INET6    10  /* Internet IPv6 Protocol 	*/
#endif

// For console output coloring
// source: https://stackoverflow.com/a/23657072/3945980
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
    union {
        struct {
            unsigned dst;
            unsigned src;
        } v4;
        struct {
            // unsigned flowlabel; //Linux v6.14
            char dst[16];
            char src[16];
        } v6;
    };
};

struct nexthop_data {
    bool invalid;
    char egress[IFNAMSIZ];
    int type;
    int family;
    union {
        struct {
            unsigned int gw;
        } v4;
        struct {
            char gw[16];
        } v6;
    };
};

struct fib_data {
    struct nexthop_data nh;
    unsigned int table_id;
    unsigned int oif;
    unsigned int iif;
    unsigned char dscp;
    unsigned short sport;
    unsigned short dport;
    union {
        struct {
            unsigned int src;
            unsigned int dst;
        } v4;
        struct {
            unsigned int flowlabel;
            unsigned char src[16];
            unsigned char dst[16];
        } v6;
    };
};

// structure for kernelspace -> userspace messaging
// with BPF ringbuffer
struct fib_event {
    enum event_type type;
    unsigned long netns;
    union {
        struct fib_data fib;
        struct rule_data rule;
    };
    bool success : 1;
};

#endif //_H_COMMON
