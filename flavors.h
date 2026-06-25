#ifndef FLAVORS_H
#define FLAVORS_H

// flowi_common::flowic_tos was changed to flowic_dscp
//  1bec9d0c0046fe4e2bfb6a1c5aadcb5d56cdb0fb between 6.17-rc2 and 6.18-rc1
//  include/net/flow.h
struct flowi_common___pre6_18 {
        int     flowic_oif;
        int     flowic_iif;
        int     flowic_l3mdev;
        __u32   flowic_mark;
        __u8    flowic_tos; // this
        __u8    flowic_scope;
        __u8    flowic_proto;
        __u8    flowic_flags;
        __u32   flowic_secid;
        kuid_t  flowic_uid;
        __u32           flowic_multipath_hash;
        struct flowi_tunnel flowic_tun_key;
};

// flowi_common::flowic_tos renamed to flowic_dscp in 6.18+
struct flowi_common___post6_18 {
        int     flowic_oif;
        int     flowic_iif;
        int     flowic_l3mdev;
        __u32   flowic_mark;
        __u8    flowic_dscp;
        __u8    flowic_scope;
        __u8    flowic_proto;
        __u8    flowic_flags;
        __u32   flowic_secid;
        kuid_t  flowic_uid;
        __u32           flowic_multipath_hash;
        struct flowi_tunnel flowic_tun_key;
};

// fib4_rule::dscp_full was added
//  b9455fef8b1fc662369d982fe97dc66e6c332699 between v6.11-rc7 and v6.12-rc1
//  ipv4/fib_rules.c
struct fib4_rule___v6_12 {
            struct fib_rule         common;
        u8                      dst_len;
        u8                      src_len;
        dscp_t                  dscp;
        dscp_t                  dscp_mask;
        u8                      dscp_full:1;    /* DSCP or TOS selector */
        __be32                  src;
        __be32                  srcmask;
        __be32                  dst;
        __be32                  dstmask;
        u32                     tclassid;
};

// fib6_rule::dscp_full was added
//  2cf630034e4ebcc52e0b69b776cafd90dc4f3919 between v6.11-rc7 and v6.12-rc1
//  ipv6/fib6_rules.c
struct fib6_rule___v6_12 {
        struct fib_rule         common;
        struct rt6key           src;
        struct rt6key           dst;
        __be32                  flowlabel;
        __be32                  flowlabel_mask;
        dscp_t                  dscp;
        dscp_t                  dscp_mask;
        u8                      dscp_full:1;    /* DSCP or TOS selector */
};

#endif // FLAVORS_H
