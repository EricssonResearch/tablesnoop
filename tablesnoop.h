#ifndef _H_TABLESNOOP
#define _H_TABLESNOOP

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "bpf/fib.skel.h"
#include "bpf/srv6.skel.h"
#include "bpf/mpls.skel.h"
#include "bpf/neigh.skel.h"
#include "bpf/fdb.skel.h"
#include "common.h"

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
    OPT_MPLS,
    OPT_SRV6,
    OPT_NEIGH,
    OPT_FDB,
};

enum feature_id {
    FEATURE_FIB,
    FEATURE_SRV6,
    FEATURE_MPLS,
    FEATURE_NEIGH,
    FEATURE_FDB,
    FEATURE_COUNT, // put new feature before this line
};

struct bpf_feature {
    const char *name;
    void *obj;
    void *(*open)(void);
    int (*load)(void *obj);
    int (*attach)(void *obj);
    void (*destroy)(void *obj);
    void (*set_env)(void *obj, struct environment *e);
    struct bpf_map *(*get_rb_map)(void *obj);
    unsigned show_flag;
    bool loaded;
};

// --- FIB wrappers ---
static void fib_set_env(void *obj, struct environment *e) {
    ((struct fib_bpf *)obj)->bss->env = *e;
}
static struct bpf_map *fib_get_rb_map(void *obj) {
    return ((struct fib_bpf *)obj)->maps.rb;
}

// --- SRV6 wrappers ---
static void srv6_set_env(void *obj, struct environment *e) {
    ((struct srv6_bpf *)obj)->bss->env = *e;
}
static struct bpf_map *srv6_get_rb_map(void *obj) {
    return ((struct srv6_bpf *)obj)->maps.rb;
}

// --- MPLS wrappers ---
static void mpls_set_env(void *obj, struct environment *e) {
    ((struct mpls_bpf *)obj)->bss->env = *e;
}
static struct bpf_map *mpls_get_rb_map(void *obj) {
    return ((struct mpls_bpf *)obj)->maps.rb;
}

// --- NEIGH wrappers ---
static void neigh_set_env(void *obj, struct environment *e) {
    ((struct neigh_bpf *)obj)->bss->env = *e;
}
static struct bpf_map *neigh_get_rb_map(void *obj) {
    return ((struct neigh_bpf *)obj)->maps.rb;
}

// --- FDB wrappers ---
static void fdb_set_env(void *obj, struct environment *e) {
    ((struct fdb_bpf *)obj)->bss->env = *e;
}
static struct bpf_map *fdb_get_rb_map(void *obj) {
    return ((struct fdb_bpf *)obj)->maps.rb;
}

static struct bpf_feature features[FEATURE_COUNT] = {
    [FEATURE_FIB] = {
        .name = "fib",
        .show_flag = SHOW_FIB4 | SHOW_FIB6 | SHOW_RULE4 | SHOW_RULE6,
        .open = (void *(*)(void))fib_bpf__open,
        .load = (int (*)(void *))fib_bpf__load,
        .attach = (int (*)(void *))fib_bpf__attach,
        .destroy = (void (*)(void *))fib_bpf__destroy,
        .set_env = fib_set_env,
        .get_rb_map = fib_get_rb_map,
    },
    [FEATURE_SRV6] = {
        .name = "srv6",
        .show_flag = SHOW_SRV6,
        .open = (void *(*)(void))srv6_bpf__open,
        .load = (int (*)(void *))srv6_bpf__load,
        .attach = (int (*)(void *))srv6_bpf__attach,
        .destroy = (void (*)(void *))srv6_bpf__destroy,
        .set_env = srv6_set_env,
        .get_rb_map = srv6_get_rb_map,
    },
    [FEATURE_MPLS] = {
        .name = "mpls",
        .show_flag = SHOW_MPLS,
        .open = (void *(*)(void))mpls_bpf__open,
        .load = (int (*)(void *))mpls_bpf__load,
        .attach = (int (*)(void *))mpls_bpf__attach,
        .destroy = (void (*)(void *))mpls_bpf__destroy,
        .set_env = mpls_set_env,
        .get_rb_map = mpls_get_rb_map,
    },
    [FEATURE_NEIGH] = {
        .name = "neigh",
        .show_flag = SHOW_NEIGH,
        .open = (void *(*)(void))neigh_bpf__open,
        .load = (int (*)(void *))neigh_bpf__load,
        .attach = (int (*)(void *))neigh_bpf__attach,
        .destroy = (void (*)(void *))neigh_bpf__destroy,
        .set_env = neigh_set_env,
        .get_rb_map = neigh_get_rb_map,
    },
    [FEATURE_FDB] = {
        .name = "fdb",
        .show_flag = SHOW_FDB,
        .open = (void *(*)(void))fdb_bpf__open,
        .load = (int (*)(void *))fdb_bpf__load,
        .attach = (int (*)(void *))fdb_bpf__attach,
        .destroy = (void (*)(void *))fdb_bpf__destroy,
        .set_env = fdb_set_env,
        .get_rb_map = fdb_get_rb_map,
    },
};

#endif //_H_TABLESNOOP