#!/usr/bin/env bash
#
# lookup_test.sh — build a 6-namespace routed chain, no root required.
#
#   [na] --ethAB|ethBA-- [nb] --ethBC|ethCB-- [nc] --ethCD|ethDC-- [nd] --ethDE|ethED-- [ne] --ethEF|ethFE-- [nf]
#    .1                   .2  .2               .3  .3               .4  .4               .5  .5                .x
#  fd01::1            fd01::2 fd02::2      fd02::3 fd03::3      fd03::4 fd04::4      fd04::5 fd05::5        fd05::x
#  10.0.1.1         10.0.1.2 10.0.2.2    10.0.2.3 10.0.3.3    10.0.3.4 10.0.4.4    10.0.4.5 10.0.5.5      10.0.5.x
#
# Usage:
#   ./lookup_test.sh [base|mpls|srv6]            # set up, then drop into a shell
#   ./lookup_test.sh [base|mpls|srv6] CMD...     # set up, run CMD, tear down
#   ./lookup_test.sh [base|mpls|srv6] run        # set up, run all scenarios, tear down
#
# Modes:
#   base   plain IPv4+IPv6 forwarding along the chain (na <-> nf reachable)
#   mpls   MPLS routing / label stacking / tc label ops
#   srv6   SRv6 End / End.DT* / End.DX* / CSID / PSP
# The default mode is "srv6".
#
# Inside the shell / for CMD, six helper functions run a command in a netns:
#   na <cmd...>  nb <cmd...>  nc <cmd...>  nd <cmd...>  ne <cmd...>  nf <cmd...>
# e.g.   na ping -c1 fd05::61
#        na ping -c1 10.0.5.61
#        ne ip -6 -s route
#
# NOTE: MPLS needs the mpls_router / mpls_iptunnel kernel modules and SRv6 needs
# IPV6_SEG6_LWTUNNEL. Loading kernel modules requires real privileges; if the
# modules are not already present an unprivileged userns cannot autoload them,
# and the corresponding mode commands will warn and be skipped.
#
set -euo pipefail

# Stage 0 (host): re-exec ourselves inside an unprivileged user+net namespace.
if [ "${1:-}" != "__inside" ]; then
    if ! unshare --user --map-root-user --net true 2>/dev/null; then
        echo "error: unprivileged user namespaces (with --net) are not available." >&2
        echo "       enable them, e.g.:" >&2
        echo "         sudo sysctl -w kernel.unprivileged_userns_clone=1   # Debian/Ubuntu" >&2
        echo "         sudo sysctl -w user.max_user_namespaces=10000" >&2
        exit 1
    fi
    exec unshare --user --map-root-user --net -- bash "$0" __inside "$@"
fi
shift   # drop the __inside sentinel; "$@" now holds [mode] [command...]

# Select the topology mode (default: srv6).
MODE="srv6"
case "${1:-}" in
    base|mpls|srv6) MODE="$1"; shift ;;
esac

# Stage 1 (inside userns): we are uid 0 here and own this network namespace,
# so we hold CAP_NET_ADMIN over it and over any netns we create below.
export PATH="/usr/sbin:/sbin:$PATH"
for tool in ip nsenter; do
    command -v "$tool" >/dev/null || { echo "error: '$tool' not found" >&2; exit 1; }
done

# Spawn a placeholder process in a fresh netns and echo its PID once the
# unshare(NEWNET) has actually taken effect (its net ns must differ from ours).
new_netns() {
    unshare --net -- sleep infinity >/dev/null 2>&1 &
    local pid=$! mynet
    mynet=$(readlink "/proc/self/ns/net")
    for _ in $(seq 1 100); do
        local p
        p=$(readlink "/proc/$pid/ns/net" 2>/dev/null || true)
        [ -n "$p" ] && [ "$p" != "$mynet" ] && { echo "$pid"; return 0; }
        sleep 0.05
    done
    echo "error: timed out creating network namespace" >&2
    return 1
}

PID_NA=$(new_netns)
PID_NB=$(new_netns)
PID_NC=$(new_netns)
PID_ND=$(new_netns)
PID_NE=$(new_netns)
PID_NF=$(new_netns)

cleanup() {
    kill "$PID_NA" "$PID_NB" "$PID_NC" "$PID_ND" "$PID_NE" "$PID_NF" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

ns_exec() { nsenter --net="/proc/$1/ns/net" "${@:2}"; }
na() { ns_exec "$PID_NA" "$@"; }
nb() { ns_exec "$PID_NB" "$@"; }
nc() { ns_exec "$PID_NC" "$@"; }
nd() { ns_exec "$PID_ND" "$@"; }
ne() { ns_exec "$PID_NE" "$@"; }
nf() { ns_exec "$PID_NF" "$@"; }

# Wire up the veths. Pairs are created here (the controller netns) and each end
# is pushed into its target netns by PID.
add_link() {  # add_link <ifA> <pidA> <ifB> <pidB>
    ip link add "$1" type veth peer name "$3"
    ip link set "$1" netns "$2"
    ip link set "$3" netns "$4"
}
add_link ethAB "$PID_NA" ethBA "$PID_NB"
add_link ethBC "$PID_NB" ethCB "$PID_NC"
add_link ethCD "$PID_NC" ethDC "$PID_ND"
add_link ethDE "$PID_ND" ethED "$PID_NE"
add_link ethEF "$PID_NE" ethFE "$PID_NF"

# Bring up loopbacks and the chain interfaces.
for h in na nb nc nd ne nf; do "$h" ip link set lo up; done
na ip link set ethAB up
nb ip link set ethBA up; nb ip link set ethBC up
nc ip link set ethCB up; nc ip link set ethCD up
nd ip link set ethDC up; nd ip link set ethDE up
ne ip link set ethED up; ne ip link set ethEF up
nf ip link set ethFE up

# IPv6
na ip addr add fd01::1/64 dev ethAB nodad
nb ip addr add fd01::2/64 dev ethBA nodad
nb ip addr add fd02::2/64 dev ethBC nodad
nc ip addr add fd02::3/64 dev ethCB nodad
nc ip addr add fd03::3/64 dev ethCD nodad
nd ip addr add fd03::4/64 dev ethDC nodad
nd ip addr add fd04::4/64 dev ethDE nodad
ne ip addr add fd04::5/64 dev ethED nodad
ne ip addr add fd05::5/64 dev ethEF nodad
# IPv4
na ip addr add 10.0.1.1/24 dev ethAB
nb ip addr add 10.0.1.2/24 dev ethBA
nb ip addr add 10.0.2.2/24 dev ethBC
nc ip addr add 10.0.2.3/24 dev ethCB
nc ip addr add 10.0.3.3/24 dev ethCD
nd ip addr add 10.0.3.4/24 dev ethDC
nd ip addr add 10.0.4.4/24 dev ethDE
ne ip addr add 10.0.4.5/24 dev ethED
ne ip addr add 10.0.5.5/24 dev ethEF

# Mode-specific configuration may depend on optional kernel features (MPLS
# modules, SRv6 lwtunnel, VRF, ...). The whole mode block runs with errexit
# relaxed (see below) so one failing command (e.g. a missing kernel feature)
# does not tear down the rest of the chain.

# ---------------------------------------------------------------------------
setup_base() {
    # plain forwarding along the chain in both families
    for h in nb nc nd ne; do
        "$h" sysctl -wq net.ipv4.ip_forward=1
        "$h" sysctl -wq net.ipv6.conf.all.forwarding=1
    done
    nf ip addr add fd05::6/64 dev ethFE nodad
    nf ip addr add 10.0.5.6/24 dev ethFE
    # forward routes toward nf's subnet (10.0.5.0/24 / fd05::/64) along the chain
    # (ne is directly connected to it)
    na ip route    add 10.0.5.0/24 via 10.0.1.2 dev ethAB
    nb ip route    add 10.0.5.0/24 via 10.0.2.3 dev ethBC
    nc ip route    add 10.0.5.0/24 via 10.0.3.4 dev ethCD
    nd ip route    add 10.0.5.0/24 via 10.0.4.5 dev ethDE
    na ip -6 route add fd05::/16    via fd01::2  dev ethAB
    nb ip -6 route add fd05::/16    via fd02::3  dev ethBC
    nc ip -6 route add fd05::/16    via fd03::4  dev ethCD
    nd ip -6 route add fd05::/16    via fd04::5  dev ethDE
    # reverse default routes nf -> na
    nf ip route    add default via 10.0.5.5 dev ethFE
    ne ip route    add default via 10.0.4.4 dev ethED
    nd ip route    add default via 10.0.3.3 dev ethDC
    nc ip route    add default via 10.0.2.2 dev ethCB
    nf ip -6 route add default via fd05::5 dev ethFE
    ne ip -6 route add default via fd04::4 dev ethED
    nd ip -6 route add default via fd03::3 dev ethDC
    nc ip -6 route add default via fd02::2 dev ethCB
    # disable rp_filter for the asymmetric IPv4 reverse path
    ne sysctl -wq net.ipv4.conf.ethEF.rp_filter=0
    nd sysctl -wq net.ipv4.conf.ethDE.rp_filter=0
    nc sysctl -wq net.ipv4.conf.ethCD.rp_filter=0
    nb sysctl -wq net.ipv4.conf.ethBC.rp_filter=0
}

# ---------------------------------------------------------------------------
# The MPLS modes need mpls_router (exposes the net.mpls.* sysctls and does the
# label routing) and mpls_iptunnel (provides the 'encap mpls' route support).
# These cannot be autoloaded from an unprivileged user namespace, so check that
# they are already present on the host before attempting any MPLS setup.
mpls_modules_loaded() {
    [ -d /proc/sys/net/mpls ] && [ -d /sys/module/mpls_iptunnel ]
}

# MPLS configuration.
setup_mpls() {
    if ! mpls_modules_loaded; then
        echo "warning: MPLS kernel modules are not loaded; skipping MPLS setup." >&2
        echo "         load them on the host (needs root) with:" >&2
        echo "           sudo modprobe mpls_router mpls_iptunnel" >&2
        echo "         an unprivileged user namespace cannot autoload them." >&2
        return 0
    fi

    # platform_labels is the highest label value allowed; enable MPLS input on
    # the ingress side of each transit/egress node.
    nb sysctl -wq net.mpls.platform_labels=10000
    nb sysctl -wq net.mpls.conf.ethBA.input=1
    nc sysctl -wq net.mpls.platform_labels=10000
    nc sysctl -wq net.mpls.conf.ethCB.input=1
    nd sysctl -wq net.mpls.platform_labels=10000
    nd sysctl -wq net.mpls.conf.ethDC.input=1
    ne sysctl -wq net.mpls.platform_labels=10000
    ne sysctl -wq net.mpls.conf.ethED.input=1

    # common routing on na toward nf
    na ip route    add 10.0.5.0/24 via 10.0.1.2 dev ethAB
    na ip -6 route add fd05::/16   via fd01::2  dev ethAB

    # ingress qdiscs for the tc-based examples
    nb tc qdisc add dev ethBA ingress
    nc tc qdisc add dev ethCB ingress
    nd tc qdisc add dev ethDC ingress
    ne tc qdisc add dev ethED ingress

    # 1. MPLS Routing (dual-stack tunnel, decap detects the IP version)
    #    The `via xxx` is only used for interface selection and MAC resolve.
    #    We can use `via inet` or `via inet6` independently of the user traffic.
    #    TTL: each hop decreases regardless of the label swapping.
    #    na ping 10.0.5.61
    #    na ping fd05::61
    nf ip addr add 10.0.5.61/24 dev ethFE
    nf ip addr add fd05::61/64  dev ethFE
    nb ip route    add 10.0.5.61/32  encap mpls 161 via inet  10.0.2.3
    nb ip -6 route add fd05::61/128  encap mpls 161 via inet6 fd02::3
    nc ip -f mpls route add 161 as 261 via inet6 fd03::4
    nd ip -f mpls route add 261 as 361 via inet6 fd04::5
    ne ip -f mpls route add 361        via inet6 fd05::61

    # 2. Label stacking with MPLS Routing
    #    Encap can add multiple labels with `mpls x/y/z`.
    #    Route can only match on the first label.
    #    Using `as x/y/z` replaces the first label with the given stack.
    #    Without `as x` the first label is popped.
    #    It cannot pop more than one label at once.
    #    na ping 10.0.5.62 ; na ping fd05::62
    nf ip addr add 10.0.5.62/24 dev ethFE
    nf ip addr add fd05::62/64  dev ethFE
    nb ip route    add 10.0.5.62/32 encap mpls 162/1162 via inet  10.0.2.3
    nb ip -6 route add fd05::62/128 encap mpls 162/1162 via inet6 fd02::3
    nc ip -f mpls route add 162 as 262 via inet6 fd03::4
    nd ip -f mpls route add 262        via inet6 fd04::5
    ne ip -f mpls route add 1162       via inet6 fd05::62

    # 3. Label swapping with Traffic Control (IPv6 only — pop needs a protocol)
    #    Note that we still need the routing, tc can only do the label manipulation.
    #    TTL: routing decreases it
    #    na ping fd05::63
    nf ip addr add fd05::63/64 dev ethFE
    nb tc filter add dev ethBA ingress protocol ipv6 flower dst_ip fd05::63/128 action mpls push label 163
    nb ip -f mpls route add 163 as 163 via inet6 fd02::3
    nc tc filter add dev ethCB ingress protocol mpls_uc flower mpls_label 163 action mpls modify label 263
    nc ip -f mpls route add 263 as 263 via inet6 fd03::4
    nd tc filter add dev ethDC ingress protocol mpls_uc flower mpls_label 263 action mpls modify label 363
    nd ip -f mpls route add 363 as 363 via inet6 fd04::5
    ne tc filter add dev ethED ingress protocol mpls_uc flower mpls_label 363 action mpls pop protocol ipv6

    # 4. Label stacking with Traffic Control (dual-stack via a service label)
    #    na ping 10.0.5.64 ; na ping fd05::64
    nf ip addr add 10.0.5.64/24 dev ethFE
    nf ip addr add fd05::64/64  dev ethFE
    nb tc filter add dev ethBA ingress protocol ipv4 flower dst_ip 10.0.5.64/32 action mpls push label 400 action mpls push label 164
    nb tc filter add dev ethBA ingress protocol ipv6 flower dst_ip fd05::64/128 action mpls push label 600 action mpls push label 164
    nb ip -f mpls route add 164 as 164 via inet6 fd02::3
    nc tc filter add dev ethCB ingress protocol mpls_uc flower mpls_label 164 action mpls push label 264
    nc ip -f mpls route add 264 as 264 via inet6 fd03::4
    nd tc filter add dev ethDC ingress protocol mpls_uc flower mpls lse depth 1 label 264 lse depth 2 label 164 action mpls pop protocol mpls_uc action mpls pop protocol mpls_uc action mpls push label 364
    nd ip -f mpls route add 364 as 364 via inet6 fd04::5
    ne tc filter add dev ethED ingress protocol mpls_uc flower mpls lse depth 1 label 364 lse depth 2 label 400 bos 1 action mpls pop protocol mpls_uc action mpls pop protocol ipv4
    ne tc filter add dev ethED ingress protocol mpls_uc flower mpls lse depth 1 label 364 lse depth 2 label 600 bos 1 action mpls pop protocol mpls_uc action mpls pop protocol ipv6

    # reverse route for the reply
    nf ip -6 route add fd01::/64    via fd05::5  dev ethFE
    ne ip -6 route add fd01::/64    via fd04::4  dev ethED
    nd ip -6 route add fd01::/64    via fd03::3  dev ethDC
    nc ip -6 route add fd01::/64    via fd02::2  dev ethCB
    nf ip route    add 10.0.1.0/24  via 10.0.5.5 dev ethFE
    ne ip route    add 10.0.1.0/24  via 10.0.4.4 dev ethED
    nd ip route    add 10.0.1.0/24  via 10.0.3.3 dev ethDC
    nc ip route    add 10.0.1.0/24  via 10.0.2.2 dev ethCB
    # disable Reverse Path Forwarding for the reverse IPv4 traffic
    ne sysctl -wq net.ipv4.conf.ethEF.rp_filter=0
    nd sysctl -wq net.ipv4.conf.ethDE.rp_filter=0
    nc sysctl -wq net.ipv4.conf.ethCD.rp_filter=0
    nb sysctl -wq net.ipv4.conf.ethBC.rp_filter=0
    # manually enable IPv6 forwarding for the reverse traffic
    nb sysctl -wq net.ipv6.conf.all.forwarding=1
    nc sysctl -wq net.ipv6.conf.all.forwarding=1
    nd sysctl -wq net.ipv6.conf.all.forwarding=1
    ne sysctl -wq net.ipv6.conf.all.forwarding=1
    # enable IPv4 forwarding so the plain-IPv4 replies can travel the chain back
    # to na
    for h in nb nc nd ne; do "$h" sysctl -wq net.ipv4.ip_forward=1; done
}

# ---------------------------------------------------------------------------
# SRv6 configuration.
setup_srv6() {
    # enable seg6 + forwarding for the na->nf direction (need 'all' AND per-if)
    for h in na nb nc nd ne nf; do
        "$h" sysctl -wq net.ipv6.conf.all.forwarding=1
        "$h" sysctl -wq net.ipv6.conf.all.seg6_enabled=1
    done
    # automatic SRv6 End processing on the intermediate hops (ingress side)
    nb sysctl -wq net.ipv6.conf.ethBA.seg6_enabled=1
    nc sysctl -wq net.ipv6.conf.ethCB.seg6_enabled=1
    nd sysctl -wq net.ipv6.conf.ethDC.seg6_enabled=1
    ne sysctl -wq net.ipv6.conf.ethED.seg6_enabled=1
    nf sysctl -wq net.ipv6.conf.ethFE.seg6_enabled=1
    # IPv4 forwarding on the transit nodes so decapsulated/replied IPv4 (e.g.
    # End.DX4/End.DT46) can travel the chain back to na
    for h in nb nc nd ne; do "$h" sysctl -wq net.ipv4.ip_forward=1; done

    # 1. Automatic End.DT46 (tunnel ends at an existing address of ne)
    #   If the destination address exists on the node and seg6_enabled=1
    #    - segments_left>0 we get End (behaves like normal source routing)
    #    - segments_left=0 we get End.DT46
    #    na ping fd05::61
    #    na ping 10.0.5.61
    nf ip addr add fd05::61/64  dev ethFE
    nf ip addr add 10.0.5.61/24 dev ethFE
    na ip -6 route add fd05::61/128  encap seg6 mode encap segs fd01::2,fd02::3,fd03::4,fd04::5 dev ethAB
    na ip route    add 10.0.5.61/32  encap seg6 mode encap segs fd01::2,fd02::3,fd03::4,fd04::5 dev ethAB

    # 2. End.DT6 with lwtunnel (tunnel ends at a non-existing address of ne)
    #    We are using the RFC 9602 address range 5f00::/16 allocated to SRv6 SID.
    #    The intermediate hops still use the automatic source routing.
    #    Note that we must advertise this non-existing address so nd knows about it.
    #    na ping fd05::62
    nf ip addr add fd05::62/64 dev ethFE
    na ip -6 route add fd05::62/128   encap seg6 mode encap segs fd01::2,fd02::3,fd03::4,5f00:4::52 dev ethAB
    nd ip -6 route add 5f00:4::52/128 via fd04::5 dev ethDE
    ne ip -6 route add 5f00:4::52/128 encap seg6local action End.DT6 count table main dev ethED

    # 3. End.DT46 with lwtunnel
    #    This one and End.DT4 can only output onto a VRF.
    #    na ping fd05::63
    #    na ping 10.0.5.63
    nf ip addr add fd05::63/64  dev ethFE
    nf ip addr add 10.0.5.63/24 dev ethFE
    na ip -6 route add fd05::63/128   encap seg6 mode encap segs fd01::2,fd02::3,fd03::4,5f00:4::53 dev ethAB
    na ip route    add 10.0.5.63/32   encap seg6 mode encap segs fd01::2,fd02::3,fd03::4,5f00:4::53 dev ethAB
    nd ip -6 route add 5f00:4::53/128 via fd04::5 dev ethDE
    ne ip link add name vrf100 type vrf table 100
    ne ip route add table 100 unreachable default metric 1000000
    ne ip link set up dev vrf100
    ne sysctl -wq net.vrf.strict_mode=1
    ne ip -6 route add 5f00:4::53/128 encap seg6local action End.DT46 count vrftable 100 dev vrf100
    ne ip route    add 10.0.5.63/32 dev ethEF table 100

    # 4. End.DX6 with lwtunnel
    #    na ping fd05::64
    nf ip addr add fd05::64/64 dev ethFE
    na ip -6 route add fd05::64/128   encap seg6 mode encap segs fd01::2,fd02::3,fd03::4,5f00:4::54 dev ethAB
    nd ip -6 route add 5f00:4::54/128 via fd04::5 dev ethDE
    ne ip -6 route add 5f00:4::54/128 encap seg6local action End.DX6 count nh6 fd05::64 dev ethED

    # 5. End.DX4 with lwtunnel
    #    na ping 10.0.5.65
    nf ip addr add 10.0.5.65/24 dev ethFE
    na ip route    add 10.0.5.65/32   encap seg6 mode encap segs fd01::2,fd02::3,fd03::4,5f00:4::55 dev ethAB
    nd ip -6 route add 5f00:4::55/128 via fd04::5 dev ethDE
    ne ip -6 route add 5f00:4::55/128 encap seg6local action End.DX4 count nh4 10.0.5.65 dev ethED

    # 6. End.DX2 with lwtunnel (L2; encapsulate on nb, MAC must match ethBA/ethFE)
    #    This one does not work for locally originated packets, so we encapsulate on nb.
    #    The MAC address handling is tricky. The DMAC of the packet sent by na must be
    #    the one on ethBA or it won't be accepted and directed into the tunnel. Also, it
    #    must be the one on ethFE, or it won't answer the ping request.
    #    The kernel selftest solves this by seting the end host MAC on the tunnel entrace.
    #    Note that this is not a true L2 tunnel, as it captures traffic on IP level, and
    #    for example ARP doesn't enter the tunnel.
    #    na ping fd05::66
    #    na ping 10.0.5.66
    nf ip addr add fd05::66/64  dev ethFE
    nf ip addr add 10.0.5.66/24 dev ethFE
    nf ip link set address 0:5:0:0:0:6 dev ethFE
    nb ip link set address 0:5:0:0:0:6 dev ethBA
    na ip -6 route add fd05::66/128 via fd01::2 dev ethAB
    na ip route    add 10.0.5.66/32 via 10.0.1.2 dev ethAB
    nb ip -6 route add fd05::66/128   encap seg6 mode l2encap segs fd02::3,fd03::4,5f00:4::56 dev ethBA
    nb ip route    add 10.0.5.66/32   encap seg6 mode l2encap segs fd02::3,fd03::4,5f00:4::56 dev ethBA
    nd ip -6 route add 5f00:4::56/128 via fd04::5 dev ethDE
    ne ip -6 route add 5f00:4::56/128 encap seg6local action End.DX2 count oif ethEF dev ethED

    # 7. End.DT46 with Reduced segment list (Linux 6.0+)
    #    Same as #2 but without adding the first hop to the SRH.
    #    Note that normal IPv6 routing header processing rejects this SRH on nb,
    #    we have to configure a SID with an End behavior for processing.
    #    na ping fd05::67
    #    na ping 10.0.5.67
    nf ip addr add fd05::67/64  dev ethFE
    nf ip addr add 10.0.5.67/24 dev ethFE
    na ip -6 route add 5f00:1::27/128 via fd01::2 dev ethAB
    nb ip -6 route add 5f00:2::37/128 via fd02::3 dev ethBC
    nc ip -6 route add 5f00:3::47/128 via fd03::4 dev ethCD
    nd ip -6 route add 5f00:4::57/128 via fd04::5 dev ethDE
    na ip -6 route add fd05::67/128 encap seg6 mode encap.red segs 5f00:1::27,5f00:2::37,5f00:3::47,5f00:4::57 dev ethAB
    na ip route    add 10.0.5.67/32 encap seg6 mode encap.red segs 5f00:1::27,5f00:2::37,5f00:3::47,5f00:4::57 dev ethAB
    nb ip -6 route add 5f00:1::27/128 encap seg6local action End count dev ethBA
    nc ip -6 route add 5f00:2::37/128 encap seg6local action End count dev ethCB
    nd ip -6 route add 5f00:3::47/128 encap seg6local action End count dev ethDC
    ne ip -6 route add 5f00:4::57/128 encap seg6local action End.DT46 count vrftable 100 dev vrf100
    ne ip route    add 10.0.5.67/32 dev ethEF table 100

    # 8. End.DT46 with Compressed SID (Linux 6.1+)
    #    This one encodes multiple steps in one IPv6 address with a locator of `lblen` bits
    #    and segments of `nflen` bits. On each hop one segment is shifted out of the segment
    #    list by the End behavior, and we can route the packet based on the first `lblen+nflen` bits.
    #    This can also be combined with Red to decrease the overhead even further.
    #    We need a seg6local End on each hop to advance the CSID list.
    #    na ping fd05::68
    #    na ping 10.0.5.68
    nf ip addr add fd05::68/64  dev ethFE
    nf ip addr add 10.0.5.68/24 dev ethFE
    na ip -6 route add fd05::68/128 encap seg6 mode encap.red segs 5f00:68:0102:0203:0304:0405:: dev ethAB
    na ip route    add 10.0.5.68/32 encap seg6 mode encap     segs 5f00:68:0102:0203:0304:0405:: dev ethAB
    na ip -6 route add 5f00:68:0102::/48 via fd01::2 dev ethAB
    nb ip -6 route add 5f00:68:0102::/48 encap seg6local action End count flavors next-csid lblen 32 nflen 16 dev ethBA
    nb ip -6 route add 5f00:68:0203::/48 via fd02::3 dev ethBC
    nc ip -6 route add 5f00:68:0203::/48 encap seg6local action End count flavors next-csid lblen 32 nflen 16 dev ethCB
    nc ip -6 route add 5f00:68:0304::/48 via fd03::4 dev ethCD
    nd ip -6 route add 5f00:68:0304::/48 encap seg6local action End count flavors next-csid lblen 32 nflen 16 dev ethDC
    nd ip -6 route add 5f00:68:0405::/48 via fd04::5 dev ethDE
    ne ip -6 route add 5f00:68:0405::/48 encap seg6local action End.DT46 count vrftable 100 dev vrf100
    ne ip route    add 10.0.5.68/32 dev ethEF table 100

    # 9. Inline with "flavor psp" on ne to remove the SRH (Linux 6.3+)
    #    With inline we don't add an outer IPv6 header, just the SRH. On ne the
    #    Penultimate Segment Pop flavor removes the SRH before handing over to nf.
    #    Note that the response from nf would be the same if we didn't have the PSP.
    #    na ping fd05::69
    nf ip addr add fd05::69/64 dev ethFE
    na ip -6 route add fd05::69/128   encap seg6 mode inline segs fd01::2,fd02::3,fd03::4,5f00:4::59 dev ethAB
    nd ip -6 route add 5f00:4::59/128 via fd04::5 dev ethDE
    ne ip -6 route add 5f00:4::59/128 encap seg6local action End count flavors psp dev ethED

    # reverse route for the reply (default route so every node is reachable)
    nf ip -6 route add default via fd05::5 dev ethFE
    ne ip -6 route add default via fd04::4 dev ethED
    nd ip -6 route add default via fd03::3 dev ethDC
    nc ip -6 route add default via fd02::2 dev ethCB
    nf ip route    add default via 10.0.5.5 dev ethFE
    ne ip route    add default via 10.0.4.4 dev ethED
    nd ip route    add default via 10.0.3.3 dev ethDC
    nc ip route    add default via 10.0.2.2 dev ethCB
    # disable Reverse Path Forwarding (RFC 3704) for the reverse IPv4 traffic
    ne sysctl -wq net.ipv4.conf.ethEF.rp_filter=0
    nd sysctl -wq net.ipv4.conf.ethDE.rp_filter=0
    nc sysctl -wq net.ipv4.conf.ethCD.rp_filter=0
    nb sysctl -wq net.ipv4.conf.ethBC.rp_filter=0
    ne sysctl -wq net.ipv4.conf.vrf100.rp_filter=0
}

# Run all mode-specific commands tolerantly (optional kernel features): relax
# errexit so a single failing command does not abort the whole setup.
set +e
case "$MODE" in
    base) setup_base ;;
    mpls) setup_mpls ;;
    srv6) setup_srv6 ;;
esac
set -e

# run_tests: ping every scenario target for the current mode, in order, and
# print a PASS/FAIL line for each. Returns non-zero if any scenario failed.
run_tests() {
    if [ "$MODE" = mpls ] && ! mpls_modules_loaded; then
        echo "skipping '$MODE' scenarios: MPLS kernel modules are not loaded" >&2
        echo "  load them on the host (needs root): sudo modprobe mpls_router mpls_iptunnel" >&2
        return 0
    fi
    local -a tests
    case "$MODE" in
        base) tests=(
            "10.0.5.6|plain IPv4"
            "fd05::6|plain IPv6"
        );;
        mpls) tests=(
            "10.0.5.61|1. MPLS routing (v4)"
            "fd05::61|1. MPLS routing (v6)"
            "10.0.5.62|2. label stacking, routing (v4)"
            "fd05::62|2. label stacking, routing (v6)"
            "fd05::63|3. label swap, tc (v6)"
            "10.0.5.64|4. label stacking, tc (v4)"
            "fd05::64|4. label stacking, tc (v6)"
        );;
        srv6) tests=(
            "fd05::61|1. automatic End.DT46 (v6)"
            "10.0.5.61|1. automatic End.DT46 (v4)"
            "fd05::62|2. End.DT6 lwtunnel (v6)"
            "fd05::63|3. End.DT46 lwtunnel/VRF (v6)"
            "10.0.5.63|3. End.DT46 lwtunnel/VRF (v4)"
            "fd05::64|4. End.DX6 (v6)"
            "10.0.5.65|5. End.DX4 (v4)"
            "fd05::66|6. End.DX2 (v6)"
            "10.0.5.66|6. End.DX2 (v4)"
            "fd05::67|7. End.DT46 reduced SRH (v6)"
            "10.0.5.67|7. End.DT46 reduced SRH (v4)"
            "fd05::68|8. End.DT46 compressed SID (v6)"
            "10.0.5.68|8. End.DT46 compressed SID (v4)"
            "fd05::69|9. inline + PSP flavor (v6)"
        );;
    esac

    local g='' r='' z=''
    if [ -t 1 ]; then g=$'\033[32m'; r=$'\033[31m'; z=$'\033[0m'; fi

    local pass=0 fail=0 line target desc
    echo "running ${#tests[@]} '$MODE' scenario(s):"
    for line in "${tests[@]}"; do
        target="${line%%|*}"; desc="${line#*|}"
        # -c2: the very first packet is often lost to neighbour discovery
        if na ping -c2 -W2 "$target" >/dev/null 2>&1; then
            printf '  %sPASS%s  %-11s  %s\n' "$g" "$z" "$target" "$desc"
            pass=$((pass + 1))
        else
            printf '  %sFAIL%s  %-11s  %s\n' "$r" "$z" "$target" "$desc"
            fail=$((fail + 1))
        fi
    done
    echo "result: $pass passed, $fail failed"
    [ "$fail" -eq 0 ]
}

cat <<EOF
netns chain is up (mode: $MODE):

  [na] -- [nb] -- [nc] -- [nd] -- [ne] -- [nf]
  fd01::1  fd01/2:  fd02/3:  fd03/4:  fd04/5:  fd05::x
  10.0.1.1 10.0.x.2 10.0.x.3 10.0.x.4 10.0.x.5 10.0.5.x

Usage:
  ./lookup_test.sh [base|mpls|srv6]            # set up, then drop into a shell
  ./lookup_test.sh [base|mpls|srv6] CMD...     # set up, run CMD, tear down
  ./lookup_test.sh [base|mpls|srv6] run        # set up, run all scenarios, tear down


Helpers:  na <cmd> | nb <cmd> | nc <cmd> | nd <cmd> | ne <cmd> | nf <cmd>
(tip: re-run as './lookup_test.sh $MODE run' to test every scenario in order)
EOF
case "$MODE" in
  base) cat <<'EOF'
Examples: na ping -c1 10.0.5.6
          na ping -c1 fd05::6
EOF
        ;;
  mpls) cat <<'EOF'
Examples: na ping -c1 10.0.5.61   # 1. MPLS routing
          na ping -c1 fd05::62    # 2. label stacking (routing)
          na ping -c1 fd05::63    # 3. label swap (tc)
          na ping -c1 10.0.5.64   # 4. label stacking (tc)
          nc tc filter show dev ethCB ingress
EOF
        ;;
  srv6) cat <<'EOF'
Examples: na ping -c1 fd05::61    # 1. automatic End.DT46
          na ping -c1 fd05::62    # 2. End.DT6        | 3. fd05::63 End.DT46
          na ping -c1 fd05::64    # 4. End.DX6        | 5. 10.0.5.65 End.DX4
          na ping -c1 fd05::66    # 6. End.DX2        | 7. fd05::67 reduced
          na ping -c1 fd05::68    # 8. compressed SID | 9. fd05::69 PSP
          ne ip -6 -s route
EOF
        ;;
esac
echo "(any 'RTNETLINK'/'Operation not supported' errors above mean a kernel feature for mode '$MODE' is missing)" >&2

# Hand control to the user, then tear everything down.
export PID_NA PID_NB PID_NC PID_ND PID_NE PID_NF
export -f ns_exec na nb nc nd ne nf

if [ "${1:-}" = "run" ]; then
    run_tests
elif [ "$#" -gt 0 ]; then
    bash -c "$*"
else
    RC=$(mktemp)
    cat > "$RC" <<EOF
PS1='(lookup_test:$MODE) \w\$ '
ns_exec(){ nsenter --net="/proc/\$1/ns/net" "\${@:2}"; }
na(){ ns_exec $PID_NA "\$@"; }
nb(){ ns_exec $PID_NB "\$@"; }
nc(){ ns_exec $PID_NC "\$@"; }
nd(){ ns_exec $PID_ND "\$@"; }
ne(){ ns_exec $PID_NE "\$@"; }
nf(){ ns_exec $PID_NF "\$@"; }
echo "type 'exit' to tear down the namespaces."
EOF
    bash --rcfile "$RC" -i || true
    rm -f "$RC"
fi
