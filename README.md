# tablesnoop

This is a real-time observability tool for Linux kernel table lookups.
Using eBPF probes, it taps into the forwarding information base (FIB) for lookups.
and provides details about them.
For example, it provides the source and destination addresses and the next-hop if the lookup was successful.
While table lookups usually triggered by packets, this is not a packet level tracer.
For tools dedicated for packet level tracing see the [similar tools](#similar-tools) section.

## Features

* IPv4 and IPv6 route lookup tracing
* IPv4 and IPv6 rule (policy) lookup tracing
* Lookup failure tracing (e.g.: no route or policy for packet)
* Verbose logging with extended namespace, interface and rule info
* Kernel-wide (global) or per-namespace tracing

## Usage

Root privileges are required for tracing.
This requirement may be relaxed in the future.

```bash
tablesnoop --help
Usage: tablesnoop [OPTION...]

  -4, --v4                   Use IPv4. By default, both IPv4 and IPv6 are logged.
  -6, --v6                   Use IPv6. By default, both IPv4 and IPv6 are logged.
  -g, --global               Collect events from all network namespace
                             (global).
      --route                Only display route lookups
      --rule                 Only display rule lookups
  -s, --separate             Insert empty line after a timeout.
  -v, --verbose              Enable detailed output.
  -x, --show_failed          Show failed lookup results
  -?, --help                 Give this help list
      --usage                Give a short usage message
```

To trace IPv4 routing table lookups including the failed ones,
across all network namespaces use the following command:

```bash
tablesnoop -4 -x -g
v4: src: 10.100.85.1  dst: 192.168.22.11 
v4: src: 10.100.85.1  dst: 192.168.22.11 --> gw: 10.100.80.1 egress: eth0
v4: src: 192.168.22.11  dst: 10.100.85.1 --> gw:  egress: eth0
v4: src: 10.100.85.1  dst: 192.168.22.11 
v4: src: 10.100.85.1  dst: 192.168.22.11 --> gw: 10.100.80.1 egress: eth0
v4: src: 0.0.0.0  dst: 8.8.8.8 
v4: src: 0.0.0.0  dst: 8.8.8.8 --> gw: 10.100.80.1 egress: eth0
v4: src: 10.100.85.1  dst: 8.8.8.8 
v4: src: 10.100.85.1  dst: 8.8.8.8 --> gw: 10.100.80.1 egress: eth0
v4: src: 8.8.8.8  dst: 10.100.85.1 --> gw:  egress: eth0
v4: src: 10.100.85.1  dst: 8.8.8.8 
v4: src: 10.100.85.1  dst: 8.8.8.8 --> gw: 10.100.80.1 egress: eth0
v4: src: 127.0.0.1  dst: 127.0.0.1 --> gw:  egress: lo
v4: src: 127.0.0.1  dst: 127.0.0.1 --> gw:  egress: lo
```

Here is a more complex example using the ROSE SRv6 [demo topology](https://github.com/netgroup/rose-srv6-tutorial/tree/master/nets/8routers-named-netns).
This network has segment routing encapsulation and decapsulation, even compressed SIDs.
The command show successful IPv6 routing lookups only with high verbosity in every network namespace on the host:

```bash
sudo tablesnoop -v -6 -g -s --route

netns: 24600 iif: lo oif: - table id: 254 dscp: 0 flowlabel: 0 v6: src: ::  dst: fd00:0:83::2 --> gw: fd00:0:13::1 egress: h13-r1
netns: 24600 iif: lo oif: - table id: 254 dscp: 0 flowlabel: 0 v6: src: ::  dst: fd00:0:83::2 --> gw: fd00:0:13::1 egress: h13-r1
netns: 24597 iif: r1-h13 oif: - table id: 254 dscp: 0 flowlabel: dbef2 v6: src: fd00:0:13::2  dst: fd00:0:83::2 --> gw: :: egress: dum0
netns: 24597 iif: r1-h13 oif: - table id: 254 dscp: 0 flowlabel: dbef2 v6: src: fcff:1::1  dst: fcff:20e:70e:40e:50e:8d6:: --> gw: fcf0:0:1:2::2 egress: r1-r2
netns: 24598 iif: r2-r1 oif: - table id: 254 dscp: 0 flowlabel: dbef2 v6: src: fcff:1::1  dst: fcff:20e:70e:40e:50e:8d6:: --> gw: :: egress: dum0
netns: 24598 iif: r2-r1 oif: - table id: 254 dscp: 0 flowlabel: dbef2 v6: src: fcff:1::1  dst: fcff:70e:40e:50e:8d6:: --> gw: fcf0:0:2:7::7 egress: r2-r7
netns: 6 iif: r7-r2 oif: - table id: 254 dscp: 0 flowlabel: dbef2 v6: src: fcff:1::1  dst: fcff:70e:40e:50e:8d6:: --> gw: :: egress: dum0
netns: 6 iif: r7-r2 oif: - table id: 254 dscp: 0 flowlabel: dbef2 v6: src: fcff:1::1  dst: fcff:40e:50e:8d6:: --> gw: fcf0:0:6:7::6 egress: r7-r6
netns: 12297 iif: r6-r7 oif: - table id: 254 dscp: 0 flowlabel: dbef2 v6: src: fcff:1::1  dst: fcff:40e:50e:8d6:: --> gw: fcf0:0:4:6::4 egress: r6-r4
netns: 28677 iif: r4-r6 oif: - table id: 254 dscp: 0 flowlabel: dbef2 v6: src: fcff:1::1  dst: fcff:40e:50e:8d6:: --> gw: :: egress: dum0
netns: 28677 iif: r4-r6 oif: - table id: 254 dscp: 0 flowlabel: dbef2 v6: src: fcff:1::1  dst: fcff:50e:8d6:: --> gw: fcf0:0:4:5::5 egress: r4-r5
netns: 28678 iif: r5-r4 oif: - table id: 254 dscp: 0 flowlabel: dbef2 v6: src: fcff:1::1  dst: fcff:50e:8d6:: --> gw: :: egress: dum0
netns: 28678 iif: r5-r4 oif: - table id: 254 dscp: 0 flowlabel: dbef2 v6: src: fcff:1::1  dst: fcff:8d6:: --> gw: fcf0:0:5:6::6 egress: r5-r6
netns: 12297 iif: r6-r5 oif: - table id: 254 dscp: 0 flowlabel: dbef2 v6: src: fcff:1::1  dst: fcff:8d6:: --> gw: fcf0:0:6:8::8 egress: r6-r8
netns: 28679 iif: r8-r6 oif: - table id: 254 dscp: 0 flowlabel: dbef2 v6: src: fcff:1::1  dst: fcff:8d6:: --> gw: :: egress: dum0
netns: 28679 iif: r8-r6 oif: - table id: 254 dscp: 0 flowlabel: dbef2 v6: src: fd00:0:13::2  dst: fd00:0:83::2 --> gw: :: egress: r8-h83
netns: 8206 iif: h83-r8 oif: - table id: 255 dscp: 0 flowlabel: dbef2 v6: src: fd00:0:13::2  dst: fd00:0:83::2 --> gw: :: egress: h83-r8
netns: 8206 iif: lo oif: h83-r8 table id: 254 dscp: 0 flowlabel: 0 v6: src: fd00:0:83::2  dst: fd00:0:13::2 --> gw: fd00:0:83::1 egress: h83-r8
netns: 28679 iif: r8-h83 oif: - table id: 254 dscp: 0 flowlabel: a1ba3 v6: src: fd00:0:83::2  dst: fd00:0:13::2 --> gw: :: egress: dum0
netns: 28679 iif: r8-h83 oif: - table id: 254 dscp: 0 flowlabel: a1ba3 v6: src: fcff:8::1  dst: fcff:7::e --> gw: fcf0:0:7:8::7 egress: r8-r7
netns: 6 iif: r7-r8 oif: - table id: 254 dscp: 0 flowlabel: a1ba3 v6: src: fcff:8::1  dst: fcff:7::e --> gw: :: egress: dum0
netns: 6 iif: r7-r8 oif: - table id: 254 dscp: 0 flowlabel: a1ba3 v6: src: fcff:8::1  dst: fcff:6::e --> gw: fcf0:0:6:7::6 egress: r7-r6
netns: 12297 iif: r6-r7 oif: - table id: 254 dscp: 0 flowlabel: a1ba3 v6: src: fcff:8::1  dst: fcff:6::e --> gw: :: egress: dum0
netns: 12297 iif: r6-r7 oif: - table id: 254 dscp: 0 flowlabel: a1ba3 v6: src: fcff:8::1  dst: fcff:5::e --> gw: fcf0:0:5:6::5 egress: r6-r5
netns: 28678 iif: r5-r6 oif: - table id: 254 dscp: 0 flowlabel: a1ba3 v6: src: fcff:8::1  dst: fcff:5::e --> gw: :: egress: dum0
netns: 28678 iif: r5-r6 oif: - table id: 254 dscp: 0 flowlabel: a1ba3 v6: src: fcff:8::1  dst: fcff:3::e --> gw: fcf0:0:4:5::4 egress: r5-r4
netns: 28677 iif: r4-r5 oif: - table id: 254 dscp: 0 flowlabel: a1ba3 v6: src: fcff:8::1  dst: fcff:3::e --> gw: fcf0:0:3:4::3 egress: r4-r3
netns: 12296 iif: r3-r4 oif: - table id: 254 dscp: 0 flowlabel: a1ba3 v6: src: fcff:8::1  dst: fcff:3::e --> gw: :: egress: dum0
netns: 12296 iif: r3-r4 oif: - table id: 254 dscp: 0 flowlabel: a1ba3 v6: src: fcff:8::1  dst: fcff:2::e --> gw: fcf0:0:2:3::2 egress: r3-r2
netns: 24598 iif: r2-r3 oif: - table id: 254 dscp: 0 flowlabel: a1ba3 v6: src: fcff:8::1  dst: fcff:2::e --> gw: :: egress: dum0
netns: 24598 iif: r2-r3 oif: - table id: 254 dscp: 0 flowlabel: a1ba3 v6: src: fcff:8::1  dst: fcff:1::d6 --> gw: fcf0:0:1:2::1 egress: r2-r1
netns: 24597 iif: r1-r2 oif: - table id: 254 dscp: 0 flowlabel: a1ba3 v6: src: fcff:8::1  dst: fcff:1::d6 --> gw: :: egress: dum0
netns: 24597 iif: r1-r2 oif: - table id: 254 dscp: 0 flowlabel: a1ba3 v6: src: fd00:0:83::2  dst: fd00:0:13::2 --> gw: :: egress: r1-h13
netns: 24600 iif: h13-r1 oif: - table id: 255 dscp: 0 flowlabel: a1ba3 v6: src: fd00:0:83::2  dst: fd00:0:13::2 --> gw: :: egress: h13-r1
```

The ping command executed on `h13` host towards `h83` IPv6 address `fd00:0:83::2`.
All lookups visible between the source and the destination over the whole path.
First, there are the lookups for the ICMP echo request, then when the source address changes to
`fd00:0:83::2` the lookups for the ICMP echo reply are traced.
The `netns` in the output is the "network namespace cookie" which is a unique identifier of the netns.

## Build

Make sure all the dependencies installed.

* libbpf v1.4.5
* clang v18
* bpftool v7.5
* Linux kernel v6.11 with BTF support enabled
  * `/sys/kernel/btf/vmlinux` exists or
  * `vmlinux.h` can be generated from DWARF

The exact package names may depending on distros.

### Debian Trixie

```bash
sudo apt install build-essential gcc-multilib clang bpftool libbpf-dev
```

### Ubuntu 24.10, 25.04

```bash
sudo apt install build-essential gcc-multilib clang linux-tools-common libbpf-dev
```

Then compile and install `tablesnoop`.
The `bpftool` executable normally only available for root.
However, functions like BTF dumping and `vmlinux.h` generation
work for unprivileged users too (if not, use `sudo`).

```bash
make
sudo make install
```

For building a self-contained static executable, use

```bash
make static
```

## Limitations

* FIB route and rule lookups only
* Only IPv4 and IPv6 nexthops supported
* Workaround for network namespace lookups
* Lookups may not traced for tunneling cases (see `dst_cache_get` calls in Linux)

## Similar tools

* [pwru](https://github.com/cilium/pwru) - packet level Linux kernel networking
debugger and tracer. It taps on every kernel function which
accepts `struct sk_buff` as a parameter and follow their execution.
Useful for low-level debugging, troubleshooting regressions.
Very verbose, depending on the traffic, a single packet can triggers
dozens of functions in the network stack.
* [ipftrace2](https://github.com/YutaroHayakawa/ipftrace2) - also a packet
level debugger. It's interface similar to `ftrace` hence the name.
It supports various output formats such as function graphs, JSON or user customized.
* [retis](https://retis.readthedocs.io/en/stable/) - packet level tracer with many features.
Supports drop reason tracing, packet tracking, conntrack status,
netfilter handle info and many more.
Live tracing and event collection for offline processing also possible.
Collect many info and very verbose, supports PCAP output.


## Potential improvements

- [ ] Support Lightweight Tunnel types
  - [ ] SRv6
  - [ ] MPLS
  - [ ] VXLAN
- [ ] Neighbor table lookups
  - [ ] ARP/ND
  - [ ] FDB
- [ ] Netfilter lookups (nftables/iptables)
- [ ] Improve compatibility
  - [ ] BTF based conditional struct member lookups
  - [ ] Support older kernels
- [ ] Improve kernel side
  - [ ] Add netns parameter for IPv4 FIB lookups
  - [ ] Net cookie or inode num based `setns`

### Authors

Ferenc Fejes, Ferenc Orosi, Balázs Varga @ Ericsson Research
