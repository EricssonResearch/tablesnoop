# tablesnoop

Tablesnoop is a real-time observability tool for Linux kernel packet forwarding table lookups.
This include IP routing lookup (v4 and v6), policy based routing rule lookups and more.

The principle behind the tool is lookup level observability:
forwarding of 1 packet can trigger multiple table lookups.
Packet level tools like `tcpdump` or `wireshark` do not show such details.
Function level tools (see [similar tools](#similar-tools) section) are useful for low
level debugging but they too verbose quick network observability.

## Features

* IPv4 and IPv6 route lookup tracing
* IPv4 and IPv6 rule (policy) lookup tracing
* Bridge forwarding database (FDB) tracing
* Neighbour table tracing (ARP/ND)
* Tunnel tracing (SRv6, MPLS)
* Lookup failure tracing (e.g.: no route or policy for packet)
* Event aggregation mode (group same lookups and show occurrence count)
* Verbose logging with extended namespace, interface and rule info
* Kernel-wide (global) or per-namespace tracing

## Usage

Root privileges are required for tracing.
This requirement may be relaxed in the future.

```bash
Usage: tablesnoop [OPTION...]

  -a, --aggregate            Event aggregation mode
      --fdb                  Show forwarding database lookups
      --fib4                 Show IPv4 FIB lookups
      --fib6                 Show IPv6 FIB lookups
  -g, --global               Collect events from all network namespaces
  -l, --lwt                  Show LightWeight Tunnel info (off by default)
      --neigh                Show neighbor lookups
      --rule4                Show IPv4 rule lookups
      --rule6                Show IPv6 rule lookups
  -s, --separator            Print separator line after a timeout
  -v, --verbose              Enable detailed output
  -x, --show_failed          Show failed lookup results
  -?, --help                 Give this help list
      --usage                Give a short usage message
```

To trace IPv4 routing table lookups including the failed ones,
across all network namespaces use the following command:

```bash
tablesnoop --fib4 -x -g
fib4: packet src 10.148.80.4 dst 1.1.1.1 fib key 0.0.0.0/0 --> gw 10.148.80.1 dev wlp194s0
fib4: packet src 0.0.0.0 dst 1.1.1.1 fib key 0.0.0.0/0 --> gw 10.148.80.1 dev wlp194s0
fib4: packet src 1.1.1.1 dst 10.148.80.4 fib key 10.148.80.4/32 --> dev wlp194s0
fib4: packet src 10.148.80.4 dst 1.1.1.1 fib key 0.0.0.0/0 --> gw 10.148.80.1 dev wlp194s0
fib4: packet src 0.0.0.0 dst 1.1.1.1 fib key 0.0.0.0/0 --> gw 10.148.80.1 dev wlp194s0
fib4: packet src 1.1.1.1 dst 10.148.80.4 fib key 10.148.80.4/32 --> dev wlp194s0
```


## Build

Make sure all the dependencies installed.

* libbpf v1.4.5
* clang v18
* bpftool v7.5
* Linux kernel v6.11 with BTF support enabled
  * `/sys/kernel/btf/vmlinux` exists or
  * `vmlinux.h` can be generated from DWARF

The exact package names may depending on distros.

### Debian Trixie and above

```bash
sudo apt install build-essential gcc-multilib clang bpftool libbpf-dev
```

### Ubuntu 24.10 and above

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

## Similar tools

* `tcpdump` - packet level tracer. Less verbose than tablesnoop,
show the packet on the wire sent or received by the interfaces.
Does not provide info about failed forwarding.
* [pwru](https://github.com/cilium/pwru) - function level Linux kernel networking debugger and tracer. It taps on every kernel function which accepts 
`struct sk_buff`as a parameter and follow their execution.
Useful for low-level debugging, troubleshooting regressions.
Very verbose, depending on the traffic, a single packet can triggers
dozens of functions in the network stack.
* [ipftrace2](https://github.com/YutaroHayakawa/ipftrace2) - also a function
level debugger. It's interface similar to `ftrace` hence the name.
It supports various output formats such as function graphs, JSON or user customized.
* [retis](https://retis.readthedocs.io/en/stable/) - function level tracer with many features.
Supports drop reason tracing, packet tracking, conntrack status,
netfilter handle info and many more.
Live tracing and event collection for offline processing also possible.
Collect many info and very verbose, supports PCAP output.

### Authors

Ferenc Fejes, Ferenc Orosi, Balázs Varga @ Ericsson Research
Miklós Máté @ BME
