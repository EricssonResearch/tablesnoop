CFLAGS=-O2 -Wall -Wextra -Wshadow -Wstrict-prototypes -Wmissing-declarations -Wwrite-strings -Werror
BPF_CC=clang
CC=clang

ifeq ($(MAKECMDGOALS),static)
  STATIC = -static
  EXTRA_FLAGS = -lelf -lz -lzstd
else
endif

BPFTOOL=$(shell which bpftool 2>/dev/null)
ifeq (, $(BPFTOOL))
	BPFTOOL=$(wildcard /usr/sbin/bpftool)
	ifeq (, $(BPFTOOL))
		$(error "bpftool not found (apt install linux-tools-common)")
	endif
endif


.PHONY: all install clean static
all: tablesnoop
static: tablesnoop

bpf/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

bpf/fib.bpf.o: bpf/fib.bpf.c bpf/vmlinux.h common.h bpf/common.bpf.h bpf/flavors.h
	$(BPF_CC) -g -O2 -target bpf -I. -c $< -o $@

bpf/fib.skel.h: bpf/fib.bpf.o
	$(BPFTOOL) gen skeleton $^ > $@

bpf/srv6.bpf.o: bpf/srv6.bpf.c bpf/vmlinux.h common.h bpf/common.bpf.h bpf/flavors.h
	$(BPF_CC) -g -O2 -target bpf -I. -c $< -o $@

bpf/srv6.skel.h: bpf/srv6.bpf.o
	$(BPFTOOL) gen skeleton $^ > $@

bpf/mpls.bpf.o: bpf/mpls.bpf.c bpf/vmlinux.h common.h bpf/flavors.h
	$(BPF_CC) -g -O2 -target bpf -I. -c $< -o $@

bpf/mpls.skel.h: bpf/mpls.bpf.o
	$(BPFTOOL) gen skeleton $^ > $@

bpf/neigh.bpf.o: bpf/neigh.bpf.c bpf/vmlinux.h common.h bpf/flavors.h
	$(BPF_CC) -g -O2 -target bpf -I. -c $< -o $@

bpf/neigh.skel.h: bpf/neigh.bpf.o
	$(BPFTOOL) gen skeleton $^ > $@

bpf/fdb.bpf.o: bpf/fdb.bpf.c bpf/vmlinux.h common.h bpf/flavors.h
	$(BPF_CC) -g -O2 -target bpf -I. -c $< -o $@

bpf/fdb.skel.h: bpf/fdb.bpf.o
	$(BPFTOOL) gen skeleton $^ > $@

tablesnoop.o: tablesnoop.c bpf/fib.skel.h bpf/srv6.skel.h bpf/mpls.skel.h bpf/neigh.skel.h bpf/fdb.skel.h tablesnoop.h common.h
	$(CC) $(STATIC) -g $(CFLAGS) -c $< -o $@

tablesnoop: tablesnoop.o
	$(CC) $(STATIC) -g $< -lbpf $(EXTRA_FLAGS) -o $@

install: tablesnoop
	cp tablesnoop /usr/local/bin/

clean:
	rm -f *.o bpf/*.o bpf/*.skel.h bpf/vmlinux.h tablesnoop
