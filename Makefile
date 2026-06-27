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

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

tablesnoop.bpf.o: tablesnoop.bpf.c vmlinux.h tablesnoop.h flavors.h
	$(BPF_CC) -g -O2 -target bpf -c $< -o $@

tablesnoop.skel.h: tablesnoop.bpf.o
	$(BPFTOOL) gen skeleton $^ > $@

tablesnoop.o: tablesnoop.c tablesnoop.skel.h tablesnoop.h
	$(CC) $(STATIC) -g $(CFLAGS) -c $< -o $@

tablesnoop: tablesnoop.o
	$(CC) $(STATIC) -g $< -lbpf $(EXTRA_FLAGS) -o $@

install: tablesnoop
	cp tablesnoop /usr/local/bin/

clean:
	rm *.o *.skel.h vmlinux.h tablesnoop
