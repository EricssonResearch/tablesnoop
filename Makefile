CFLAGS=-O2 -Wall -Wextra -Wshadow -Wstrict-prototypes -Wmissing-declarations -Wwrite-strings -Werror -pg
BPF_CC=clang
CC=clang

ifeq ($(MAKECMDGOALS),static)
  STATIC = -static
  EXTRA_FLAGS = -lelf -lz -lzstd
  TARGET = -D__TARGET_ARCH_X64
else
  TARGET = -D__TARGET_ARCH_X86
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

tablesnoop.bpf.o: tablesnoop.bpf.c vmlinux.h tablesnoop.h
	$(BPF_CC) -g -O2 -target bpf $(TARGET) -c $< -o $@

tablesnoop.skel.h: tablesnoop.bpf.o
	$(BPFTOOL) gen skeleton $^ > $@

lib.a: lib.c lib.h
	$(CC) $(STATIC) -g $(CFLAGS) -c $< -o $@

tablesnoop.o: tablesnoop.c tablesnoop.skel.h tablesnoop.h
	$(CC) $(STATIC) -g $(CFLAGS) -c $< -o $@

tablesnoop: tablesnoop.o lib.a
	$(CC) $(STATIC) -g $< -lbpf lib.a $(EXTRA_FLAGS) -o $@

install: tablesnoop
	cp tablesnoop /usr/local/bin/

clean:
	rm *.a *.o *.skel.h vmlinux.h tablesnoop
