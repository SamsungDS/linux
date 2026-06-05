# SPDX-License-Identifier: GPL-2.0
#
# Standalone build for the per-disk block-layer error-injection demonstrator.
#
# This is intentionally self-contained so it can be built outside the kernel
# build system, against a libbpf and bpftool from the kernel tree (or from a
# distro package).  Adjust the variables below if your paths differ.
#
# Usage:
#   make VMLINUX_BTF=/sys/kernel/btf/vmlinux        # generate vmlinux.h + build
#   ./blk_error_inject_loader /dev/<scratch-disk>
#
# Prerequisites: clang (with BPF target), bpftool, libbpf headers + library.

CLANG		?= clang
BPFTOOL		?= bpftool
ARCH		?= $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

# Where to read BTF from to generate vmlinux.h.  Defaults to the running
# kernel; override with the vmlinux of the kernel you built.
VMLINUX_BTF	?= /sys/kernel/btf/vmlinux

# libbpf: point these at your tree/distro install if needed.
LIBBPF_CFLAGS	?= $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LDLIBS	?= $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf)

BPF_CFLAGS	= -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I.

.PHONY: all clean
all: blk_error_inject_loader

vmlinux.h:
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

blk_error_inject.bpf.o: blk_error_inject.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

blk_error_inject.skel.h: blk_error_inject.bpf.o
	$(BPFTOOL) gen skeleton $< name blk_error_inject_bpf > $@

blk_error_inject_loader: blk_error_inject_loader.c blk_error_inject.skel.h
	$(CC) -g -Wall $(LIBBPF_CFLAGS) -I. $< -o $@ $(LIBBPF_LDLIBS)

clean:
	rm -f vmlinux.h blk_error_inject.bpf.o blk_error_inject.skel.h \
	      blk_error_inject_loader
