# Per-disk block-layer error injection via BPF struct_ops (PoC)

This is a proof-of-concept that lets a BPF program decide, per bio, which
`blk_status_t` (if any) to inject for a single disk.  It is an additive,
optional complement to the static rule based error injection of
`CONFIG_FAIL_MAKE_REQUEST` (`block/error-injection.c`).

## Design in one paragraph

The kernel exposes a struct_ops type `blk_error_inject_ops`:

```c
struct blk_error_inject_ops {
	dev_t			dev;	/* whole-disk dev_t, set by userspace */
	struct block_device	*bdev;	/* kernel-private */
	void (*inject)(struct bio *bio);
};
```

A BPF program implements `->inject()` and attaches to one gendisk, selected by
the `dev` field written into the struct_ops map value before attach.  The
callback receives the bio as a trusted, read-only `PTR_TO_BTF_ID`.  To fail an
I/O it calls the kernel kfunc `bpf_bio_inject_error(bio, status)`, which
validates the status and records it on the bio; **the kernel performs the
completion** (`bio_endio()`) once the callback returns.  The program may not
write `bio->bi_status` or call `bio_endio()` directly, and it still holds the
bio as a trusted pointer after the kfunc, so leaving the completion to the
kernel avoids a use-after-free.  A static key keeps the I/O hot path free while
nothing is attached, and only one program may be attached to a disk at a time.

Key kernel files:

- `include/linux/blk-error-inject.h` - the `blk_error_inject_ops` vtable.
- `block/blk-error-inject-bpf.c` - the struct_ops registrant, the RCU/static-key
  gate, the per-disk reg()/unreg(), and the `bpf_bio_inject_error()` kfunc.
- `block/error-injection.c` - the call site inside `__blk_error_inject()`.

## Required kernel configuration

```
CONFIG_FAIL_MAKE_REQUEST=y
CONFIG_BLK_ERROR_INJECT_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_DEBUG_INFO_BTF=y
```

`CONFIG_DEBUG_INFO_BTF=y` makes the kernel emit the BTF needed both to register
the struct_ops type and to generate `vmlinux.h` for the program.

## Build the BPF side

The `Makefile` here is standalone and uses `clang`, `bpftool`, and `libbpf`.

```sh
# Generate vmlinux.h from the running kernel (or pass the vmlinux you built):
make VMLINUX_BTF=/sys/kernel/btf/vmlinux
```

This produces `blk_error_inject_loader`.

## Arm the disk, then attach

Injection only happens on a disk that is armed for `FAIL_MAKE_REQUEST`, i.e. one
whose `BD_MAKE_IT_FAIL` flag is set.  Arm a scratch disk (NOT one with data you
care about), then attach the program to it:

```sh
# Arm the disk so submit_bio_noacct_nocheck() reaches the injection path:
echo 1 | sudo tee /sys/block/<scratch>/make-it-fail

# Attach; the loader writes the disk's dev_t into the struct_ops value, then
# holds the link live until Ctrl-C:
sudo ./blk_error_inject_loader /dev/<scratch>
```

The loader resolves `/dev/<scratch>` to its whole-disk `dev_t`; `reg()` pins the
matching `block_device` for the duration of the attachment.

## Test recipe

The demo program fails every WRITE whose start sector is in `[0, 2048)` with
`BLK_STS_IOERR`.

```sh
# In another terminal, write to the start of the armed disk with direct I/O so
# the bio targets sector 0.  O_DIRECT requires the transfer to be a multiple of
# the device logical block size, so use that as bs (a 512-byte direct I/O on a
# 4K-LBA device fails with EINVAL *before* any bio is built, which is not the
# injection):
bs=$(cat /sys/block/<scratch>/queue/logical_block_size)   # e.g. 4096
sudo dd if=/dev/zero of=/dev/<scratch> bs=$bs count=1 oflag=direct
# expect: "dd: error writing '/dev/<scratch>': Input/output error"

# A read of the same region succeeds (the demo only fails WRITEs):
sudo dd if=/dev/<scratch> of=/dev/null bs=$bs count=1 iflag=direct
```

`bi_sector` is always in 512-byte units regardless of the device LBA, so a 4K
write at LBA 0 spans sectors 0-7, within `[0, 2048)`.  Writes past sector 2048,
and all reads, are unaffected.

When done, Ctrl-C the loader to detach, and disarm the disk:

```sh
echo 0 | sudo tee /sys/block/<scratch>/make-it-fail
```

## Scope / caveats

This is a PoC.  Full functional validation requires building the patched kernel
with the configs above and running it in a VM or on bare metal.  The static-key
gate, RCU teardown, read-only bio access, and the per-disk reg()/unreg() are
written to mirror the in-tree struct_ops registrants (`net/sched/bpf_qdisc.c`
for the kfunc and trusted-arg handling, `drivers/hid/bpf/hid_bpf_struct_ops.c`
for the per-object attach model).
