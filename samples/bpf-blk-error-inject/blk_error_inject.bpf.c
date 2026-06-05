// SPDX-License-Identifier: GPL-2.0
/*
 * Demonstrator BPF program for per-disk block-layer error injection.
 *
 * It implements the kernel "blk_error_inject_ops" struct_ops type (see
 * block/blk-error-inject-bpf.c).  The ->inject() callback receives a trusted,
 * read-only bio.  To fail an I/O it calls the bpf_bio_inject_error() kfunc with
 * the desired blk_status_t; the kernel performs the completion once the
 * callback returns.  Returning without calling the kfunc lets the bio proceed.
 *
 * Policy implemented here, as a demo: fail every WRITE whose start sector is in
 * the [0, 2048) range with BLK_STS_IOERR; let everything else through.
 *
 * The bio is a trusted PTR_TO_BTF_ID, so its fields are read with direct
 * dereferences (bio->...); clang still emits CO-RE relocations for the field
 * offsets, so the program stays portable across kernels that expose the same
 * layout in BTF.  bpf_probe_read_kernel()/BPF_CORE_READ() must not be used for
 * a trusted struct_ops argument.
 *
 * The target disk is selected by the dev_t written into the struct_ops map
 * value (the "dev" member) by the loader before attach.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

/* Mirrors of in-kernel constants not necessarily emitted into vmlinux.h. */
#define REQ_OP_BITS	8
#define REQ_OP_MASK	((1 << REQ_OP_BITS) - 1)
#define REQ_OP_WRITE	1

#define BLK_STS_IOERR	10

#define DEMO_FAIL_END_SECTOR	2048ULL		/* exclusive */

/*
 * kfunc exposed by the kernel to this struct_ops type.  It records the status
 * to inject on @bio; the kernel completes the bio after ->inject() returns.
 */
extern int bpf_bio_inject_error(struct bio *bio, int status) __ksym;

SEC("struct_ops/inject")
void BPF_PROG(inject, struct bio *bio)
{
	__u64 sector = bio->bi_iter.bi_sector;
	unsigned int opf = bio->bi_opf;

	if ((opf & REQ_OP_MASK) != REQ_OP_WRITE)
		return;

	if (sector < DEMO_FAIL_END_SECTOR)
		bpf_bio_inject_error(bio, BLK_STS_IOERR);
}

SEC(".struct_ops.link")
struct blk_error_inject_ops blk_error_inject = {
	.inject = (void *)inject,
};
