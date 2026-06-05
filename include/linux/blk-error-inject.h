/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BLK_ERROR_INJECT_H
#define _LINUX_BLK_ERROR_INJECT_H

#include <linux/blk_types.h>

struct bio;
struct block_device;

/*
 * Programmable, per-disk block-layer error injection via BPF struct_ops.
 *
 * An attached BPF program supplies the policy for one gendisk.  Given a
 * trusted, read-only @bio its ->inject() callback decides whether the I/O
 * should fail by calling the bpf_bio_inject_error() kfunc, which records the
 * desired blk_status_t on the bio.  The kernel owns the completion: after
 * ->inject() returns it performs bio_endio() if a status was recorded.
 */
struct blk_error_inject_ops {
	/*
	 * Whole-disk device number identifying the gendisk to attach to.
	 * Set by userspace in the struct_ops map value before attach.
	 */
	dev_t				dev;

	/* Kernel-private: the pinned block_device resolved from @dev. */
	struct block_device		*bdev;

	void (*inject)(struct bio *bio);
};
#endif
