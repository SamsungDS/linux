// SPDX-License-Identifier: GPL-2.0
/*
 * Programmable, per-disk block-layer error injection via BPF struct_ops.
 *
 * A BPF program attaches to a single gendisk, identified by its whole-disk
 * dev_t.  For every bio that reaches the error-injection path (which only
 * happens once the disk is armed via BD_MAKE_IT_FAIL) the program's ->inject()
 * callback is invoked with a trusted, read-only bio.  The program decides
 * whether to fail the I/O by calling the bpf_bio_inject_error() kfunc, which
 * records the desired blk_status_t on the bio.  The kernel owns the completion:
 * once ->inject() returns it performs bio_endio() if a status was recorded.
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-error-inject.h>
#include <linux/rcupdate.h>
#include "blk.h"

DEFINE_STATIC_KEY_FALSE(blk_error_inject_bpf_enabled);

static struct bpf_struct_ops bpf_blk_error_inject_ops;

bool __blk_error_inject_bpf(struct bio *bio)
{
	struct gendisk *disk = bio->bi_bdev->bd_disk;
	struct blk_error_inject_ops *ops;
	bool consumed = false;

	rcu_read_lock();
	ops = rcu_dereference(disk->bpf_error_inject);
	if (ops) {
		/*
		 * The program records its decision on the bio via the
		 * bpf_bio_inject_error() kfunc.  It must not complete the bio
		 * itself: it still holds @bio as a trusted pointer after the
		 * call, so the kernel performs the completion below, once the
		 * program is done and outside the RCU read-side section.
		 */
		ops->inject(bio);
		consumed = bio->bi_status != BLK_STS_OK;
	}
	rcu_read_unlock();

	if (consumed) {
		bio_endio(bio);
		return true;
	}
	return false;
}

static bool blk_error_inject_ops_is_valid_access(int off, int size,
						 enum bpf_access_type type,
						 const struct bpf_prog *prog,
						 struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static int blk_error_inject_ops_btf_struct_access(struct bpf_verifier_log *log,
						  const struct bpf_reg_state *reg,
						  int off, int size)
{
	/*
	 * The bio is handed to the program read-only.  It may only be mutated
	 * through the bpf_bio_inject_error() kfunc, never via direct BPF
	 * stores, so reject every write here.
	 */
	bpf_log(log, "only read is supported\n");
	return -EACCES;
}

static const struct bpf_verifier_ops blk_error_inject_verifier_ops = {
	.get_func_proto		= bpf_base_func_proto,
	.is_valid_access	= blk_error_inject_ops_is_valid_access,
	.btf_struct_access	= blk_error_inject_ops_btf_struct_access,
};

static int blk_error_inject_ops_init(struct btf *btf)
{
	return 0;
}

static int blk_error_inject_ops_check_member(const struct btf_type *t,
					     const struct btf_member *member,
					     const struct bpf_prog *prog)
{
	/*
	 * ->inject() runs from submit_bio_noacct_nocheck(), which may execute
	 * with current->bio_list set or in atomic context, so sleepable
	 * programs cannot be attached.
	 */
	if (prog->sleepable)
		return -EINVAL;

	return 0;
}

static int blk_error_inject_ops_init_member(const struct btf_type *t,
					    const struct btf_member *member,
					    void *kdata, const void *udata)
{
	const struct blk_error_inject_ops *uops;
	struct blk_error_inject_ops *kops;
	u32 moff;

	uops = (const struct blk_error_inject_ops *)udata;
	kops = (struct blk_error_inject_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct blk_error_inject_ops, dev):
		/*
		 * Copy the userspace-supplied dev_t and return 1 to tell the
		 * struct_ops core the field has been handled; otherwise the
		 * verifier would reject a non-zero scalar member.
		 */
		kops->dev = uops->dev;
		return 1;
	}

	return 0;
}

static int blk_error_inject_validate(void *kdata)
{
	struct blk_error_inject_ops *ops = kdata;

	/*
	 * inject() is the only operation and the hot path calls it
	 * unconditionally, so a vtable without it would NULL-deref.
	 */
	if (!ops->inject)
		return -EINVAL;

	return 0;
}

static int blk_error_inject_reg(void *kdata, struct bpf_link *link)
{
	struct blk_error_inject_ops *ops = kdata;
	struct block_device *bdev;
	struct gendisk *disk;
	int err = 0;

	if (!ops->dev)
		return -EINVAL;

	bdev = blkdev_get_no_open(ops->dev, false);
	if (!bdev)
		return -ENODEV;
	disk = bdev->bd_disk;

	mutex_lock(&disk->error_injection_lock);
	if (rcu_access_pointer(disk->bpf_error_inject)) {
		err = -EBUSY;
		goto out_unlock;
	}

	ops->bdev = bdev;
	rcu_assign_pointer(disk->bpf_error_inject, ops);
	mutex_unlock(&disk->error_injection_lock);

	static_branch_inc(&blk_error_inject_bpf_enabled);
	return 0;

out_unlock:
	mutex_unlock(&disk->error_injection_lock);
	blkdev_put_no_open(bdev);
	return err;
}

static void blk_error_inject_unreg(void *kdata, struct bpf_link *link)
{
	struct blk_error_inject_ops *ops = kdata;
	struct block_device *bdev = ops->bdev;
	struct gendisk *disk = bdev->bd_disk;

	mutex_lock(&disk->error_injection_lock);
	rcu_assign_pointer(disk->bpf_error_inject, NULL);
	mutex_unlock(&disk->error_injection_lock);

	static_branch_dec(&blk_error_inject_bpf_enabled);

	/*
	 * Drain any in-flight ->inject() callers before the struct_ops image
	 * is freed by the core and before the underlying block_device pin is
	 * dropped.
	 */
	synchronize_rcu();

	ops->bdev = NULL;
	blkdev_put_no_open(bdev);
}

static void __bpf_blk_error_inject(struct bio *bio)
{
}

static struct blk_error_inject_ops __bpf_blk_error_inject_ops = {
	.inject = __bpf_blk_error_inject,
};

static struct bpf_struct_ops bpf_blk_error_inject_ops = {
	.verifier_ops	= &blk_error_inject_verifier_ops,
	.init		= blk_error_inject_ops_init,
	.check_member	= blk_error_inject_ops_check_member,
	.init_member	= blk_error_inject_ops_init_member,
	.validate	= blk_error_inject_validate,
	.reg		= blk_error_inject_reg,
	.unreg		= blk_error_inject_unreg,
	.cfi_stubs	= &__bpf_blk_error_inject_ops,
	.owner		= THIS_MODULE,
	.name		= "blk_error_inject_ops",
};

__bpf_kfunc_start_defs();

/*
 * Record the blk_status_t the program wants to inject on @bio.  The kernel
 * applies it (bio_endio) after ->inject() returns.  The verifier does not
 * range-check @status, so validate it here.
 */
__bpf_kfunc int bpf_bio_inject_error(struct bio *bio, int status)
{
	if (!blk_status_is_valid((__force blk_status_t)status))
		return -EINVAL;
	bio->bi_status = (__force blk_status_t)status;
	return 0;
}

__bpf_kfunc_end_defs();

/*
 * No KF_TRUSTED_ARGS: kfunc arguments are trusted by default, and the bio is
 * passed as a trusted struct_ops callback argument.
 */
BTF_KFUNCS_START(blk_error_inject_kfunc_ids)
BTF_ID_FLAGS(func, bpf_bio_inject_error)
BTF_KFUNCS_END(blk_error_inject_kfunc_ids)

static int blk_error_inject_kfunc_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	if (!btf_id_set8_contains(&blk_error_inject_kfunc_ids, kfunc_id))
		return 0;
	if (prog->aux->st_ops != &bpf_blk_error_inject_ops)
		return -EACCES;
	return 0;
}

static const struct btf_kfunc_id_set blk_error_inject_kfunc_set = {
	.owner	= THIS_MODULE,
	.set	= &blk_error_inject_kfunc_ids,
	.filter = blk_error_inject_kfunc_filter,
};

static int __init blk_error_inject_bpf_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&blk_error_inject_kfunc_set);
	ret = ret ?: register_bpf_struct_ops(&bpf_blk_error_inject_ops,
					     blk_error_inject_ops);
	return ret;
}
late_initcall(blk_error_inject_bpf_init);
