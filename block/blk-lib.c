// SPDX-License-Identifier: GPL-2.0
/*
 * Functions related to generic helpers functions
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/scatterlist.h>

#include "blk.h"

static sector_t bio_discard_limit(struct block_device *bdev, sector_t sector)
{
	unsigned int discard_granularity = bdev_discard_granularity(bdev);
	sector_t granularity_aligned_sector;

	if (bdev_is_partition(bdev))
		sector += bdev->bd_start_sect;

	granularity_aligned_sector =
		round_up(sector, discard_granularity >> SECTOR_SHIFT);

	/*
	 * Make sure subsequent bios start aligned to the discard granularity if
	 * it needs to be split.
	 */
	if (granularity_aligned_sector != sector)
		return granularity_aligned_sector - sector;

	/*
	 * Align the bio size to the discard granularity to make splitting the bio
	 * at discard granularity boundaries easier in the driver if needed.
	 */
	return round_down(UINT_MAX, discard_granularity) >> SECTOR_SHIFT;
}

int __blkdev_issue_discard(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, struct bio **biop)
{
	struct bio *bio = *biop;
	sector_t bs_mask;

	if (bdev_read_only(bdev))
		return -EPERM;
	if (!bdev_max_discard_sectors(bdev))
		return -EOPNOTSUPP;

	/* In case the discard granularity isn't set by buggy device driver */
	if (WARN_ON_ONCE(!bdev_discard_granularity(bdev))) {
		pr_err_ratelimited("%pg: Error: discard_granularity is 0.\n",
				   bdev);
		return -EOPNOTSUPP;
	}

	bs_mask = (bdev_logical_block_size(bdev) >> 9) - 1;
	if ((sector | nr_sects) & bs_mask)
		return -EINVAL;

	if (!nr_sects)
		return -EINVAL;

	while (nr_sects) {
		sector_t req_sects =
			min(nr_sects, bio_discard_limit(bdev, sector));

		bio = blk_next_bio(bio, bdev, 0, REQ_OP_DISCARD, gfp_mask);
		bio->bi_iter.bi_sector = sector;
		bio->bi_iter.bi_size = req_sects << 9;
		sector += req_sects;
		nr_sects -= req_sects;

		/*
		 * We can loop for a long time in here, if someone does
		 * full device discards (like mkfs). Be nice and allow
		 * us to schedule out to avoid softlocking if preempt
		 * is disabled.
		 */
		cond_resched();
	}

	*biop = bio;
	return 0;
}
EXPORT_SYMBOL(__blkdev_issue_discard);

/**
 * blkdev_issue_discard - queue a discard
 * @bdev:	blockdev to issue discard for
 * @sector:	start sector
 * @nr_sects:	number of sectors to discard
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 *
 * Description:
 *    Issue a discard request for the sectors in question.
 */
int blkdev_issue_discard(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask)
{
	struct bio *bio = NULL;
	struct blk_plug plug;
	int ret;

	blk_start_plug(&plug);
	ret = __blkdev_issue_discard(bdev, sector, nr_sects, gfp_mask, &bio);
	if (!ret && bio) {
		ret = submit_bio_wait(bio);
		if (ret == -EOPNOTSUPP)
			ret = 0;
		bio_put(bio);
	}
	blk_finish_plug(&plug);

	return ret;
}
EXPORT_SYMBOL(blkdev_issue_discard);

/*
 * For synchronous copy offload/emulation, wait and process all in-flight BIOs.
 * This must only be called once all bios have been issued so that the refcount
 * can only decrease. This just waits for all bios to make it through
 * bio_copy_*_write_end_io. IO errors are propagated through cio->io_error.
 */
static int cio_await_completion(struct cio *cio)
{
	int ret = 0;

	atomic_dec(&cio->refcount);

	if (cio->endio)
		return 0;

	if (atomic_read(&cio->refcount)) {
		__set_current_state(TASK_UNINTERRUPTIBLE);
		blk_io_schedule();
	}

	ret = cio->io_err;
	kfree(cio);

	return ret;
}

static void blk_copy_offload_write_end_io(struct bio *bio)
{
	struct copy_ctx *ctx = bio->bi_private;
	struct cio *cio = ctx->cio;
	sector_t clen;
	int ri = ctx->range_idx;

	if (bio->bi_status) {
		cio->io_err = blk_status_to_errno(bio->bi_status);
		clen = (bio->bi_iter.bi_sector << SECTOR_SHIFT) -
			cio->ranges[ri].dst;
		cio->ranges[ri].comp_len = min_t(sector_t, clen,
				cio->ranges[ri].comp_len);
	}
	__free_page(bio->bi_io_vec[0].bv_page);
	bio_put(bio);

	if (atomic_dec_and_test(&ctx->refcount))
		kfree(ctx);
	if (atomic_dec_and_test(&cio->refcount)) {
		if (cio->endio) {
			cio->endio(cio->private, cio->io_err);
			kfree(cio);
		} else
			blk_wake_io_task(cio->waiter);
	}
}

static void blk_copy_offload_read_end_io(struct bio *read_bio)
{
	struct copy_ctx *ctx = read_bio->bi_private;
	struct cio *cio = ctx->cio;
	sector_t clen;
	int ri = ctx->range_idx;
	unsigned long flags;

	if (read_bio->bi_status) {
		cio->io_err = blk_status_to_errno(read_bio->bi_status);
		goto err_rw_bio;
	}

	/* For zoned device, we check if completed bio is first entry in linked
	 * list,
	 * if yes, we start the worker to submit write bios.
	 * if not, then we just update status of bio in ctx,
	 * once the worker gets scheduled, it will submit writes for all
	 * the consecutive REQ_COPY_READ_COMPLETE bios.
	 */
	if (bdev_is_zoned(ctx->write_bio->bi_bdev)) {
		spin_lock_irqsave(&cio->list_lock, flags);
		ctx->status = REQ_COPY_READ_COMPLETE;
		if (ctx == list_first_entry(&cio->list,
					struct copy_ctx, list)) {
			spin_unlock_irqrestore(&cio->list_lock, flags);
			schedule_work(&ctx->dispatch_work);
			goto free_read_bio;
		}
		spin_unlock_irqrestore(&cio->list_lock, flags);
	} else
		schedule_work(&ctx->dispatch_work);

free_read_bio:
	bio_put(read_bio);

	return;

err_rw_bio:
	clen = (read_bio->bi_iter.bi_sector << SECTOR_SHIFT) -
					cio->ranges[ri].src;
	cio->ranges[ri].comp_len = min_t(sector_t, clen,
					cio->ranges[ri].comp_len);
	__free_page(read_bio->bi_io_vec[0].bv_page);
	bio_put(ctx->write_bio);
	bio_put(read_bio);
	if (atomic_dec_and_test(&ctx->refcount))
		kfree(ctx);
	if (atomic_dec_and_test(&cio->refcount)) {
		if (cio->endio) {
			cio->endio(cio->private, cio->io_err);
			kfree(cio);
		} else
			blk_wake_io_task(cio->waiter);
	}
}

static void blk_copy_dispatch_work_fn(struct work_struct *work)
{
	struct copy_ctx *ctx = container_of(work, struct copy_ctx,
			dispatch_work);

	submit_bio(ctx->write_bio);
}

static void blk_zoned_copy_dispatch_work_fn(struct work_struct *work)
{
	struct copy_ctx *ctx = container_of(work, struct copy_ctx,
			dispatch_work);
	struct cio *cio = ctx->cio;
	unsigned long flags = 0;

	atomic_inc(&cio->refcount);
	spin_lock_irqsave(&cio->list_lock, flags);

	while (!list_empty(&cio->list)) {
		ctx = list_first_entry(&cio->list, struct copy_ctx, list);

		if (ctx->status == REQ_COPY_READ_PROGRESS)
			break;

		atomic_inc(&ctx->refcount);
		ctx->status = REQ_COPY_WRITE_PROGRESS;
		spin_unlock_irqrestore(&cio->list_lock, flags);
		submit_bio(ctx->write_bio);
		spin_lock_irqsave(&cio->list_lock, flags);

		list_del(&ctx->list);
		if (atomic_dec_and_test(&ctx->refcount))
			kfree(ctx);
	}

	spin_unlock_irqrestore(&cio->list_lock, flags);
	if (atomic_dec_and_test(&cio->refcount))
		blk_wake_io_task(cio->waiter);
}

/*
 * blk_copy_offload	- Use device's native copy offload feature.
 * we perform copy operation by sending 2 bio.
 * 1. First we send a read bio with REQ_COPY flag along with a token and source
 * and length. Once read bio reaches driver layer, device driver adds all the
 * source info to token and does a fake completion.
 * 2. Once read opration completes, we issue write with REQ_COPY flag with same
 * token. In driver layer, token info is used to form a copy offload command.
 *
 * For conventional devices we submit write bio independentenly once read
 * completes. For zoned devices , reads can complete out of order, so we
 * maintain a linked list and submit writes in the order, reads are submitted.
 */
static int blk_copy_offload(struct block_device *src_bdev,
		struct block_device *dst_bdev, struct range_entry *ranges,
		int nr, cio_iodone_t end_io, void *private, gfp_t gfp_mask)
{
	struct cio *cio;
	struct copy_ctx *ctx;
	struct bio *read_bio, *write_bio;
	struct page *token;
	sector_t src_blk, copy_len, dst_blk;
	sector_t rem, max_copy_len;
	int ri = 0, ret = 0;
	unsigned long flags;

	cio = kzalloc(sizeof(struct cio), GFP_KERNEL);
	if (!cio)
		return -ENOMEM;
	cio->ranges = ranges;
	atomic_set(&cio->refcount, 1);
	cio->waiter = current;
	cio->endio = end_io;
	cio->private = private;
	if (bdev_is_zoned(dst_bdev)) {
		INIT_LIST_HEAD(&cio->list);
		spin_lock_init(&cio->list_lock);
	}

	max_copy_len = min(bdev_max_copy_sectors(src_bdev),
			bdev_max_copy_sectors(dst_bdev)) << SECTOR_SHIFT;

	for (ri = 0; ri < nr; ri++) {
		cio->ranges[ri].comp_len = ranges[ri].len;
		src_blk = ranges[ri].src;
		dst_blk = ranges[ri].dst;
		for (rem = ranges[ri].len; rem > 0; rem -= copy_len) {
			copy_len = min(rem, max_copy_len);

			token = alloc_page(gfp_mask);
			if (unlikely(!token)) {
				ret = -ENOMEM;
				goto err_token;
			}

			ctx = kzalloc(sizeof(struct copy_ctx), gfp_mask);
			if (!ctx) {
				ret = -ENOMEM;
				goto err_ctx;
			}
			read_bio = bio_alloc(src_bdev, 1, REQ_OP_READ | REQ_COPY
					| REQ_SYNC | REQ_NOMERGE, gfp_mask);
			if (!read_bio) {
				ret = -ENOMEM;
				goto err_read_bio;
			}
			write_bio = bio_alloc(dst_bdev, 1, REQ_OP_WRITE
					| REQ_COPY | REQ_SYNC | REQ_NOMERGE,
					gfp_mask);
			if (!write_bio) {
				cio->io_err = -ENOMEM;
				goto err_write_bio;
			}

			ctx->cio = cio;
			ctx->range_idx = ri;
			ctx->write_bio = write_bio;
			atomic_set(&ctx->refcount, 1);

			if (bdev_is_zoned(dst_bdev)) {
				INIT_WORK(&ctx->dispatch_work,
					blk_zoned_copy_dispatch_work_fn);
				INIT_LIST_HEAD(&ctx->list);
				spin_lock_irqsave(&cio->list_lock, flags);
				ctx->status = REQ_COPY_READ_PROGRESS;
				list_add_tail(&ctx->list, &cio->list);
				spin_unlock_irqrestore(&cio->list_lock, flags);
			} else
				INIT_WORK(&ctx->dispatch_work,
					blk_copy_dispatch_work_fn);

			__bio_add_page(read_bio, token, PAGE_SIZE, 0);
			read_bio->bi_iter.bi_size = copy_len;
			read_bio->bi_iter.bi_sector = src_blk >> SECTOR_SHIFT;
			read_bio->bi_end_io = blk_copy_offload_read_end_io;
			read_bio->bi_private = ctx;

			__bio_add_page(write_bio, token, PAGE_SIZE, 0);
			write_bio->bi_iter.bi_size = copy_len;
			write_bio->bi_end_io = blk_copy_offload_write_end_io;
			write_bio->bi_iter.bi_sector = dst_blk >> SECTOR_SHIFT;
			write_bio->bi_private = ctx;

			atomic_inc(&cio->refcount);
			submit_bio(read_bio);
			src_blk += copy_len;
			dst_blk += copy_len;
		}
	}

	/* Wait for completion of all IO's*/
	return cio_await_completion(cio);

err_write_bio:
	bio_put(read_bio);
err_read_bio:
	kfree(ctx);
err_ctx:
	__free_page(token);
err_token:
	ranges[ri].comp_len = min_t(sector_t,
			ranges[ri].comp_len, (ranges[ri].len - rem));

	cio->io_err = ret;
	return cio_await_completion(cio);
}

static inline int blk_copy_sanity_check(struct block_device *src_bdev,
	struct block_device *dst_bdev, struct range_entry *ranges, int nr)
{
	unsigned int align_mask = max(bdev_logical_block_size(dst_bdev),
					bdev_logical_block_size(src_bdev)) - 1;
	sector_t len = 0;
	int i;

	if (!nr)
		return -EINVAL;

	if (nr >= MAX_COPY_NR_RANGE)
		return -EINVAL;

	if (bdev_read_only(dst_bdev))
		return -EPERM;

	for (i = 0; i < nr; i++) {
		if (!ranges[i].len)
			return -EINVAL;

		len += ranges[i].len;
		if ((ranges[i].dst & align_mask) ||
				(ranges[i].src & align_mask) ||
				(ranges[i].len & align_mask))
			return -EINVAL;
		ranges[i].comp_len = 0;
	}

	if (len && len >= MAX_COPY_TOTAL_LENGTH)
		return -EINVAL;

	return 0;
}

static void *blk_alloc_buf(sector_t req_size, sector_t *alloc_size,
		gfp_t gfp_mask)
{
	int min_size = PAGE_SIZE;
	void *buf;

	while (req_size >= min_size) {
		buf = kvmalloc(req_size, gfp_mask);
		if (buf) {
			*alloc_size = req_size;
			return buf;
		}
		/* retry half the requested size */
		req_size >>= 1;
	}

	return NULL;
}

static void blk_copy_emulate_write_end_io(struct bio *bio)
{
	struct copy_ctx *ctx = bio->bi_private;
	struct cio *cio = ctx->cio;
	sector_t clen;
	int ri = ctx->range_idx;

	if (bio->bi_status) {
		cio->io_err = blk_status_to_errno(bio->bi_status);
		clen = (bio->bi_iter.bi_sector << SECTOR_SHIFT) -
			cio->ranges[ri].dst;
		cio->ranges[ri].comp_len = min_t(sector_t, clen,
				cio->ranges[ri].comp_len);
	}
	kvfree(page_address(bio->bi_io_vec[0].bv_page));
	bio_map_kern_endio(bio);
	if (atomic_dec_and_test(&ctx->refcount))
		kfree(ctx);
	if (atomic_dec_and_test(&cio->refcount)) {
		if (cio->endio) {
			cio->endio(cio->private, cio->io_err);
			kfree(cio);
		} else
			blk_wake_io_task(cio->waiter);
	}
}

static void blk_copy_emulate_read_end_io(struct bio *read_bio)
{
	struct copy_ctx *ctx = read_bio->bi_private;
	struct cio *cio = ctx->cio;
	sector_t clen;
	int ri = ctx->range_idx;
	unsigned long flags;

	if (read_bio->bi_status) {
		cio->io_err = blk_status_to_errno(read_bio->bi_status);
		goto err_rw_bio;
	}

	/* For zoned device, we check if completed bio is first entry in linked
	 * list,
	 * if yes, we start the worker to submit write bios.
	 * if not, then we just update status of bio in ctx,
	 * once the worker gets scheduled, it will submit writes for all
	 * the consecutive REQ_COPY_READ_COMPLETE bios.
	 */
	if (bdev_is_zoned(ctx->write_bio->bi_bdev)) {
		spin_lock_irqsave(&cio->list_lock, flags);
		ctx->status = REQ_COPY_READ_COMPLETE;
		if (ctx == list_first_entry(&cio->list,
					struct copy_ctx, list)) {
			spin_unlock_irqrestore(&cio->list_lock, flags);
			schedule_work(&ctx->dispatch_work);
			goto free_read_bio;
		}
		spin_unlock_irqrestore(&cio->list_lock, flags);
	} else
		schedule_work(&ctx->dispatch_work);

free_read_bio:
	kfree(read_bio);

	return;

err_rw_bio:
	clen = (read_bio->bi_iter.bi_sector << SECTOR_SHIFT) -
					cio->ranges[ri].src;
	cio->ranges[ri].comp_len = min_t(sector_t, clen,
					cio->ranges[ri].comp_len);
	__free_page(read_bio->bi_io_vec[0].bv_page);
	bio_map_kern_endio(read_bio);
	if (atomic_dec_and_test(&ctx->refcount))
		kfree(ctx);
	if (atomic_dec_and_test(&cio->refcount)) {
		if (cio->endio) {
			cio->endio(cio->private, cio->io_err);
			kfree(cio);
		} else
			blk_wake_io_task(cio->waiter);
	}
}

/*
 * If native copy offload feature is absent, this function tries to emulate,
 * by copying data from source to a temporary buffer and from buffer to
 * destination device.
 */
static int blk_copy_emulate(struct block_device *src_bdev,
		struct block_device *dst_bdev, struct range_entry *ranges,
		int nr, cio_iodone_t end_io, void *private, gfp_t gfp_mask)
{
	struct request_queue *sq = bdev_get_queue(src_bdev);
	struct request_queue *dq = bdev_get_queue(dst_bdev);
	struct bio *read_bio, *write_bio;
	void *buf = NULL;
	struct copy_ctx *ctx;
	struct cio *cio;
	sector_t src, dst, offset, buf_len, req_len, rem = 0;
	int ri = 0, ret = 0;
	unsigned long flags;
	sector_t max_src_hw_len = min_t(unsigned int, queue_max_hw_sectors(sq),
			queue_max_segments(sq) << (PAGE_SHIFT - SECTOR_SHIFT))
			<< SECTOR_SHIFT;
	sector_t max_dst_hw_len = min_t(unsigned int, queue_max_hw_sectors(dq),
			queue_max_segments(dq) << (PAGE_SHIFT - SECTOR_SHIFT))
			<< SECTOR_SHIFT;
	sector_t max_hw_len = min_t(unsigned int,
			max_src_hw_len, max_dst_hw_len);

	cio = kzalloc(sizeof(struct cio), GFP_KERNEL);
	if (!cio)
		return -ENOMEM;
	cio->ranges = ranges;
	atomic_set(&cio->refcount, 1);
	cio->waiter = current;
	cio->endio = end_io;
	cio->private = private;

	if (bdev_is_zoned(dst_bdev)) {
		INIT_LIST_HEAD(&cio->list);
		spin_lock_init(&cio->list_lock);
	}

	for (ri = 0; ri < nr; ri++) {
		offset = ranges[ri].comp_len;
		src = ranges[ri].src + offset;
		dst = ranges[ri].dst + offset;
		/* If IO fails, we truncate comp_len */
		ranges[ri].comp_len = ranges[ri].len;

		for (rem = ranges[ri].len - offset; rem > 0; rem -= buf_len) {
			req_len = min_t(int, max_hw_len, rem);

			buf = blk_alloc_buf(req_len, &buf_len, gfp_mask);
			if (!buf) {
				ret = -ENOMEM;
				goto err_alloc_buf;
			}

			ctx = kzalloc(sizeof(struct copy_ctx), gfp_mask);
			if (!ctx) {
				ret = -ENOMEM;
				goto err_ctx;
			}

			read_bio = bio_map_kern(sq, buf, buf_len, gfp_mask);
			if (IS_ERR(read_bio)) {
				ret = PTR_ERR(read_bio);
				goto err_read_bio;
			}

			write_bio = bio_map_kern(dq, buf, buf_len, gfp_mask);
			if (IS_ERR(write_bio)) {
				ret = PTR_ERR(write_bio);
				goto err_write_bio;
			}

			ctx->cio = cio;
			ctx->range_idx = ri;
			ctx->write_bio = write_bio;
			atomic_set(&ctx->refcount, 1);

			read_bio->bi_iter.bi_sector = src >> SECTOR_SHIFT;
			read_bio->bi_iter.bi_size = buf_len;
			read_bio->bi_opf = REQ_OP_READ | REQ_SYNC;
			bio_set_dev(read_bio, src_bdev);
			read_bio->bi_end_io = blk_copy_emulate_read_end_io;
			read_bio->bi_private = ctx;

			write_bio->bi_iter.bi_size = buf_len;
			write_bio->bi_opf = REQ_OP_WRITE | REQ_SYNC;
			bio_set_dev(write_bio, dst_bdev);
			write_bio->bi_end_io = blk_copy_emulate_write_end_io;
			write_bio->bi_iter.bi_sector = dst >> SECTOR_SHIFT;
			write_bio->bi_private = ctx;

			if (bdev_is_zoned(dst_bdev)) {
				INIT_WORK(&ctx->dispatch_work,
					blk_zoned_copy_dispatch_work_fn);
				INIT_LIST_HEAD(&ctx->list);
				spin_lock_irqsave(&cio->list_lock, flags);
				ctx->status = REQ_COPY_READ_PROGRESS;
				list_add_tail(&ctx->list, &cio->list);
				spin_unlock_irqrestore(&cio->list_lock, flags);
			} else
				INIT_WORK(&ctx->dispatch_work,
					blk_copy_dispatch_work_fn);

			atomic_inc(&cio->refcount);
			submit_bio(read_bio);

			src += buf_len;
			dst += buf_len;
		}
	}

	/* Wait for completion of all IO's*/
	return cio_await_completion(cio);

err_write_bio:
	bio_put(read_bio);
err_read_bio:
	kfree(ctx);
err_ctx:
	kvfree(buf);
err_alloc_buf:
	ranges[ri].comp_len -= min_t(sector_t,
			ranges[ri].comp_len, (ranges[ri].len - rem));

	cio->io_err = ret;
	return cio_await_completion(cio);
}

static inline bool blk_check_copy_offload(struct request_queue *src_q,
		struct request_queue *dst_q)
{
	return blk_queue_copy(dst_q) && blk_queue_copy(src_q);
}

/*
 * blkdev_issue_copy - queue a copy
 * @src_bdev:	source block device
 * @dst_bdev:	destination block device
 * @ranges:	array of source/dest/len,
 *		ranges are expected to be allocated/freed by caller
 * @nr:		number of source ranges to copy
 * @end_io:	end_io function to be called on completion of copy operation,
 *		for synchronous operation this should be NULL
 * @private:	end_io function will be called with this private data, should be
 *		NULL, if operation is synchronous in nature
 * @gfp_mask:   memory allocation flags (for bio_alloc)
 *
 * Description:
 *	Copy source ranges from source block device to destination block
 *	device. length of a source range cannot be zero. Max total length of
 *	copy is limited to MAX_COPY_TOTAL_LENGTH and also maximum number of
 *	entries is limited to MAX_COPY_NR_RANGE
 */
int blkdev_issue_copy(struct block_device *src_bdev,
	struct block_device *dst_bdev, struct range_entry *ranges, int nr,
	cio_iodone_t end_io, void *private, gfp_t gfp_mask)
{
	struct request_queue *src_q = bdev_get_queue(src_bdev);
	struct request_queue *dst_q = bdev_get_queue(dst_bdev);
	int ret = -EINVAL;
	bool offload = false;

	ret = blk_copy_sanity_check(src_bdev, dst_bdev, ranges, nr);
	if (ret)
		return ret;

	offload = blk_check_copy_offload(src_q, dst_q);
	if (offload)
		ret = blk_copy_offload(src_bdev, dst_bdev, ranges, nr,
				end_io, private, gfp_mask);

	if (ret || !offload)
		ret = blk_copy_emulate(src_bdev, dst_bdev, ranges, nr,
				end_io, private, gfp_mask);

	return ret;
}
EXPORT_SYMBOL_GPL(blkdev_issue_copy);

static int __blkdev_issue_write_zeroes(struct block_device *bdev,
		sector_t sector, sector_t nr_sects, gfp_t gfp_mask,
		struct bio **biop, unsigned flags)
{
	struct bio *bio = *biop;
	unsigned int max_write_zeroes_sectors;

	if (bdev_read_only(bdev))
		return -EPERM;

	/* Ensure that max_write_zeroes_sectors doesn't overflow bi_size */
	max_write_zeroes_sectors = bdev_write_zeroes_sectors(bdev);

	if (max_write_zeroes_sectors == 0)
		return -EOPNOTSUPP;

	while (nr_sects) {
		bio = blk_next_bio(bio, bdev, 0, REQ_OP_WRITE_ZEROES, gfp_mask);
		bio->bi_iter.bi_sector = sector;
		if (flags & BLKDEV_ZERO_NOUNMAP)
			bio->bi_opf |= REQ_NOUNMAP;

		if (nr_sects > max_write_zeroes_sectors) {
			bio->bi_iter.bi_size = max_write_zeroes_sectors << 9;
			nr_sects -= max_write_zeroes_sectors;
			sector += max_write_zeroes_sectors;
		} else {
			bio->bi_iter.bi_size = nr_sects << 9;
			nr_sects = 0;
		}
		cond_resched();
	}

	*biop = bio;
	return 0;
}

/*
 * Convert a number of 512B sectors to a number of pages.
 * The result is limited to a number of pages that can fit into a BIO.
 * Also make sure that the result is always at least 1 (page) for the cases
 * where nr_sects is lower than the number of sectors in a page.
 */
static unsigned int __blkdev_sectors_to_bio_pages(sector_t nr_sects)
{
	sector_t pages = DIV_ROUND_UP_SECTOR_T(nr_sects, PAGE_SIZE / 512);

	return min(pages, (sector_t)BIO_MAX_VECS);
}

static int __blkdev_issue_zero_pages(struct block_device *bdev,
		sector_t sector, sector_t nr_sects, gfp_t gfp_mask,
		struct bio **biop)
{
	struct bio *bio = *biop;
	int bi_size = 0;
	unsigned int sz;

	if (bdev_read_only(bdev))
		return -EPERM;

	while (nr_sects != 0) {
		bio = blk_next_bio(bio, bdev, __blkdev_sectors_to_bio_pages(nr_sects),
				   REQ_OP_WRITE, gfp_mask);
		bio->bi_iter.bi_sector = sector;

		while (nr_sects != 0) {
			sz = min((sector_t) PAGE_SIZE, nr_sects << 9);
			bi_size = bio_add_page(bio, ZERO_PAGE(0), sz, 0);
			nr_sects -= bi_size >> 9;
			sector += bi_size >> 9;
			if (bi_size < sz)
				break;
		}
		cond_resched();
	}

	*biop = bio;
	return 0;
}

/**
 * __blkdev_issue_zeroout - generate number of zero filed write bios
 * @bdev:	blockdev to issue
 * @sector:	start sector
 * @nr_sects:	number of sectors to write
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 * @biop:	pointer to anchor bio
 * @flags:	controls detailed behavior
 *
 * Description:
 *  Zero-fill a block range, either using hardware offload or by explicitly
 *  writing zeroes to the device.
 *
 *  If a device is using logical block provisioning, the underlying space will
 *  not be released if %flags contains BLKDEV_ZERO_NOUNMAP.
 *
 *  If %flags contains BLKDEV_ZERO_NOFALLBACK, the function will return
 *  -EOPNOTSUPP if no explicit hardware offload for zeroing is provided.
 */
int __blkdev_issue_zeroout(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, struct bio **biop,
		unsigned flags)
{
	int ret;
	sector_t bs_mask;

	bs_mask = (bdev_logical_block_size(bdev) >> 9) - 1;
	if ((sector | nr_sects) & bs_mask)
		return -EINVAL;

	ret = __blkdev_issue_write_zeroes(bdev, sector, nr_sects, gfp_mask,
			biop, flags);
	if (ret != -EOPNOTSUPP || (flags & BLKDEV_ZERO_NOFALLBACK))
		return ret;

	return __blkdev_issue_zero_pages(bdev, sector, nr_sects, gfp_mask,
					 biop);
}
EXPORT_SYMBOL(__blkdev_issue_zeroout);

/**
 * blkdev_issue_zeroout - zero-fill a block range
 * @bdev:	blockdev to write
 * @sector:	start sector
 * @nr_sects:	number of sectors to write
 * @gfp_mask:	memory allocation flags (for bio_alloc)
 * @flags:	controls detailed behavior
 *
 * Description:
 *  Zero-fill a block range, either using hardware offload or by explicitly
 *  writing zeroes to the device.  See __blkdev_issue_zeroout() for the
 *  valid values for %flags.
 */
int blkdev_issue_zeroout(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp_mask, unsigned flags)
{
	int ret = 0;
	sector_t bs_mask;
	struct bio *bio;
	struct blk_plug plug;
	bool try_write_zeroes = !!bdev_write_zeroes_sectors(bdev);

	bs_mask = (bdev_logical_block_size(bdev) >> 9) - 1;
	if ((sector | nr_sects) & bs_mask)
		return -EINVAL;

retry:
	bio = NULL;
	blk_start_plug(&plug);
	if (try_write_zeroes) {
		ret = __blkdev_issue_write_zeroes(bdev, sector, nr_sects,
						  gfp_mask, &bio, flags);
	} else if (!(flags & BLKDEV_ZERO_NOFALLBACK)) {
		ret = __blkdev_issue_zero_pages(bdev, sector, nr_sects,
						gfp_mask, &bio);
	} else {
		/* No zeroing offload support */
		ret = -EOPNOTSUPP;
	}
	if (ret == 0 && bio) {
		ret = submit_bio_wait(bio);
		bio_put(bio);
	}
	blk_finish_plug(&plug);
	if (ret && try_write_zeroes) {
		if (!(flags & BLKDEV_ZERO_NOFALLBACK)) {
			try_write_zeroes = false;
			goto retry;
		}
		if (!bdev_write_zeroes_sectors(bdev)) {
			/*
			 * Zeroing offload support was indicated, but the
			 * device reported ILLEGAL REQUEST (for some devices
			 * there is no non-destructive way to verify whether
			 * WRITE ZEROES is actually supported).
			 */
			ret = -EOPNOTSUPP;
		}
	}

	return ret;
}
EXPORT_SYMBOL(blkdev_issue_zeroout);

int blkdev_issue_secure_erase(struct block_device *bdev, sector_t sector,
		sector_t nr_sects, gfp_t gfp)
{
	sector_t bs_mask = (bdev_logical_block_size(bdev) >> 9) - 1;
	unsigned int max_sectors = bdev_max_secure_erase_sectors(bdev);
	struct bio *bio = NULL;
	struct blk_plug plug;
	int ret = 0;

	/* make sure that "len << SECTOR_SHIFT" doesn't overflow */
	if (max_sectors > UINT_MAX >> SECTOR_SHIFT)
		max_sectors = UINT_MAX >> SECTOR_SHIFT;
	max_sectors &= ~bs_mask;

	if (max_sectors == 0)
		return -EOPNOTSUPP;
	if ((sector | nr_sects) & bs_mask)
		return -EINVAL;
	if (bdev_read_only(bdev))
		return -EPERM;

	blk_start_plug(&plug);
	for (;;) {
		unsigned int len = min_t(sector_t, nr_sects, max_sectors);

		bio = blk_next_bio(bio, bdev, 0, REQ_OP_SECURE_ERASE, gfp);
		bio->bi_iter.bi_sector = sector;
		bio->bi_iter.bi_size = len << SECTOR_SHIFT;

		sector += len;
		nr_sects -= len;
		if (!nr_sects) {
			ret = submit_bio_wait(bio);
			bio_put(bio);
			break;
		}
		cond_resched();
	}
	blk_finish_plug(&plug);

	return ret;
}
EXPORT_SYMBOL(blkdev_issue_secure_erase);
