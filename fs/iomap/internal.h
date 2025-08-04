/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _IOMAP_INTERNAL_H
#define _IOMAP_INTERNAL_H 1

#include <linux/blk-integrity.h>

#define IOEND_BATCH_SIZE	4096

/*
 * Normally we can build bios as big as the data structure supports.
 *
 * But for integrity protected I/O we need to respect the maximum size of the
 * single contiguous allocation for the integrity buffer which is sized for
 * the worse case of 8 bytes of integrity metadata per 512 byte sector (or
 * ("integrity interval").
 *
 * Additionally integrity vecs still need to be built to hardware limits
 * instead of being split by the block layer like the data payload, so we
 * need to limit ourselfs to the segment size here.
 */
static_assert(SZ_128M <= BLK_INTEGRITY_MAX_SIZE / 8 * 512);
static inline size_t iomap_max_bio_size(const struct iomap *iomap)
{
	if (iomap->flags & IOMAP_F_INTEGRITY)
		return min(SZ_128M, bdev_limits(iomap->bdev)->max_segment_size);
	return SIZE_MAX;
}

void ioend_finish_bio(struct iomap_ioend *ioend);
u32 iomap_finish_ioend_buffered_read(struct iomap_ioend *ioend);
u32 iomap_finish_ioend_direct(struct iomap_ioend *ioend);

#endif /* _IOMAP_INTERNAL_H */
