#include "data-csum.h"
#include <linux/blk-integrity.h>
#include <linux/bio-integrity.h>


void * btrfs_data_csum_alloc(struct bio *bio)
{
	struct blk_integrity *bi = blk_get_integrity(bio->bi_bdev->bd_disk);
	struct bio_integrity_payload *bip;
	unsigned int buf_size;
	void *buf;

	if (!bi)
		return NULL;

	buf_size = bio_integrity_bytes(bi, bio_sectors(bio));
	buf = kmalloc(buf_size, GFP_NOFS | __GFP_NOFAIL);
	bip = bio_integrity_alloc(bio, GFP_NOFS | __GFP_NOFAIL, 1);
	if (!bio_integrity_add_page(bio, virt_to_page(buf), buf_size,
				offset_in_page(buf)))
		WARN_ON_ONCE(1);

	if (bi->csum_type) {
		if (bi->csum_type == BLK_INTEGRITY_CSUM_IP)
			bip->bip_flags |= BIP_IP_CHECKSUM;
		bip->bip_flags |= BIP_CHECK_GUARD;
	}
	if (bi->flags & BLK_INTEGRITY_REF_TAG)
		bip->bip_flags |= BIP_CHECK_REFTAG;
	bip_set_seed(bip, bio->bi_iter.bi_sector);
	return buf;
}

void btrfs_data_csum_generate(struct bio *bio)
{
	struct blk_integrity *bi = blk_get_integrity(bio->bi_bdev->bd_disk);

	if (!bi || !bi->csum_type)
		return;

	btrfs_data_csum_alloc(bio);
	blk_integrity_generate(bio);
}

int btrfs_data_csum_verify(struct bio *bio)
{
	struct blk_integrity *bi = blk_get_integrity(bio->bi_bdev->bd_disk);

	if (!bi || !bi->csum_type)
		return 0;
	return blk_integrity_verify_all(bio, bio->bi_iter.bi_sector);
}
