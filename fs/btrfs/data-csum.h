#include<linux/blk_types.h>

void * btrfs_data_csum_alloc(struct bio *bio);
void btrfs_data_csum_generate(struct bio *bio);
int btrfs_data_csum_verify(struct bio *bio);

