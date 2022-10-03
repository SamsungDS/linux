#ifndef _LINUX_CXLFS_H
#define _LINUX_CXLFS_H

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/atomic.h>
#include <linux/radix-tree.h>
#define MAX_CXLSSD_COUNT CONFIG_CXLSSD_MAX_COUNT

typedef struct _cxlssd_space_info{
	/*device name for ID*/
	unsigned long long base_addr;
	unsigned long size;
	// CXLSSD PoC is a very special device, it need to be fully initialized by
	// nvme driver before we can attempt to access any data, early initialize
	// the space information will lead to race condition where the kernel could
	// attempt to mount a non-CXLSSD device in parallel with CXLSSD initialization
	// and use the HDM region to detect whether this is a CXLSSD and lead to
	// system hang, we add a pointer here to make sure fs layer knows this
	// HDM belongs to which device and wont attempt to mount it unless the
	// bdev matches block dev
	void* dev;
}cxlssd_space_info;

extern int cxl_vma_mapper(struct file *file, struct vm_area_struct *vma, cxlssd_space_info *si);
extern vm_fault_t cxl_filemap_fault(struct vm_fault *vmf, cxlssd_space_info *si);
extern void __init init_cxlssd_space_info(void);
extern void register_cxlssd_space_info(unsigned long addr, unsigned long size, void* dev);
extern void unregister_cxlssd_space_info(unsigned long addr, unsigned long size, void* dev);
extern void print_cxlssd_space_info(void);
extern cxlssd_space_info *get_cxlssd_space_info(void* data, unsigned long size, unsigned long long offset, void* dev);
extern int get_nr_cxlssd(void);
extern void* get_cxlssd_address(int idx, unsigned long size, unsigned long long offset);
extern void unmap_cxlssd_address(void *cxl_data);
extern cxlssd_space_info *get_cxlssd_space_info_by_idx(int idx);

extern atomic_long_t _totalcxlmem_size;
static inline unsigned long totalcxlmem_size(void)
{
	return (unsigned long)atomic_long_read(&_totalcxlmem_size);
}

static inline void totalcxlmem_add(long size)
{
	atomic_long_add(size, &_totalcxlmem_size);
}

static inline void totalcxlmem_remove(long size)
{
	atomic_long_sub(size, &_totalcxlmem_size);
}
#endif
