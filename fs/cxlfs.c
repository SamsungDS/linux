/*
 * fs/cxlfs.c
 * Memory Solution Lab, SAMSUNG Electronics
 * 2021 Heekwon Park<heekwon.p@samsung.com>
 * 2021-2022 Tong Zhang<t.zhang2@samsung.com>
 */
#include <linux/atomic.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/cxlfs.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/memcontrol.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/pagevec.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/uio.h>
#include <linux/vmstat.h>
#include <linux/pfn_t.h>
#include <linux/sizes.h>
#include <linux/mmu_notifier.h>
#include <linux/iomap.h>
#include <linux/io.h>
#include <linux/fiemap.h>
#include <linux/pfn_t.h>
#include <asm/pgalloc.h>
#include <asm-generic/bug.h>

static int nr_cxlssd;

atomic_long_t _totalcxlmem_size __read_mostly;
EXPORT_SYMBOL(_totalcxlmem_size);
atomic_long_t _mapped_cxlmem_size __read_mostly;
EXPORT_SYMBOL(_mapped_cxlmem_size);

static uint64_t get_part_offset_from_file(struct file *file)
{
	struct block_device *bdev;
	if (!file->f_inode)
		return 0;
	if (!file->f_inode->i_sb)
		return 0;
	bdev = file->f_inode->i_sb->s_bdev;
	if (!bdev) {
		WARN_ONCE(1, "bdev is null?");
		return 0;
	}
	return bdev->bd_start_sect * 512;
}

cxlssd_space_info *cxlssd_si;
int cxl_vma_mapper(struct file *file, struct vm_area_struct *vma,
		   cxlssd_space_info *si)
{
	/* 
	 * We need to define struct cxlssd_device and add it into ext4_sb_info 
	 */
	unsigned long long cxlmem_base_addr = si->base_addr;
	unsigned long size = vma->vm_end - vma->vm_start;
	uint64_t part_offset;
	unsigned long vaddr;
	int i, ret;
	struct fiemap info_fiemap;
	size_t fiebuffer_size;
	struct fiemap *fiemap;
	struct fiemap_extent *emap;

	part_offset = get_part_offset_from_file(file);
	// printk("%s:%d part_offset = 0x%llx\n", __FILE__, __LINE__, part_offset);

	// get how many extents are there
	info_fiemap.fm_flags = FIEMAP_FLAG_SYNC;
	info_fiemap.fm_start = vma->vm_pgoff << PAGE_SHIFT;
	info_fiemap.fm_length = size;
	info_fiemap.fm_extent_count = 0;
	if (get_fiemap(file, &info_fiemap)) {
		printk("%s:%d Coult not get fiemap\n", __FILE__, __LINE__);
		fput(file);
		return -EBADF;
	}
	// printk("%s:%d %d extents\n", __FILE__,__LINE__, info_fiemap.fm_mapped_extents);
	// we expect file system use 4k block size
	fiebuffer_size =
		sizeof(struct fiemap) +
		sizeof(struct fiemap_extent) * info_fiemap.fm_mapped_extents;
	fiemap = kzalloc(fiebuffer_size, GFP_KERNEL);
	if (!fiemap) {
		printk("%s:%d Could not allocate memory\n",__FILE__,__LINE__);
		return -ENOMEM;
	}

	fiemap->fm_flags = FIEMAP_FLAG_SYNC;
	fiemap->fm_start = vma->vm_pgoff << PAGE_SHIFT;
	fiemap->fm_length = size;
	fiemap->fm_extent_count = info_fiemap.fm_mapped_extents;

	ret = get_fiemap(file, fiemap);
	if (ret) {
		printk("%s:%d Could not get fiemap %d!\n",__FILE__,__LINE__, ret);
		ret = -EBADF;
		goto end;
	}

	emap = fiemap->fm_extents;
	vaddr = vma->vm_start;

	// iterate through each file extent and try to map them
	for (i = 0; i < fiemap->fm_mapped_extents; i++) {
		unsigned long fe_size = emap[i].fe_length;
		uint64_t phy_addr = cxlmem_base_addr + part_offset + 
				     emap[i].fe_physical;
		unsigned long pfn = phy_addr >> PAGE_SHIFT;
		printk("%s:%d vaddr=0x%lx phy_addr=0x%llx size=0x%lx\n",__FILE__,__LINE__, vaddr, phy_addr, fe_size);
		if (IS_CXLSSD_HUGEPAGE(vma->vm_flags)) {
			int cnt = 0;
			// user requested Huge Page. Although FS use 4k  block size, 
			// if they fall perfectly within 2MB boundary, it is possible
			// to wire them up using 2MB page size (PMD SIZE in x86_64)
			// ret = vmf_insert_pfn_pmd(vmf, pfn, vma->vm_flags & VM_WRITE);
			// handle not aligned prefix
			//uint64_t prefix_size = PMD_SIZE - phy_addr % PMD_SIZE;
			uint64_t prefix_size = (PMD_SIZE - vaddr % PMD_SIZE ) % PMD_SIZE;
			if (prefix_size != 0) {
				if (prefix_size>fe_size)
					prefix_size = fe_size;
				// printk("%s:%d prefix: vaddr=0x%lx pfn=0x%lx prefix_size=0x%llx\n",__FILE__,__LINE__, vaddr, pfn, prefix_size);
				ret = remap_pfn_range_notrack(vma, vaddr, pfn, prefix_size,
					      vma->vm_page_prot);
				if (ret)
					goto fini;
				vaddr += prefix_size;
				phy_addr += prefix_size;
				pfn = phy_addr >> PAGE_SHIFT;
				fe_size -= prefix_size;
			}
			// still not aligned ?
			if (!IS_ALIGNED(vaddr, PMD_SIZE) || (!IS_ALIGNED(phy_addr,PMD_SIZE))) {
				printk("%s:%d performance tip: not able to use huge page since page is"
					" not aligned, try move virtual address to align prefix size "
					"with phyaddress prefix size\n",__FILE__,__LINE__);
				goto fallback;
			}
			// handle aligned 2MB page(s)
			while (fe_size >= PMD_SIZE) {
				// printk("%s:%d 2MB page: vaddr=0x%lx pfn=0x%lx\n",__FILE__,__LINE__, vaddr, pfn);
				ret = remap_pfn_single_pmd_hugepage(vma, vaddr, 
					pfn, PMD_SIZE, vma->vm_page_prot);
				// try fallback method
				if (ret)
					break;
				vaddr += PMD_SIZE;
				//FIXME: have to align to 2MB?
				phy_addr += PMD_SIZE;
				pfn = phy_addr >> PAGE_SHIFT;
				fe_size -= PMD_SIZE;
				cnt++;
			}
			printk("%s:%d mapped %d 2MB pages\n",__FILE__,__LINE__, cnt);
			// handle remaining pages<2MB in fallback
		}
fallback:
		// fallback map method, also take care of remaining pages cannot
		// fit into the 2MB huge page
		if (fe_size!=0) {
			// printk("%s:%d remaining pages: vaddr=0x%lx phy_addr=0x%llx size=0x%llx\n",__FILE__,__LINE__, vaddr, phy_addr, fe_size);
			ret = remap_pfn_range_notrack(vma, vaddr, pfn, fe_size,
					      vma->vm_page_prot);
		}
fini:
		if (ret) {
			pr_err("Could not map cxl memory!\n");
			goto end;
		}
		vaddr += fe_size;
	}
	printk("[CXLSSD: %d in %s] Instant mapping is done!\n", __LINE__,
	       __func__);
end:
	kfree(fiemap);
	return ret;
}

EXPORT_SYMBOL(cxl_vma_mapper);

cxlssd_space_info *get_cxlssd_space_info(void *data, unsigned long size,
					 unsigned long long offset,
					 void *dev)
{
	int i;
	void *cxl_data;
	for (i = 0; i < nr_cxlssd; i++) {
		cxlssd_space_info *si = &cxlssd_si[i];
		if (si->dev!=dev)
			continue;
		if (offset + size > si->size)
			continue;
		cxl_data = memremap(si->base_addr + offset, size, MEMREMAP_WB);
		if (!cxl_data) {
			printk("%s:%d Cannot map CXLSSD at 0x%llx\n", __FILE__,__LINE__,(uint64_t)(si->base_addr+offset));
			continue;
		}
		// now try to flush CPU cache that might have stale Cache entries
		clflush_cache_range(cxl_data, size);
		if (!memcmp(data, cxl_data, size)) {
			printk("[CXLSSD: %d in %s]Found CXLSSD space for given File system CXL Memory base address : 0x%llx(size: 0x%lx)\n",
			       __LINE__, __func__, si->base_addr, si->size);
			memunmap(cxl_data);
			return si;
		} else {
			printk("%s:%d content mismatch!\n", __FILE__,__LINE__);
		}
		memunmap(cxl_data);
	}

	printk("[CXLSSD: %d in %s] This is not CXLSSD(there is no corresponding cxlssd space for the given filesystem)\n",
	       __LINE__, __func__);
	return NULL;
}

int get_nr_cxlssd(void)
{
	return nr_cxlssd;
}

void *get_cxlssd_address(int idx, unsigned long size, unsigned long long offset)
{
	void *cxl_data;
	cxlssd_space_info *si = &cxlssd_si[idx];
	if (offset + size > si->size)
		return NULL;
	cxl_data = ioremap(si->base_addr + offset, size);
	return cxl_data;
}

void unmap_cxlssd_address(void *cxl_data)
{
	if (cxl_data)
		iounmap(cxl_data);
}

cxlssd_space_info *get_cxlssd_space_info_by_idx(int idx)
{
	return &cxlssd_si[idx];
}

/*
 * this is where we handle page fault for cxl memory
 * User can do mmap first then the page structure is actually created later 
 * in this page fault handler
 * TODO: need to deal with other cases, like COW page etc...
 */
vm_fault_t cxl_filemap_fault(struct vm_fault *vmf, cxlssd_space_info *si)
{
	/* 
	 * We need to define struct cxlssd_device and add it into ext4_sb_info 
	 */
	unsigned long long cxlmem_base_addr = si->base_addr;
	uint64_t part_offset;
	struct vm_area_struct *vma = vmf->vma;
	struct file *file = vmf->vma->vm_file;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	// this is the offset we need to ask fiemap
	pgoff_t pgoff = vmf->pgoff;
	loff_t pos = (loff_t)pgoff << PAGE_SHIFT;
	// get the pfn using pos and fiemap -- or iomap_begin
	unsigned long pfn;
	// the faulting virtual address
	unsigned long vaddr = vmf->address;
	struct fiemap *fiemap;
	struct fiemap_extent *emap;

	part_offset = get_part_offset_from_file(file);
	// printk("%s:%d part_offset = 0x%llx\n",__FILE__,__LINE__, part_offset);

	// printk("%s:%d %s pgoff=0x%lx faulting virtual address=0x%lx\n",__FILE__,__LINE__,__func__, pgoff, vmf->address);

	if (unlikely(pos >= i_size_read(inode)))
		return VM_FAULT_SIGBUS;
	// find out the corresponding cxl address
	fiemap = kzalloc(sizeof(struct fiemap) + sizeof(struct fiemap_extent),
			 GFP_KERNEL);
	if (!fiemap)
		return VM_FAULT_OOM;
	fiemap->fm_flags = FIEMAP_FLAG_SYNC;
	fiemap->fm_start = pos;
	fiemap->fm_length = PAGE_SIZE;
	fiemap->fm_extent_count = 1;
	if (get_fiemap(file, fiemap)) {
		kfree(fiemap);
		return VM_FAULT_SIGBUS;
	}
	emap = fiemap->fm_extents;
	pfn = (emap[0].fe_logical - pos + emap[0].fe_physical +
	       cxlmem_base_addr + part_offset) >>
	      PAGE_SHIFT;
	kfree(fiemap);
	// the actual mapping
	if (vma->vm_flags & VM_WRITE)
		return vmf_insert_mixed_mkwrite(
			vma, vaddr, __pfn_to_pfn_t(pfn, PFN_DEV | PFN_MAP));
	return vmf_insert_mixed(vma, vaddr,
				__pfn_to_pfn_t(pfn, PFN_DEV | PFN_MAP));
}

EXPORT_SYMBOL(cxl_filemap_fault);

void __init init_cxlssd_space_info(void)
{
	cxlssd_si = (cxlssd_space_info *)vmalloc(sizeof(cxlssd_space_info) *
						 MAX_CXLSSD_COUNT);
	nr_cxlssd = 0;
}

// try to find cxlssd space info entry
// return non-negative if found
// -1 on not found,
// -2 on overlapping address
int find_cxlssd_space_info(unsigned long addr, unsigned long size, void* dev)
{
	int i;
	// avoid registering duplicate or overlapping address space
	for (i = 0; i < nr_cxlssd; i++) {
		cxlssd_space_info *si = &cxlssd_si[i];
		unsigned long astart = si->base_addr;
		unsigned long astop = astart + si->size - 1;
		unsigned long bstart = addr;
		unsigned long bstop = addr + size - 1;
		if ((astop < bstart) || (bstop < astart))
			continue;
		// give a warning unless they are exactly the same
		if (((si->base_addr == addr) && (si->size == size) && (si->dev == dev)))
			return i;
		return -2;
	}
	return -1;
}

void register_cxlssd_space_info(unsigned long addr, unsigned long size, void* dev)
{
	int i;
	cxlssd_space_info *si;
	/*
	 * PoC: It is called from start_kernel or setup_arch to set based address.
	 * TODO: It should be called from cxl mem device driver when it do cxl_probe.
	 */
	if (nr_cxlssd >= MAX_CXLSSD_COUNT) {
		printk("Kernel can only support %d CXL SSD, consider increase MAX_CXLSSD_COUNT\n",
		       MAX_CXLSSD_COUNT);
		return;
	}
	// avoid registering duplicate or overlapping address space
	i = find_cxlssd_space_info(addr, size, dev);
	if (i >= 0) {
		return;
	} else if (i == -2) {
		printk("Detected overlapping CXL address space: 0x%lx, size:0x%lx\n",
		       addr, size);
		return;
	}
	si = &cxlssd_si[nr_cxlssd++];
	si->base_addr = addr;
	si->size = size;
	si->dev = dev;
	totalcxlmem_add(size);
}
EXPORT_SYMBOL(register_cxlssd_space_info);

void unregister_cxlssd_space_info(unsigned long addr, unsigned long size, void *dev)
{
	int i = find_cxlssd_space_info(addr, size, dev);
	// we expect exact match, otherwise this is a bug
	BUG_ON(i < 0);
	for (; i < nr_cxlssd - 1; i++) {
		cxlssd_si[i].base_addr = cxlssd_si[i + 1].base_addr;
		cxlssd_si[i].size = cxlssd_si[i + 1].size;
	}
	nr_cxlssd--;
	totalcxlmem_remove(size);
}
EXPORT_SYMBOL(unregister_cxlssd_space_info);

void print_cxlssd_space_info(void)
{
	int i;
	for (i = 0; i < nr_cxlssd; i++) {
		cxlssd_space_info *si = &cxlssd_si[i];
		printk("[CXLSSD: %d in %s]CXL Memory base address : 0x%llx(size: 0x%lx)\n",
		       __LINE__, __func__, si->base_addr, si->size);
	}
}
EXPORT_SYMBOL(print_cxlssd_space_info);
#if 0
int setup_cxlmem_addr(struct cxlssd_device *cxl_dev){

	cxl_dev->base_addr = cxlssda_si
}
#endif
