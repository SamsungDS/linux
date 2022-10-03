///
/// show cxlssdinfo file under /proc/cxlssdinfo
///
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/mmzone.h>
#include <linux/proc_fs.h>
#include <linux/percpu.h>
#include <linux/seq_file.h>
#include <linux/swap.h>
#include <linux/vmstat.h>
#include <linux/atomic.h>
#ifdef CONFIG_CMA
#include <linux/cma.h>
#endif
#include <asm/page.h>
#include <linux/cxlfs.h>

#define GB_SHIFT (30)
static void show_val_gb(struct seq_file *m, const char *s, unsigned long num)
{
	seq_put_decimal_ull_width(m, s, num >> (GB_SHIFT), 8);
	seq_write(m, " GB\n", 4);
}

static int cxlssdinfo_proc_show(struct seq_file *m, void *v)
{

	/*
	 * CXL Memory Total Size & range infomation
	 * CXL Memory Size & range infomation per device
	 * CXL SSD LRU information
	 * page cache vs CXL DAX size
	 * Huge page mapping vs normal page mapping
	 * and more
	 */

	show_val_gb(m, "CXLSSD Memory Total Size:       ", totalcxlmem_size());

	return 0;
}

static int __init proc_cxlssdinfo_init(void)
{
	proc_create_single("cxlssdinfo", 0, NULL, cxlssdinfo_proc_show);
	return 0;
}
fs_initcall(proc_cxlssdinfo_init);

