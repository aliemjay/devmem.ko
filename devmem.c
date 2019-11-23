// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/drivers/char/mem.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Added devfs support.
 *    Jan-11-1998, C. Scott Ananian <cananian@alumni.princeton.edu>
 *  Shared /dev/zero mmapping support, Feb 2000, Kanoj Sarcar <kanoj@sgi.com>
 */

#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mman.h>
#include <linux/random.h>
#include <linux/init.h>
#include <linux/raw.h>
#include <linux/tty.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/device.h>
#include <linux/highmem.h>
#include <linux/backing-dev.h>
#include <linux/shmem_fs.h>
#include <linux/splice.h>
#include <linux/pfn.h>
#include <linux/export.h>
#include <linux/io.h>
#include <linux/uio.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/kallsyms.h>
#include "override.h"

#include <linux/uaccess.h>

#ifdef CONFIG_IA64
# include <linux/efi.h>
#endif

#undef MEM_MAJOR
#define MEM_MAJOR 60
#define DEVPORT_MINOR	4

#define IGNORE_VALID_PHYS_ADDR
#warning "Ignoring ARCH_HAS_VALID_PHYS_ADDR_RANGE! You can now access the whole physical range. Please check if this arch requires special treatment of non-RAM addresses. If so, you may only use /dev/mem via mmap interface and using the arch-specific io helper functions (e.g. readb)"

#define IGNORE_STRICT_DEVMEM
#warning "Ignoring CONFIG_STRICT_DEVMEM! System RAM and IO memory reserved by device drivers are now accessible."

static u8 debug_mode = 0;
#define debug(fmt, ...) \
	if (debug_mode) printk(KERN_DEBUG "devmem: " fmt "\n", ##__VA_ARGS__);

static inline unsigned long size_inside_page(unsigned long start,
					     unsigned long size)
{
	unsigned long sz;

	sz = PAGE_SIZE - (start & (PAGE_SIZE - 1));

	return min(sz, size);
}

#ifndef ARCH_HAS_VALID_PHYS_ADDR_RANGE
inline int valid_phys_addr_range(phys_addr_t addr, size_t count)
{
	return addr + count <= __pa(high_memory);
}

inline int valid_mmap_phys_addr_range(unsigned long pfn, size_t size)
{
	return 1;
}
#endif

#ifdef CONFIG_STRICT_DEVMEM
static inline int page_is_allowed(unsigned long pfn)
{
	return devmem_is_allowed(pfn);
}
static inline int range_is_allowed(unsigned long pfn, unsigned long size)
{
	u64 from = ((u64)pfn) << PAGE_SHIFT;
	u64 to = from + size;
	u64 cursor = from;

	while (cursor < to) {
		if (!devmem_is_allowed(pfn))
			return 0;
		cursor += PAGE_SIZE;
		pfn++;
	}
	return 1;
}
#else
static inline int page_is_allowed(unsigned long pfn)
{
	return 1;
}
static inline int range_is_allowed(unsigned long pfn, unsigned long size)
{
	return 1;
}
#endif

#ifndef unxlate_dev_mem_ptr
#define unxlate_dev_mem_ptr unxlate_dev_mem_ptr
void __weak unxlate_dev_mem_ptr(phys_addr_t phys, void *addr)
{
}
#endif

static struct {
	u32 debugfs_addr, addr;
	u8 debugfs_logsz, logsz; /* = log2(size) */
	void *virt;
	atomic_t mutex;
} iomem = {
	.mutex = ATOMIC_INIT(1),
};

static bool mut_try_lock(atomic_t *mut) {
	if (!arch_atomic_dec_and_test(mut)) {
		arch_atomic_inc(mut);
		return false;
	} else
		return true;
}

static void mut_release(atomic_t *mut) {
	arch_atomic_inc(mut);
}

static int open_iomem(struct inode *inode, struct file *filp)
{
	phys_addr_t addr = iomem.debugfs_addr;
	u8 logsz = iomem.debugfs_logsz;
	u8 size = 1 << logsz;

	debug("valid_phys_* @%p, o_valid_.. @%p", &valid_phys_addr_range,
	      o_valid_phys_addr_range);
	if (logsz > 2 || addr >> logsz << logsz != addr ||
	    valid_phys_addr_range(addr, size))
		return -EINVAL;
	debug("passed test 1");

	if (!mut_try_lock(&iomem.mutex))
		return -ENFILE;

	iomem.virt = ioremap_nocache(addr, size);
	if (!iomem.virt) goto recover_lock;
	iomem.addr = addr;
	iomem.logsz = logsz;
	return 0;

recover_lock:
	mut_release(&iomem.mutex);
	return -EINVAL;
}

static ssize_t read_iomem(struct file *file, char __user *buf,
			  size_t count, loff_t *ppos)
{
	char *logsz_fmt[] = { "0x%02x\n", "0x%04x\n", "0x%08x\n" };
	u32 val = 0;
	char outbuf[14];
	int outbuf_sz = (1 << iomem.logsz) * 2 + 4;

	if (count < outbuf_sz)
		return -EINVAL;
	if (*ppos != 0)
		return 0;

	switch (iomem.logsz) {
		case 0: val = readb(iomem.virt); break;
		case 1: val = readw(iomem.virt); break;
		case 2: val = readl(iomem.virt); break;
	}

	snprintf(outbuf, outbuf_sz, logsz_fmt[iomem.logsz], val);
	outbuf_sz = strlen(outbuf);
	copy_to_user(buf, (void *)outbuf, outbuf_sz);

	*ppos += outbuf_sz;
	return outbuf_sz;
}

static ssize_t write_iomem(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	u32 val = 0;
	char inbuf[14];
	int inbuf_sz = (1 << iomem.logsz) * 2 + 4;

	if (count > inbuf_sz || *ppos != 0
	    || copy_from_user(inbuf, buf, inbuf_sz) != 0
	    || sscanf(inbuf, "0x%x", &val) != 1)
		return -EINVAL;

	switch (iomem.logsz) {
		case 0: writeb(val, iomem.virt); break;
		case 1: writew(val, iomem.virt); break;
		case 2: writel(val, iomem.virt); break;
	}

	*ppos += count;
	return count;
}

static int release_iomem(struct inode *inode, struct file *file)
{
	iounmap(iomem.virt);
	iomem.virt = NULL;
	mut_release(&iomem.mutex);
	return 0;
}

static const struct file_operations iomem_fops = {
	.owner = THIS_MODULE,
	.open = open_iomem,
	.read = read_iomem,
	.write = write_iomem,
	.release = release_iomem,
};

/*
 * This funcion reads the *physical* memory. The f_pos points directly to the
 * memory location.
 */
static ssize_t read_mem(struct file *file, char __user *buf,
			size_t count, loff_t *ppos)
{
	phys_addr_t p = *ppos;
	ssize_t read, sz;
	void *ptr;
	char *bounce;
	int err;

	debug("reading pos %llx / reading virt %p / "
	      "high mem pos %p / high mem phys %lx...",
	      p, __va(p), high_memory, __pa(high_memory));
	if (p != *ppos)
		return 0;

#ifndef IGNORE_VALID_PHYS_ADDR
	if (!valid_phys_addr_range(p, count))
		return -EFAULT;
	debug("\tphys addr is valid");
#endif
	read = 0;
#ifdef __ARCH_HAS_NO_PAGE_ZERO_MAPPED
	/* we don't have page 0 mapped on sparc and m68k.. */
	if (p < PAGE_SIZE) {
		sz = size_inside_page(p, count);
		if (sz > 0) {
			if (clear_user(buf, sz))
				return -EFAULT;
			buf += sz;
			p += sz;
			count -= sz;
			read += sz;
		}
	}
#endif

	bounce = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!bounce)
		return -ENOMEM;

	while (count > 0) {
		unsigned long remaining;
		int allowed = 1, probe;

		sz = size_inside_page(p, count);

#ifndef IGNORE_STRICT_DEVMEM
		err = -EPERM;
		allowed = page_is_allowed(p >> PAGE_SHIFT);
		if (!allowed)
			goto failed;
#endif

		err = -EFAULT;
		if (allowed == 2) {
			/* Show zeros for restricted memory. */
			remaining = clear_user(buf, sz);
		} else {
			/*
			 * On ia64 if a page has been mapped somewhere as
			 * uncached, then it must also be accessed uncached
			 * by the kernel or data corruption may occur.
			 */
			ptr = xlate_dev_mem_ptr(p);
			if (!ptr)
				goto failed;
			debug("\tpassed xlate_dev_kmem_ptr");

			probe = probe_kernel_read(bounce, ptr, sz);
			unxlate_dev_mem_ptr(p, ptr);
			if (probe)
				goto failed;
			debug("\tpassed probe_kernel_read");

			remaining = copy_to_user(buf, bounce, sz);
		}

		if (remaining)
			goto failed;

		buf += sz;
		p += sz;
		count -= sz;
		read += sz;
	}
	kfree(bounce);

	*ppos += read;
	return read;

failed:
	kfree(bounce);
	return err;
}

static ssize_t write_mem(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
	phys_addr_t p = *ppos;
	ssize_t written, sz;
	unsigned long copied;
	void *ptr;

	if (p != *ppos)
		return -EFBIG;

#ifndef IGNORE_VALID_PHYS_ADDR
	if (!valid_phys_addr_range(p, count))
		return -EFAULT;
#endif

	written = 0;

#ifdef __ARCH_HAS_NO_PAGE_ZERO_MAPPED
	/* we don't have page 0 mapped on sparc and m68k.. */
	if (p < PAGE_SIZE) {
		sz = size_inside_page(p, count);
		/* Hmm. Do something? */
		buf += sz;
		p += sz;
		count -= sz;
		written += sz;
	}
#endif

	while (count > 0) {
		int allowed = 1;

		sz = size_inside_page(p, count);

#ifndef IGNORE_STRICT_DEVMEM
		allowed = page_is_allowed(p >> PAGE_SHIFT);
		if (!allowed)
			return -EPERM;
#endif

		/* Skip actual writing when a page is marked as restricted. */
		if (allowed == 1) {
			/*
			 * On ia64 if a page has been mapped somewhere as
			 * uncached, then it must also be accessed uncached
			 * by the kernel or data corruption may occur.
			 */
			ptr = xlate_dev_mem_ptr(p);
			if (!ptr) {
				if (written)
					break;
				return -EFAULT;
			}

			copied = copy_from_user(ptr, buf, sz);
			unxlate_dev_mem_ptr(p, ptr);
			if (copied) {
				written += sz - copied;
				if (written)
					break;
				return -EFAULT;
			}
		}

		buf += sz;
		p += sz;
		count -= sz;
		written += sz;
	}

	*ppos += written;
	return written;
}

int __weak phys_mem_access_prot_allowed(struct file *file,
	unsigned long pfn, unsigned long size, pgprot_t *vma_prot)
{
	return 1;
}

#ifndef __HAVE_PHYS_MEM_ACCESS_PROT

/*
 * Architectures vary in how they handle caching for addresses
 * outside of main memory.
 *
 */
#ifdef pgprot_noncached
static int uncached_access(struct file *file, phys_addr_t addr)
{
#if defined(CONFIG_IA64)
	/*
	 * On ia64, we ignore O_DSYNC because we cannot tolerate memory
	 * attribute aliases.
	 */
	return !(efi_mem_attributes(addr) & EFI_MEMORY_WB);
#elif defined(CONFIG_MIPS)
	{
		extern int __uncached_access(struct file *file,
					     unsigned long addr);

		return __uncached_access(file, addr);
	}
#else
	/*
	 * Accessing memory above the top the kernel knows about or through a
	 * file pointer
	 * that was marked O_DSYNC will be done non-cached.
	 */
	if (file->f_flags & O_DSYNC)
		return 1;
	return addr >= __pa(high_memory);
#endif
}
#endif

static pgprot_t phys_mem_access_prot(struct file *file, unsigned long pfn,
				     unsigned long size, pgprot_t vma_prot)
{
#ifdef pgprot_noncached
	phys_addr_t offset = pfn << PAGE_SHIFT;

	if (uncached_access(file, offset))
		return pgprot_noncached(vma_prot);
#endif
	return vma_prot;
}
#endif

#ifndef CONFIG_MMU
static unsigned long get_unmapped_area_mem(struct file *file,
					   unsigned long addr,
					   unsigned long len,
					   unsigned long pgoff,
					   unsigned long flags)
{
#ifndef IGNORE_VALID_PHYS_ADDR
	if (!valid_mmap_phys_addr_range(pgoff, len))
		return (unsigned long) -EINVAL;
#endif
	return pgoff << PAGE_SHIFT;
}

/* permit direct mmap, for read, write or exec */
static unsigned memory_mmap_capabilities(struct file *file)
{
	return NOMMU_MAP_DIRECT |
		NOMMU_MAP_READ | NOMMU_MAP_WRITE | NOMMU_MAP_EXEC;
}

static unsigned zero_mmap_capabilities(struct file *file)
{
	return NOMMU_MAP_COPY;
}

/* can't do an in-place private mapping if there's no MMU */
static inline int private_mapping_ok(struct vm_area_struct *vma)
{
	return vma->vm_flags & VM_MAYSHARE;
}
#else

static inline int private_mapping_ok(struct vm_area_struct *vma)
{
	return 1;
}
#endif

static const struct vm_operations_struct mmap_mem_ops = {
#ifdef CONFIG_HAVE_IOREMAP_PROT
	.access = generic_access_phys
#endif
};

static int mmap_mem(struct file *file, struct vm_area_struct *vma)
{
	size_t size = vma->vm_end - vma->vm_start;
	phys_addr_t offset = (phys_addr_t)vma->vm_pgoff << PAGE_SHIFT;

	/* Does it even fit in phys_addr_t? */
	if (offset >> PAGE_SHIFT != vma->vm_pgoff)
		return -EINVAL;

	/* It's illegal to wrap around the end of the physical address space. */
	if (offset + (phys_addr_t)size - 1 < offset)
		return -EINVAL;

#ifndef IGNORE_VALID_PHYS_ADDR
	if (!valid_mmap_phys_addr_range(vma->vm_pgoff, size))
		return -EINVAL;
#endif

	if (!private_mapping_ok(vma))
		return -ENOSYS;

	/*
	if (!range_is_allowed(vma->vm_pgoff, size))
		return -EPERM;
	*/

	if (!phys_mem_access_prot_allowed(file, vma->vm_pgoff, size,
						&vma->vm_page_prot))
		return -EINVAL;

	vma->vm_page_prot = phys_mem_access_prot(file, vma->vm_pgoff,
						 size,
						 vma->vm_page_prot);

	vma->vm_ops = &mmap_mem_ops;

	/* Remap-pfn-range will mark the range VM_IO */
	if (remap_pfn_range(vma,
			    vma->vm_start,
			    vma->vm_pgoff,
			    size,
			    vma->vm_page_prot)) {
		return -EAGAIN;
	}
	return 0;
}

static int mmap_kmem(struct file *file, struct vm_area_struct *vma)
{
	unsigned long pfn;

	/* Turn a kernel-virtual address into a physical page frame */
	pfn = __pa((u64)vma->vm_pgoff << PAGE_SHIFT) >> PAGE_SHIFT;

	/*
	 * RED-PEN: on some architectures there is more mapped memory than
	 * available in mem_map which pfn_valid checks for. Perhaps should add a
	 * new macro here.
	 *
	 * RED-PEN: vmalloc is not supported right now.
	 */
	if (!pfn_valid(pfn))
		return -EIO;

	vma->vm_pgoff = pfn;
	return mmap_mem(file, vma);
}

/*
 * This function reads the *virtual* memory as seen by the kernel.
 */
static ssize_t read_kmem(struct file *file, char __user *buf,
			 size_t count, loff_t *ppos)
{
	unsigned long p = *ppos;
	ssize_t low_count, read, sz;
	char *kbuf; /* k-addr because vread() takes vmlist_lock rwlock */
	int err = 0;

	read = 0;
	if (p < (unsigned long) high_memory) {
		low_count = count;
		if (count > (unsigned long)high_memory - p)
			low_count = (unsigned long)high_memory - p;

#ifdef __ARCH_HAS_NO_PAGE_ZERO_MAPPED
		/* we don't have page 0 mapped on sparc and m68k.. */
		if (p < PAGE_SIZE && low_count > 0) {
			sz = size_inside_page(p, low_count);
			if (clear_user(buf, sz))
				return -EFAULT;
			buf += sz;
			p += sz;
			read += sz;
			low_count -= sz;
			count -= sz;
		}
#endif
		while (low_count > 0) {
			sz = size_inside_page(p, low_count);

			/*
			 * On ia64 if a page has been mapped somewhere as
			 * uncached, then it must also be accessed uncached
			 * by the kernel or data corruption may occur
			 */
			kbuf = xlate_dev_kmem_ptr((void *)p);
			if (!virt_addr_valid(kbuf))
				return -ENXIO;

			if (copy_to_user(buf, kbuf, sz))
				return -EFAULT;
			buf += sz;
			p += sz;
			read += sz;
			low_count -= sz;
			count -= sz;
		}
	}

	if (count > 0) {
		kbuf = (char *)__get_free_page(GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;
		while (count > 0) {
			sz = size_inside_page(p, count);
			if (!is_vmalloc_or_module_addr((void *)p)) {
				err = -ENXIO;
				break;
			}
			sz = vread(kbuf, (char *)p, sz);
			if (!sz)
				break;
			if (copy_to_user(buf, kbuf, sz)) {
				err = -EFAULT;
				break;
			}
			count -= sz;
			buf += sz;
			read += sz;
			p += sz;
		}
		free_page((unsigned long)kbuf);
	}
	*ppos = p;
	return read ? read : err;
}


static ssize_t do_write_kmem(unsigned long p, const char __user *buf,
				size_t count, loff_t *ppos)
{
	ssize_t written, sz;
	unsigned long copied;

	written = 0;
#ifdef __ARCH_HAS_NO_PAGE_ZERO_MAPPED
	/* we don't have page 0 mapped on sparc and m68k.. */
	if (p < PAGE_SIZE) {
		sz = size_inside_page(p, count);
		/* Hmm. Do something? */
		buf += sz;
		p += sz;
		count -= sz;
		written += sz;
	}
#endif

	while (count > 0) {
		void *ptr;

		sz = size_inside_page(p, count);

		/*
		 * On ia64 if a page has been mapped somewhere as uncached, then
		 * it must also be accessed uncached by the kernel or data
		 * corruption may occur.
		 */
		ptr = xlate_dev_kmem_ptr((void *)p);
		if (!virt_addr_valid(ptr))
			return -ENXIO;

		copied = copy_from_user(ptr, buf, sz);
		if (copied) {
			written += sz - copied;
			if (written)
				break;
			return -EFAULT;
		}
		buf += sz;
		p += sz;
		count -= sz;
		written += sz;
	}

	*ppos += written;
	return written;
}

/*
 * This function writes to the *virtual* memory as seen by the kernel.
 */
static ssize_t write_kmem(struct file *file, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	unsigned long p = *ppos;
	ssize_t wrote = 0;
	ssize_t virtr = 0;
	char *kbuf; /* k-addr because vwrite() takes vmlist_lock rwlock */
	int err = 0;

	if (p < (unsigned long) high_memory) {
		unsigned long to_write = min_t(unsigned long, count,
					       (unsigned long)high_memory - p);
		wrote = do_write_kmem(p, buf, to_write, ppos);
		if (wrote != to_write)
			return wrote;
		p += wrote;
		buf += wrote;
		count -= wrote;
	}

	if (count > 0) {
		kbuf = (char *)__get_free_page(GFP_KERNEL);
		if (!kbuf)
			return wrote ? wrote : -ENOMEM;
		while (count > 0) {
			unsigned long sz = size_inside_page(p, count);
			unsigned long n;

			if (!is_vmalloc_or_module_addr((void *)p)) {
				err = -ENXIO;
				break;
			}
			n = copy_from_user(kbuf, buf, sz);
			if (n) {
				err = -EFAULT;
				break;
			}
			vwrite(kbuf, (char *)p, sz);
			count -= sz;
			buf += sz;
			virtr += sz;
			p += sz;
		}
		free_page((unsigned long)kbuf);
	}

	*ppos = p;
	return virtr + wrote ? : err;
}

static ssize_t read_port(struct file *file, char __user *buf,
			 size_t count, loff_t *ppos)
{
	unsigned long i = *ppos;
	char __user *tmp = buf;

	if (!access_ok(buf, count))
		return -EFAULT;
	while (count-- > 0 && i < 65536) {
		if (__put_user(inb(i), tmp) < 0)
			return -EFAULT;
		i++;
		tmp++;
	}
	*ppos = i;
	return tmp-buf;
}

static ssize_t write_port(struct file *file, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	unsigned long i = *ppos;
	const char __user *tmp = buf;

	if (!access_ok(buf, count))
		return -EFAULT;
	while (count-- > 0 && i < 65536) {
		char c;

		if (__get_user(c, tmp)) {
			if (tmp > buf)
				break;
			return -EFAULT;
		}
		outb(c, i);
		i++;
		tmp++;
	}
	*ppos = i;
	return tmp-buf;
}

static ssize_t read_null(struct file *file, char __user *buf,
			 size_t count, loff_t *ppos)
{
	return 0;
}

static ssize_t write_null(struct file *file, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	return count;
}

static ssize_t read_iter_null(struct kiocb *iocb, struct iov_iter *to)
{
	return 0;
}

static ssize_t write_iter_null(struct kiocb *iocb, struct iov_iter *from)
{
	size_t count = iov_iter_count(from);
	iov_iter_advance(from, count);
	return count;
}

static int pipe_to_null(struct pipe_inode_info *info, struct pipe_buffer *buf,
			struct splice_desc *sd)
{
	return sd->len;
}

static ssize_t splice_write_null(struct pipe_inode_info *pipe, struct file *out,
				 loff_t *ppos, size_t len, unsigned int flags)
{
	return splice_from_pipe(pipe, out, ppos, len, flags, pipe_to_null);
}

static ssize_t read_iter_zero(struct kiocb *iocb, struct iov_iter *iter)
{
	size_t written = 0;

	while (iov_iter_count(iter)) {
		size_t chunk = iov_iter_count(iter), n;

		if (chunk > PAGE_SIZE)
			chunk = PAGE_SIZE;	/* Just for latency reasons */
		n = iov_iter_zero(chunk, iter);
		if (!n && iov_iter_count(iter))
			return written ? written : -EFAULT;
		written += n;
		if (signal_pending(current))
			return written ? written : -ERESTARTSYS;
		cond_resched();
	}
	return written;
}

static int mmap_zero(struct file *file, struct vm_area_struct *vma)
{
#ifndef CONFIG_MMU
	return -ENOSYS;
#endif
	if (vma->vm_flags & VM_SHARED)
		return shmem_zero_setup(vma);
	vma_set_anonymous(vma);
	return 0;
}

static unsigned long get_unmapped_area_zero(struct file *file,
				unsigned long addr, unsigned long len,
				unsigned long pgoff, unsigned long flags)
{
#ifdef CONFIG_MMU
	if (flags & MAP_SHARED) {
		/*
		 * mmap_zero() will call shmem_zero_setup() to create a file,
		 * so use shmem's get_unmapped_area in case it can be huge;
		 * and pass NULL for file as in mmap.c's get_unmapped_area(),
		 * so as not to confuse shmem with our handle on "/dev/zero".
		 */
		return shmem_get_unmapped_area(NULL, addr, len, pgoff, flags);
	}

	/* Otherwise flags & MAP_PRIVATE: with no shmem object beneath it */
	return current->mm->get_unmapped_area(file, addr, len, pgoff, flags);
#else
	return -ENOSYS;
#endif
}

static ssize_t write_full(struct file *file, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	return -ENOSPC;
}

/*
 * Special lseek() function for /dev/null and /dev/zero.  Most notably, you
 * can fopen() both devices with "a" now.  This was previously impossible.
 * -- SRB.
 */
static loff_t null_lseek(struct file *file, loff_t offset, int orig)
{
	return file->f_pos = 0;
}

/*
 * The memory devices use the full 32/64 bits of the offset, and so we cannot
 * check against negative addresses: they are ok. The return value is weird,
 * though, in that case (0).
 *
 * also note that seeking relative to the "end of file" isn't supported:
 * it has no meaning, so it returns -EINVAL.
 */
static loff_t memory_lseek(struct file *file, loff_t offset, int orig)
{
	loff_t ret;

	inode_lock(file_inode(file));
	switch (orig) {
	case SEEK_CUR:
		offset += file->f_pos;
		/* fall through */
	case SEEK_SET:
		/* to avoid userland mistaking f_pos=-9 as -EBADF=-9 */
		if ((unsigned long long)offset >= -MAX_ERRNO) {
			ret = -EOVERFLOW;
			break;
		}
		file->f_pos = offset;
		ret = file->f_pos;
		force_successful_syscall_return();
		break;
	default:
		ret = -EINVAL;
	}
	debug("seeked to pos %llx", file->f_pos);
	inode_unlock(file_inode(file));
	return ret;
}

static int open_port(struct inode *inode, struct file *filp)
{
	filp->f_mode |= FMODE_UNSIGNED_OFFSET;
	return capable(CAP_SYS_RAWIO) ? 0 : -EPERM;
}

#define zero_lseek	null_lseek
#define full_lseek      null_lseek
#define write_zero	write_null
#define write_iter_zero	write_iter_null
#define open_mem	open_port
#define open_kmem	open_mem

static const struct file_operations __maybe_unused mem_fops = {
	.llseek		= memory_lseek,
	.read		= read_mem,
	.write		= write_mem,
	.mmap		= mmap_mem,
	.open		= open_mem,
#ifndef CONFIG_MMU
	.get_unmapped_area = get_unmapped_area_mem,
	.mmap_capabilities = memory_mmap_capabilities,
#endif
};

static const struct file_operations __maybe_unused kmem_fops = {
	.llseek		= memory_lseek,
	.read		= read_kmem,
	.write		= write_kmem,
	.mmap		= mmap_kmem,
	.open		= open_kmem,
#ifndef CONFIG_MMU
	.get_unmapped_area = get_unmapped_area_mem,
	.mmap_capabilities = memory_mmap_capabilities,
#endif
};

static const struct file_operations null_fops = {
	.llseek		= null_lseek,
	.read		= read_null,
	.write		= write_null,
	.read_iter	= read_iter_null,
	.write_iter	= write_iter_null,
	.splice_write	= splice_write_null,
};

static const struct file_operations __maybe_unused port_fops = {
	.llseek		= memory_lseek,
	.read		= read_port,
	.write		= write_port,
	.open		= open_port,
};

static const struct file_operations zero_fops = {
	.llseek		= zero_lseek,
	.write		= write_zero,
	.read_iter	= read_iter_zero,
	.write_iter	= write_iter_zero,
	.mmap		= mmap_zero,
	.get_unmapped_area = get_unmapped_area_zero,
#ifndef CONFIG_MMU
	.mmap_capabilities = zero_mmap_capabilities,
#endif
};

static const struct file_operations full_fops = {
	.llseek		= full_lseek,
	.read_iter	= read_iter_zero,
	.write		= write_full,
};

static const struct memdev {
	const char *name;
	umode_t mode;
	const struct file_operations *fops;
	fmode_t fmode;
} devlist[] = {
#ifdef CONFIG_DEVMEM
	 [1] = { "mem-relaxed", 0, &mem_fops, FMODE_UNSIGNED_OFFSET },
#endif
#ifdef CONFIG_DEVKMEM
	 [2] = { "kmem", 0, &kmem_fops, FMODE_UNSIGNED_OFFSET },
#endif
	 [3] = { "null", 0666, &null_fops, 0 },
#ifdef CONFIG_DEVPORT
	 [4] = { "port", 0, &port_fops, 0 },
#endif
	 [5] = { "zero", 0666, &zero_fops, 0 },
	 [7] = { "full", 0666, &full_fops, 0 },
	 /*
	  * TODO:the following *_fops are not constant.
	  * Set them in module init.
	 [8] = { "random", 0666, &random_fops, 0 },
	 [9] = { "urandom", 0666, &urandom_fops, 0 },
#ifdef CONFIG_PRINTK
	[11] = { "kmsg", 0644, &kmsg_fops, 0 },
#endif
	*/
};

static int memory_open(struct inode *inode, struct file *filp)
{
	int minor;
	const struct memdev *dev;

	minor = iminor(inode);
	if (minor >= ARRAY_SIZE(devlist))
		return -ENXIO;

	dev = &devlist[minor];
	if (!dev->fops)
		return -ENXIO;

	filp->f_op = dev->fops;
	filp->f_mode |= dev->fmode;

	if (dev->fops->open)
		return dev->fops->open(inode, filp);

	return 0;
}

static const struct file_operations memory_fops = {
	.open = memory_open,
	.llseek = noop_llseek,
};

static char *mem_devnode(struct device *dev, umode_t *mode)
{
	if (mode && devlist[MINOR(dev->devt)].mode)
		*mode = devlist[MINOR(dev->devt)].mode;
	return NULL;
}

static struct class *mem_class;

static int __init chr_dev_init(void)
{
	int minor;

	if (register_chrdev(MEM_MAJOR, "devmem", &memory_fops))
		printk("unable to get major %d for memory devs\n", MEM_MAJOR);

	mem_class = class_create(THIS_MODULE, "devmem");
	if (IS_ERR(mem_class))
		return PTR_ERR(mem_class);

	mem_class->devnode = mem_devnode;
	for (minor = 1; minor < ARRAY_SIZE(devlist); minor++) {
		if (!devlist[minor].name)
			continue;

		/*
		 * Create /dev/port?
		 */
		if ((minor == DEVPORT_MINOR) && !arch_has_dev_port())
			continue;

		device_create(mem_class, NULL, MKDEV(MEM_MAJOR, minor),
			      NULL, devlist[minor].name);
	}

	return 0;
}

static void __exit chr_dev_exit(void)
{
	int minor;

	for (minor = 1; minor < ARRAY_SIZE(devlist); minor++) {
		if (!devlist[minor].name)
			continue;
		if ((minor == DEVPORT_MINOR) && !arch_has_dev_port())
			continue;

		device_destroy(mem_class, MKDEV(MEM_MAJOR, minor));
	}

	class_destroy(mem_class);

	unregister_chrdev(MEM_MAJOR, "devmem");
}

static struct dentry *debugfs_dir;

static int __init devmem_init(void)
{
	const struct o_sym *sym;

	/* Resolve unexported symbols manually */
	for (sym = o_syms; sym < &o_syms[ARRAY_SIZE(o_syms)]; sym++) {
		*sym->sym = kallsyms_lookup_name(sym->orig_name);
		if (! *sym->sym)
			return -1;
	}

	/* Create character devices */
	chr_dev_init();

	debugfs_dir = debugfs_create_dir("devmem", NULL);
	if (!debugfs_dir)
		return -ENOMEM;
	debugfs_create_u8("debug_mode", 0644, debugfs_dir, &debug_mode);

	/* iomem files */
	debugfs_create_file("iomem", 0644, debugfs_dir, NULL, &iomem_fops);
	debugfs_create_u8("iomem-log2size", 0644, debugfs_dir,
			  &iomem.debugfs_logsz);
	debugfs_create_u32("iomem-addr", 0644, debugfs_dir,
			   &iomem.debugfs_addr);

	return 0;
}

static void __exit devmem_exit(void)
{
	debugfs_remove_recursive(debugfs_dir);
	chr_dev_exit();
}

module_init(devmem_init);
module_exit(devmem_exit);
MODULE_LICENSE("GPL");
