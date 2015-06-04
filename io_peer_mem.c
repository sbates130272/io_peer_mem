/*
 * Copyright (c) 2015, PMC-Sierra Inc.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#include <rdma/peer_mem.h>

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/cdev.h>

#define NAME    "io_peer_mem"
#define VERSION "0.2"

MODULE_AUTHOR("Logan Gunthorpe");
MODULE_DESCRIPTION("MMAP'd IO memory plug-in");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(VERSION);

#ifdef DEBUG
#define debug_msg(FMT, ARGS...) printk(NAME ": " FMT, ## ARGS)
#else
#define debug_msg(FMT, ARGS...)
#endif

/**
 * This is copied from drivers/media/v4l2-core/videobuf2-memops.c:
 *
 * This function attempts to acquire an area mapped in the userspace for
 * the duration of a hardware mapping. The area is "locked" by performing
 * the same set of operation that are done when process calls fork() and
 * memory areas are duplicated.
 */
static struct vm_area_struct *get_vma(struct vm_area_struct *vma)
{
	struct vm_area_struct *vma_copy;

	vma_copy = kmalloc(sizeof(*vma_copy), GFP_KERNEL);
	if (vma_copy == NULL)
		return NULL;

	if (vma->vm_ops && vma->vm_ops->open)
		vma->vm_ops->open(vma);

	if (vma->vm_file)
		get_file(vma->vm_file);

	memcpy(vma_copy, vma, sizeof(*vma));

	vma_copy->vm_next = NULL;
	vma_copy->vm_prev = NULL;

	return vma_copy;
}

static void put_vma(struct vm_area_struct *vma)
{
	if (!vma)
		return;

	if (vma->vm_ops && vma->vm_ops->close)
		vma->vm_ops->close(vma);

	if (vma->vm_file)
		fput(vma->vm_file);

	kfree(vma);
}

struct context {
	unsigned long addr;
	size_t size;
	struct vm_area_struct *vma;
};

static void fault_missing_pages(struct vm_area_struct *vma, unsigned long start,
				unsigned long end)
{
	unsigned long pfn;

	if (!(vma->vm_flags & VM_MIXEDMAP))
		return;

	for (; start < end; start += PAGE_SIZE) {
		if (!follow_pfn(vma, start, &pfn))
			continue;

		handle_mm_fault(current->mm, vma, start, FAULT_FLAG_WRITE);
	}
}

static int is_uverbs_file(struct vm_area_struct *vma)
{
	/* There is an ugly corner case leak possible:
	 *   If a malicous userspace process grabs the uverbs file descriptor
	 *   (for /dev/infinband/uverbs*), mmaps it, and tries to register
	 *   that memory via io_peer_mem then this module will successfully
	 *   register the memory, and take a reference to that file.
	 *
	 *   Seeing the uverbs code only cleans up memory regions only after
	 *   that file is closed, and io_peer_mem will only release that file
	 *   when the cleanup occurs, a deadlock will occur and the registration
	 *   will be permanently leaked.
	 *
	 * This code handles this situation in a bit of an hackish way:
	 *   we check if the backing file's i_cdev's kobjs's name starts with
	 *   "uverbs" and refuses to map it if it does.
	 */
	struct inode *i;

	if (!vma->vm_file || !vma->vm_file->f_inode)
		return 0;

	i = vma->vm_file->f_inode;

	if (!S_ISCHR(i->i_mode) || i->i_cdev == NULL)
		return 0;

	return strncmp(i->i_cdev->kobj.name, "uverbs", strlen("uverbs")) == 0;
}


static int acquire(unsigned long addr, size_t size, void *peer_mem_private_data,
		   char *peer_mem_name, void **context)
{
	struct vm_area_struct *vma = NULL;
	struct context *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	unsigned long pfn, end;

	if (!ctx)
		return 0;

	ctx->addr = addr;
	ctx->size = size;

	end = addr + size;

	vma = find_vma(current->mm, addr);

	if (!vma || vma->vm_end < end)
		goto err;

	debug_msg("vma: %lx %lx %lx %zx\n", addr, vma->vm_end - vma->vm_start,
		  vma->vm_flags, size);

	if (is_uverbs_file(vma)) {
		pr_err(NAME ": can't register a uverbs device!\n");
		goto err;
	}

	if (!(vma->vm_flags & VM_WRITE))
		goto err;

	fault_missing_pages(vma, addr & PAGE_MASK, end);

	if (follow_pfn(vma, addr, &pfn))
		goto err;

	debug_msg("pfn: %lx\n", pfn << PAGE_SHIFT);
	debug_msg("acquire %p\n", ctx);

	ctx->vma = get_vma(vma);

	if (ctx->vma == NULL) {
		printk(NAME ": could not allocate VMA!\n");
		goto err;
	}


	*context = ctx;
	__module_get(THIS_MODULE);
	return 1;

err:
	kfree(ctx);
	return 0;
}

static void release(void *context)
{
	struct context *ctx = (struct context *) context;

	debug_msg("release %p\n", context);

	put_vma(ctx->vma);

	kfree(context);
	module_put(THIS_MODULE);
}

static int get_pages(unsigned long addr, size_t size, int write, int force,
		     struct sg_table *sg_head, void *context,
		     u64 core_context)
{
	struct context *ctx = (struct context *) context;

	int ret = sg_alloc_table(sg_head, (ctx->size + PAGE_SIZE-1) / PAGE_SIZE,
				 GFP_KERNEL);
	if (ret)
		return ret;

	return 0;
}

static void put_pages(struct sg_table *sg_head, void *context)
{
	sg_free_table(sg_head);
}

static int dma_map(struct sg_table *sg_head, void *context,
		      struct device *dma_device, int dmasync,
		      int *nmap)
{
	struct scatterlist *sg;
	struct context *ctx = (struct context *) context;
	unsigned long pfn;
	unsigned long addr = ctx->addr;
	unsigned long size = ctx->size;
	int i, ret;

	*nmap = ctx->size / PAGE_SIZE;

	for_each_sg(sg_head->sgl, sg,  (ctx->size + PAGE_SIZE-1) / PAGE_SIZE, i) {
		sg_set_page(sg, NULL, PAGE_SIZE, 0);

		if ((ret = follow_pfn(ctx->vma, addr, &pfn)))
			return ret;

		sg->dma_address = (pfn << PAGE_SHIFT);;
		sg->dma_length = PAGE_SIZE;
		sg->offset = addr & ~PAGE_MASK;

		debug_msg("sg[%d] %lx %x %d\n", i,
			  (unsigned long) sg->dma_address,
			  sg->dma_length, sg->offset);

		addr += sg->dma_length - sg->offset;
		size -= sg->dma_length - sg->offset;

		if (!size) {
			*nmap = i+1;
			break;
		}
	}

	return 0;
}

static int dma_unmap(struct sg_table *sg_head, void *context,
			   struct device  *dma_device)
{
	return 0;
}

static unsigned long get_page_size(void *context)
{
	return PAGE_SIZE;
}

static struct peer_memory_client io_mem_client = {
	.name           = NAME,
	.version        = VERSION,
	.acquire	= acquire,
	.get_pages	= get_pages,
	.dma_map	= dma_map,
	.dma_unmap	= dma_unmap,
	.put_pages	= put_pages,
	.get_page_size	= get_page_size,
	.release	= release,
};


static void *reg_handle;
static int __init io_mem_init(void)
{
	reg_handle = ib_register_peer_memory_client(&io_mem_client, NULL);

	if (!reg_handle)
		return -EINVAL;

	printk(NAME ": module loaded\n");

	return 0;
}

static void __exit io_mem_cleanup(void)
{
	printk(NAME ": module unloaded\n");
	ib_unregister_peer_memory_client(reg_handle);
}

module_init(io_mem_init);
module_exit(io_mem_cleanup);
