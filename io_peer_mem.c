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

#define NAME    "io_peer_mem"
#define VERSION "0.1"

MODULE_AUTHOR("Logan Gunthorpe");
MODULE_DESCRIPTION("MMAP'd IO memory plug-in");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(VERSION);

#ifdef DEBUG
#define debug_msg(FMT, ARGS...) printk(NAME ": " FMT, ## ARGS)
#else
#define debug_msg(FMT, ARGS...)
#endif


struct context {
	unsigned long addr;
	size_t size;
	unsigned long npages;
};

static int acquire(unsigned long addr, size_t size, void *peer_mem_private_data,
		   char *peer_mem_name, void **context)
{
	struct vm_area_struct *vma = NULL;
	struct context *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	unsigned long pfn;

	if (!ctx)
		return 0;

	ctx->addr = addr;
	ctx->size = size;
	ctx->npages = 0;

	vma = find_vma(current->mm, addr);

	do {
		if (!vma)
			goto err;

		debug_msg("vma: %lx %lx %lx\n", addr, vma->vm_end - vma->vm_start,
			  vma->vm_flags);

		if (vma->vm_flags & VM_MIXEDMAP)
			handle_mm_fault(current->mm, vma, addr, FAULT_FLAG_WRITE);

		if (follow_pfn(vma, addr, &pfn))
			goto err;

		debug_msg("pfn: %lx\n", pfn << PAGE_SHIFT);
		size -= min_t(unsigned long, size, vma->vm_end - addr);
		ctx->npages++;
		vma = vma->vm_next;
	} while(size);

	debug_msg("acquire %p\n", ctx);

	*context = ctx;
	__module_get(THIS_MODULE);
	return 1;

err:
	kfree(ctx);
	return 0;
}

static void release(void *context)
{
	debug_msg("release %p\n", context);
	kfree(context);
	module_put(THIS_MODULE);
	return;
}

static int get_pages(unsigned long addr, size_t size, int write, int force,
		     struct sg_table *sg_head, void *context,
		     u64 core_context)
{
	struct context *ctx = (struct context *) context;
	int ret = sg_alloc_table(sg_head, ctx->npages, GFP_KERNEL);
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
	struct vm_area_struct *vma = NULL;
	unsigned long addr = ctx->addr;
	unsigned long size = ctx->size;
	unsigned long pfn;
	int i;

	vma = find_vma(current->mm, addr);

	for_each_sg(sg_head->sgl, sg, ctx->npages, i) {
		if (!vma)
			return -EINVAL;

		if (follow_pfn(vma, addr, &pfn))
			return -EINVAL;

		sg_set_page(sg, NULL, PAGE_SIZE, 0);
		sg->dma_address = pfn << PAGE_SHIFT;
		sg->dma_length = min_t(unsigned long, size, vma->vm_end - addr);
		sg->offset = 0;

		debug_msg("sg[%d] %lx %x\n", i,
			  (unsigned long) sg->dma_address,
			  sg->dma_length);

		size -= sg->dma_length;
		vma = vma->vm_next;

		if (!size)
			break;

	}

	*nmap = i+1;

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
