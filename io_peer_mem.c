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

/*
 * CAVEAT:
 *
 * At present, this module allows for memory regions to be invalidated
 * at any time by any changes to the underlying MMU mapping and therefore
 * does not provide the usual guarantees that ensure MRs are locked and
 * permanent in memory. Thus, userspace programs using MRs mapped through
 * this module must be aware that their memory targets may become
 * invalidated at anytime and verbs against them may fail with
 * IBV_WC_REM_INV_REQ_ERR errors. If the application is critical in anyway,
 * code may be necessary to re-register regions for when verbs against them
 * fail.
 *
 * Due to this undesireable situation, the author of this module recommends
 * against including this code, as is, in the upstream kernel and users should
 * be cautious if they use it in production environments.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <rdma/peer_mem.h>

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mmu_notifier.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>

#define VERSION "0.3"

MODULE_AUTHOR("Logan Gunthorpe");
MODULE_DESCRIPTION("MMAP'd IO memory plug-in");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(VERSION);

static void *reg_handle;
static invalidate_peer_memory mem_invalidate_callback;

struct context {
	unsigned long addr;
	size_t size;
	u64 core_context;
	struct mmu_notifier mn;
	struct mm_struct *owning_mm;
	int active;
	struct work_struct cleanup_work;
	struct mutex mmu_mutex;
};

static void do_invalidate(struct context *ctx)
{
	mutex_lock(&ctx->mmu_mutex);

	if (!ctx->active)
		goto unlock_and_return;

	ctx->active = 0;
	pr_debug("invalidated\n");
	mem_invalidate_callback(reg_handle, ctx->core_context);

unlock_and_return:
	mutex_unlock(&ctx->mmu_mutex);
}

static void mmu_release(struct mmu_notifier *mn,
			struct mm_struct *mm)
{
	struct context *ctx = container_of(mn, struct context, mn);
	pr_debug("mmu_release\n");
	do_invalidate(ctx);
}

static void mmu_invalidate_range(struct mmu_notifier *mn,
				 struct mm_struct *mm,
				 unsigned long start, unsigned long end)
{
	struct context *ctx = container_of(mn, struct context, mn);

	if (start >= (ctx->addr + ctx->size) || ctx->addr >= end)
		return;

	pr_debug("mmu_invalidate_range %lx-%lx\n", start, end);
	do_invalidate(ctx);
}

static void mmu_invalidate_page(struct mmu_notifier *mn,
				struct mm_struct *mm,
				unsigned long address)
{
	struct context *ctx = container_of(mn, struct context, mn);

	if (address < ctx->addr || address < (ctx->addr + ctx->size))
		return;

	pr_debug("mmu_invalidate_page %lx\n", address);
	do_invalidate(ctx);
}

static struct mmu_notifier_ops mmu_notifier_ops = {
	.release = mmu_release,
	.invalidate_range = mmu_invalidate_range,
	.invalidate_page = mmu_invalidate_page,
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
	ctx->active = 0;
	ctx->owning_mm = current->mm;

	if (ctx->owning_mm == NULL)
		return 0;

	end = addr + size;

	vma = find_vma(current->mm, addr);

	if (!vma || vma->vm_end < end)
		goto err;

	pr_debug("vma: %lx %lx %lx %zx\n", addr, vma->vm_end - vma->vm_start,
		  vma->vm_flags, size);

	if (!(vma->vm_flags & VM_WRITE))
		goto err;

	fault_missing_pages(vma, addr & PAGE_MASK, end);

	if (follow_pfn(vma, addr, &pfn))
		goto err;

	pr_debug("pfn: %lx\n", pfn << PAGE_SHIFT);

	mutex_init(&ctx->mmu_mutex);

	ctx->mn.ops = &mmu_notifier_ops;

	if (mmu_notifier_register(&ctx->mn, ctx->owning_mm)) {
		pr_err("Failed to register mmu_notifier\n");
		return 0;
	}

	pr_debug("acquire %p\n", ctx);
	*context = ctx;
	__module_get(THIS_MODULE);
	return 1;

err:
	kfree(ctx);
	return 0;
}

static void deferred_cleanup(struct work_struct *work)
{
	struct context *ctx = container_of(work, struct context, cleanup_work);

	pr_debug("cleanup %p\n", ctx);

	mmu_notifier_unregister(&ctx->mn, ctx->owning_mm);
	kfree(ctx);
	module_put(THIS_MODULE);
}

static void release(void *context)
{
	struct context *ctx = (struct context *) context;

	pr_debug("release %p\n", context);

	INIT_WORK(&ctx->cleanup_work, deferred_cleanup);
	schedule_work(&ctx->cleanup_work);
}

static int get_pages(unsigned long addr, size_t size, int write, int force,
		     struct sg_table *sg_head, void *context,
		     u64 core_context)
{
	struct context *ctx = (struct context *) context;
	int ret;

	ctx->core_context = core_context;
	ctx->active = 1;

	ret = sg_alloc_table(sg_head, (ctx->size + PAGE_SIZE-1) / PAGE_SIZE,
				 GFP_KERNEL);
	if (ret)
		return ret;


	return 0;
}

static void put_pages(struct sg_table *sg_head, void *context)
{
	struct context *ctx = (struct context *) context;

	ctx->active = 0;
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
	struct vm_area_struct *vma = NULL;

	*nmap = ctx->size / PAGE_SIZE;

	vma = find_vma(ctx->owning_mm, ctx->addr);
	if (!vma)
		return 1;

	for_each_sg(sg_head->sgl, sg,  (ctx->size + PAGE_SIZE-1) / PAGE_SIZE, i) {
		sg_set_page(sg, NULL, PAGE_SIZE, 0);

		if ((ret = follow_pfn(vma, addr, &pfn)))
			return ret;

		sg->dma_address = (pfn << PAGE_SHIFT);;
		sg->dma_length = PAGE_SIZE;
		sg->offset = addr & ~PAGE_MASK;

		pr_debug("sg[%d] %lx %x %d\n", i,
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
	.name           = KBUILD_MODNAME,
	.version        = VERSION,
	.acquire	= acquire,
	.get_pages	= get_pages,
	.dma_map	= dma_map,
	.dma_unmap	= dma_unmap,
	.put_pages	= put_pages,
	.get_page_size	= get_page_size,
	.release	= release,
};

static int __init io_mem_init(void)
{
	reg_handle = ib_register_peer_memory_client(&io_mem_client,
						    &mem_invalidate_callback);

	if (!reg_handle)
		return -EINVAL;

	pr_info("module loaded\n");

	return 0;
}

static void __exit io_mem_cleanup(void)
{
	pr_info("module unloaded\n");
	ib_unregister_peer_memory_client(reg_handle);
}

module_init(io_mem_init);
module_exit(io_mem_cleanup);
