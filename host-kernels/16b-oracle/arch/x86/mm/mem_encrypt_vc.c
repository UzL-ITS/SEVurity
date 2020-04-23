// SPDX-License-Identifier: GPL-2.0
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2019 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#define DISABLE_BRANCH_PROFILING

#include <stdarg.h>

#include <linux/mem_encrypt.h>
#include <linux/percpu-defs.h>
#include <linux/printk.h>
#include <linux/context_tracking.h>

#include <asm/mem_encrypt_vc.h>
#include <asm/set_memory.h>
#include <asm/svm.h>
#include <asm/msr-index.h>
#include <asm/traps.h>
#include <asm/insn.h>
#include <asm/fpu/internal.h>

#define DR7_RESET_VALUE	0x400

typedef int (*vmg_nae_exit_t)(struct ghcb *ghcb, unsigned long ghcb_pa,
			      struct pt_regs *regs, struct insn *insn);

static DEFINE_PER_CPU_DECRYPTED(struct ghcb, ghcb_page) __aligned(PAGE_SIZE);

static DEFINE_PER_CPU(unsigned long, cached_dr7) = DR7_RESET_VALUE;

static struct ghcb *early_ghcb_va;

static void vmg_exception(unsigned int excp)
{
	switch (excp) {
	case X86_TRAP_GP:
	case X86_TRAP_UD:
		break;
	default:
		WARN(1, "vmgexit exception is not valid (%u)\n", excp);
	}
}

int vmg_exit(struct ghcb *ghcb, u64 exit_code,
	     u64 exit_info_1, u64 exit_info_2)
{
	unsigned int action, reason;

	ghcb->save.sw_exit_code = exit_code;
	ghcb->save.sw_exit_info_1 = exit_info_1;
	ghcb->save.sw_exit_info_2 = exit_info_2;

	/* VMGEXIT instruction */
	asm volatile ("rep; vmmcall" ::: "memory");

	if (!ghcb->save.sw_exit_info_1)
		return 0;

	reason = upper_32_bits(ghcb->save.sw_exit_info_1);
	action = lower_32_bits(ghcb->save.sw_exit_info_1);

	switch (action) {
	case 1:
		vmg_exception(reason);
		break;
	default:
		WARN(1, "vmgexit action is not valid (%u)\n", action);
	}

	return reason;
}

static unsigned long vc_start(struct ghcb *ghcb)
{
	unsigned long flags;

	local_irq_save(flags);
	preempt_disable();

	memset(&ghcb->save, 0, sizeof(ghcb->save));

	ghcb->protocol_version = GHCB_VERSION_MAX;
	ghcb->ghcb_usage = GHCB_USAGE_STANDARD;

	return flags;
}

static void vc_finish(struct ghcb *ghcb, unsigned long flags)
{
	local_irq_restore(flags);
	preempt_enable();
}

static long *vmg_reg_idx_to_pt_reg(struct pt_regs *regs, u8 reg)
{
	switch (reg) {
	case 0:		return &regs->ax;
	case 1:		return &regs->cx;
	case 2:		return &regs->dx;
	case 3:		return &regs->bx;
	case 4:		return &regs->sp;
	case 5:		return &regs->bp;
	case 6:		return &regs->si;
	case 7:		return &regs->di;
	case 8:		return &regs->r8;
	case 9:		return &regs->r9;
	case 10:	return &regs->r10;
	case 11:	return &regs->r11;
	case 12:	return &regs->r12;
	case 13:	return &regs->r13;
	case 14:	return &regs->r14;
	case 15:	return &regs->r15;
	}

	/* reg is a u8, so can never get here, but just in case */
	WARN_ONCE(1, "register index is not valid: %#hhx\n", reg);

	return NULL;
}

static phys_addr_t vmg_slow_virt_to_phys(struct ghcb *ghcb, long vaddr)
{
	unsigned long va = (unsigned long)vaddr;
	unsigned int level;
	phys_addr_t pa;
	pgd_t *pgd;
	pte_t *pte;

	pgd = pgd_offset(current->active_mm, va);
	pte = lookup_address_in_pgd(pgd, va, &level);
	if (!pte)
		return 0;

	pa = (phys_addr_t)pte_pfn(*pte) << PAGE_SHIFT;
	pa |= va & ~page_level_mask(level);

	return pa;
}

static bool vmg_insn_repmode(struct insn *insn)
{
	unsigned int i;

	for (i = 0; i < insn->prefixes.nbytes; i++) {
		switch (insn->prefixes.bytes[i]) {
		case 0xf2:
		case 0xf3:
			return true;
		}
	}

	return false;
}

static long vmg_insn_rmdata(struct insn *insn, struct pt_regs *regs)
{
	long effective_addr;
	u8 mod, rm;

	if (!insn->modrm.nbytes)
		return 0;

	if (insn_rip_relative(insn))
		return regs->ip + insn->displacement.value;

	mod = X86_MODRM_MOD(insn->modrm.value);
	rm = X86_MODRM_RM(insn->modrm.value);

	if (insn->rex_prefix.nbytes && X86_REX_B(insn->rex_prefix.value))
		rm |= 0x8;

	if (mod == 3)
		return *vmg_reg_idx_to_pt_reg(regs, rm);

	switch (mod) {
	case 1:
	case 2:
		effective_addr = insn->displacement.value;
		break;
	default:
		effective_addr = 0;
	}

	if (insn->sib.nbytes) {
		u8 scale, index, base;

		scale = X86_SIB_SCALE(insn->sib.value);
		index = X86_SIB_INDEX(insn->sib.value);
		base = X86_SIB_BASE(insn->sib.value);
		if (insn->rex_prefix.nbytes &&
		    X86_REX_X(insn->rex_prefix.value))
			index |= 0x8;
		if (insn->rex_prefix.nbytes &&
		    X86_REX_B(insn->rex_prefix.value))
			base |= 0x8;

		if (index != 4)
			effective_addr += (*vmg_reg_idx_to_pt_reg(regs, index) << scale);

		if ((base != 5) || mod)
			effective_addr += *vmg_reg_idx_to_pt_reg(regs, base);
		else
			effective_addr += insn->displacement.value;
	} else {
		effective_addr += *vmg_reg_idx_to_pt_reg(regs, rm);
	}

	return effective_addr;
}

static long *vmg_insn_regdata(struct insn *insn, struct pt_regs *regs)
{
	u8 reg;

	if (!insn->modrm.nbytes)
		return 0;

	reg = X86_MODRM_REG(insn->modrm.value);
	if (insn->rex_prefix.nbytes && X86_REX_R(insn->rex_prefix.value))
		reg |= 0x8;

	return vmg_reg_idx_to_pt_reg(regs, reg);
}

static void vmg_insn_init(struct insn *insn, char *insn_buffer,
			  unsigned long ip)
{
	int insn_len, bytes_rem;

	if (ip > TASK_SIZE) {
		insn_buffer = (void *)ip;
		insn_len = MAX_INSN_SIZE;
	} else {
		bytes_rem = copy_from_user(insn_buffer, (const void __user *)ip,
					   MAX_INSN_SIZE);
		insn_len = MAX_INSN_SIZE - bytes_rem;
	}

	insn_init(insn, insn_buffer, insn_len, true);

	/* Parse the full instruction */
	insn_get_length(insn);

	/*
	 * TODO: Error checking
	 *   If insn->immediate.got is not set after insn_get_length() then
	 *   the parsing failed at some point.
	 */
}

static int vmg_dr7_read(struct ghcb *ghcb, unsigned long ghcb_pa,
			struct pt_regs *regs, struct insn *insn)
{
	unsigned long *reg;
	u8 rm;

	/* MOV DRn always treats MOD == 3 no matter how encoded */
	rm = X86_MODRM_RM(insn->modrm.value);
	if (insn->rex_prefix.nbytes && X86_REX_B(insn->rex_prefix.value))
		rm |= 0x8;
	reg = (unsigned long *)vmg_reg_idx_to_pt_reg(regs, rm);

	*reg = this_cpu_read(cached_dr7);

	return 0;
}

static int vmg_dr7_write(struct ghcb *ghcb, unsigned long ghcb_pa,
			 struct pt_regs *regs, struct insn *insn)
{
	unsigned long *reg;
	int ret;
	u8 rm;

	/* MOV DRn always treats MOD == 3 no matter how encoded */
	rm = X86_MODRM_RM(insn->modrm.value);
	if (insn->rex_prefix.nbytes && X86_REX_B(insn->rex_prefix.value))
		rm |= 0x8;
	reg = (unsigned long *)vmg_reg_idx_to_pt_reg(regs, rm);

	/* Using a value of 0 for ExitInfo1 means RAX holds the value */
	ghcb->save.rax = *reg;
	ghcb_reg_set_valid(ghcb, VMSA_REG_RAX);

	ret = vmg_exit(ghcb, SVM_EXIT_WRITE_DR7, 0, 0);
	if (ret)
		return ret;

	this_cpu_write(cached_dr7, *reg);

	return 0;
}

static int vmg_rdtsc(struct ghcb *ghcb, unsigned long ghcb_pa,
		     struct pt_regs *regs, struct insn *insn)
{
	int ret;

	ret = vmg_exit(ghcb, SVM_EXIT_RDTSC, 0, 0);
	if (ret)
		return ret;

	if (!ghcb_reg_is_valid(ghcb, VMSA_REG_RAX) ||
	    !ghcb_reg_is_valid(ghcb, VMSA_REG_RDX)) {
		vmg_exit(ghcb, SVM_VMGEXIT_UNSUPPORTED_EVENT,
			 SVM_EXIT_RDTSC, 0);
		return -EINVAL;
	}
	regs->ax = ghcb->save.rax;
	regs->dx = ghcb->save.rdx;

	return 0;
}

static int vmg_rdpmc(struct ghcb *ghcb, unsigned long ghcb_pa,
		     struct pt_regs *regs, struct insn *insn)
{
	int ret;

	ghcb->save.rcx = regs->cx;
	ghcb_reg_set_valid(ghcb, VMSA_REG_RCX);

	ret = vmg_exit(ghcb, SVM_EXIT_RDPMC, 0, 0);
	if (ret)
		return ret;

	if (!ghcb_reg_is_valid(ghcb, VMSA_REG_RAX) ||
	    !ghcb_reg_is_valid(ghcb, VMSA_REG_RDX)) {
		vmg_exit(ghcb, SVM_VMGEXIT_UNSUPPORTED_EVENT,
			 SVM_EXIT_RDPMC, 0);
		return -EINVAL;
	}
	regs->ax = ghcb->save.rax;
	regs->dx = ghcb->save.rdx;

	return 0;
}

static int vmg_cpuid(struct ghcb *ghcb, unsigned long ghcb_pa,
		     struct pt_regs *regs, struct insn *insn)
{
	int ret;

	ghcb->save.rax = regs->ax;
	ghcb_reg_set_valid(ghcb, VMSA_REG_RAX);
	ghcb->save.rcx = regs->cx;
	ghcb_reg_set_valid(ghcb, VMSA_REG_RCX);
	if (regs->ax == 0x0000000d) {
		ghcb->save.xcr0 = (__read_cr4() & X86_CR4_OSXSAVE)
			? xgetbv(0) : 1;
		ghcb_reg_set_valid(ghcb, VMSA_REG_XCR0);
	}

	ret = vmg_exit(ghcb, SVM_EXIT_CPUID, 0, 0);
	if (ret)
		return ret;

	if (!ghcb_reg_is_valid(ghcb, VMSA_REG_RAX) ||
	    !ghcb_reg_is_valid(ghcb, VMSA_REG_RBX) ||
	    !ghcb_reg_is_valid(ghcb, VMSA_REG_RCX) ||
	    !ghcb_reg_is_valid(ghcb, VMSA_REG_RDX)) {
		vmg_exit(ghcb, SVM_VMGEXIT_UNSUPPORTED_EVENT,
			 SVM_EXIT_CPUID, 0);
		return -EINVAL;
	}
	regs->ax = ghcb->save.rax;
	regs->bx = ghcb->save.rbx;
	regs->cx = ghcb->save.rcx;
	regs->dx = ghcb->save.rdx;

	return 0;
}

static int vmg_invd(struct ghcb *ghcb, unsigned long ghcb_pa,
		    struct pt_regs *regs, struct insn *insn)
{
	return vmg_exit(ghcb, SVM_EXIT_INVD, 0, 0);
}

#define IOIO_TYPE_STR	BIT(2)
#define IOIO_TYPE_IN	1
#define IOIO_TYPE_INS	(IOIO_TYPE_IN | IOIO_TYPE_STR)
#define IOIO_TYPE_OUT	0
#define IOIO_TYPE_OUTS	(IOIO_TYPE_OUT | IOIO_TYPE_STR)

#define IOIO_REP	BIT(3)

#define IOIO_ADDR_64	BIT(9)
#define IOIO_ADDR_32	BIT(8)
#define IOIO_ADDR_16	BIT(7)

#define IOIO_DATA_32	BIT(6)
#define IOIO_DATA_16	BIT(5)
#define IOIO_DATA_8	BIT(4)

#define IOIO_SEG_ES	(0 << 10)
#define IOIO_SEG_DS	(3 << 10)

static u32 vmg_ioio_exitinfo(struct insn *insn, struct pt_regs *regs)
{
	u32 exitinfo = 0;

	switch (insn->opcode.bytes[0]) {
	/* INS opcodes */
	case 0x6c:
	case 0x6d:
		exitinfo |= IOIO_TYPE_INS;
		exitinfo |= IOIO_SEG_ES;
		exitinfo |= (regs->dx & 0xffff) << 16;
		break;

	/* OUTS opcodes */
	case 0x6e:
	case 0x6f:
		exitinfo |= IOIO_TYPE_OUTS;
		exitinfo |= IOIO_SEG_DS;
		exitinfo |= (regs->dx & 0xffff) << 16;
		break;

	/* IN immediate opcodes */
	case 0xe4:
	case 0xe5:
		exitinfo |= IOIO_TYPE_IN;
		exitinfo |= insn->immediate.value << 16;
		break;

	/* OUT immediate opcodes */
	case 0xe6:
	case 0xe7:
		exitinfo |= IOIO_TYPE_OUT;
		exitinfo |= insn->immediate.value << 16;
		break;

	/* IN register opcodes */
	case 0xec:
	case 0xed:
		exitinfo |= IOIO_TYPE_IN;
		exitinfo |= (regs->dx & 0xffff) << 16;
		break;

	/* OUT register opcodes */
	case 0xee:
	case 0xef:
		exitinfo |= IOIO_TYPE_OUT;
		exitinfo |= (regs->dx & 0xffff) << 16;
		break;

	default:
		return 0;
	}

	switch (insn->opcode.bytes[0]) {
	case 0x6c:
	case 0x6e:
	case 0xe4:
	case 0xe6:
	case 0xec:
	case 0xee:
		/* Single byte opcodes */
		exitinfo |= IOIO_DATA_8;
		break;
	default:
		/* Length determined by instruction parsing */
		exitinfo |= (insn->opnd_bytes == 2) ? IOIO_DATA_16
						    : IOIO_DATA_32;
	}

	switch (insn->addr_bytes) {
	case 2: exitinfo |= IOIO_ADDR_16; break;
	case 4: exitinfo |= IOIO_ADDR_32; break;
	case 8: exitinfo |= IOIO_ADDR_64; break;
	}

	if (vmg_insn_repmode(insn))
		exitinfo |= IOIO_REP;

	return exitinfo;
}

static int vmg_ioio(struct ghcb *ghcb, unsigned long ghcb_pa,
		    struct pt_regs *regs, struct insn *insn)
{
	u64 exit_info_1, exit_info_2;
	int ret;

	exit_info_1 = vmg_ioio_exitinfo(insn, regs);
	if (!exit_info_1) {
		/* Not a valid IOIO operation */
		vmg_exit(ghcb, SVM_VMGEXIT_UNSUPPORTED_EVENT, SVM_EXIT_IOIO, 0);
		WARN(1, "ioio operation is not valid\n");
		return -EINVAL;
	}

	if (!(exit_info_1 & IOIO_TYPE_IN)) {
		ghcb->save.rax = regs->ax;
		ghcb_reg_set_valid(ghcb, VMSA_REG_RAX);
	}

	/*
	 * TODO: This is needed for the merging cases (size<32 bits)
	 *       Pass in zero and perform merge here (only for non-string) to
	 *       avoid exposing rax unnecessarily.
	 */
	ghcb->save.rax = regs->ax;
	ghcb_reg_set_valid(ghcb, VMSA_REG_RAX);

	if (exit_info_1 & IOIO_TYPE_STR) {
		unsigned int io_bytes, vmg_exit_bytes;
		unsigned int ghcb_count, op_count;

		io_bytes = (exit_info_1 >> 4) & 0x7;
		ghcb_count = sizeof(ghcb->shared_buffer) / io_bytes;

		op_count = (exit_info_1 & IOIO_REP) ? regs->cx : 1;
		while (op_count) {
			exit_info_2 = min(op_count, ghcb_count);
			vmg_exit_bytes = exit_info_2 * io_bytes;

			if (!(exit_info_1 & IOIO_TYPE_IN)) {
				memcpy(ghcb->shared_buffer, (void *)regs->si,
				       vmg_exit_bytes);
				regs->si += vmg_exit_bytes;
			}

			ghcb->save.sw_scratch = ghcb_pa + offsetof(struct ghcb, shared_buffer);
			ret = vmg_exit(ghcb, SVM_EXIT_IOIO, exit_info_1, exit_info_2);
			if (ret)
				return ret;

			if (exit_info_1 & IOIO_TYPE_IN) {
				memcpy((void *)regs->di, ghcb->shared_buffer, vmg_exit_bytes);
				regs->di += vmg_exit_bytes;
			}

			if (exit_info_1 & IOIO_REP)
				regs->cx -= exit_info_2;

			op_count -= exit_info_2;
		}
	} else {
		ret = vmg_exit(ghcb, SVM_EXIT_IOIO, exit_info_1, 0);
		if (ret)
			return ret;

		if (exit_info_1 & IOIO_TYPE_IN) {
			if (!ghcb_reg_is_valid(ghcb, VMSA_REG_RAX)) {
				vmg_exit(ghcb, SVM_VMGEXIT_UNSUPPORTED_EVENT,
					 SVM_EXIT_IOIO, 0);
				return -EINVAL;
			}
			regs->ax = ghcb->save.rax;
		}
	}

	return 0;
}

static int vmg_msr(struct ghcb *ghcb, unsigned long ghcb_pa,
		   struct pt_regs *regs, struct insn *insn)
{
	u64 exit_info_1 = 0;
	int ret;

	switch (insn->opcode.bytes[1]) {
	case 0x30:	/* WRMSR */
		exit_info_1 = 1;
		ghcb->save.rax = regs->ax;
		ghcb_reg_set_valid(ghcb, VMSA_REG_RAX);
		ghcb->save.rdx = regs->dx;
		ghcb_reg_set_valid(ghcb, VMSA_REG_RDX);
		/* Fallthrough */
	case 0x32:	/* RDMSR */
		ghcb->save.rcx = regs->cx;
		ghcb_reg_set_valid(ghcb, VMSA_REG_RCX);
		break;
	default:
		vmg_exit(ghcb, SVM_VMGEXIT_UNSUPPORTED_EVENT,
			 SVM_EXIT_MSR, insn->opcode.bytes[0]);
		return -EINVAL;
	}

	ret = vmg_exit(ghcb, SVM_EXIT_MSR, exit_info_1, 0);
	if (ret)
		return ret;

	if (!exit_info_1) {
		if (!ghcb_reg_is_valid(ghcb, VMSA_REG_RAX) ||
		    !ghcb_reg_is_valid(ghcb, VMSA_REG_RDX)) {
			vmg_exit(ghcb, SVM_VMGEXIT_UNSUPPORTED_EVENT,
				 SVM_EXIT_MSR, 1);
			return -EINVAL;
		}
		regs->ax = ghcb->save.rax;
		regs->dx = ghcb->save.rdx;
	}

	return 0;
}

static int vmg_vmmcall(struct ghcb *ghcb, unsigned long ghcb_pa,
		       struct pt_regs *regs, struct insn *insn)
{
	int ret;

	if (x86_platform.hyper.sev_es_hypercall)
		return x86_platform.hyper.sev_es_hypercall(ghcb, ghcb_pa,
							   regs, insn);

	ghcb->save.rax = regs->ax;
	ghcb_reg_set_valid(ghcb, VMSA_REG_RAX);
	ghcb->save.cpl = (u8)(regs->cs & 0x3);
	ghcb_reg_set_valid(ghcb, VMSA_REG_CPL);

	ret = vmg_exit(ghcb, SVM_EXIT_VMMCALL, 0, 0);
	if (ret)
		return ret;

	if (!ghcb_reg_is_valid(ghcb, VMSA_REG_RAX)) {
		vmg_exit(ghcb, SVM_VMGEXIT_UNSUPPORTED_EVENT,
			 SVM_EXIT_VMMCALL, 0);
		return -EINVAL;
	}
	regs->ax = ghcb->save.rax;

	return 0;
}

static int vmg_rdtscp(struct ghcb *ghcb, unsigned long ghcb_pa,
		      struct pt_regs *regs, struct insn *insn)
{
	int ret;

	ret = vmg_exit(ghcb, SVM_EXIT_RDTSCP, 0, 0);
	if (ret)
		return ret;

	if (!ghcb_reg_is_valid(ghcb, VMSA_REG_RAX) ||
	    !ghcb_reg_is_valid(ghcb, VMSA_REG_RCX) ||
	    !ghcb_reg_is_valid(ghcb, VMSA_REG_RDX)) {
		vmg_exit(ghcb, SVM_VMGEXIT_UNSUPPORTED_EVENT,
			 SVM_EXIT_RDTSCP, 0);
		return -EINVAL;
	}
	regs->ax = ghcb->save.rax;
	regs->cx = ghcb->save.rcx;
	regs->dx = ghcb->save.rdx;

	return 0;
}

static int vmg_wbinvd(struct ghcb *ghcb, unsigned long ghcb_pa,
		      struct pt_regs *regs, struct insn *insn)
{
	return vmg_exit(ghcb, SVM_EXIT_WBINVD, 0, 0);
}

static int vmg_monitor(struct ghcb *ghcb, unsigned long ghcb_pa,
		       struct pt_regs *regs, struct insn *insn)
{
	unsigned long monitor_pa = 0;
	unsigned int level;
	pgd_t *pgd;
	pte_t *pte;

	pgd = __va(read_cr3_pa());
	pgd += pgd_index(regs->ax);
	pte = lookup_address_in_pgd(pgd, regs->ax, &level);
	if (pte && pte_present(*pte)) {
		unsigned long offset;
		phys_addr_t pa;

		switch (level) {
		case PG_LEVEL_1G:
			pa = (phys_addr_t)pud_pfn(*(pud_t *)pte) << PAGE_SHIFT;
			offset = regs->ax & ~PUD_PAGE_MASK;
			break;
		case PG_LEVEL_2M:
			pa = (phys_addr_t)pmd_pfn(*(pmd_t *)pte) << PAGE_SHIFT;
			offset = regs->ax & ~PMD_PAGE_MASK;
			break;
		default:
			pa = (phys_addr_t)pte_pfn(*pte) << PAGE_SHIFT;
			offset = regs->ax & ~PAGE_MASK;
			break;
		}

		monitor_pa = pa | offset;
	}

	ghcb->save.rax = monitor_pa;
	ghcb_reg_set_valid(ghcb, VMSA_REG_RAX);
	ghcb->save.rcx = regs->cx;
	ghcb_reg_set_valid(ghcb, VMSA_REG_RCX);
	ghcb->save.rdx = regs->dx;
	ghcb_reg_set_valid(ghcb, VMSA_REG_RDX);

	return vmg_exit(ghcb, SVM_EXIT_MONITOR, 0, 0);
}

static int vmg_mwait(struct ghcb *ghcb, unsigned long ghcb_pa,
		     struct pt_regs *regs, struct insn *insn)
{
	ghcb->save.rax = regs->ax;
	ghcb_reg_set_valid(ghcb, VMSA_REG_RAX);
	ghcb->save.rcx = regs->cx;
	ghcb_reg_set_valid(ghcb, VMSA_REG_RCX);

	return vmg_exit(ghcb, SVM_EXIT_MWAIT, 0, 0);
}

static int vmg_mmio_exec(struct ghcb *ghcb, unsigned long ghcb_pa,
			 struct pt_regs *regs, struct insn *insn,
			 unsigned int bytes, bool read)
{
	u64 exit_code, exit_info_1, exit_info_2;

	/* Register-direct addressing mode not supported with MMIO */
	if (X86_MODRM_MOD(insn->modrm.value) == 3)
		return vmg_exit(ghcb, SVM_VMGEXIT_UNSUPPORTED_EVENT, SVM_EXIT_NPF, 0);

	exit_code = read ? SVM_VMGEXIT_MMIO_READ : SVM_VMGEXIT_MMIO_WRITE;

	exit_info_1 = vmg_insn_rmdata(insn, regs);
	exit_info_1 = vmg_slow_virt_to_phys(ghcb, exit_info_1);
	exit_info_2 = bytes;	// Can never be greater than 8

	ghcb->save.sw_scratch = ghcb_pa + offsetof(struct ghcb, shared_buffer);

	return vmg_exit(ghcb, exit_code, exit_info_1, exit_info_2);
}

static int vmg_mmio(struct ghcb *ghcb, unsigned long ghcb_pa,
		    struct pt_regs *regs, struct insn *insn)
{
	unsigned int bytes = 0;
	int ret, sign_byte;
	long *reg_data;
	u8 opcode;

	if (insn->opcode.bytes[0] != 0x0f)
		opcode = insn->opcode.bytes[0];
	else
		opcode = insn->opcode.bytes[1];

	switch (opcode) {
	/* MMIO Write */
	case 0x88:
		bytes = 1;
		/* Fallthrough */
	case 0x89:
		if (!bytes)
			bytes = insn->opnd_bytes;

		reg_data = vmg_insn_regdata(insn, regs);
		memcpy(ghcb->shared_buffer, reg_data, bytes);

		ret = vmg_mmio_exec(ghcb, ghcb_pa, regs, insn, bytes, false);
		break;

	case 0xc6:
		bytes = 1;
		/* Fallthrough */
	case 0xc7:
		if (!bytes)
			bytes = insn->opnd_bytes;

		memcpy(ghcb->shared_buffer, insn->immediate1.bytes, bytes);

		ret = vmg_mmio_exec(ghcb, ghcb_pa, regs, insn, bytes, false);
		break;

	/* MMIO Read */
	case 0x8a:
		bytes = 1;
		/* Fallthrough */
	case 0x8b:
		if (!bytes)
			bytes = insn->opnd_bytes;

		ret = vmg_mmio_exec(ghcb, ghcb_pa, regs, insn, bytes, true);
		if (ret)
			break;

		reg_data = vmg_insn_regdata(insn, regs);
		if (bytes == 4)
			*reg_data = 0;	/* Zero-extend for 32-bit operation */

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;

	/* MMIO Read w/ zero-extension */
	case 0xb6:
		bytes = 1;
		/* Fallthrough */
	case 0xb7:
		if (!bytes)
			bytes = 2;

		ret = vmg_mmio_exec(ghcb, ghcb_pa, regs, insn, bytes, true);
		if (ret)
			break;

		/* Zero extend based on operand size */
		reg_data = vmg_insn_regdata(insn, regs);
		memset(reg_data, 0, insn->opnd_bytes);

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;

	/* MMIO Read w/ sign-extension */
	case 0xbe:
		bytes = 1;
		/* Fallthrough */
	case 0xbf:
		if (!bytes)
			bytes = 2;

		ret = vmg_mmio_exec(ghcb, ghcb_pa, regs, insn, bytes, true);
		if (ret)
			break;

		/* Sign extend based on operand size */
		reg_data = vmg_insn_regdata(insn, regs);
		if (bytes == 1) {
			u8 *val = (u8 *)ghcb->shared_buffer;

			sign_byte = (*val & 0x80) ? 0x00 : 0xff;
		} else {
			u16 *val = (u16 *)ghcb->shared_buffer;

			sign_byte = (*val & 0x8000) ? 0x00 : 0xff;
		}
		memset(reg_data, sign_byte, insn->opnd_bytes);

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;

	default:
		ret = vmg_exit(ghcb, SVM_VMGEXIT_UNSUPPORTED_EVENT, SVM_EXIT_NPF, 0);
	}

	return ret;
}

static int sev_es_vc_exception(struct pt_regs *regs, long error_code)
{
	char insn_buffer[MAX_INSN_SIZE];
	vmg_nae_exit_t nae_exit = NULL;
	enum ctx_state prev_state;
	unsigned long ghcb_pa;
	unsigned long flags;
	struct ghcb *ghcb;
	struct insn insn;
	int ret;

	prev_state = exception_enter();

	ghcb_pa = native_read_msr(MSR_AMD64_SEV_GHCB);
	if (!ghcb_pa ||
	    ((ghcb_pa & GHCB_MSR_INFO_MASK) == GHCB_MSR_SEV_INFO_RESP)) {
		/* GHCB not yet established, so set it up */
		ghcb_pa = __pa(this_cpu_ptr(&ghcb_page));
		native_wrmsrl(MSR_AMD64_SEV_GHCB, ghcb_pa);
	}

	/* Get the proper GHCB virtual address to use */
	if (ghcb_pa == __pa(early_ghcb)) {
		ghcb = early_ghcb_va;
	} else {
		WARN_ONCE(ghcb_pa != __pa(this_cpu_ptr(&ghcb_page)),
			  "GHCB MSR value was not what was expected\n");

		ghcb = this_cpu_ptr(&ghcb_page);
	}

	flags = vc_start(ghcb);

	switch (error_code) {
	case SVM_EXIT_EXCP_BASE + X86_TRAP_DB:
		ret = vmg_exit(ghcb, SVM_VMGEXIT_NMI_COMPLETE, 0, 0);
		break;
	case SVM_EXIT_READ_DR7:
		nae_exit = vmg_dr7_read;
		break;
	case SVM_EXIT_WRITE_DR7:
		nae_exit = vmg_dr7_write;
		break;
	case SVM_EXIT_RDTSC:
		nae_exit = vmg_rdtsc;
		break;
	case SVM_EXIT_RDPMC:
		nae_exit = vmg_rdpmc;
		break;
	case SVM_EXIT_CPUID:
		nae_exit = vmg_cpuid;
		break;
	case SVM_EXIT_INVD:
		nae_exit = vmg_invd;
		break;
	case SVM_EXIT_IOIO:
		nae_exit = vmg_ioio;
		break;
	case SVM_EXIT_MSR:
		nae_exit = vmg_msr;
		break;
	case SVM_EXIT_VMMCALL:
		nae_exit = vmg_vmmcall;
		break;
	case SVM_EXIT_RDTSCP:
		nae_exit = vmg_rdtscp;
		break;
	case SVM_EXIT_WBINVD:
		nae_exit = vmg_wbinvd;
		break;
	case SVM_EXIT_MONITOR:
		nae_exit = vmg_monitor;
		break;
	case SVM_EXIT_MWAIT:
		nae_exit = vmg_mwait;
		break;
	case SVM_EXIT_NPF:
		nae_exit = vmg_mmio;
		break;
	default:
		ret = vmg_exit(ghcb, SVM_VMGEXIT_UNSUPPORTED_EVENT,
			       error_code, 0);
	}

	if (nae_exit) {
		vmg_insn_init(&insn, insn_buffer, regs->ip);
		ret = nae_exit(ghcb, ghcb_pa, regs, &insn);
		if (!ret)
			regs->ip += insn.length;
	}

	vc_finish(ghcb, flags);

	exception_exit(prev_state);

	return ret;
}

dotraplinkage void do_vmm_communication(struct pt_regs *regs, long error_code)
{
	int ret;

	ret = sev_es_vc_exception(regs, error_code);
	if (!ret)
		return;

	switch (ret) {
	case X86_TRAP_GP:
		do_general_protection(regs, 0);
		break;
	case X86_TRAP_UD:
		do_invalid_op(regs, 0);
		break;
	}
}

void __init early_ghcb_init(void)
{
	unsigned long early_ghcb_pa;

	if (!sev_es_active())
		return;

	early_ghcb_pa = __pa(early_ghcb);
	early_ghcb_va = early_memremap_decrypted(early_ghcb_pa, PAGE_SIZE);
	BUG_ON(!early_ghcb_va);

	memset(early_ghcb_va, 0, PAGE_SIZE);

	native_wrmsrl(MSR_AMD64_SEV_GHCB, early_ghcb_pa);
}

void __init ghcb_init(void)
{
	unsigned long flags;
	struct ghcb *ghcb;
	int cpu, ret;

	if (!sev_es_active())
		return;

	for_each_possible_cpu(cpu) {
		struct ghcb *ghcb = &per_cpu(ghcb_page, cpu);

		set_memory_decrypted((unsigned long)ghcb,
				     sizeof(ghcb_page) >> PAGE_SHIFT);
		memset(ghcb, 0, sizeof(*ghcb));
	}

	/*
	 * Switch the BSP over from the early GHCB page to the per-CPU GHCB
	 * page and un-map the early mapping.
	 */
	native_wrmsrl(MSR_AMD64_SEV_GHCB, __pa(this_cpu_ptr(&ghcb_page)));

	early_memunmap(early_ghcb_va, PAGE_SIZE);

	/* Retrieve the AP Jump Table address using VMGEXIT */
	ghcb = this_cpu_ptr(&ghcb_page);

	flags = vc_start(ghcb);

	ret = vmg_exit(ghcb, SVM_VMGEXIT_AP_JUMP_TABLE, 1, 0);
	if (ret)
		WARN(1, "error retrieving SEV-ES jump table address\n");

	sev_es_ap_jump_table_pa = ghcb->save.sw_exit_info_2;

	vc_finish(ghcb, flags);
}
