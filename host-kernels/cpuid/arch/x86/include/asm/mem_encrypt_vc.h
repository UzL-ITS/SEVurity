/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2019 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#ifndef __X86_MEM_ENCRYPT_VC_H__
#define __X86_MEM_ENCRYPT_VC_H__

#include <linux/types.h>

struct ghcb;

#ifdef CONFIG_AMD_MEM_ENCRYPT

extern unsigned char early_ghcb[PAGE_SIZE];

void __init early_ghcb_init(void);
void __init ghcb_init(void);

int vmg_exit(struct ghcb *ghcb, u64 exit_code,
	     u64 exit_info_1, u64 exit_info_2);

#else

void __init early_ghcb_init(void) { }
void __init ghcb_init(void) { }

static inline int vmg_exit(struct ghcb *ghcb, u64 exit_code,
			   u64 exit_info_1, u64 exit_info_2)
{
	return -ENOTSUPP;
}

#endif	/* CONFIG_AMD_MEM_ENCRYPT */

#endif	/* __X86_MEM_ENCRYPT_VC_H__ */
