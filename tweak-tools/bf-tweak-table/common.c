#include "common.h"
#include "tweak.h"

#include <linux/slab.h> //for kmalloc

#include <asm/segment.h>       //for filesystem functions
#include <asm/uaccess.h>       //for filesystem functions
#include <linux/buffer_head.h> //for filesystem functions
#include <linux/fs.h>          //for filesystem functions
#include <linux/version.h> //for checking kernel version

/*
 *Performs some simple checks on calc_tweak
 */
void test_calc_tweak() {
  u8 *buffer;
  u64 paddr1;

  buffer = kmalloc(BLOCK, GFP_KERNEL);

  paddr1 = 0x1 << 30;
  calc_tweak(paddr1, buffer);
  BUG_ON(!array_cmp(buffer, tweaks[30], BLOCK));

  paddr1 = 0x1 << 12;
  calc_tweak(paddr1, buffer);
  BUG_ON(!array_cmp(buffer, tweaks[12], BLOCK));

  // This test is expected to fail. Thus there is not ! in the BUG_ON macro
  paddr1 = 0x1 << 11;
  calc_tweak(paddr1, buffer);
  BUG_ON(array_cmp(buffer, tweaks[12], BLOCK));

  kfree(buffer);
}
/*
 * Swaps content of two 4K memory regions. Expected use is to swap ciphertexts
 * @page1_noenc pointer to 4K memory block
 * @page2_noenc pointer to 4K memory block
 */
void swap_page_content(void *page1_noenc, void *page2_noenc) {

  void *tmp;
  tmp = kmalloc(PAGE_SIZE, GFP_KERNEL);

  memcpy(tmp, page1_noenc, PAGE_SIZE); // store page1 in tmp

  memcpy(page1_noenc, page2_noenc, PAGE_SIZE); // overwrite page1 with page2

  memcpy(page2_noenc, tmp, PAGE_SIZE); // overwrite page2 with tmp

  kfree(tmp);
}

/*
 * Prints the first @length bytes of @data with a line break every BLOCK bytes
 */
void print_blockwise(void *data, size_t length) {
  int i;
  u8 *data_bw;
  data_bw = (u8 *)data;
  if (length % BLOCK != 0) {
    printk(KERN_INFO
           "revtweak: print_blockwise: length is not a multiple of 16 byte\n");
  }

  for (i = 0; i < length; i++) {
    if (i % BLOCK == 0) {
      printk(KERN_INFO "%02x ", data_bw[i]);
    } else if (i == length - 1) {
      printk(KERN_CONT " %02x\n", data_bw[i]);
    } else {
      printk(KERN_CONT " %02x ", data_bw[i]);
    }
  }
}

/*
 * Xores the fist BLOCK bytes of @first_nlock_noenc and @second_block_noenc
 * and stores the result in @result
 */
void block_xor(u8 *first_block_noenc, u8 *second_block_noenc, u8 *result) {
  int i;

  for (i = 0; i < BLOCK; i++) {
    result[i] = first_block_noenc[i] ^ second_block_noenc[i];
  }
}

/*
 * Swap the first two BLOCK bytes of data_noenc
 */
void swap_first_two_blocks(void *data_noenc) {
  // swap first two blocks via non encrypted mapping
  u8 tmp[BLOCK];
  memcpy(&tmp, data_noenc, BLOCK);
  memcpy(data_noenc, data_noenc + BLOCK, BLOCK);
  memcpy(data_noenc + BLOCK, &tmp, BLOCK);
}

/*
 * Uses the tweak table from tweak.h
 * @hpa host physical address for which the tweak is calculated
 * @result 16 byte array in which the tweak gets stored
 */
void calc_tweak(hpa_t hpa, uint8_t *result) {
  calc_custom_tweak(hpa, result, tweaks, sizeof(tweaks) / sizeof(tweaks[0]));
}

/*
 * Uses the supplied tweaks instead of the tweak table from tweak.h
 * @hpa host physical address for which the tweak is calculated
 * @result 16 byte array in which the tweak gets stored
 */
void calc_custom_tweak(hpa_t hpa, uint8_t *result,
                       uint8_t (*custom_tweaks)[BLOCK], uint64_t tweak_count) {
  int i, j;
  u64 mask;
  // init result with zeroes
  memset(result, 0, BLOCK);

  mask = 0x0000000000000001;

  // calculate tweak pattern;
  for (i = 0; i < 64; i++) {
    if (hpa & mask) {
      if (i >= tweak_count) {
        printk("Currently only addresses up to %llu bits are supported",
               tweak_count);
        BUG();
      }
      for (j = 0; j < 16; j++) {
        result[j] ^= custom_tweaks[i][j];
      }
    }
    // shift mask bit one position to the left
    mask = mask << 1;
  }
}

/*
 * Xor first @length bytes of @target and tweak and store the result in @target
 */
void xor_in_place(u8 *target, u8 *tweak, int length) {
  int i;

  for (i = 0; i < length; i++) {
    target[i] ^= tweak[i];
  }
}

void __map_enc_noenc(u64 hfn, void **enc, void **noenc, pgprot_t flags_enc, pgprot_t flags_noenc) {
  struct page *p;
  p = pfn_to_page(hfn);
  (*enc) = vmap(&p, 1, 0, flags_enc);
  (*noenc) = vmap(&p, 1, 0, flags_noenc);
}

/*
 * N.B. Call with pointer to pinter, since we want to manipulate the value of
 * the pointer itself
 */
void map_enc_noenc(u64 hfn, void **enc, void **noenc) {
  __map_enc_noenc(hfn,enc,noenc,PAGE_KERNEL_NOCACHE,__pgprot(__PAGE_KERNEL_NOCACHE));
}

/*
 * N.B. Call with pointer to pinter, since we want to manipulate the value of
 * the pointer itself
 */
void map_enc_noenc_cached(u64 hfn, void **enc, void **noenc) {
  __map_enc_noenc(hfn,enc,noenc,PAGE_KERNEL, __pgprot(__PAGE_KERNEL));
}
/*
 * Compare the first @length bytes of @arr1 bytewise with  @arr2
 * @return false if there is a missmatch
 */
bool array_cmp(u8 *arr1, u8 *arr2, u64 length) {
  u64 i;
  for (i = 0; i < length; i++) {
    if (arr1[i] != arr2[i]) {
      return false;
    }
  }
  return true;
}

/*
 * Convert @hfn to g pha with page offset @offset
 */
hpa_t hfn_to_hpa(hfn_t hfn, unsigned int offset) {
  if (offset > 0xFFF) {
    printk(KERN_CRIT "hfn_to_hpa: offset was larger than 0xfff");
    BUG();
  }

  return (hpa_t)(hfn << 12) + offset;
}

/*
 * @return page offset of @hpa
 */
uint64_t hpa_to_offset(hpa_t hpa) { return (hpa & 0xfff); }

/*
 * Convert @hpa to a hfn
 */
hfn_t hpa_to_hfn(hpa_t hpa) { return (hfn_t)(hpa >> 12); }

struct file *driver_file_open(const char *path) {
  struct file *filp = NULL;
  mm_segment_t oldfs;
  oldfs = get_fs();

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,1,0)
  set_fs(get_ds());
#else
  set_fs(KERNEL_DS);
#endif
  filp = filp_open(path, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO);
  set_fs(oldfs);
  return (filp);
}

void driver_file_close(struct file *filp) { filp_close(filp, NULL); }

/*
 * Attention: only supports files up two 2GB
 * @return number of bytes written
 */
int driver_file_write(struct file *file, unsigned long long offset,
                      unsigned char *data, u64 size) {
  int ret;
  mm_segment_t oldfs;
  loff_t pos = offset;
  oldfs = get_fs();
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,1,0)
  set_fs(get_ds());
#else
  set_fs(KERNEL_DS);
#endif

  // vfs_setpos(file, pos, pos + PAGE_SIZE);
  // Workaround for vfs_setpos, not implemented on my version of linux.
  spin_lock(&file->f_lock);
  file->f_pos = pos;
  // file->f_version = 0;
  // printk(KERN_INFO "set position to  %llx\n", pos);
  spin_unlock(&file->f_lock);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
  ret = kernel_write(file, data, size, &pos);
#else
  ret = vfs_write(file, data, size, &pos);
#endif
  // vfs_fsync(file, 0);
  set_fs(oldfs);
  return (ret);
}

int driver_file_read(struct file *file, unsigned long long offset,
                     unsigned char *data, unsigned int size) {
  int ret;
  mm_segment_t oldfs;
  loff_t pos = offset;
  oldfs = get_fs();
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,1,0)
  set_fs(get_ds());
#else
  set_fs(KERNEL_DS);
#endif

  // vfs_setpos(file, pos, pos + PAGE_SIZE);
  // Workaround for vfs_setpos, not implemented on my version of linux.
  spin_lock(&file->f_lock);
  file->f_pos = pos;
  // file->f_version = 0;
  // printk(KERN_INFO "set position to read %llx\n", pos);
  spin_unlock(&file->f_lock);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
  ret = kernel_read(file, data, size, &pos);
#else
  ret = vfs_read(file, data, size, &pos);
#endif
  // vfs_fsync(file, 0);
  set_fs(oldfs);
  return (ret);
}
