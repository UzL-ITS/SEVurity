#include <asm/cacheflush.h> // wbinvd()
#include <asm/tlbflush.h>   // __flush_tlb_all()
#include <linux/device.h>   //for creating file in /dev/
#include <linux/init.h> // Macros used to mark up functions e.g., __init __exit
#include <linux/kernel.h>  // Contains types, macros, functions for the kernel
#include <linux/kthread.h> //for kernel threads
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>  // Core header for loading LKMs into the kernel
#include <linux/proc_fs.h> //proc_create
#include <linux/slab.h>
#include <linux/uaccess.h> //copy_from_user and related functions

#include "bf_tweak_base_ioctls.h" //definition of ioctls used by this module
#include "common.h" //helper functions for tweaks, printing blocks etc
#include "tweak.h"  //tweak values

MODULE_LICENSE("GPL"); ///< The license type -- this affects runtime behavior

#define PFN_BASE_PAGE 0x200000ull

// offset bits in 1GB Hugepage
#define HP_PAGE_SHIFT 31

#define MAX_TWEAKS 42
// parameters

// index of address bit for which the tweak should be bruteforced
static int bit_pos = -1;
module_param(bit_pos, int, 0660);

static int32_t start_value = 0;
module_param(start_value, uint, 0660);

struct class *my_class;
dev_t my_dev;

static struct proc_dir_entry *dev_file;


// start hp stuff
#define MAX_OFFSET 0x1ULL << (HP_PAGE_SHIFT - 1)
#define GB_IN_B 1073741824
struct page **hp_pages;
int nid;
uint64_t npages;
// end hp stuff

/**
@user_gva : contains gva to hp in user space
@page : result param. *** because we want to write to a ** array. allocated in
function, caller must free
@nid : result param
**/
void user_gva_to_page(uint64_t user_gva, uint64_t bufsize, struct page ***pages,
                      int *nid, uint64_t *npages) {
  int retval;

  (*npages) = 1 + (bufsize - 1) / PAGE_SIZE;

  (*pages) = vmalloc((*npages) * sizeof(struct page *));

  down_read(&current->mm->mmap_sem);
  retval =
      get_user_pages(user_gva, (*npages), 1 /* Write enable */, (*pages), NULL);
  up_read(&current->mm->mmap_sem);

  (*nid) = page_to_nid((*pages)[0]); // Remap on the same NUMA node.
}

void *map_hp_cached(struct page **pages, int nid, uint64_t npages,
                    bool map_encrypted) {
  void *remapped;

  pgprot_t prot;
  if (map_encrypted)
    prot = PAGE_KERNEL;
  else
    prot = __pgprot(__PAGE_KERNEL);

  remapped = vm_map_ram(pages, npages, nid, prot);
  return remapped;
}

void *map_hp_nocache(struct page **pages, int nid, uint64_t npages,
                     bool map_encrypted) {
  void *remapped;

  pgprot_t prot;
  if (map_encrypted)
    prot = PAGE_KERNEL_NOCACHE;
  else
    prot = __pgprot(__PAGE_KERNEL_NOCACHE);

  printk("in map_hp_nocache: value of pages = %p\n", pages);
  remapped = vm_map_ram(pages, npages, nid, prot);
  return remapped;
}

void thread_print_tweak_summary( uint8_t (*trans_tweaks)[16],int first_index, int last_index);


typedef struct {
  int first_bit;
  int last_bit;
  uint8_t (*tweaks)[16];
  uint64_t hfn_hp;
} bf_inside_hp_ctx_st;

bf_inside_hp_ctx_st *bf_inside_hp_ctx;


typedef struct {
  int first_bit;
  int last_bit;
  uint8_t (*tweaks)[16];
} bf_high_ctx_st;

bf_high_ctx_st *bf_high_ctx;
int bf_inside_hp(void *ctx);
int bf_high(void *ctx);

static struct task_struct *bf_thread;

//copy known tweaks in the beginning;
//then add tweaks as they are discovered by bruteforcer
static uint8_t (*thread_tweaks)[16];

static DEFINE_SPINLOCK(thread_state_lock);
static int thread_state = 0;

static long my_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
  void __user *argp;
  if (_IOC_TYPE(cmd) != MYDRBASE)
    return -EINVAL;

  switch (cmd) {
  case BF_TWEAK_PASS_HP: {
    pass_hp_param_st pass_hp_param; // parameters from BF_TWEAK_PASS_HP
    uint64_t hfn_hp;
    int i;
    int (*thread_fn)(void *data);
    void *thread_data;
    printk("BF_TWEAK_PASS_HP: got called\n");
    argp = (void __user *)arg;

    printk("BF_TWEAK_PASS_HP: casted arg\n");
    if (copy_from_user(&pass_hp_param, argp, sizeof(pass_hp_param_st))) {
      return -EFAULT;
    }
    printk("BF_TWEAK_PASS_HP: copied param from user space\n");

    user_gva_to_page(pass_hp_param.user_hp_ptr, GB_IN_B, &hp_pages, &nid,
                     &npages);
    printk("BF_TWEAK_PASS_HP: called user_gva_to_page\n");

    hfn_hp = page_to_pfn(hp_pages[0]);


  thread_tweaks = (uint8_t (*)[16])vmalloc(MAX_TWEAKS * sizeof( uint8_t (*)[16]));
  //copy known tweaks
  for( i = 0; i < pass_hp_param.index_first_bit;i ++) { 
    memcpy(thread_tweaks[i],tweaks[i],16);
  }
  
    
    if( pass_hp_param.index_last_bit < 29) {
      bf_inside_hp_ctx = (bf_inside_hp_ctx_st *)vmalloc(sizeof(bf_inside_hp_ctx_st));

      bf_inside_hp_ctx->first_bit = pass_hp_param.index_first_bit;
      bf_inside_hp_ctx->last_bit = pass_hp_param.index_last_bit;
      bf_inside_hp_ctx->tweaks = thread_tweaks;
      bf_inside_hp_ctx->hfn_hp = hfn_hp;
      thread_fn = bf_inside_hp;
      thread_data = (void*)bf_inside_hp_ctx;
    }
    else {
       
      bf_high_ctx = (bf_high_ctx_st*)vmalloc(sizeof(bf_high_ctx_st));
      bf_high_ctx->first_bit = pass_hp_param.index_first_bit;
      bf_high_ctx->last_bit = pass_hp_param.index_last_bit;
      bf_high_ctx->tweaks = thread_tweaks;
      thread_fn = bf_high;
      thread_data = (void*)bf_high_ctx;
    }

    bf_thread =
        kthread_create(thread_fn, thread_data, "bf_thread");
    if (bf_thread) {
      printk("starting bf_thread!\n");
      wake_up_process(bf_thread);
    }

    return 0;
  } break;

  default:
    return -EINVAL;
  }
}

struct file_operations my_fops = {.owner = THIS_MODULE,
                                  .unlocked_ioctl = my_ioctl};


enum bf_phase { Prepare, Move, Check };

/**
 * Copies bswap of @counter 4 times into tweak;
 **/
void int_to_tweak(uint32_t counter, uint8_t tweak[16]) {
  counter = __builtin_bswap32(counter);
  memcpy(tweak, &counter, sizeof(counter));
  memcpy(tweak + 4, &counter, sizeof(counter));
  memcpy(tweak + 8, &counter, sizeof(counter));
  memcpy(tweak + 12, &counter, sizeof(counter));
}

/**
 * Do Cipher move between offsets in hp that only differ at @index_bf_bit
 * @param last_bit: index of highest bit in hp
 * @param index_bf_bit:  bit for which the tweak should be bruteforced
 * @param prepare: if set, the values which should be encrypted are written.
 If *theese values get copied to theire target location. The caller must flush
 caches and tlb between calls. This "two phase split" reduces the amount of
 flushes which increases performance
 **/
int do_pair_move(int last_bit, int index_bf_bit, uint8_t *hp_c,
                 uint8_t *hp_no_c, uint8_t plain[16], uint64_t *guess_counter,
                 enum bf_phase state) {
#undef LDB
  //#define LDB

  int bit_index;
  uint8_t guessed_tweak[16];
  for (bit_index = index_bf_bit + 1; bit_index < last_bit; bit_index++) {
    uint64_t source_offset = (0x1 << bit_index);
    uint64_t target_offset = source_offset | (0x1 << index_bf_bit);

    switch (state) {
    case Prepare:
      // encrypt plaintext
      memcpy(hp_c + source_offset, plain, 16);
#ifdef LDB
      /* if ((source_offset == (0x1 << index_bf_bit + 1)) ||
           (source_offset == (0x1 << (last_bit - 1)))) {*/
      printk("do_pair_move: state Prepare: encrypted in offset %016llx\t "
             "max_offset is %016llx\n",
             source_offset, MAX_OFFSET);
      //}
#endif
      break;
    case Move:
      // move ciphertext and apply guessed tweak to ciphertext
      memcpy(hp_no_c + target_offset, hp_no_c + source_offset, 16);
      int_to_tweak(*guess_counter, guessed_tweak);
      (*guess_counter)++;

      xor_in_place(hp_no_c + target_offset, guessed_tweak, 16);
#ifdef LDB

      printk("do_pair_move: state Move: moved from offset %016llx to offset "
             "%016llx\n",
             source_offset, target_offset);
#endif
      break;
    case Check:
      // Detweak encryption result
      int_to_tweak(*guess_counter, guessed_tweak);
      xor_in_place(hp_c + target_offset, guessed_tweak, 16);

      // if true our guess for the tweak was correct
      if (array_cmp(hp_c + target_offset, plain, 16)) {
        return 1;
      }
      (*guess_counter)++;
      break;
    default:
      BUG(); // should never be reached
    }
  }
  return 0;
}

int do_full_move(int index_bf_bit, uint8_t *hp_c, uint8_t *hp_no_c,
                 uint8_t plain[16], uint8_t (*tweaks)[16],
                 uint64_t *guess_counter, enum bf_phase state, uint8_t orig_cipher[16],
                 uint64_t offset_base_ciphertext,uint64_t max_offset,uint64_t hfn_base_src,
                 uint64_t hfn_base_dst,uint64_t shift) {
#undef LDB
//#define LDB
  
#ifdef LDB
//  printk("in do_full_move: offset_base_ciphertext = %016llx\n base ciphertext:\n",offset_base_ciphertext);
 // print_blockwise(orig_cipher,16);
#endif
  uint8_t cipher_buf[16], tweak_buf[16];
  uint64_t offset, tmp;
  if (state == Prepare) {
    return 0;
  }

  // loop over offsets from start of hp up to the 16 bytes before 0x1 <<
  // index_of_bit; ciphertext was already written in prepare phase. we only
  // need to copy
  for (offset = 0; offset < max_offset; offset += 16) {
    if ((*guess_counter) % 0x00100000 == 0) {
      printk("do_full_move: at guess_counter = %08llx in state %d\n", *guess_counter,state);
    }
    if (state == Move) {
      // copy ciphertext, apply tweak difference, write to target location
      //memcpy(cipher_buf, hp_no_c + offset_base_ciphertext, 16);
      memcpy(cipher_buf,orig_cipher,16);

      // omit hpa_base_hp since its the same for both
      // only keep bits with index < index_bf_bit because we do not have tweak
      // for the higher bits
      tmp = ((hfn_base_src << shift) | offset_base_ciphertext) ^ ((hfn_base_dst << shift) | offset);
      tmp &= ((0x1ULL << index_bf_bit) - 1);
      calc_tweak(tmp, tweak_buf);

      xor_in_place(cipher_buf, tweak_buf, 16);
      // apply guessed tweak
      int_to_tweak(*guess_counter, tweak_buf);

      (*guess_counter)++;

      xor_in_place(cipher_buf, tweak_buf, 16);

      memcpy(hp_no_c + offset, cipher_buf, 16);
    } else if (state == Check) {
      // Detweak

      // omit hpa_base_hp since its the same for both
      // only keep bits with index < index_bf_bit because we do not have tweak
      // for the higher bits
      tmp = ((hfn_base_src << shift) | offset_base_ciphertext) ^ ((hfn_base_dst << shift) | offset);
      tmp &= ((0x1ULL << index_bf_bit) - 1);
      calc_tweak(tmp, tweak_buf);

      xor_in_place(hp_c + offset, tweak_buf, 16);

      // apply gussed tweak

      int_to_tweak(*guess_counter, tweak_buf);
      xor_in_place(hp_c + offset, tweak_buf, 16);

      // if true our guess was corrent
      if (array_cmp(hp_c + offset, plain, 16)) {
        return 1;
      }

      (*guess_counter)++;
    } else {
      BUG(); // should never be reached
    }
  }
#ifdef LDB
  printk("in do full_move: loop ended at offset =%016llx\n", offset);
#endif
  return 0;
}

int bf_inside_hp(void *ctx) {
#undef LDB
  //#define LDB
  spin_lock(&thread_state_lock);
  if( thread_state != 0 ) {
    printk("bf_inside_hp: expected thread_state to be zero but it was %d.aborting",thread_state);
    spin_unlock(&thread_state_lock);
    do_exit(1);
  }
  thread_state = 1;
  spin_unlock(&thread_state_lock);


  bf_inside_hp_ctx_st *params = (bf_inside_hp_ctx_st *)ctx;
  int first_bit = params->first_bit;
  int last_bit = params->last_bit;
  uint8_t(*tweaks)[16] = params->tweaks;
  uint64_t hfn_hp = params->hfn_hp;

  uint8_t *hp_c, *hp_no_c;
  uint64_t base_hpa_hp,offset_base_ciphertext;
  uint8_t plain[16],cipher[16];
  int bit_index;
  memset(plain, 0, 16);

  base_hpa_hp = hfn_hp << HP_PAGE_SHIFT;
  printk("hfn_hp =\t %016llx\nbf_inside_hp: base_hpa_hp =\t %016llx\n", hfn_hp,
         base_hpa_hp);

  printk("ping\n");
  if (first_bit < 4) {
    printk("first_bit must be >= 4. aborting\n");
    spin_lock(&thread_state_lock);
    thread_state = 0;
    spin_unlock(&thread_state_lock);
    do_exit(1);
  }
  printk("ping\n");
  if (last_bit > 29) {
    printk("last_bit must be <= 28. aborting\n");
    spin_lock(&thread_state_lock);
    thread_state = 0;
    spin_unlock(&thread_state_lock);
    do_exit(1);
  }

  printk("ping\n");
  hp_c = (uint8_t *)map_hp_cached(hp_pages, nid, npages, true);
  hp_no_c = (uint8_t *)map_hp_cached(hp_pages, nid, npages, false);

  printk("ping\n");
  // loop over all bits which should be bruteforced
  bool bit_index_changed = true;
  bool pair_move_enabled = true;
  for (bit_index = first_bit; bit_index <= last_bit; bit_index++, bit_index_changed  = true) {
  offset_base_ciphertext = (0x1 << bit_index);
  pair_move_enabled = first_bit <= 9;
    printk("bf_inside_hp: processing bit_index = %d\n", bit_index);

    enum bf_phase state;
    // incremented inside the do_pair_move and do_full_move functions
    uint64_t guess_counter = 0;
    uint64_t start_guess_counter = guess_counter;
    bool found;
    found = false;
    do {
      // progess update
      if (guess_counter % 0x00010000 == 0) {
        printk("at guess_counter = %08llx\n", guess_counter);
      }
      for (state = Prepare; state <= Check; state++) {
        int err;
#ifdef LDB
        printk("in state %d\n", state);
#endif
        // in one Prepare,Move, Check cycle the same counter must be used
        // start_guess_counter is updated after one such cycle ends
        guess_counter = start_guess_counter;

        if( pair_move_enabled ) {
          // do bits below bit_index
          if (0 > (err = do_pair_move(last_bit, bit_index, hp_c, hp_no_c, plain,
                                      &guess_counter, state))) {
            printk("do_pair_move aborted with %d!abort bf_inside_hp!\n", err);
            spin_lock(&thread_state_lock);
            thread_state = 0;
            spin_unlock(&thread_state_lock);
            do_exit(1);
          } else if (err == 1 && state == Check) { // found solution
            uint8_t found_tweak[16];
            printk("The Tweak for bit with index %d is:\n", bit_index);
            int_to_tweak(guess_counter, found_tweak);
            print_blockwise(found_tweak, 16);
            //store in thread_tweak table
            memcpy(tweaks[bit_index],found_tweak,16);
            //store in thread_tweak table
            memcpy(tweaks[bit_index],found_tweak,16);
            found = true;
          }
        }

        if (state == Prepare) {
          if( bit_index_changed) {
            // encrypt plaintext
            memcpy(hp_c + offset_base_ciphertext, plain, 16);
            printk("encrypted base ciphertext in offset %016llx\n",offset_base_ciphertext);
          }
        }
        else {
          // do bits above bit_index
          if( bit_index_changed ) {
            memcpy(cipher,hp_no_c + offset_base_ciphertext,16);
          }
          if (0 > (err = do_full_move(bit_index, hp_c, hp_no_c, plain, tweaks,
                                      &guess_counter, state,cipher,offset_base_ciphertext,
                                      (0x1ULL << bit_index ),hfn_hp,hfn_hp,HP_PAGE_SHIFT)
                )) {
            printk("do_full_move aborted with %d!abort bf_inside_hp!\n", err);
            spin_lock(&thread_state_lock);
            thread_state = 0;
            spin_unlock(&thread_state_lock);
            do_exit(1);
          } else if (err == 1 && state == Check) {
            uint8_t found_tweak[16];
            printk("The Tweak for bit with index %d is:\n", bit_index);
            int_to_tweak(guess_counter, found_tweak);
            print_blockwise(found_tweak, 16);
            //store in thread_tweak table
            memcpy(tweaks[bit_index],found_tweak,16);
            found = true;
          }
        }
        if( pair_move_enabled || (bit_index_changed && state == Prepare) || state == Move) {
          wbinvd();
          __flush_tlb_all();
          }
      }
      bit_index_changed = false;

      // allow other threads to run. Else the system becomes really unresponsive
      //printk("before schedule call\n");
      cond_resched();
      //printk("after schedule call\n");

      // check if we are asked to terminate
      if (kthread_should_stop()) {
        spin_lock(&thread_state_lock);
        thread_state = 0;
        spin_unlock(&thread_state_lock);
        do_exit(2);
      }

      // increase value for next cycle
      start_guess_counter = guess_counter;
    } while (state != Check && guess_counter <=  0xFFFFFFFF &&
             !found);
  }


  printk("bf_inside_hp_done\n");
  spin_lock(&thread_state_lock);
  thread_state = 0;
  spin_unlock(&thread_state_lock);
  thread_print_tweak_summary(tweaks,first_bit,last_bit);
  do_exit(0);
}





int bf_high(void *ctx) {
#undef LDB
  //#define LDB

  bf_high_ctx_st *params = (bf_high_ctx_st *)ctx;
  int first_bit = params->first_bit;
  int last_bit = params->last_bit;
  uint8_t(*tweaks)[16] = params->tweaks;

  uint8_t *ptr_src_c, *ptr_src_no_c;
  uint8_t *ptr_dst_c, *ptr_dst_no_c;
  uint64_t hfn_base_src, hfn_base_dst;
  uint64_t offset_base_ciphertext = 0;
  uint8_t plain[16],cipher[16];
  int bit_index;
  memset(plain, 0, 16);

    spin_lock(&thread_state_lock);
    if( thread_state != 0 ) {
      printk("inside bf_high: expected thread_state to be zero but it was %d.aborting\n",thread_state);
      spin_unlock(&thread_state_lock);
      do_exit(1);
    }
  spin_unlock(&thread_state_lock);
  printk("ping\n");
  if (first_bit < 29) {
    printk("first_bit must be >= 28. Use bf_inside_hp for smaller indice (it's faster). aborting\n");
    spin_lock(&thread_state_lock);
    thread_state = 0;
    spin_unlock(&thread_state_lock);
    do_exit(1);
  }


  // loop over all bits which should be bruteforced
  bool bit_index_changed = true;
  for (bit_index = first_bit; bit_index <= last_bit; bit_index++, bit_index_changed  = true) {
    printk("bf_high: processing bit_index = %d\n", bit_index);


  //allocate pages
  hfn_base_src = 0x1ULL << (bit_index - PAGE_SHIFT);
  hfn_base_dst = 0x1ULL << (bit_index - PAGE_SHIFT -1 );
  printk("bf_high: hfn_base_src =\t %016llx\nhfn_base_dst =\t %016llx\n",hfn_base_src,hfn_base_dst);
  map_enc_noenc_cached(hfn_base_src,(void*)&ptr_src_c,(void*)&ptr_src_no_c);
  map_enc_noenc_cached(hfn_base_dst,(void*)&ptr_dst_c,(void*)&ptr_dst_no_c);


    enum bf_phase state;
    // incremented inside the do_pair_move and do_full_move functions
    uint64_t guess_counter = 0;
    uint64_t start_guess_counter = guess_counter;
    bool found;
    found = false;
    do {
      // progess update
      if (guess_counter % 0x00100000 == 0) {
        printk("at guess_counter = %08llx\n", guess_counter);
      }
      for (state = Prepare; state <= Check; state++) {
        int err;
#ifdef LDB
        printk("in state %d\n", state);
#endif
        // in one Prepare,Move, Check cycle the same counter must be used
        // start_guess_counter is updated after one such cycle ends
        guess_counter = start_guess_counter;

        if (state == Prepare) {
          if( bit_index_changed) {
            // encrypt plaintext
            memcpy(ptr_src_c + offset_base_ciphertext, plain, 16);
            printk("encrypted base ciphertext in offset %016llx\n",offset_base_ciphertext);
          }
        }
        else {
          // do bits above bit_index
          if( bit_index_changed ) {
            memcpy(cipher,ptr_src_no_c + offset_base_ciphertext,16);
          }
          if (0 > (err = do_full_move(bit_index, ptr_dst_c, ptr_dst_no_c, plain, tweaks,
                                      &guess_counter, state,cipher,offset_base_ciphertext,PAGE_SIZE,hfn_base_src,hfn_base_dst,PAGE_SHIFT))) {
            printk("do_full_move aborted with %d!abort bf_inside_hp!\n", err);
            spin_lock(&thread_state_lock);
            thread_state = 0;
            spin_unlock(&thread_state_lock);
            do_exit(1);
          } else if (err == 1 && state == Check) {
            uint8_t found_tweak[16];
            printk("The Tweak for bit with index %d is:\n", bit_index);
            int_to_tweak(guess_counter, found_tweak);
            print_blockwise(found_tweak, 16);
            found = true;
          }
        }
        if( (bit_index_changed && state == Prepare) || state == Move) {
          wbinvd();
          __flush_tlb_all();
          }
      }
      bit_index_changed = false;

      // allow other threads to run. Else the system becomes really unresponsive
      //printk("before schedule call\n");
      cond_resched();
      //printk("after schedule call\n");

      // check if we are asked to terminate
      if (kthread_should_stop()) {
        spin_lock(&thread_state_lock);
        thread_state = 0;
        spin_unlock(&thread_state_lock);
        do_exit(2);
      }

      // increase value for next cycle
      start_guess_counter = guess_counter;
    } while (state != Check && guess_counter <=  0xFFFFFFFF &&
             !found);
  }
  printk("bf_inside_hp_done");
  spin_lock(&thread_state_lock);
  thread_state = 0;
  spin_unlock(&thread_state_lock);
  do_exit(0);
  thread_print_tweak_summary(tweaks,first_bit,last_bit);
}

static int __init bf_tweak_init(void) {

  /*
my_class = class_create(THIS_MODULE, "bf_tweak_class");
device_create(my_class, NULL, my_dev, NULL, "bf_tweak");
*/
  dev_file = proc_create(DEV_NAME, 0777, NULL, &my_fops);
  printk("bf_tweak: init done\n");

  return 0;
}

static void __exit bf_tweak_exit(void) {
  vfree(hp_pages);
  proc_remove(dev_file);
  // stop bf_thread if it is running
  //spin_lock(&thread_state_lock);
  if( bf_thread != NULL && thread_state != 0 ) {
    kthread_stop(bf_thread);
  }
  //spin_unlock(&thread_state_lock);
  vfree(bf_inside_hp_ctx);
  vfree(bf_high_ctx);
  vfree(thread_tweaks);
  printk(KERN_INFO "exited bf-tweak\n");
}

void thread_print_tweak_summary( uint8_t (*trans_tweaks)[16],int first_index, int last_index) {
  int i;
  printk("The bruteforcers found the following tweaks:\n");
  for( i = first_index; i <= last_index;i++) {
    printk("Tweak for bit with index %d is:\n",i);
    print_blockwise(trans_tweaks[i],16);
  }
}
module_init(bf_tweak_init);
module_exit(bf_tweak_exit);
