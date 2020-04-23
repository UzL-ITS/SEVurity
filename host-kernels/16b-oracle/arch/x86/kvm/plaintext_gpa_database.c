#include "linux/plaintext_gpa_database.h"
#include <linux/kvm_host.h> // address cast functions
#include <linux/vmalloc.h>

db_entry_t **db = NULL;
uint64_t db_count = 0;

static uint64_t __gpa_to_index(uint64_t gpa) { return (gpa >> 12); }

static bool __is_entry_valid(uint64_t offset, db_entry_t *db_entry) {
  int bucket;
  if (offset % CIPHER_BLOCK != 0) {
    printk("in %s line %d __is_entry_valid: offset is not 16 byte "
           "aligned, returning false",
           __FILE__, __LINE__);
    return false;
  }

  // printk("__is_entry_valid: called with offset(pre shift) %03llx\n", offset);
  // we do not care for the lowest 4 bits, since they index inside a block
  offset = offset >> 4;

  // printk("__is_entry_valid: called with offset %03llx\n", offset);
  // flags are stored in 4 64 bit integers. div by 64 to get the index
  bucket = offset / 64;
  // printk("__is_entry_valid: goes to bucket %d\n", bucket);
  // check bit
  /*printk("__is_entry_valid: value %016llx\tmask %016llx",
         db_entry->entry_valid[bucket], (0x1ull << (offset % 64)));*/
  return db_entry->entry_valid[bucket] & (0x1ull << (offset % 64));
};
static void __mark_entry_valid(uint64_t offset, db_entry_t *db_entry) {

  int bucket;
  if (offset % CIPHER_BLOCK != 0) {
    printk("in %s line %d __is_entry_valid: offset is not 16 byte "
           "aligned, returning false",
           __FILE__, __LINE__);
    return;
  }

  // we do not care for the lowest 4 bits, since they index inside a block
  offset = offset >> 4;

  // printk("__is_entry_valid: called with offset %03llx\n", offset);
  // flags are stored in 4 64 bit integers. div by 64 to get the index
  bucket = offset / 64;
  // printk("__is_entry_valid: goes to bucket %d\n", bucket);
  // set bit
  /*printk("__is_entry_valid:(before) value %016llx\tmask %016llx",
         db_entry->entry_valid[bucket], (0x1ull << (offset % 64)));*/
  db_entry->entry_valid[bucket] |= (0x1ull << (offset % 64));
  /*printk("__is_entry_valid:(after) value %016llx\tmask %016llx",
         db_entry->entry_valid[bucket], (0x1ull << (offset % 64)));*/
};

static int64_t __get_page_offset(uint64_t gpa) { return gpa & 0xFFF; }

//TODO: this is called with vm memory as an argument. misleading parameter name
int alloc_db(uint64_t vmlinuz_bytes) {
  uint64_t bytes, gfn;
  if (db != NULL) {
    return -1;
  }
  printk("alloc_db : called with %016llx as argument\n",vmlinuz_bytes);
  db_count = (vmlinuz_bytes / PAGE_SIZE) + 1;
  bytes = db_count * sizeof(db_entry_t *); // N.B: sizeof pointer to an entry
  printk("going to allocate %llu bytes of memory. Highest valid index is %llu",
         bytes, db_count);
  // do not use kmalloc because our memory request is to large for conitnous
  // kernel memory
  db = (db_entry_t **)vmalloc(bytes);
  for (gfn = 0; gfn < db_count; gfn++) {
    db[gfn] = NULL;
  }
  return 0;
}
void free_db() {
  if (db != NULL) {
    uint64_t gfn;
    printk("free_db: db_count is %llu\n", db_count);
    for (gfn = 0; gfn < db_count; gfn++) {
      // printk("free_db: at index %llu\n", gfn);
      if (db[gfn] != NULL) {
        vfree(db[gfn]);
        db[gfn] = NULL;
      }
    }
    vfree(db);
    // N.B. freeing does not set the pointer to NULL
    db = NULL;
  }
}

/*
 * Updates the variable for the next free entry so that
 * successive calls yield valid indices
 */
/*int __get_next_free_entry(void) {
  if (last_db_entry < (db_count - 1)) {
    last_db_entry++;
    return last_db_entry;
  }
  return -1;
}*/

bool db_add_incomplete(gpa_t gpa, uint8_t *plaintext) {
  db_entry_t *db_entry;
  uint64_t index;
  int i;
  index = __gpa_to_index(gpa);

  // check if index is valid
  if (index >= (db_count - 1)) {
    printk("in %s line %d db_add_incomplete: gpa %016llx yields invalid index "
           "%llu\n",
           __FILE__, __LINE__, gpa, index);
    return false;
  }

  // alloc page entry if it does  not exists
  if (db[index] == NULL) {
    printk_ratelimited(
        "in %s line %d db_add_incomplete: entry for gpa %016llx was null=> "
        "allocating\n",
        __FILE__, __LINE__, gpa);
    db[index] = vmalloc(sizeof(db_entry_t));
    db_entry = db[index];
  }
  // check for duplicate
  else {
    db_entry = db[index];
    if (__is_entry_valid(gpa & 0xFFF, db_entry)) {
      /*printk_ratelimited(
          "in %s line %d db_add_incomplete: there already is an entry for "
          "gpa=%016llx. Nothing is changed\n",
          __FILE__, __LINE__, gpa)*/
      return false;
    }
  }

  // Fill in partial data and mark as not valid
  db_entry->gfn = gpa >> 12;
  memcpy(db_entry->plaintext + __get_page_offset(gpa), plaintext, CIPHER_BLOCK);

  db_entry->hfn_valid = false;
  for (i = 0;
       i < (sizeof(db_entry->entry_valid) / sizeof(db_entry->entry_valid[0]));
       i++) {
    db_entry->entry_valid[i] = 0;
  }
  return true;
}

/*
 * Content of @ciphertext is copied, caller can free pointer
 */
bool db_entry_finalize(gpa_t gpa, hfn_t hfn, uint8_t *ciphertext) {
  db_entry_t *db_entry;
  uint64_t index;

  // check if index is valid
  index = __gpa_to_index(gpa);
  if (index >= (db_count - 1)) {
    printk("in %s line %d db_add_incopleete: gpa %016llx yields invalid index "
           "%llu\n",
           __FILE__, __LINE__, gpa, index);
    return false;
  }

  db_entry = db_get(gpa);
  if (db_entry == NULL) {
    printk("in %s line %d db_entry_finalize: did not find entry for "
           "gpa=%016llx. max db gfn is %016llx\n",
           __FILE__, __LINE__, gpa,db_count);
    return false;
  }

  if (!db_entry->hfn_valid) {
    db_entry->hfn = hfn;
    db_entry->hfn_valid = true;
  } else if (hfn != db_entry->hfn) {
    printk("in %s line %d db_entry_finalize: called with hfn=%016llx allthough"
           "hfn was already set to %016llx\n",
           __FILE__, __LINE__, hfn, db_entry->hfn);
  }

  if (__is_entry_valid((gpa & 0xfffull), db_entry)) {
    /*printk("in %s line %d db_entry_finalize: entry for gpa=%016llx was already
       " "valid. Nothing was changed",
           __FILE__, __LINE__, gpa);*/
    return false;
  }

  memcpy(db_entry->ciphertext + __get_page_offset(gpa), ciphertext,
         CIPHER_BLOCK);
  __mark_entry_valid(__get_page_offset(gpa), db_entry);
  // printk("gpa %016llx maps to hfn %016llx\n", gpa, hfn);
  return true;
}

/*int db_get_index(gpa_t gpa) {
  int res, i;
  res = -1;

  for (i = 0; i <= last_db_entry; i++) {
    if (db[i].gpa == gpa) {
      return i;
    }
  }
  return res;
}*/

db_entry_t *db_get(gpa_t gpa) { return db[__gpa_to_index(gpa)]; }

/*
 * @return gpa from which the ciphertext should be moved. This can be used
 * to get the ciphertext from the database
 * @return If a source is found, it is stored in @gpa and true is returned
 */
bool find_source_for_move(hpa_t target, __u8 *wanted_plaintext, int length,
                          uint64_t *gpa) {
  return 0 ==
         __find_source_for_move(target, wanted_plaintext, length, 0, gpa, true);
}

static int __process_page(db_entry_t *db_entry, uint64_t *skipped_pages,
                          hpa_t target, __u8 *wanted_plaintext, int length,
                          unsigned int offset, uint64_t *gpa, uint64_t gfn) {
  uint64_t off;
  __u8 tweak_diff[CIPHER_BLOCK], xor_buffer[CIPHER_BLOCK];

  // an entry represents a whole page, loop over every offset
  for (off = 0; off < PAGE_SIZE; off += CIPHER_BLOCK) {
    // check if entry has valid data for this offset
    if (db_entry->hfn_valid &&
        ((db_entry->hfn << 12) + (target & 0xfff)) !=
            target && // exlcude @target from solution space
        __is_entry_valid(off, db_entry)) {
      // skip pages that are mapped to to high gpas
      if (0 != __calc_tweak(target ^ (pfn_to_hpa(db_entry->hfn) + off),
                            tweak_diff, tweaks,
                            sizeof(tweaks) / sizeof(tweaks[0]), false)) {
        skipped_pages++;
        break;
      }

      // calc result of move
      memcpy(xor_buffer, db_entry->plaintext + off, CIPHER_BLOCK);
      xor_in_place(xor_buffer, tweak_diff);
      // if true we found a source => done
      if (_has_prefix(xor_buffer, wanted_plaintext, length, offset)) {
        // return
        (*gpa) = (gfn << 12) + off;
        return 0;
      }
    }
  }
  return 1;
}

// TODO: reset this on loading new plaintext
#define SIZE_GFN_LOOKUP_CACHE 40
uint64_t gfn_lookup_cache[SIZE_GFN_LOOKUP_CACHE];
int count_gfn_lookup_cache, next_insert_gfn_lookup_cache;

void reset_lookup_cache(void) {
  count_gfn_lookup_cache = 0;
  next_insert_gfn_lookup_cache = 0;
}

int __find_source_for_move(hpa_t target, __u8 *wanted_plaintext, int length,
                           unsigned int offset, uint64_t *gpa,
                           bool fail_on_add) {

  uint64_t gfn;
  uint64_t skipped_pages,off,valid_entries;
  int i;
  skipped_pages = 0;
  valid_entries = 0;

  //start debug
  for (gfn = 0; gfn < db_count; gfn++) {
    db_entry_t *db_entry = db[gfn];
    if (db_entry == NULL) {
      continue;
    }
	  // an entry represents a whole page, loop over every offset
	  for (off = 0; off < PAGE_SIZE; off += CIPHER_BLOCK) {
	    // check if entry has valid data for this offset
	    if (db_entry->hfn_valid &&
		((db_entry->hfn << 12) + (target & 0xfff)) !=
		    target && // exlcude @target from solution space
		__is_entry_valid(off, db_entry)) {
		    valid_entries++;
	    }
	  }
  }
  printk("found %016llx valid entries a 16 bytes\n",valid_entries);
  ////end debug

  // test cached entries first
  for (i = 0; i < count_gfn_lookup_cache; i++) {
	 db_entry_t *db_entry;
    gfn = gfn_lookup_cache[i];
    db_entry = db[gfn];
    // skip null entries
    if (db_entry == NULL) {
      continue;
    }
    if (0 == __process_page(db_entry, &skipped_pages, target, wanted_plaintext,
                            length, offset, gpa, gfn)) {
      return 0;
    }
  }

  // loop over db entries
  for (gfn = 0; gfn < db_count; gfn++) {
    db_entry_t *db_entry = db[gfn];
    // skip null entries
    if (db_entry == NULL) {
      continue;
    }
    if (0 == __process_page(db_entry, &skipped_pages, target, wanted_plaintext,
                            length, offset, gpa, gfn)) {

      gfn_lookup_cache[next_insert_gfn_lookup_cache] = gfn;
      if (count_gfn_lookup_cache < SIZE_GFN_LOOKUP_CACHE) {
        count_gfn_lookup_cache++;
      }
      // fifo
      next_insert_gfn_lookup_cache =
          (next_insert_gfn_lookup_cache + 1) % SIZE_GFN_LOOKUP_CACHE;

      return 0;
    }
  }
  // if we reach this, we did not find a source, indicate failure
  printk("in %s line %d : __find_source_for_move : %lld pages where omitted "
         "(too high)\n",
         __FILE__, __LINE__, skipped_pages);
  return 1;
}

/*
 * Uses the tweak table from tweak.h
 * @hpa host physical address for which the tweak is calculated
 * @result 16 byte array in which the tweak gets stored
 */
void calc_tweak(hpa_t hpa, __u8 result[CIPHER_BLOCK]) {
  __calc_tweak(hpa, result, tweaks, sizeof(tweaks) / sizeof(tweaks[0]), true);
}

/*
 * Uses the supplied tweaks instead of the tweak table from tweak.h
 * @hpa host physical address for which the tweak is calculated
 * @fail_on_addr: controls if hpa whose gpa is to high should result  in a BUG()
 * or not
 * @result 16 byte array in which the tweak gets stored
 */
int __calc_tweak(hpa_t hpa, __u8 result[CIPHER_BLOCK],
                 __u8 (*custom_tweaks)[CIPHER_BLOCK], __u64 tweak_count,
                 bool fail_on_addr) {
  int i, j;
  u64 mask;
  // init result with zeroes
  memset(result, 0, CIPHER_BLOCK);

  mask = 0x0000000000000001;

  // calculate tweak pattern;
  for (i = 0; i < 64; i++) {
    if (hpa & mask) {
      if (i >= tweak_count) {
        printk_ratelimited(
            KERN_CRIT
            "__calc_tweak got called with hpa %016llx but currently only "
            "addresses up to %llu bits are supported",
            hpa, tweak_count);
        if (fail_on_addr) {
          BUG();
        } else {
          return 1;
        }
      }
      for (j = 0; j < 16; j++) {
        result[j] ^= custom_tweaks[i][j];
      }
    }
    // shift mask bit one position to the left
    mask = mask << 1;
  }
  return 0;
}

/*
 * Xor first @length bytes of @target and tweak and store the result in @target
 */
void xor_in_place(u8 target[CIPHER_BLOCK], u8 tweak[CIPHER_BLOCK]) {
  int i;

  for (i = 0; i < CIPHER_BLOCK; i++) {
    target[i] ^= tweak[i];
  }
}

/*
 * Compare the first @length bytes of @arr1 bytewise with  @arr2
 * @return false if there is a missmatch
 */
bool has_prefix(__u8 moved_block[CIPHER_BLOCK], __u8 *prefix,
                unsigned int length) {
  return _has_prefix(moved_block, prefix, length, 0);
}

/*
 * Compare the  @length bytes of @arr1+@offset bytewise with  @arr2
 * @return false if there is a missmatch
 */
bool _has_prefix(__u8 moved_block[CIPHER_BLOCK], __u8 *prefix,
                 unsigned int length, unsigned int offset) {
  u64 i;
  if (length + offset > CIPHER_BLOCK) {
    printk(KERN_CRIT
           "in %s line %d has_prefix: supplied length+offset is larger then "
           "CIPHER_BLOCK, at most the first CIPHER_BLOCK bytes are used",
           __FILE__, __LINE__);
    length = CIPHER_BLOCK;
  }
  for (i = 0; i < length; i++) {
    if (moved_block[i + offset] != prefix[i]) {
      return false;
    }
  }
  return true;
}

void print_blockwise(uint8_t *data, uint64_t length) {
  int i;
  if (length % CIPHER_BLOCK != 0) {
    printk("print_blockwise: length %lld is not a multiple of CIPHER_BLOCK",
           length);
  }
  for (i = 0; i < length; i++) {
    if (i % CIPHER_BLOCK == 0) {
      printk("%02x ", data[i]);
    } else {
      printk(KERN_CONT " %02x ", data[i]);
    }
  }
  printk("\n");
}

__u8 tweaks[32][16] = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                       {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                       {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                       {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // index 3
                       {0x82, 0x25, 0x38, 0x38, 0x82, 0x25, 0x38, 0x38, 0x82,
                        0x25, 0x38, 0x38, 0x82, 0x25, 0x38, 0x38},
                       {0xec, 0x09, 0x07, 0x9c, 0xec, 0x09, 0x07, 0x9c, 0xec,
                        0x09, 0x07, 0x9c, 0xec, 0x09, 0x07, 0x9c},
                       {0x40, 0x00, 0x00, 0x18, 0x40, 0x00, 0x00, 0x18, 0x40,
                        0x00, 0x00, 0x18, 0x40, 0x00, 0x00, 0x18},
                       {0x81, 0x02, 0xa2, 0x3a, 0x81, 0x02, 0xa2, 0x3a, 0x81,
                        0x02, 0xa2, 0x3a, 0x81, 0x02, 0xa2, 0x3a},
                       {0x77, 0xd9, 0x10, 0x77, 0x77, 0xd9, 0x10, 0x77, 0x77,
                        0xd9, 0x10, 0x77, 0x77, 0xd9, 0x10, 0x77}, // index 8
                       {0xb0, 0x10, 0xb2, 0xc0, 0xb0, 0x10, 0xb2, 0xc0, 0xb0,
                        0x10, 0xb2, 0xc0, 0xb0, 0x10, 0xb2, 0xc0},
                       {0x53, 0x6d, 0x54, 0x4d, 0x53, 0x6d, 0x54, 0x4d, 0x53,
                        0x6d, 0x54, 0x4d, 0x53, 0x6d, 0x54, 0x4d},
                       {0x15, 0x68, 0xee, 0x53, 0x15, 0x68, 0xee, 0x53, 0x15,
                        0x68, 0xee, 0x53, 0x15, 0x68, 0xee, 0x53},
                       {0xb0, 0x92, 0x30, 0xc2, 0xb0, 0x92, 0x30, 0xc2, 0xb0,
                        0x92, 0x30, 0xc2, 0xb0, 0x92, 0x30, 0xc2}, // index 12
                       {0x96, 0x70, 0xff, 0x8e, 0x96, 0x70, 0xff, 0x8e, 0x96,
                        0x70, 0xff, 0x8e, 0x96, 0x70, 0xff, 0x8e},
                       {0x36, 0x1b, 0x90, 0xd5, 0x36, 0x1b, 0x90, 0xd5, 0x36,
                        0x1b, 0x90, 0xd5, 0x36, 0x1b, 0x90, 0xd5},
                       {0x04, 0x00, 0xc2, 0x36, 0x04, 0x00, 0xc2, 0x36, 0x04,
                        0x00, 0xc2, 0x36, 0x04, 0x00, 0xc2, 0x36},
                       {0xe8, 0x18, 0x29, 0x85, 0xe8, 0x18, 0x29, 0x85, 0xe8,
                        0x18, 0x29, 0x85, 0xe8, 0x18, 0x29, 0x85},
                       {0xbd, 0x31, 0xf9, 0x2a, 0xbd, 0x31, 0xf9, 0x2a, 0xbd,
                        0x31, 0xf9, 0x2a, 0xbd, 0x31, 0xf9, 0x2a},
                       {0xa5, 0x0d, 0x37, 0x44, 0xa5, 0x0d, 0x37, 0x44, 0xa5,
                        0x0d, 0x37, 0x44, 0xa5, 0x0d, 0x37, 0x44}, // index 18
                       {0xf4, 0x31, 0xd8, 0x4c, 0xf4, 0x31, 0xd8, 0x4c, 0xf4,
                        0x31, 0xd8, 0x4c, 0xf4, 0x31, 0xd8, 0x4c},
                       {0x02, 0x04, 0x31, 0x81, 0x02, 0x04, 0x31, 0x81, 0x02,
                        0x04, 0x31, 0x81, 0x02, 0x04, 0x31, 0x81},
                       {0xb3, 0x71, 0x32, 0xa1, 0xb3, 0x71, 0x32, 0xa1, 0xb3,
                        0x71, 0x32, 0xa1, 0xb3, 0x71, 0x32, 0xa1},
                       {0x50, 0x8a, 0xc0, 0x6c, 0x50, 0x8a, 0xc0, 0x6c, 0x50,
                        0x8a, 0xc0, 0x6c, 0x50, 0x8a, 0xc0, 0x6c},
                       {0x16, 0x8a, 0x80, 0x20, 0x16, 0x8a, 0x80, 0x20, 0x16,
                        0x8a, 0x80, 0x20, 0x16, 0x8a, 0x80, 0x20},
                       {0x7f, 0x9b, 0xc0, 0x07, 0x7f, 0x9b, 0xc0, 0x07, 0x7f,
                        0x9b, 0xc0, 0x07, 0x7f, 0x9b, 0xc0, 0x07}, // index 24
                       {0x00, 0xdb, 0x04, 0x07, 0x00, 0xdb, 0x04, 0x07, 0x00,
                        0xdb, 0x04, 0x07, 0x00, 0xdb, 0x04, 0x07},
                       {0x7f, 0x00, 0x04, 0x04, 0x7f, 0x00, 0x04, 0x04, 0x7f,
                        0x00, 0x04, 0x04, 0x7f, 0x00, 0x04, 0x04},
                       {0x70, 0xfa, 0x01, 0xbe, 0x70, 0xfa, 0x01, 0xbe, 0x70,
                        0xfa, 0x01, 0xbe, 0x70, 0xfa, 0x01, 0xbe},
                       {0xbb, 0x3d, 0x28, 0x90, 0xbb, 0x3d, 0x28, 0x90, 0xbb,
                        0x3d, 0x28, 0x90, 0xbb, 0x3d, 0x28, 0x90}, // index 28
                       {0xbd, 0x2d, 0xd5, 0x26, 0xbd, 0x2d, 0xd5, 0x26, 0xbd,
                        0x2d, 0xd5, 0x26, 0xbd, 0x2d, 0xd5, 0x26},
                       {0x1c, 0x5d, 0x6c, 0xe2, 0x1c, 0x5d, 0x6c, 0xe2, 0x1c,
                        0x5d, 0x6c, 0xe2, 0x1c, 0x5d, 0x6c, 0xe2},
                       {0x4f, 0x5c, 0xe7, 0x27, 0x4f, 0x5c, 0xe7, 0x27, 0x4f,
                        0x5c, 0xe7, 0x27, 0x4f, 0x5c, 0xe7, 0x27}};
