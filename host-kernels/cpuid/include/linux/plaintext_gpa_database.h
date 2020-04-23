#ifndef PLAINTEXT_GPA_DATABASE
#define PLAINTEXT_GPA_DATABASE

#define BLOCKS_PER_PAGE 256
#define CIPHER_BLOCK 16

#include <linux/kvm_types.h> //hpa_t etc..
#include <linux/types.h>     //bool ..

typedef struct {
  hfn_t hfn;
  gfn_t gfn;
  uint8_t ciphertext[4096];
  uint8_t plaintext[4096];
  uint64_t entry_valid[4];
  bool hfn_valid;

} db_entry_t;
// extern int last_db_entry;
extern uint64_t db_count;
extern db_entry_t **db;
extern __u8 tweaks[32][16];

int alloc_db(uint64_t vmlinuz_bytes);
void free_db(void);
bool db_add_incomplete(gpa_t gpa, uint8_t *plaintext);
bool db_entry_finalize(gpa_t gpa, hfn_t hfn, uint8_t *ciphertext);
// int db_get_index(gpa_t gpa);
db_entry_t *db_get(gpa_t gpa);
bool find_source_for_move(hpa_t target, __u8 *wanted_plaintext, int length,
                          uint64_t *gpa);
int __find_source_for_move(hpa_t target, __u8 *wanted_plaintext, int length,
                           unsigned int offset, uint64_t *gpa,
                           bool fail_on_addr);
void calc_tweak(hpa_t hpa, uint8_t result[CIPHER_BLOCK]);
int __calc_tweak(hpa_t hpa, uint8_t result[CIPHER_BLOCK],
                 uint8_t (*custom_tweaks)[CIPHER_BLOCK], uint64_t tweak_count,
                 bool fail_on_addr);
void xor_in_place(uint8_t target[CIPHER_BLOCK], uint8_t tweak[CIPHER_BLOCK]);
bool has_prefix(__u8 moved_block[CIPHER_BLOCK], __u8 *prefix,
                unsigned int length);
bool _has_prefix(__u8 moved_block[CIPHER_BLOCK], __u8 *prefix,
                 unsigned int length, unsigned int offset);
void print_blockwise(uint8_t *data, uint64_t length);
void reset_lookup_cache(void);
#endif
