#ifndef COMNON_H
#define COMMON_H
#include <linux/fs.h>
#include <linux/types.h>

#define BLOCK 16
#define BLOCKS_PER_PAGE 256

/*
 * Use theese types to make clear which type of address is expected
 */
typedef uint64_t hpa_t;
typedef uint64_t hfn_t;

void test_calc_tweak(void);
void swap_page_content(void *page1_noenc, void *page2_noenc);
void print_blockwise(void *data, size_t length);
void block_xor(u8 *first_block, u8 *second_block, u8 *result);
void swap_first_two_blocks(void *data_noenc);

void calc_tweak(hpa_t hpa, uint8_t *result);
void calc_custom_tweak(hpa_t hpa, uint8_t *result,
                       uint8_t (*custom_tweaks)[BLOCK], uint64_t tweak_count);
void xor_in_place(u8 *target, u8 *tweak, int length);

void map_enc_noenc(u64 hfn, void **enc, void **noenc);
void map_enc_noenc_cached(u64 hfn, void **enc, void **noenc); 
bool array_cmp(u8 *arr1, u8 *arr2, u64 length);

hpa_t hfn_to_hpa(hfn_t hfn, unsigned int offset);
hfn_t hpa_to_hfn(hpa_t hpa);
uint64_t hpa_to_offset(hpa_t hpa);

struct file *driver_file_open(const char *path);
void driver_file_close(struct file *filp);
int driver_file_write(struct file *file, unsigned long long offset,
                      unsigned char *data, u64 size);
int driver_file_read(struct file *file, unsigned long long offset,
                     unsigned char *data, unsigned int size);

#endif
