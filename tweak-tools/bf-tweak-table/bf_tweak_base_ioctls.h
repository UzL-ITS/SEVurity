#ifndef BF_TWEAK_BASE_IOCTLS
#define BF_TWEAK_BASE_IOCTLS
#ifndef USERSPACE
#include <linux/types.h> //uint64_t
#else
#include <stdint.h>
#endif
#define DEV_NAME "bf_tweak"
#define MYDRBASE 'k'
typedef struct {
  uint64_t user_hp_ptr;
  uint64_t length;
  // uint64_t user_tweak_table_ptr;
  int index_first_bit;
  int index_last_bit;

} pass_hp_param_st;
#define BF_TWEAK_PASS_HP _IOWR(MYDRBASE, 1, pass_hp_param_st)

#endif // BF_TWEAK_BASE_IOCTLS
