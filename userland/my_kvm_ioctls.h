#ifndef MY_KVM_IOCTLS
#define MY_KVM_IOCTLS

#include <linux/types.h>
// pid of a vm from the shell will be written in the string str_pid
// in kvm_main.c and then converted into a number (pid_t type)
// for the case KVM_MAPPING_CHANGE
typedef struct mapping_change_param {
  char gfn1[8];
  char gfn2[8];
  char str_pid[16];

} mapping_change_param_t;

// for the cases KVM_TRACKING_ENABLE and KVM_TRACKING_DISABLE
typedef struct str_pid_param {
  char str_pid[16];
} str_pid_param_t;

typedef struct {
  uint64_t gpa;
  uint64_t user_space_buffer;
  uint64_t length;
} dump_page_param_t;

typedef struct {
  uint64_t gpa;
  uint64_t user_space_buffer;
  uint64_t length;
} write_page_param_t;

typedef struct {
  uint64_t gpa;
  uint8_t *injection_code_buffer;
  uint64_t length;
  uint8_t insert_at_back;
  uint32_t target_value;
  uint32_t prev_prev_eax;
  uint32_t prev_eax;
  uint32_t type;
} inject_param_t;

typedef write_page_param_t load_plaintext_param_t;

#define KVMIO 0xAE

#define KVM_GET_API_VERSION _IO(KVMIO, 0x00)
//#define KVM_TRACKING_ENABLE       _IO(KVMIO,   0x0b)
//#define KVM_TRACKING_DISABLE      _IO(KVMIO,   0x0c)
#define KVM_TRACKING_ENABLE _IOWR(KVMIO, 0x0b, str_pid_param_t)
#define KVM_TRACKING_DISABLE _IOWR(KVMIO, 0x0c, str_pid_param_t)
#define KVM_MAPPING_CHANGE _IOWR(KVMIO, 0x0d, mapping_change_param_t)

#define KVM_DUMP_PAGE _IOWR(KVMIO, 0x0e, dump_page_param_t)
#define KVM_WRITE_PAGE _IOWR(KVMIO, 0x0f, write_page_param_t)
#define KVM_PROTMAP_REPLAY _IO(KVMIO, 0x10)
#define KVM_DUMP_PAGE_HOSTDEC _IOWR(KVMIO, 0x11, dump_page_param_t)
#define KVM_LOAD_KNOWN_PLAINTEXT _IOWR(KVMIO, 0x12, load_plaintext_param_t)
#define KVM_INJECT_CODE _IOWR(KVMIO, 0x13, inject_param_t)
#define KVM_START_PAGE_RESTRICTIONS _IO(KVMIO, 0x14)
#endif // MY_KVM_IOCTLS
