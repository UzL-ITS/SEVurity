#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include <errno.h>
#include <sys/mman.h>

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
typedef dump_page_param_t write_page_param_t;
typedef write_page_param_t load_plaintext_param_t;

#define KVMIO 0xAE
#define KVM_GET_API_VERSION _IO(KVMIO, 0x00)
#define KVM_TRACKING_ENABLE _IOWR(KVMIO, 0x0b, str_pid_param_t)
#define KVM_TRACKING_DISABLE _IOWR(KVMIO, 0x0c, str_pid_param_t)
#define KVM_PROTMAP_REPLAY _IO(KVMIO, 0x10)
#define KVM_LOAD_KNOWN_PLAINTEXT _IOWR(KVMIO, 0x12, load_plaintext_param_t)

int main(int argc, char **argv) {
  int ret = 0;
  int err;
  void *text_vmlinuz_ptr = NULL;
  int fd_kvm = -1;
  FILE *text_vmlinuz;
  if (argc != 3) {
    printf("Usage: load_kown_plaintext <path to text section of> <nr "
           "of bytes to use from text section in dec> "
           "vmlinuz\n");
    return 1;
  }

  fd_kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
  if (fd_kvm < 0) {
    perror("failed to open /dev/kvm");
    ret = -1;
    goto finish;
  }
  printf("opened /dev/kvm\n");

  printf("argv[1]=%s\n", argv[1]);
  text_vmlinuz = fopen(argv[1], "r");
  if (text_vmlinuz == NULL) {
    fprintf(stderr, "error opening vmlinuz text section file: %s",
            strerror(errno));
    ret = -1;
    goto finish;
  }

  long bytes_vmlinuz_text_section = atol(argv[2]);
  if (bytes_vmlinuz_text_section == 0) {
    fprintf(stderr, "error converting %s to a number\n", argv[2]);
  }

  text_vmlinuz_ptr = malloc(bytes_vmlinuz_text_section);

  if (text_vmlinuz_ptr == NULL) {
    fprintf(stderr, "error allocating memory\n");
    ret = -1;
    goto finish;
  }

  // copy from file
  err = fread(text_vmlinuz_ptr, bytes_vmlinuz_text_section, 1, text_vmlinuz);
  if (err != 1) {
    printf("expected to read %d blocks of size %lx but only read %d\n", 1,
           bytes_vmlinuz_text_section, err);
    ret = -1;
    goto finish;
  }

  printf("Copied %s to vaddr %p\n", argv[1], text_vmlinuz_ptr);

  load_plaintext_param_t load_plaintext_param = {
      .gpa = 0x3600000,
      .user_space_buffer = (uint64_t)text_vmlinuz_ptr,
      .length = bytes_vmlinuz_text_section};

  err = ioctl(fd_kvm, KVM_LOAD_KNOWN_PLAINTEXT, &load_plaintext_param);
  if (err == -1) {
    perror("ioctl(fd_kvm,KVM_LOAD_KNOWN_PLAINTEXT) failed");
    ret = -1;
    goto finish;
  }
  if (err > 0) {
    printf("ioctl(fd_kvm,KVM_LOAD_KNOWN_PLAINTEXT) returned: %d", err);
  }

finish:
  free(text_vmlinuz_ptr);
  close(fd_kvm);
  fclose(text_vmlinuz);
  return ret;
}
