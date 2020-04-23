#define USERSPACE
#include "../bf_tweak_base_ioctls.h" //ioctl defs of kernel module
#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h> //ioctl sys call
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define GB_IN_B 1073741824ULL
#define MB_IN_B 1048576ULL

#define IOC_DEV_PATH

int main(int argc, char **argv) {

  int fdHPG, fdHPM;
  int err = 0;

  if (argc != 3) {
    printf("Usage: userserpace-alloca-hugepage: <index_first_bit> "
           "<index_last_bit>\n");
    return 1;
  }

  int index_first_bit = atoi(argv[1]);
  int index_last_bit = atoi(argv[2]);

  fdHPG = open("/mnt/hugetlb/myhpg", O_CREAT | O_RDWR, 0755);
  if (fdHPG == -1) {
    fprintf(stderr, "Failed to open huge page file because: %s\n",
            strerror(errno));
    err = 1;
    goto finish;
  }

  long int *buffer_1gb = (long int *)mmap(0, GB_IN_B, PROT_READ | PROT_WRITE,
                                          MAP_SHARED, fdHPG, 0);

  if (buffer_1gb == NULL) {
    fprintf(stderr, "Failed to mmap hugepage because: %s\n", strerror(errno));
    err = 1;
    goto finish;
  }
  for (int i = 0; i < 100; i++) {
    buffer_1gb[i] = i;
  }
  printf("Successfully allocated 1gb hugepage!\n");

  //######################
  // pass pointer to kernel module via ioctl
  //######################

  int fdDEVFile = open("/proc/bf_tweak", O_CREAT | O_RDWR, 0755);
  if (fdDEVFile == -1) {
    fprintf(stderr, "Failed to open bf_tweak device file because %s\n",
            strerror(errno));
    err = 1;
    goto finish;
  }

  pass_hp_param_st pass_hp_param = {.user_hp_ptr = (uint64_t)buffer_1gb,
                                    .length = GB_IN_B,
                                    .index_first_bit = index_first_bit,
                                    .index_last_bit = index_last_bit};
  err = ioctl(fdDEVFile, BF_TWEAK_PASS_HP, &pass_hp_param);
  if (err < 0) {
    fprintf(stderr, "ioctl failed with %d\n", err);
    err = 1;
    goto finish;
  }

  printf("Passed HP to kernel module. Wait untils it is finished, then press "
         "key to release buffer_1gb\n");
  getchar();

finish:
  close(fdHPG);
  munmap(buffer_1gb, GB_IN_B);
  close(fdDEVFile);
  return err;
}
