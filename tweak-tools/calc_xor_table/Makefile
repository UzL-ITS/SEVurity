obj-m += calc_xor.o

EXTRA_CFLAGS += $(CFLAGS_EXTRA) -fno-pie

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean

