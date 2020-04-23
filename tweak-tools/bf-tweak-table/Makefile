#see https://stackoverflow.com/questions/7490070/missing-component-in-a-kernel-module-with-several-source-files for explanation of object files
bf-tweak-objs := bf_tweak_base.o tweak.o common.o
obj-m += bf-tweak.o
 
all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) clean
