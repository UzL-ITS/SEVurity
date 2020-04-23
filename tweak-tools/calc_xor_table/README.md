This file describes the usage of the kernel-module 'calc_xor.c' 
as well as its approach and implementation.

# Module-Setup

The module is compiled normaly as a kernel module.
(Regarding rights: It is declared with 'MODULE_LICENSE("GPL v2")
This is important for the linker to be able to find the necessary
libraries and functions, but elsewhere from no further importance.)

The kernel-module is compiled with a standard Makefile similar to the
following:
```
obj-m+=calc_xor.o

KERNELTREE ?= /lib/modules/$(shell uname -r)/build 

all:
	make -C $(KERNELTREE) M0$(PWD) modules

clean:
	make -C $(KERNELTREE) M=$(PWD) clean
```
The KERNELTREE is the path to the 'build' directory where your
compiled kernel is located. 

# Usage

The Makefile and source-file have to be in the same directory.
The module takes your maximum RAM size as a parameter. Counted in
GB and entered in hexadecimal.
Now compile and run the module as follows (for 4GB RAM):
```
$ make
$ sudo insmod calc_xor.ko size=0x4
$ sudo dmesg
```

'make' compiles the whole kernelmodule.
'insmod' loads the kernelmodule in the kernel and runs it.
'dmesg' shows the kernel messages where the calculated XOR-table
is printed to.
In the output of 'dmesg' you will see the steps for the calculation
of the XOR-table as well as the whole XOR-table at the end. It is
printed in byte order.  The entry '00 00 de ad be ef 00 00' resembles
that no valid entry was found. (All valid entries repeat themselfs 
after 4 byte.)
 
