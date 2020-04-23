# Tweak Reversing Tools

Contains Tools for reverse engineering the tweak function of AMD SEV.
The Kernel Module bf-tweak.ko can be used to brute force the tweaks on AMD EPYC CPUs with 
"xor encrypt xor" style tweak function.


### Setup

Compile and load the Kernel Module.

This module requires that a 1GB Hugepage is available at /mnt/hugetlb/myhpg. (See https://wiki.debian.org/Hugepages for setting up hugepages).
If the path is not to your liking you need to edit the "open" call in userspace/userspace-alloc-hugepage.c".


Enter all known tweaks in "tweak.c". If you want to brute force the tweak for bit "x" you must enter tweaks for
bits [0,x-1].

### Usage

Call userpace/userspace-alloc.hugepage.c first index last index
This allocates the allocates the hugepage and starts the bruteforce process.
Currently [first index,last index] must either be a subset of [4,28] or a subset [29, highest bit allowed by installed memory]
but not of both (to lazy to adapt logic).

The bruteforce process can be aborted, by unloading the module
The thread performing the work only listens to signals after a certain amount of work is done. So it may take
a moment before the thread is terminated. Furthermore the thread hogs one CPU until a certain amount of work is done.
This may trigger "softlockup CPU stuck for xx seconds" errors in dmesg. These warnings are not critical.
Also the system sometimes hangs for a few seconds.

### TODO
Brute forcing bits >=29 could be brought to similar speed as bruteforcing bits < 29 by copying to more than one page.
