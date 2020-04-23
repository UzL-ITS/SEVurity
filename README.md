# Description
This repository contains the code our our paper "SEVurity: No Security without Integrity" [1].
The paper will be presented at the IEEE S&P 2020. There is a pre-print version of arXiv [2].


# Content

- guest-kernels : Contains the two kernels used in the guest/VM. Kernel version 5.0.0-27 is used for non SEV and plain SEV (meaning no SEV-ES) experiments and kernel 5.1.0-sev-es-guest is used for the SEV-ES experiments.

- userland : Userland part of the code

- host-kernels : Source code of the modified host kernel for the attack

- tweak-tools : Tools for reverse engineering the tweak function. "calc_xor_table" can be used to get the weak values on a "XE-style" system. "bf-tweak-table" can be used to brute force tweaks on a "XEX-style" system. Both directories contain additional Readmes.

# Attacks

- We only reverse engineered 31 tweak values, so you have to restrict the host memory used for the VM accordingly. We achieved this by restricting the memory available to the host system with "mem=4396MB"

- The code currently only works with a single VM running, that only uses one VCPU.

## Cpuid Attack
This is the attack described in Section IV.B of the paper.

### Setup
1. Switch to host-kernels/cpuid

2. Run the "genAdresses" script for the guest kernel you want to use. The SystemMap file can be obtained from the .deb package of the guest kernel.
	This script generates some C files that are compiled into the host kernel KVM module and contain addresses used for attacking the guest kernel.
	If you want to use another guest kernel edit the script at the "#EDITME" locations.

3. Edit "arch/x86/kvm/cpuid.c" and "arch/x86/kvm/mmu.c" at the "#EDITME" locations to configure whether you want to a SEV or non-SEV guest and whether your system uses the XE-style or the XEX-style tweak function.

4. Compile the kernel with "/my-make-kernel.sh" and install it on the host system. On subsequent changes you only need to recompile the KVM kernel module. This can be done with "my-make-kvm-modules.sh".

### Attack
1. Run the "userland/do-load-<kernel version>-plaintext.sh" script. This will populate the known plaintext database in the kernel module.

2. Start the VM with the launch-qemu.sh script provided by AMD[3].

The state of the attack can be monitored via "dmesg -wH" on the host system.


## 16 byte Oracle attack
This is the attack from Section VI of the paper.

### Setup
1. Switch to host-kernels/16b-oracle

2. Run the "genAdresses" script for the guest kernel you want to use. The SystemMap file can be obtained from the .deb package of the guest kernel.
	This script generates some C files that are compiled into the host kernel KVM module and contain addresses used for attacking the guest kernel.
	If you want to use another guest kernel edit the script at the "#EDITME" locations.

3. Edit "arch/x86/kvm/mmu.c" at the "#EDITME" locations to configure whether you want to a SEV or non-SEV guest and whether your system uses the XE-style or the XEX-style tweak function.

4. Compile the kernel with "/my-make-kernel.sh" and install it on the host system. On subsequent changes you only need to recompile the KVM kernel module. This can be done with "my-make-kvm-modules.sh".

### Attack
1. Run the "userland/do-load-<kernel version>-plaintext.sh" script. This will populate the known plaintext database in the kernel module.

2. Start the VM with the launch-qemu.sh script provided by AMD[3].

3. Start the "userland/do-complex-injection.sh" script. This must be done before the kernel starts booting. For experimenting it's convenient to set a rather large timeout in the GRUB boot menu giving ample time to start the script.

4. Enter a 16 byte aligned GPA where the injection should take place.

Test Setup:
The folder "gadget-injection-victim" contains a test program for injections.
The addresses in "gadget-injection-victim/addresses.txt" are only valid if the program is compiled with "-falign-functions=16" and ASLR is disabled in the guest.
Start the program in the guest and translate the GVA of the "victim" function to a GFN via the pagemap interface. A convenient way is to use the program in [4].
Combine the GFN with the page offset of the "victim" function and enter the result into the prompt of "do-complex-injeciton.sh" on the host system.
As soon as the initial injections are done ( follow dmesg on host) switch to the VM and continue the victim program by pressing any key.

Current limitations:
The current implementation does not clean up after itself, i.e. the stack is not restored and neither is the modified program code.
In the case of the stack this might trigger stack protection mechanisms like canaries. Under Linux, program code is usually mapped into memory from a file.
Any changes to the code in memory are thus also present in the binary file. Thus the program in the guest setup should be recompiled after injections.

# Overview of changes made to the kernel
Due to some unfortunate auto-indent decision diffing the code against a plain kernel might prove difficult.
The following is a broad overview of the changes the kernel.

- virt/kvm/kvm_main.c
	- Added custom ioctls to "kvm_dev_ioctl"
	- Modified "kvm_destroy_vm" and "kvm_dev_ioctl_create_vm" to get a reference to the main VM struct and perform tasks on creation and destruction of the VM.
	- Added several memory manipulation functions like "read_physical" and "write_physical" to manipulate VM memory.

- arch/x86/kvm/plaintext_gpa_database.c : Code for known plaintext ciphertext database.

- arch/x86/kvm/mmu.c
	 - Modified the page fault handler for tracked pages ( "page_fault_handle_page_track" ) to monitor the state of the VM. The attack on KASLR is implemented here.

- /arch/x86/kvm/cpuid.c
	 - kvm_emulate_cpuid : This is the handler for cpuid emulation. For the cpuid attack we manipulated it in order to detect when the kernel is at the position we want to attack. For the "main" 16 byte injection attack we monitored it to keep track of the state of the injected program and monitor it accordingly.


# References
- [1] https://doi.ieeecomputersociety.org/10.1109/SP40000.2020.00080
- [2] Added soon
- [3] https://github.com/AMDESE/AMDSEV
- [4] http://fivelinesofcode.blogspot.com/2014/03/how-to-translate-virtual-to-physical.html
