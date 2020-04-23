#/bin/sh
cores=$(nproc --all)
#sudo -u luca make distclean &&
./my-configure-sev.sh &&
make clean M=arch/x86/kvm/ &&
make -j $cores scripts &&
make -j $cores prepare &&
make -j $cores modules_prepare &&
cp /usr/src/linux-headers-`uname -r`/Module.symvers arch/x86/kvm/Module.symvers  &&
cp /usr/src/linux-headers-`uname -r`/Module.symvers Module.symvers  &&
chown luca:luca arch/x86/kvm/Module.symvers
cp "/boot/System.map-$(uname -r)" . 
cp "/boot/System.map-$(uname -r)" arch/x86/kvm/
touch .scmversion &&
make -j $cores modules M=arch/x86/kvm/ LOCALVERSION= &&
make modules_install M=arch/x86/kvm/ LOCALVERSION= &&

echo "Unload old modules" 
modprobe -r kvm_amd kvm 
cp ./arch/x86/kvm/kvm.ko "/lib/modules/$(uname -r)/kernel/arch/x86/kvm/"
cp ./arch/x86/kvm/kvm-amd.ko "/lib/modules/$(uname -r)/kernel/arch/x86/kvm/"
echo "Load new modules"
modprobe kvm-amd sev=1
#insmod "/lib/modules/$(uname -r)/kernel/virt/lib/irqbypass.ko"
#insmod ./arch/x86/kvm/kvm.ko 
#insmod "/lib/modules/$(uname -r)/kernel/drivers/crypto/ccp/ccp.ko"
#insmod ./arch/x86/kvm/kvm-amd.ko sev=1 
