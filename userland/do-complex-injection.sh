#!/bin/bash

pid=$(pidof /usr/local/bin/qemu-system-x86_64) 
echo "Script: pid is $pid" 
gcc complex-injection.c -o complex-injection &&
~/kvm-development/userland-tools/complex-injection $pid
