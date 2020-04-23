#!/bin/sh

rm .config
cp base-config .config

#amd sme/sev stuff
./scripts/config --enable CONFIG_AMD_MEM_ENCRYPT
./scripts/config --disable AMD_MEM_ENCRYPT_ACTIVE_BY_DEFAULT
./scripts/config --disable CONFIG_DEBUG_INFO
./scripts/config --enable CRYPTO_DEV_SP_PSP
./scripts/config --module CRYPTO_DEV_CCP_DD
./scripts/config --enable CONFIG_CRYPTO_DEV_CCP

./scripts/config --enable CONFIG_KVM_AMD_SEV

./scripts/config --disable CONFIG_LOCALVERSION_AUTO
./scripts/config --disable CONFIG_AMD_SEV_ES_GUEST


make olddefconfig
