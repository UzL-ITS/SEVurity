#!/bin/sh
./my-configure-sev.sh
make oldconfig -j $(nproc --all) deb-pkg LOCALVERSION=
