#!/bin/bash

gcc load_known_plaintext.c -o load_known_plaintext &&
~/kvm-development/userland-tools/load_known_plaintext $1 $2
