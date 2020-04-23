#!/bin/bash


function parse {
#for some reason its not possible to use $1 directly in the expression used in the for loop
arr=($1)
for symb in "${arr[@]}"
do
	echo "Looking up $symb"
	# regexp is needed to get exact matches
	res=$(echo "$symbols" | grep -x -E "[0-9a-fA-F]+ . $symb")
	#Just a sanity check. This should not happen
	if [ $(echo "$res" | wc -l) -ne 1 ]
	then
		echo "There are multiple results for $symb. This should not happen"
		exit
	fi

	#split by whitespace
	tokens=( $res )
	line="const u64 paddr_""${tokens[2]} = 0x${tokens[0]}ull - $2 +  $3;"
	echo "Going to write: $line"
	echo "$line" >> "$4"
done
}

function write_dyn_header {

#for some reason its not possible to use $1 directly in the expression used in the for loop
arr=($1)
for symb in "${arr[@]}"
do
s="extern const u64 paddr_""$symb"";"
	echo "Writing: $s"
	echo "$s" >> $2
done
}


if [ -z "$1" ]
then
	echo "Usage: genAdresses.sh <path to SystemMap file>"
	exit
fi

#output files used by kernel module
source_file="arch/x86/kvm/kvm_targets.c"
header_file="include/linux/kvm_targets.h"

#New function names can be added to theese arrays.
#For now it's the editors task to check to which section they belong


textSectionNames=("urandom_read add_interrupt_randomness add_disk_randomness crng_reseed crng_backtrack_protect extract_crng get_random_bytes protection_map __handle_mm_fault alloc_pages_vma do_page_fault __startup_64 do_execve do_mmap do_execve_file flush_old_exec search_binary_handler copy_strings_kernel mmap_region __audit_bprm proc_exec_connector start_thread sched_exec arch_align_stack install_exec_creds")

dataSectionNames=("crng_node_pool sme_me_mask")

bssSectionNames=("primary_crng x86_64_start_kernel sme_enable ")

echo "Prepare Header file"
#write header file
echo "//This file is auto generated"  > "$header_file"
echo "#ifndef KVM_TARGETS_H" >> "$header_file"
echo "#define KVM_TARGETS_H" >> "$header_file"


echo "extern const u64 paddrVmlinuzTextSection;" >> "$header_file"
echo "extern const u64 offsetVmlinuzTextSection;" >> "$header_file"

echo "extern const u64 paddrVmlinuxTextSection;" >>"$header_file"
echo "extern const u64 vaddrVmlinuxTextSection;" >> "$header_file"

echo "extern const u64 paddrVmlinuxDataSection;" >> "$header_file"
echo "extern const u64 vaddrVmlinuxDataSection;" >> "$header_file"

echo "extern const u64 paddrVmlinuxBssSection;" >> "$header_file"
echo "extern const u64 vaddrVmlinuxBssSection;" >> "$header_file"

echo "extern const u64 paddr_choose_random_location;" >> "$header_file";

write_dyn_header "${textSectionNames[@]}" $header_file
write_dyn_header "${dataSectionNames[@]}" $header_file
write_dyn_header "${bssSectionNames[@]}"  $header_file

echo "#endif" >> "$header_file"


echo " Preparing source file"
#reset source  file
echo "//This file is auto generated"  > "$source_file"
echo "#include <linux/types.h>" >> $source_file

#hardcoded for now. Don't now how to calculate them automatically

#Observed from non sev ramdump of vm
#EDITME
paddrVmlinuzTextSection=0x4000000
paddrVmlinuxTextSection=0x4000000


#offset of text section obtained with objdump from vmlinuz binary
#EDITME
offsetVmlinuzTextSection=0x004200

#magic values are the load addresses of the segments containing the data and txt section obtained with readelf from vmlinux binary
#EDITME magic values
paddrVmlinuxDataSection=$(($paddrVmlinuxTextSection + 0x2200000- 0x1000000))
paddrVmlinuxBssSection=$(($paddrVmlinuxTextSection + 0x27f7000 - 0x1000000))


#magic values are the load addresses of the segments containing the data ant txt section
#EDITME
vaddrVmlinuxTextSection=0xffffffff81000000
vaddrVmlinuxDataSection=0xffffffff82200000
vaddrVmlinuxBssSection=0xffffffff827f7000


echo "const u64 paddrVmlinuzTextSection=$paddrVmlinuzTextSection""ull;" >> "$source_file"
echo "#define paddrVmlinuzTextSection $paddrVmlinuzTextSection""ull " >> "$source_file"

echo "const u64 offsetVmlinuzTextSection=$offsetVmlinuzTextSection""ull;" >> "$source_file"
echo "#define offsetVmlinuzTextSection $offsetVmlinuzTextSection""ull " >> "$source_file"


echo "const u64 paddrVmlinuxTextSection=$paddrVmlinuxTextSection""ull;" >> "$source_file"
echo "#define paddrVmlinuxTextSection $paddrVmlinuxTextSection""ull " >> "$source_file"

echo "const u64 vaddrVmlinuxTextSection=$vaddrVmlinuxTextSection""ull;" >> "$source_file"
echo "#define vaddrVmlinuxTextSection $vaddrVmlinuxTextSection""ull " >> "$source_file"


echo "const u64 paddrVmlinuxDataSection=$paddrVmlinuxDataSection""ull;" >> "$source_file"
echo "#define paddrVmlinuxDataSection $paddrVmlinuxDataSection""ull " >> "$source_file"


echo "const u64 vaddrVmlinuxDataSection=$vaddrVmlinuxDataSection""ull;" >> "$source_file"
echo "#define vaddrVmlinuxDataSection $vaddrVmlinuxDataSection""ull " >> "$source_file"


echo "const u64 paddrVmlinuxBssSection=$paddrVmlinuxBssSection""ull;" >> "$source_file"
echo "#define paddrVmlinuxBssSection $paddrVmlinuxBssSection""ull " >> "$source_file"


echo "const u64 vaddrVmlinuxBssSection=$vaddrVmlinuxBssSection""ull;" >> "$source_file"
echo "#define vaddrVmlinuxBssSection $vaddrVmlinuxBssSection""ull " >> "$source_file"


#For vmlinuz there is no SystemMap file and i do not now how to compile it 
#with debug info. The following offsets where obtained by manual analysis

#EDITME magic number
#NOTE: magic values already includes -offsetVmlinuzTextSection
#NOTE: in the config for sev-guests provided by amd CONFIG_RANDOIZE_BASE is not set and thus defaults
# to "no". Hence KASLR is not active in theese kernels anyway
paddr_choose_random_location=$((0x7A9010+ $paddrVmlinuzTextSection))

echo "const u64 paddr_choose_random_location=$paddr_choose_random_location""ull;" >> "$source_file";



#generate file with name and addresses of symbols from file in first argument

#symbols=$(nm $1)
# $1 should point to the System.map file of the target kernel
symbols=$(cat $1)


parse "${textSectionNames[@]}" vaddrVmlinuxTextSection paddrVmlinuxTextSection $source_file

parse "${dataSectionNames[@]}" vaddrVmlinuxDataSection paddrVmlinuxDataSection $source_file

parse "${bssSectionNames[@]}" vaddrVmlinuxBssSection paddrVmlinuxBssSection $source_file

