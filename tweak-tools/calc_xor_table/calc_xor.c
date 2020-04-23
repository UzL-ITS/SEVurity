#include <linux/init.h>
#include <linux/module.h>
//#include <linux/gfp.h>
//#include <linux/fs.h>
//#include <linux/device.h>
#include <linux/miscdevice.h>
//#include <linux/uaccess.h>
//#include <linux/io.h>
//#include <linux/mm.h>
//#include <asm/pgtable.h>
//#include <asm/io.h>
//#include <asm/irqflags.h>
//#include <linux/slab.h>
//#include <linux/jiffies.h>
#include <asm/cacheflush.h>
//#include <asm/tlbflush.h>
//#include <linux/timex.h>
//#include <asm/set_memory.h>
//#include <asm/page.h>
//#include <linux/vmalloc.h>
//#include "check_enc.h"

MODULE_LICENSE("GPL v2");

#define DRIVERNAME "calc_xor"

char* enc_buffer;
char* clear_buffer;
static unsigned int size=0;
module_param(size, int, 0);
MODULE_PARM_DESC(size, "RAM Size in GB saved as unsigned int"); 

ssize_t check_write(struct file* f,const char __user* buf,size_t size,loff_t* off) {

    printk("I am not to be used");
    return 0;
}


static const struct file_operations check_fops = {
    .write = &check_write,
};


static struct miscdevice check_misc = {
    MISC_DYNAMIC_MINOR,
    "calc_xor",
    &check_fops,
};
/*
* enc and noenc are Pointer to memory allocated by this module 
* and are to be read and written.
* enc2 and noenc2 are only read and are the addresses eith only one offset bit set.
*/
static int calc_entry_page(void* enc, void* noenc, void* enc2, void* noenc2, unsigned long* table_entry){
    printk("Switch encrypted views \n");
    ((unsigned long*)noenc)[0]=((unsigned long*)noenc2)[0];
    ((unsigned long*)noenc)[1]=((unsigned long*)noenc2)[1];
	//cipher1=((unsigned long*)enc)[0]^((unsigned long*)enc)[i];
	//cipher2=((unsigned long*)enc)[1]^((unsigned long*)enc)[i+1];
	
    //printk("%lx",((unsigned long*)enc)[0]);
    *table_entry=((unsigned long*)enc)[0];
    //printk("%lx",((unsigned long*)enc)[1]);
//	printk("XOR-Cipher: ");
//	printk("%lx%lx",((unsigned long*)noenc)[0]^((unsigned long*)noenc)[i],((unsigned long*)noenc)[1]^((unsigned long*)noenc)[i+1]);
/*
    // This step is not necessary. The idea was to switch back the cipher texts
    // right now zeros are written into to get the old state of the contet as
    // written in the main function again, but this is unnecessary for the 
    // calculation
    ((unsigned long*)enc)[0]=0x0;
    ((unsigned long*)enc)[1]=0x0;
*/  
  return 0;
}
/*
* enc and noenc to be read and written. enc2 and noenc2 only read.
* enc and noenc are allocated by this kernel module.
* enc2 and noenc2 are related to any memory which physical address has
* table_entry is the to be calculated entry 
* only one bit set
*/
static int calc_entry(unsigned long * enc, unsigned long * noenc, unsigned long* m1, void* noenc1, unsigned long* m2, void* noenc2, unsigned long* table_entry, unsigned long s){
     printk("Write encryption in own page\n"); 
    
    ((unsigned long*)noenc)[0]=((unsigned long*)noenc1)[0];
    ((unsigned long*)noenc)[1]=((unsigned long*)noenc1)[1];
    ((unsigned long*)noenc)[2]=((unsigned long*)noenc2)[0];
    ((unsigned long*)noenc)[3]=((unsigned long*)noenc2)[1];
    *table_entry= enc[0] ^ enc[2] ^ s ^ m1[0] ^ m2[0];
    
    return 0;
}   

static int __init calc_xor_init(void) {
    int i; // Loop-variable
    int m; // Table-entry counter
    size = (__builtin_clz(size)-32)*(-1)+30; // maximum addressable bit
    struct page* page_1; // to be allocated
    struct page* page_2; // remaped with pfn_to_page
    struct page* page_3; // remaped with pfn_to_page
    void* enc; // C-bit set so encrypting component active, pointer to page1
    void* noenc; // C-bit unset encrypting compnent (Secure Processor) inactive
    void* enc2; // C-bit set
    void* noenc2; //C-bit unset
    void* enc3; //C-bit set
    void* noenc3; //C-bit unset
    /* 
    * to be calculated XOR-table.
    * as the XOR-table entries are repetitions of integers
    * it is stored as unsigned long instead of 128bit
    */ 
    unsigned long XOR_table[48]={0}; 
    

    printk(KERN_INFO "%s: Module started\n", DRIVERNAME);
    // allocation of one page
    page_1 = alloc_page(GFP_KERNEL); 
    // create pointer with and without set C-bit to allocated page   
    enc = vmap(&page_1,1,0,PAGE_KERNEL_NOCACHE);
    noenc = vmap(&page_1,1,0,__pgprot(__PAGE_KERNEL_NOCACHE)); 

    // print encrypted and decrypted view to check if encryption is working
    // and active
    printk("Allocated 1 page at 0x%016lx.", page_to_pfn(page_1));
    // This mapping does not contain the 
    // "_PAGE_ENC" flag. See: "arch/x86/include/pgtable_types.h"
    printk("Writing first 128bit Block, offset 0x000:");
    ((unsigned long*)enc)[0] = 0x0;
    ((unsigned long*)enc)[1] = 0x0;
    printk("Reading from first Block: ");
    printk("%lx",((unsigned long*)enc)[0]);
    printk("%lx",((unsigned long*)enc)[1]);
    printk("Encrypted view: ");
    printk("%lx",((unsigned long*)noenc)[0]);
    printk("%lx",((unsigned long*)noenc)[1]);
    printk("\n");

    // Start with the calculation. m=4 because of 128bit AES so the last 4 bit
    // are always 0. no Table-entries are used for these
    m=4;
    // as address bits have to be set for the XOR-table entries to be computed
    // on the cipher, skip the first address where no offset-bit is set and
    // start with 1 wher only the last bit is set.
    i=1;
    // Calculation of XOR-table entries 4-11 via the allocated page as explained
    // in the documentation
    for(i = 1; i <= 128; i= i*2){
        printk("--------------------- RUN i=%x ENTRY: %d  --------------------------",i, m); 
	// noenc Pointer to table offset with only one set offset-bit
	noenc2=((unsigned long*)noenc)+i*2; 
	// enc Pointer to table offset with only one set offset-bit
	enc2=((unsigned long*)enc)+i*2;
	/*
	* Write to be encrypted 0s. 
	* Always write 128bit blockwise, especially with the ciphers
	* else the decrypted view will be distorted
	*/   
	((unsigned long*)enc2)[0] = 0x0;
	((unsigned long*)enc2)[1] = 0x0;
	// call the function calculating the XOR-table entry
	calc_entry_page(enc, noenc, enc2, noenc2,&XOR_table[m]);
	// print the new calculated entry
	printk("XOR-table-entry[%d]:0x%016lx\n",m,XOR_table[m]);
	// increase the XOR-Table entry counter
	m++;
    }
    //----------------------the remaining XOR-Table-Entries-------------------
    printk("*************Starting with remaining XOR-Table-Entries:**************\n");
    /* 
    * reset the loop variable i to zero.
    * not to 1 because i is only used as shift operand for the addresses 
    * 0x10 and 0x11
    */
    i=0;
    /*
    * size is our maximum addrassable bit.
    * As we shift PageFrameNumbers instead of addresses the maximum 
    * addressable bit of the PFN is size-12 because the offset has 12bit.
    * As the shifted PFNs already have 2 bit they can only be shifted 2 less bit
    * resulting in size-12-2=size-14 as maximum for i.
    */
    for(i=0; i < size-14; i++){
	// Shift second PFN resulting in 0x10, 0x100, 0x1000 ...
	printk("Page2_PFN:%lx\n", 2ul<<i);
	page_2 = pfn_to_page(2ul << i);
	// Shift third PFN resulting in 0x11, 0x110, 0x1100 ...
	printk("Page3_PFN:%lx\n", 3ul<<i);
	page_3 = pfn_to_page(3ull << i);	
	/*
	*  Note: pfn2 ^ pfn3 = 1ul << i; 
	*  Therefore, the calculated XOR-table entry is the one
	*  of the physical address: 0x1000 << i;
	*/

	// Pointer mappings to the remapped pages
	enc2 = vmap(&page_2,1,0,PAGE_KERNEL_NOCACHE);
	noenc2 = vmap(&page_2,1,0,__pgprot(__PAGE_KERNEL_NOCACHE));
	enc3 = vmap(&page_3,1,0,PAGE_KERNEL_NOCACHE);
	noenc3 = vmap(&page_3,1,0,__pgprot(__PAGE_KERNEL_NOCACHE));
	
	/*
	* The pages remaped through their PFN have to be encrypted
	* Otherwise the calculation will not work.
	*/
	calc_entry((unsigned long*)enc,(unsigned long*)noenc,(unsigned long*)enc2,noenc2,(unsigned long*) enc3, noenc3,&XOR_table[m],XOR_table[4]);
	if(((int *)XOR_table)[m*2] == ((int*)XOR_table)[m*2+1]){
	    printk("XOR-table-entry[%d]:0x%016lx \n",m,XOR_table[m]);
	    m++;
	    continue;
	}

	// print error-message if no valid entry was found. Pages may have been
	// unencrypted. As countermeassure one could safe the current content
	// of this address write encrypted zeros in it. Try the calculation again
	// and write the earlier content back. At best with the address access 
	// locked for other process'
	printk("************ERROR NO valid XOR-Table-Entry found********\n");
	XOR_table[m]=0x0000efbeadde0000;
	m++;
    }
    /*
    * to calculate the last entry we use 0x01 and 0x11 to get 0x10
    */ 
    printk("Page2_PFN:%lx\n", 1ul<<18);
    page_2 = pfn_to_page(1ul << i);
    printk("Page3_PFN:%lx\n", 3ul<<18);
    page_3 = pfn_to_page(3ul << i);	
    enc2 = vmap(&page_2,1,0,PAGE_KERNEL_NOCACHE);
    noenc2 = vmap(&page_2,1,0,__pgprot(__PAGE_KERNEL_NOCACHE));
    enc3 = vmap(&page_3,1,0,PAGE_KERNEL_NOCACHE);
    noenc3 = vmap(&page_3,1,0,__pgprot(__PAGE_KERNEL_NOCACHE));
	
    /*
    * Same problem as above. When the pages are not encrypted the whole
    * procedure will not work.
    * For some reason we don't know the calculation for the 31th bit always fails
    * The people from Luebeck have the same problem and also do not know why.
    */ 
    calc_entry((unsigned long*)enc,(unsigned long*)noenc,(unsigned long*)enc2,noenc2,(unsigned long*) enc3, noenc3,&XOR_table[m],XOR_table[4]);
    if(((int *)XOR_table)[m*2] == ((int*)XOR_table)[m*2+1]){
        printk("XOR-table-entry[%d]:0x%016lx\n",m,XOR_table[m]);
    }
    // print error-message if no valid entry was found. Pages may have been
    // unencrypted. As countermeassure one could safe the current content
    // of this address write encrypted zeros in it. Try the calculation again
    // and write the earlier content back. At best with the address access locked
    // for other process'
    printk("****************ERROR NO valid XOR-Table-Entry found********\n");
    XOR_table[m]=0x0000efbeadde0000;
    m++;   
    printk("***************XOR-Table-Entries in Byte Order**************\n"); 
    //Printing whole table in Byte Order
    for(i=0; i < m; i++){
	printk("XOR-Table-Entry[%02d]: %02x %02x %02x %02x %02x %02x %02x %02x\n",i, ((unsigned char*)XOR_table)[i*8 + 0],((unsigned char*)XOR_table)[i*8 + 1],((unsigned char*)XOR_table)[i*8 + 2],((unsigned char*)XOR_table)[i*8 + 3],((unsigned char*)XOR_table)[i*8 + 4],((unsigned char*)XOR_table)[i*8 + 5],((unsigned char*)XOR_table)[i*8 + 6], ((unsigned char*)XOR_table)[i*8 + 7]) ;
    }
    
    // This is important for the module to exit the right way. If this is missing
    // your module will crash befor returning and you will not be able to
    // unload it ($ rmmod). To unload it, you will then need to restart your
    // system.
    if(misc_register(&check_misc)) {
        return -ENODEV;
    }
    return 0;
}

static void __exit calc_xor_exit(void) {
    misc_deregister(&check_misc);

    printk(KERN_INFO "%s: Module stopped", DRIVERNAME);
    printk("\n");
}

MODULE_LICENSE("GPL v2");
module_init(calc_xor_init);
module_exit(calc_xor_exit);
