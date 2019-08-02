#include <linux/init.h>
#include <linux/module.h>
#include <linux/const.h>
#include <linux/errno.h>
#include <linux/fs.h>   /* Needed for KERN_INFO */
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/smp.h>
#include <linux/major.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/uaccess.h>
#include <linux/gfp.h>

#define X86_CR4_VMXE_BIT	13 /* enable VMX virtualization */
#define X86_CR4_VMXE		_BITUL(X86_CR4_VMXE_BIT)
#define FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX	(1<<2)
#define FEATURE_CONTROL_LOCKED				(1<<0)
#define MSR_IA32_FEATURE_CONTROL        0x0000003a
// CH 23.7, Vol 3
// Enter in VMX mode
int getVmxOperation(void) {
    //unsigned long cr0;
	unsigned long cr4;
    uint64_t feature_control;
	uint64_t required;

    // setting CR4.VMXE[bit 13] = 1
    __asm__ __volatile__("mov %%cr4, %0" : "=r"(cr4) : : "memory");
    cr4 |= X86_CR4_VMXE;
    __asm__ __volatile__("mov %0, %%cr4" : : "r"(cr4) : "memory");
    return 1;

    /*
	 * Configure IA32_FEATURE_CONTROL MSR to allow VMXON:
	 *  Bit 0: Lock bit. If clear, VMXON causes a #GP.
	 *  Bit 2: Enables VMXON outside of SMX operation. If clear, VMXON
	 *    outside of SMX causes a #GP.
	 */
	required = FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;
	required |= FEATURE_CONTROL_LOCKED;
	feature_control = rdmsr(MSR_IA32_FEATURE_CONTROL);
	if ((feature_control & required) != required)
		wrmsr(MSR_IA32_FEATURE_CONTROL, feature_control | required);
}

// CH 23.6, Vol 3
// Checking the support of VMX
int vmxSupport(void)
{

    int getVmxSupport, vmxBit;
    __asm__("mov $1, %rax");
    __asm__("cpuid");
    __asm__("mov %%ecx , %0\n\t":"=r" (getVmxSupport));
    vmxBit = (getVmxSupport >> 5) & 1;
    if (vmxBit == 1){
        return 1;
    }
    else {
        return 0;
    }
    return 0;

}

int __init start_init(void)
{
    int vmxSupportPresent;

    if (vmxSupport()){
        getVmxOperation();
    }
    else {
        printk(KERN_INFO "VMX support not present\n");
    }
    return 0;
}

static void __exit end_exit(void)
{
    printk(KERN_INFO "Bye Bye\n");
}







module_init(start_init);
module_exit(end_exit);
