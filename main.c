#include <linux/init.h>
#include <linux/module.h>

// Checking the support of VMX
int vmxSupport(void)
{

    int getVmxSupport, vmxBit;
    __asm__("mov $1, %rax");
    __asm__("cpuid");
    __asm__("mov %%ecx , %0\n\t":"=r" (getVmxSupport));
    vmxBit = (getVmxSupport >> 5) & 1;
    if (vmxBit == 1){
        printk(KERN_INFO "VMX support is present");
    }
    else {
        printk(KERN_INFO "VMX support is absent");
    }
    return 0;

}

int __init start_init(void)
{
    vmxSupport();
    return 0;
}

static void __exit end_exit(void)
{
    printk(KERN_INFO "Bye Bye\n");
}







module_init(start_init);
module_exit(end_exit);
