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
#include <linux/slab.h>
#include <asm/asm.h>
#include <asm/errno.h>
#include "macro.h"
#include "protovirt.h"

// guest vm stack size
#define GUEST_STACK_SIZE 				64
// code that will be run by guest
static void guest_code(void)
{
    asm volatile("cpuid");

}

// CH 23.6, Vol 3
// Checking the support of VMX
bool vmxSupport(void)
{

    int getVmxSupport, vmxBit;
    __asm__("mov $1, %rax");
    __asm__("cpuid");
    __asm__("mov %%ecx , %0\n\t":"=r" (getVmxSupport));
    vmxBit = (getVmxSupport >> 5) & 1;
    if (vmxBit == 1){
        return true;
    }
    else {
        return false;
    }
    return false;

}


// CH 24.2, Vol 3
// VMCS region
bool vmcsOperations(void) {
	long int vmcsPhyRegion = 0;
	if (allocVmcsRegion()){
		vmcsPhyRegion = __pa(vmcsRegion);
		*(uint32_t *)vmcsRegion = vmcs_revision_id();
	}
	else {
		return false;
	}

	//making the vmcs active and current
	if (_vmptrld(vmcsPhyRegion))
		return false;
	return true;
}
// CH 23.7, Vol 3
// Enter in VMX mode
bool getVmxOperation(void) {
    //unsigned long cr0;
	unsigned long cr4;
	unsigned long cr0;
    uint64_t feature_control;
	uint64_t required;
	long int vmxon_phy_region = 0;
	u32 low1 = 0;
    // setting CR4.VMXE[bit 13] = 1
    __asm__ __volatile__("mov %%cr4, %0" : "=r"(cr4) : : "memory");
    cr4 |= X86_CR4_VMXE;
    __asm__ __volatile__("mov %0, %%cr4" : : "r"(cr4) : "memory");

    /*
	 * Configure IA32_FEATURE_CONTROL MSR to allow VMXON:
	 *  Bit 0: Lock bit. If clear, VMXON causes a #GP.
	 *  Bit 2: Enables VMXON outside of SMX operation. If clear, VMXON
	 *    outside of SMX causes a #GP.
	 */
	required = FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;
	required |= FEATURE_CONTROL_LOCKED;
	feature_control = __rdmsr1(MSR_IA32_FEATURE_CONTROL);
	printk(KERN_INFO "RDMS output is %ld", (long)feature_control);

	if ((feature_control & required) != required) {
		wrmsr(MSR_IA32_FEATURE_CONTROL, feature_control | required, low1);
	}

	/*
	 * Ensure bits in CR0 and CR4 are valid in VMX operation:
	 * - Bit X is 1 in _FIXED0: bit X is fixed to 1 in CRx.
	 * - Bit X is 0 in _FIXED1: bit X is fixed to 0 in CRx.
	 */
	__asm__ __volatile__("mov %%cr0, %0" : "=r"(cr0) : : "memory");
	cr0 &= __rdmsr1(MSR_IA32_VMX_CR0_FIXED1);
	cr0 |= __rdmsr1(MSR_IA32_VMX_CR0_FIXED0);
	__asm__ __volatile__("mov %0, %%cr0" : : "r"(cr0) : "memory");

	__asm__ __volatile__("mov %%cr4, %0" : "=r"(cr4) : : "memory");
	cr4 &= __rdmsr1(MSR_IA32_VMX_CR4_FIXED1);
	cr4 |= __rdmsr1(MSR_IA32_VMX_CR4_FIXED0);
	__asm__ __volatile__("mov %0, %%cr4" : : "r"(cr4) : "memory");

	// allocating 4kib((4096 bytes) of memory for vmxon region
	vmxonRegion = kzalloc(MYPAGE_SIZE,GFP_KERNEL);
   	if(vmxonRegion==NULL){
		printk(KERN_INFO "Error allocating vmxon region\n");
      	return false;
   	}
	vmxon_phy_region = __pa(vmxonRegion);
	*(uint32_t *)vmxonRegion = vmcs_revision_id();
	if (_vmxon(vmxon_phy_region))
		return false;
	return true;
}


// CH 26.2.1, Vol 3
// Initializing VMCS control field
bool initVmcsControlField(void) {
	// checking of any of the default1 controls may be 0:
	//not doing it for now.

	// CH A.3.1, Vol 3
	// setting pin based controls, proc based controls, vm exit controls
	// and vm entry controls

	uint32_t pinbased_control0 = __rdmsr1(MSR_IA32_VMX_PINBASED_CTLS);
	uint32_t pinbased_control1 = __rdmsr1(MSR_IA32_VMX_PINBASED_CTLS) >> 32;
	uint32_t procbased_control0 = __rdmsr1(MSR_IA32_VMX_PROCBASED_CTLS);
	uint32_t procbased_control1 = __rdmsr1(MSR_IA32_VMX_PROCBASED_CTLS) >> 32;
	uint32_t procbased_secondary_control0 = __rdmsr1(MSR_IA32_VMX_PROCBASED_CTLS2);
	uint32_t procbased_secondary_control1 = __rdmsr1(MSR_IA32_VMX_PROCBASED_CTLS2) >> 32;
	uint32_t vm_exit_control0 = __rdmsr1(MSR_IA32_VMX_EXIT_CTLS);
	uint32_t vm_exit_control1 = __rdmsr1(MSR_IA32_VMX_EXIT_CTLS) >> 32;
	uint32_t vm_entry_control0 = __rdmsr1(MSR_IA32_VMX_ENTRY_CTLS);
	uint32_t vm_entry_control1 = __rdmsr1(MSR_IA32_VMX_ENTRY_CTLS) >> 32;


	// setting final value to write to control fields
	uint32_t pinbased_control_final = (pinbased_control0 & pinbased_control1);
	uint32_t procbased_control_final = (procbased_control0 & procbased_control1);
	uint32_t procbased_secondary_control_final = (procbased_secondary_control0 & procbased_secondary_control1);
	uint32_t vm_exit_control_final = (vm_exit_control0 & vm_exit_control1);
	uint32_t vm_entry_control_final = (vm_entry_control0 & vm_entry_control1);

	/* CH 24.7.1, Vol 3
	// for supporting 64 bit host
	//uint32_t host_address_space = 1 << 9;
	vm_exit_control_final = vm_exit_control_final | host_address_space;
	*/
	/* To enable secondary controls
	// procbased_control_final = procbased_control_final | ACTIVATE_SECONDARY_CONTROLS;
	*/
	/* for enabling unrestricted guest mode
	uint64_t unrestricted_guest = 1 << 7;
	// for enabling ept
	uint64_t enabling_ept = 1 << 1;
	//uint32_t procbased_secondary_control_final = procbased_secondary_control_final | unrestricted_guest | enabling_ept;
	*/

	// writing the value to control field*/
	vmwrite(PIN_BASED_VM_EXEC_CONTROLS, pinbased_control_final);
	vmwrite(PROC_BASED_VM_EXEC_CONTROLS, procbased_control_final);
	vmwrite(PROC2_BASED_VM_EXEC_CONTROLS, procbased_secondary_control_final);
	vmwrite(VM_EXIT_CONTROLS, vm_exit_control_final);
	vmwrite(VM_ENTRY_CONTROLS, vm_entry_control_final);
	// to ignore the guest exception
	// maybe optional
	vmwrite(EXCEPTION_BITMAP, 0);

	vmwrite(VIRTUAL_PROCESSOR_ID, 0);

	vmwrite(VM_EXIT_CONTROLS, __rdmsr1(MSR_IA32_VMX_EXIT_CTLS) |
		VM_EXIT_HOST_ADDR_SPACE_SIZE);	  /* 64-bit host */
	vmwrite(VM_ENTRY_CONTROLS, __rdmsr1(MSR_IA32_VMX_ENTRY_CTLS) |
		VM_ENTRY_IA32E_MODE);		  /* 64-bit guest */


	// CH 26.2.2, Vol 3
	// Checks on Host Control Registers and MSRs
	vmwrite(HOST_CR0, get_cr0());
	vmwrite(HOST_CR3, get_cr3());
	vmwrite(HOST_CR4, get_cr4());

	//setting host selectors fields
	vmwrite(HOST_ES_SELECTOR, get_es1());
	vmwrite(HOST_CS_SELECTOR, get_cs1());
	vmwrite(HOST_SS_SELECTOR, get_ss1());
	vmwrite(HOST_DS_SELECTOR, get_ds1());
	vmwrite(HOST_FS_SELECTOR, get_fs1());
	vmwrite(HOST_GS_SELECTOR, get_gs1());
	vmwrite(HOST_TR_SELECTOR, get_tr1());
	vmwrite(HOST_FS_BASE, __rdmsr1(MSR_FS_BASE));
	vmwrite(HOST_GS_BASE, __rdmsr1(MSR_GS_BASE));
	vmwrite(HOST_TR_BASE, get_desc64_base((struct desc64 *)(get_gdt_base1() + get_tr1())));
	vmwrite(HOST_GDTR_BASE, get_gdt_base1());
	vmwrite(HOST_IDTR_BASE, get_idt_base1());
	vmwrite(HOST_IA32_SYSENTER_ESP, __rdmsr1(MSR_IA32_SYSENTER_ESP));
	vmwrite(HOST_IA32_SYSENTER_EIP, __rdmsr1(MSR_IA32_SYSENTER_EIP));
	vmwrite(HOST_IA32_SYSENTER_CS, __rdmsr(MSR_IA32_SYSENTER_CS));



	// CH 26.3, Vol 3
	// setting the guest control area
	vmwrite(GUEST_ES_SELECTOR, vmreadz(HOST_ES_SELECTOR));
	vmwrite(GUEST_CS_SELECTOR, vmreadz(HOST_CS_SELECTOR));
	vmwrite(GUEST_SS_SELECTOR, vmreadz(HOST_SS_SELECTOR));
	vmwrite(GUEST_DS_SELECTOR, vmreadz(HOST_DS_SELECTOR));
	vmwrite(GUEST_FS_SELECTOR, vmreadz(HOST_FS_SELECTOR));
	vmwrite(GUEST_GS_SELECTOR, vmreadz(HOST_GS_SELECTOR));
	vmwrite(GUEST_LDTR_SELECTOR, 0);
	vmwrite(GUEST_TR_SELECTOR, vmreadz(HOST_TR_SELECTOR));
	vmwrite(GUEST_INTR_STATUS, 0);
	vmwrite(GUEST_PML_INDEX, 0);

	vmwrite(VMCS_LINK_POINTER, -1ll);
	vmwrite(GUEST_IA32_DEBUGCTL, 0);
	vmwrite(GUEST_IA32_PAT, vmreadz(HOST_IA32_PAT));
	vmwrite(GUEST_IA32_EFER, vmreadz(HOST_IA32_EFER));
	vmwrite(GUEST_IA32_PERF_GLOBAL_CTRL,
		vmreadz(HOST_IA32_PERF_GLOBAL_CTRL));

	vmwrite(GUEST_ES_LIMIT, -1);
	vmwrite(GUEST_CS_LIMIT, -1);
	vmwrite(GUEST_SS_LIMIT, -1);
	vmwrite(GUEST_DS_LIMIT, -1);
	vmwrite(GUEST_FS_LIMIT, -1);
	vmwrite(GUEST_GS_LIMIT, -1);
	vmwrite(GUEST_LDTR_LIMIT, -1);
	vmwrite(GUEST_TR_LIMIT, 0x67);
	vmwrite(GUEST_GDTR_LIMIT, 0xffff);
	vmwrite(GUEST_IDTR_LIMIT, 0xffff);
	vmwrite(GUEST_ES_AR_BYTES,
		vmreadz(GUEST_ES_SELECTOR) == 0 ? 0x10000 : 0xc093);
	vmwrite(GUEST_CS_AR_BYTES, 0xa09b);
	vmwrite(GUEST_SS_AR_BYTES, 0xc093);
	vmwrite(GUEST_DS_AR_BYTES,
		vmreadz(GUEST_DS_SELECTOR) == 0 ? 0x10000 : 0xc093);
	vmwrite(GUEST_FS_AR_BYTES,
		vmreadz(GUEST_FS_SELECTOR) == 0 ? 0x10000 : 0xc093);
	vmwrite(GUEST_GS_AR_BYTES,
		vmreadz(GUEST_GS_SELECTOR) == 0 ? 0x10000 : 0xc093);
	vmwrite(GUEST_LDTR_AR_BYTES, 0x10000);
	vmwrite(GUEST_TR_AR_BYTES, 0x8b);
	vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmwrite(GUEST_ACTIVITY_STATE, 0);
	vmwrite(GUEST_SYSENTER_CS, vmreadz(HOST_IA32_SYSENTER_CS));
	vmwrite(VMX_PREEMPTION_TIMER_VALUE, 0);

	vmwrite(GUEST_CR0, vmreadz(HOST_CR0));
	vmwrite(GUEST_CR3, vmreadz(HOST_CR3));
	vmwrite(GUEST_CR4, vmreadz(HOST_CR4));
	vmwrite(GUEST_ES_BASE, 0);
	vmwrite(GUEST_CS_BASE, 0);
	vmwrite(GUEST_SS_BASE, 0);
	vmwrite(GUEST_DS_BASE, 0);
	vmwrite(GUEST_FS_BASE, vmreadz(HOST_FS_BASE));
	vmwrite(GUEST_GS_BASE, vmreadz(HOST_GS_BASE));
	vmwrite(GUEST_LDTR_BASE, 0);
	vmwrite(GUEST_TR_BASE, vmreadz(HOST_TR_BASE));
	vmwrite(GUEST_GDTR_BASE, vmreadz(HOST_GDTR_BASE));
	vmwrite(GUEST_IDTR_BASE, vmreadz(HOST_IDTR_BASE));
	vmwrite(GUEST_RFLAGS, 2);
	vmwrite(GUEST_SYSENTER_ESP, vmreadz(HOST_IA32_SYSENTER_ESP));
	vmwrite(GUEST_SYSENTER_EIP, vmreadz(HOST_IA32_SYSENTER_EIP));
	// setting up rip and rsp for guest
	void *costum_rip;
	void *costum_rsp;

	unsigned long guest_stack[GUEST_STACK_SIZE];
	costum_rsp = &guest_stack[GUEST_STACK_SIZE];
	costum_rip = guest_code;
	vmwrite(GUEST_RSP, (uint64_t)costum_rsp);
	vmwrite(GUEST_RIP, (uint64_t)costum_rip);

	return true;
}

bool initVmLaunchProcess(void){
	int vmlaunch_status = _vmlaunch();
	printk(KERN_INFO "VMLAUNCH status is %lu!\n", (unsigned long)vmlaunch_status);
	printk(KERN_INFO "Vm exit reason is-> %lu!\n", (unsigned long)vmExit_reason());
	return true;
}
bool vmxoffOperation(void)
{
	if (deallocate_vmxon_region()) {
		printk(KERN_INFO "Successfully freed allocated vmxon region!\n");
	}
	else {
		printk(KERN_INFO "Error freeing allocated vmxon region!\n");
	}
	if (deallocate_vmcs_region()) {
		printk(KERN_INFO "Successfully freed allocated vmcs region!\n");
	}
	else {
		printk(KERN_INFO "Error freeing allocated vmcs region!\n");
	}
	asm volatile ("vmxoff\n" : : : "cc");
	return true;
}

int __init start_init(void)
{
    if (!vmxSupport()){
		printk(KERN_INFO "VMX support not present! EXITING");
		return 0;
	}
	else {
		printk(KERN_INFO "VMX support present! CONTINUING");
	}
	if (!getVmxOperation()) {
		printk(KERN_INFO "VMX Operation failed! EXITING");
		return 0;
	}
	else {
		printk(KERN_INFO "VMX Operation succeeded! CONTINUING");
	}
	if (!vmcsOperations()) {
		printk(KERN_INFO "VMCS Operation failed! EXITING");
		return 0;
	}
	else {
		printk(KERN_INFO "VMX Operation succeeded! CONTINUING");
	}
	if (!initVmcsControlField()) {
		printk(KERN_INFO "Initialization of VMCS Control field failed! EXITING");
		return 0;
	}
	else {
		printk(KERN_INFO "Initializing of control fields to the most basic settings succeeded! CONTINUING");
	}
	if (!initVmLaunchProcess()) {
		printk(KERN_INFO "VMLAUNCH failed! EXITING");
		return 0;
	}
	else {
		printk(KERN_INFO "VMLAUNCH succeeded! CONTINUING");
	}
	if (!vmxoffOperation()) {
		printk(KERN_INFO "VMXOFF operation failed! EXITING");
		return 0;
	}
	else {
		printk(KERN_INFO "VMXOFF Operation succeeded! CONTINUING");
	}
    return 0;
}

static void __exit end_exit(void)
{
    printk(KERN_INFO "Bye Bye\n");
}

module_init(start_init);
module_exit(end_exit);


MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Shubham Dubey");
MODULE_DESCRIPTION("ProtoVirt- A Lightweight Hypervisior ");
