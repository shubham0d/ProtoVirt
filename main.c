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
#include <linux/kvm.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <asm/asm.h>
#include <asm/errno.h>
#include <asm/kvm.h>
#include <asm/cpumask.h>
#include <asm/processor.h>

#define MYPAGE_SIZE 4096
#define X86_CR4_VMXE_BIT	13 /* enable VMX virtualization */
#define X86_CR4_VMXE		_BITUL(X86_CR4_VMXE_BIT)
#define FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX	(1<<2)
#define FEATURE_CONTROL_LOCKED				(1<<0)
#define MSR_IA32_FEATURE_CONTROL        0x0000003a
#define MSR_IA32_VMX_BASIC              0x00000480

// for vmcs control field
#define MSR_IA32_VMX_PINBASED_CTLS		0x00000481
#define MSR_IA32_VMX_PROCBASED_CTLS		0x00000482
#define MSR_IA32_VMX_PROCBASED_CTLS2	0x0000048b
#define MSR_IA32_VMX_EXIT_CTLS			0x00000483
#define MSR_IA32_VMX_ENTRY_CTLS			0x00000484
// CH B.3.1
// Table B-8. Encodings for 32-Bit Control Fields
#define PIN_BASED_VM_EXEC_CONTROLS		0x00004000
#define PROC_BASED_VM_EXEC_CONTROLS		0x00004002
#define PROC2_BASED_VM_EXEC_CONTROLS	0x0000401e
#define VM_EXIT_CONTROLS				0x0000400c
#define VM_ENTRY_CONTROLS				0x00004012
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS	0x80000000
#define VIRTUAL_PROCESSOR_ID			0x00000000
#define POSTED_INTR_NV					0x00000002
#define PAGE_FAULT_ERROR_CODE_MASK		0x00004006
#define PAGE_FAULT_ERROR_CODE_MATCH		0x00004008
#define CR3_TARGET_COUNT				0x0000400a
#define VM_EXIT_HOST_ADDR_SPACE_SIZE	0x00000200
#define VM_EXIT_MSR_STORE_COUNT			0x0000400e
#define VM_EXIT_MSR_LOAD_COUNT			0x00004010
#define TPR_THRESHOLD					0x0000401c
#define VM_ENTRY_MSR_LOAD_COUNT			0x00004014
#define VM_ENTRY_INTR_INFO_FIELD		0x00004016
#define CR0_GUEST_HOST_MASK				0x00006000
#define CR4_GUEST_HOST_MASK				0x00006002
#define CR0_READ_SHADOW					0x00006004
#define CR4_READ_SHADOW					0x00006006
#define VM_ENTRY_IA32E_MODE				0x00000200


#define EXCEPTION_BITMAP				0x00004004
// CH B.2.1
// Table B-4. Encodings for 64-Bit Control Fields
#define EPT_POINTER						0x0000201a



// for checks on host control registers
#define HOST_CR0						0x00006c00
#define	HOST_CR3						0x00006c02
#define	HOST_CR4						0x00006c04
// CH B.1.3, Vol 3
#define HOST_ES_SELECTOR				0x00000c00
#define HOST_CS_SELECTOR				0x00000c02
#define HOST_SS_SELECTOR				0x00000c04
#define HOST_DS_SELECTOR				0x00000c06
#define HOST_FS_SELECTOR				0x00000c08
#define HOST_GS_SELECTOR				0x00000c0a
#define HOST_TR_SELECTOR				0x00000c0c
#define HOST_FS_BASE					0x00006c06
#define HOST_GS_BASE					0x00006c08
#define HOST_TR_BASE					0x00006c0a
#define HOST_GDTR_BASE					0x00006c0c
#define HOST_IDTR_BASE					0x00006c0e
#define HOST_IA32_SYSENTER_ESP			0x00006c10
#define HOST_IA32_SYSENTER_EIP			0x00006c12
#define HOST_IA32_SYSENTER_CS			0x00004c00
#define HOST_RSP						0x00006c14
#define	HOST_RIP						0x00006c16
#define VM_EXIT_LOAD_IA32_PAT			0x00080000
#define VM_EXIT_LOAD_IA32_EFER			0x00200000
#define VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL	0x00001000
#define MSR_IA32_CR_PAT					0x00000277
#define MSR_EFER						0xc0000080
#define MSR_CORE_PERF_GLOBAL_CTRL		0x0000038f
#define HOST_IA32_PAT					0x00002c00
#define HOST_IA32_EFER					0x00002c02
#define HOST_IA32_PERF_GLOBAL_CTRL		0x00002c04

// for Initializing guest control area
// CH B.1.2, Vol 3
#define GUEST_ES_SELECTOR				0x00000800
#define GUEST_CS_SELECTOR				0x00000802
#define GUEST_SS_SELECTOR				0x00000804
#define GUEST_DS_SELECTOR				0x00000806
#define GUEST_FS_SELECTOR				0x00000808
#define GUEST_GS_SELECTOR				0x0000080a
#define GUEST_LDTR_SELECTOR				0x0000080c
#define GUEST_TR_SELECTOR				0x0000080e
// CH B.1.3, Vol 3
#define GUEST_IA32_DEBUGCTL				0x00002802
#define GUEST_IA32_PAT					0x00002804
#define GUEST_IA32_EFER					0x00002806
#define GUEST_IA32_PERF_GLOBAL_CTRL		0x00002808
// CH B.3.3, Vol 3
#define GUEST_ES_LIMIT					0x00004800
#define GUEST_CS_LIMIT					0x00004802
#define GUEST_SS_LIMIT					0x00004804
#define GUEST_DS_LIMIT					0x00004806
#define GUEST_FS_LIMIT					0x00004808
#define GUEST_GS_LIMIT					0x0000480a
#define GUEST_LDTR_LIMIT				0x0000480c
#define GUEST_TR_LIMIT					0x0000480e
#define GUEST_GDTR_LIMIT				0x00004810
#define GUEST_IDTR_LIMIT				0x00004812
#define GUEST_ES_AR_BYTES				0x00004814
#define GUEST_CS_AR_BYTES				0x00004816
#define GUEST_SS_AR_BYTES				0x00004818
#define GUEST_DS_AR_BYTES				0x0000481a
#define GUEST_FS_AR_BYTES				0x0000481c
#define GUEST_GS_AR_BYTES				0x0000481e
#define GUEST_LDTR_AR_BYTES				0x00004820
#define GUEST_TR_AR_BYTES				0x00004822
// CH B.4.3, Vol 3
#define GUEST_CR0						0x00006800
#define GUEST_CR3						0x00006802
#define GUEST_CR4						0x00006804
#define GUEST_ES_BASE					0x00006806
#define GUEST_CS_BASE					0x00006808
#define GUEST_SS_BASE					0x0000680a
#define GUEST_DS_BASE					0x0000680c
#define GUEST_FS_BASE					0x0000680e
#define GUEST_GS_BASE					0x00006810
#define GUEST_LDTR_BASE					0x00006812
#define GUEST_TR_BASE					0x00006814
#define GUEST_GDTR_BASE					0x00006816
#define GUEST_IDTR_BASE					0x00006818
#define GUEST_DR7						0x0000681a
#define	GUEST_RSP						0x0000681c
#define	GUEST_RIP						0x0000681e
#define	GUEST_RFLAGS					0x00006820
#define VMCS_LINK_POINTER				0x00002800
#define GUEST_INTR_STATUS				0x00000810
#define GUEST_PML_INDEX					0x00000812
#define GUEST_INTERRUPTIBILITY_INFO		0x00004824
#define GUEST_ACTIVITY_STATE			0X00004826
#define GUEST_SYSENTER_CS				0x0000482A
#define VMX_PREEMPTION_TIMER_VALUE		0x0000482E
#define GUEST_PENDING_DBG_EXCEPTIONS	0x00006822
#define GUEST_SYSENTER_ESP				0x00006824
#define GUEST_SYSENTER_EIP				0x00006826


#define GUEST_STACK_SIZE 				64

#define ACTIVATE_SECONDARY_CONTROLS		(1<<31)

#define MSR_IA32_VMX_CR0_FIXED0         0x00000486
#define MSR_IA32_VMX_CR0_FIXED1         0x00000487
#define MSR_IA32_VMX_CR4_FIXED0         0x00000488
#define MSR_IA32_VMX_CR4_FIXED1         0x00000489
#define MSR_IA32_SYSENTER_CS			0x00000174

#define VM_EXIT_REASON			 		0x00004402
#define VM_INSTRUCTION_ERROR			0x00004000  // CH 26.1, Vol 3
#define EAX_EDX_VAL(val, low, high)	((low) | (high) << 32)
#define EAX_EDX_RET(val, low, high)	"=a" (low), "=d" (high)


uint64_t *vmxonRegion = NULL;
uint64_t *vmcsRegion = NULL;



struct desc64 {
	uint16_t limit0;
	uint16_t base0;
	unsigned base1:8, s:1, type:4, dpl:2, p:1;
	unsigned limit1:4, avl:1, l:1, db:1, g:1, base2:8;
	uint32_t base3;
	uint32_t zero1;
} __attribute__((packed));

// CH 30.3, Vol 3
// VMXON instruction - Enter VMX operation
static inline int _vmxon(uint64_t phys)
{
	uint8_t ret;

	__asm__ __volatile__ ("vmxon %[pa]; setna %[ret]"
		: [ret]"=rm"(ret)
		: [pa]"m"(phys)
		: "cc", "memory");
	return ret;
}

// CH 24.11.2, Vol 3
static inline int vmread(uint64_t encoding, uint64_t *value)
{
	uint64_t tmp;
	uint8_t ret;
	/*
	if (enable_evmcs)
		return evmcs_vmread(encoding, value);
	*/
	__asm__ __volatile__("vmread %[encoding], %[value]; setna %[ret]"
		: [value]"=rm"(tmp), [ret]"=rm"(ret)
		: [encoding]"r"(encoding)
		: "cc", "memory");

	*value = tmp;
	return ret;
}

/*
 * A wrapper around vmread that ignores errors and returns zero if the
 * vmread instruction fails.
 */
static inline uint64_t vmreadz(uint64_t encoding)
{
	uint64_t value = 0;
	vmread(encoding, &value);
	return value;
}

static inline int vmwrite(uint64_t encoding, uint64_t value)
{
	uint8_t ret;
	__asm__ __volatile__ ("vmwrite %[value], %[encoding]; setna %[ret]"
		: [ret]"=rm"(ret)
		: [value]"rm"(value), [encoding]"r"(encoding)
		: "cc", "memory");

	return ret;
}

static inline int _vmlaunch(void)
{
	int ret;

	__asm__ __volatile__("push %%rbp;"
			     "push %%rcx;"
			     "push %%rdx;"
			     "push %%rsi;"
			     "push %%rdi;"
			     "push $0;"
			     "vmwrite %%rsp, %[host_rsp];"
			     "lea 1f(%%rip), %%rax;"
			     "vmwrite %%rax, %[host_rip];"
			     "vmlaunch;"
			     "incq (%%rsp);"
			     "1: pop %%rax;"
			     "pop %%rdi;"
			     "pop %%rsi;"
			     "pop %%rdx;"
			     "pop %%rcx;"
			     "pop %%rbp;"
			     : [ret]"=&a"(ret)
			     : [host_rsp]"r"((uint64_t)HOST_RSP),
			       [host_rip]"r"((uint64_t)HOST_RIP)
			     : "memory", "cc", "rbx", "r8", "r9", "r10",
			       "r11", "r12", "r13", "r14", "r15");
	return ret;
}

static inline uint64_t get_cr0(void)
{
	uint64_t cr0;

	__asm__ __volatile__("mov %%cr0, %[cr0]"
			     : /* output */ [cr0]"=r"(cr0));
	return cr0;
}

static inline uint64_t get_cr3(void)
{
	uint64_t cr3;

	__asm__ __volatile__("mov %%cr3, %[cr3]"
			     : /* output */ [cr3]"=r"(cr3));
	return cr3;
}

static inline uint64_t get_cr4(void)
{
	uint64_t cr4;

	__asm__ __volatile__("mov %%cr4, %[cr4]"
			     : /* output */ [cr4]"=r"(cr4));
	return cr4;
}


static inline uint16_t get_es1(void)
{
	uint16_t es;

	__asm__ __volatile__("mov %%es, %[es]"
			     : /* output */ [es]"=rm"(es));
	return es;
}

static inline uint16_t get_cs1(void)
{
	uint16_t cs;

	__asm__ __volatile__("mov %%cs, %[cs]"
			     : /* output */ [cs]"=rm"(cs));
	return cs;
}

static inline uint16_t get_ss1(void)
{
	uint16_t ss;

	__asm__ __volatile__("mov %%ss, %[ss]"
			     : /* output */ [ss]"=rm"(ss));
	return ss;
}

static inline uint16_t get_ds1(void)
{
	uint16_t ds;

	__asm__ __volatile__("mov %%ds, %[ds]"
			     : /* output */ [ds]"=rm"(ds));
	return ds;
}

static inline uint16_t get_fs1(void)
{
	uint16_t fs;

	__asm__ __volatile__("mov %%fs, %[fs]"
			     : /* output */ [fs]"=rm"(fs));
	return fs;
}

static inline uint16_t get_gs1(void)
{
	uint16_t gs;

	__asm__ __volatile__("mov %%gs, %[gs]"
			     : /* output */ [gs]"=rm"(gs));
	return gs;
}

static inline uint16_t get_tr1(void)
{
	uint16_t tr;

	__asm__ __volatile__("str %[tr]"
			     : /* output */ [tr]"=rm"(tr));
	return tr;
}

static inline uint64_t get_gdt_base1(void)
{
	struct desc_ptr gdt;
	__asm__ __volatile__("sgdt %[gdt]"
			     : /* output */ [gdt]"=m"(gdt));
	return gdt.address;
}

static inline uint64_t get_idt_base1(void)
{
	struct desc_ptr idt;
	__asm__ __volatile__("sidt %[idt]"
			     : /* output */ [idt]"=m"(idt));
	return idt.address;
}

/*
uint32_t vmExit_reason(void) {
	uint32_t exit_reason = vmreadz(VM_EXIT_REASON);
	return exit_reason;
}
*/
// Dealloc vmxon region
bool deallocate_vmxon_region(void) {
	if(vmxonRegion){
	    kfree(vmxonRegion);
		return true;
   	}
   	return false;
}

/* Dealloc vmcs guest region*/
bool deallocate_vmcs_region(void) {
	if(vmcsRegion){
    	printk(KERN_INFO "Freeing allocated vmcs region!\n");
    	kfree(vmcsRegion);
		return true;
	}
	return false;
}

static inline int _vmptrld(uint64_t vmcs_pa)
{
	uint8_t ret;

	__asm__ __volatile__ ("vmptrld %[pa]; setna %[ret]"
		: [ret]"=rm"(ret)
		: [pa]"m"(vmcs_pa)
		: "cc", "memory");
	return ret;
}

static inline unsigned long long notrace __rdmsr1(unsigned int msr)
{
	DECLARE_ARGS(val, low, high);

	asm volatile("1: rdmsr\n"
		     "2:\n"
		     _ASM_EXTABLE_HANDLE(1b, 2b, ex_handler_rdmsr_unsafe)
		     : EAX_EDX_RET(val, low, high) : "c" (msr));

	return EAX_EDX_VAL(val, low, high);
}

// CH 24.2, Vol 3
// getting vmcs revision identifier
static inline uint32_t vmcs_revision_id(void)
{
	return __rdmsr1(MSR_IA32_VMX_BASIC);
}
// CH 27.2.1, Vol 3
// Basic VM exit reason
uint32_t vmExit_reason(void) {
	uint32_t exit_reason = vmreadz(VM_EXIT_REASON);
	exit_reason = exit_reason & 0xffff;
	return exit_reason;
}


// CH 23.7, Vol 3
// Enter in VMX mode
bool allocVmcsRegion(void) {
	vmcsRegion = kzalloc(MYPAGE_SIZE,GFP_KERNEL);
   	if(vmcsRegion==NULL){
		printk(KERN_INFO "Error allocating vmcs region\n");
      	return false;
   	}
	return true;
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
// Ch A.2, Vol 3
// indicate whether any of the default1 controls may be 0
// if return 0, all the default1 controls are reserved and must be 1.
// if return 1,not all the default1 controls are reserved, and
// some (but not necessarily all) may be 0.
unsigned long long default1_controls(void){
	unsigned long long check_default1_controls = (unsigned long long)((__rdmsr1(MSR_IA32_VMX_BASIC) << 55) & 1);
	//printk(KERN_INFO "default1 controls value!---%llu\n", check_default1_controls);
	return check_default1_controls;
}

static inline uint64_t get_desc64_base(const struct desc64 *desc)
{
	return ((uint64_t)desc->base3 << 32) |
		(desc->base0 | ((desc->base1) << 16) | ((desc->base2) << 24));
}

static void guest_code(void)
{
	/* Exit to L0 */
    asm volatile("cpuid");

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

	// CH 24.7.1, Vol 3
	//for supporting 64 bit host
	// maybe optional
	//uint32_t host_address_space = 1 << 9;
	//vm_exit_control_final = vm_exit_control_final | host_address_space;

	procbased_control_final = procbased_control_final | ACTIVATE_SECONDARY_CONTROLS;
	// for enabling unrestricted guest mode
	// maybe optional
	//uint64_t unrestricted_guest = 1 << 7;
	// for enabling ept
	// maybe optional
	//uint64_t enabling_ept = 1 << 1;
	//uint32_t procbased_secondary_control_final = procbased_secondary_control_final | unrestricted_guest | enabling_ept;
	// writing the value to control field*/
	vmwrite(PIN_BASED_VM_EXEC_CONTROLS, pinbased_control_final);
	vmwrite(PROC_BASED_VM_EXEC_CONTROLS, procbased_control_final);
	vmwrite(PROC2_BASED_VM_EXEC_CONTROLS, procbased_secondary_control_final);
	vmwrite(VM_EXIT_CONTROLS, vm_exit_control_final);
	vmwrite(VM_ENTRY_CONTROLS, vm_entry_control_final);
	// to ignore the guest exception
	vmwrite(EXCEPTION_BITMAP, 0);

	vmwrite(VIRTUAL_PROCESSOR_ID, 0);

	vmwrite(VM_EXIT_CONTROLS, __rdmsr1(MSR_IA32_VMX_EXIT_CTLS) |
		VM_EXIT_HOST_ADDR_SPACE_SIZE);	  /* 64-bit host */
	vmwrite(VM_ENTRY_CONTROLS, __rdmsr1(MSR_IA32_VMX_ENTRY_CTLS) |
		VM_ENTRY_IA32E_MODE);		  /* 64-bit guest */

	vmwrite(CR0_READ_SHADOW, get_cr0());
	vmwrite(CR4_READ_SHADOW, get_cr4());

	/* from kvm vmx.c source code
	vmwrite(PIN_BASED_VM_EXEC_CONTROLS, __rdmsr1(MSR_IA32_VMX_TRUE_PINBASED_CTLS));
if (!vmwrite(PROC2_BASED_VM_EXEC_CONTROLS, 0))
	vmwrite(PROC_BASED_VM_EXEC_CONTROLS,
		__rdmsr1(MSR_IA32_VMX_TRUE_PROCBASED_CTLS) | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS);
else
	vmwrite(PROC_BASED_VM_EXEC_CONTROLS, __rdmsr1(MSR_IA32_VMX_TRUE_PROCBASED_CTLS));
	*/
	// CH 26.2.2, Vol 3
	// Checks on Host Control Registers and MSRs
	vmwrite(HOST_CR0, get_cr0());
	vmwrite(HOST_CR3, get_cr3());
	vmwrite(HOST_CR4, get_cr4());
	/* optional stuff
	uint32_t exit_controls = vmreadz(VM_EXIT_CONTROLS);
	if (exit_controls & VM_EXIT_LOAD_IA32_PAT)
		vmwrite(HOST_IA32_PAT, __rdmsr1(MSR_IA32_CR_PAT));
	if (exit_controls & VM_EXIT_LOAD_IA32_EFER)
		vmwrite(HOST_IA32_EFER, __rdmsr1(MSR_EFER));
	if (exit_controls & VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL)
		vmwrite(HOST_IA32_PERF_GLOBAL_CTRL,
			__rdmsr1(MSR_CORE_PERF_GLOBAL_CTRL));
	*/
	// Doing EPT stuff
	// Move to another function later.

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
	/* setup of selectors according to linux kernel vmx.c module
	vmwrite(GUEST_ES_SELECTOR, vmreadz(HOST_ES_SELECTOR));
	vmwrite(GUEST_CS_SELECTOR, vmreadz(HOST_CS_SELECTOR));
	vmwrite(GUEST_SS_SELECTOR, vmreadz(HOST_SS_SELECTOR));
	vmwrite(GUEST_DS_SELECTOR, vmreadz(HOST_DS_SELECTOR));
	vmwrite(GUEST_FS_SELECTOR, vmreadz(HOST_FS_SELECTOR));
	vmwrite(GUEST_GS_SELECTOR, vmreadz(HOST_GS_SELECTOR));
	vmwrite(GUEST_TR_SELECTOR, vmreadz(HOST_TR_SELECTOR));
	vmwrite(GUEST_LDTR_SELECTOR, 0);
	*/
	/* my part of guest area
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

	vmwrite(VMCS_LINK_POINTER, -1ll);//or 0xffffffff
	vmwrite(GUEST_IA32_PAT, vmreadz(HOST_IA32_PAT));
	vmwrite(GUEST_IA32_DEBUGCTL, 0);
	vmwrite(GUEST_IA32_EFER, vmreadz(HOST_IA32_EFER));
	vmwrite(GUEST_IA32_PERF_GLOBAL_CTRL, vmreadz(HOST_IA32_PERF_GLOBAL_CTRL));

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
	vmwrite(GUEST_ES_AR_BYTES, 0x93);
	vmwrite(GUEST_CS_AR_BYTES, 0x93);
	vmwrite(GUEST_SS_AR_BYTES, 0x93);
	vmwrite(GUEST_DS_AR_BYTES, 0x93);
	vmwrite(GUEST_FS_AR_BYTES, 0x93);
	vmwrite(GUEST_GS_AR_BYTES, 0x93);
	vmwrite(GUEST_LDTR_AR_BYTES, 0x82);
	vmwrite(GUEST_TR_AR_BYTES, 0x82);


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
	vmwrite(GUEST_PENDING_DBG_EXCEPTIONS, 0);
	vmwrite(GUEST_SYSENTER_ESP, vmreadz(HOST_IA32_SYSENTER_ESP));
	vmwrite(GUEST_SYSENTER_EIP, vmreadz(HOST_IA32_SYSENTER_EIP));

	vmwrite(GUEST_DR7, 0x400);
	*/
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
	vmwrite(GUEST_DR7, 0x400);
	vmwrite(GUEST_RFLAGS, 2);
	vmwrite(GUEST_PENDING_DBG_EXCEPTIONS, 0);
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
	vmwrite(GUEST_RFLAGS, 2);

	return true;
}

bool initVmLaunchProcess(void){
	int vmlaunch_status = _vmlaunch();
	printk(KERN_INFO "VMLAUNCH status is %lu!\n", (unsigned long)vmlaunch_status);
	printk(KERN_INFO "Vm exit reason is->-> %lu!\n", (unsigned long)vmExit_reason());
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
