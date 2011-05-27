/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#ifndef __ARM_KVM_EMULATE_H__
#define __ARM_KVM_EMULATE_H__

#include <linux/kvm_host.h>
#include <asm/kvm_asm.h>

#define VCPU_MODE(_vcpu) \
	(*((_vcpu)->arch.mode))

/* Get vcpu register for current mode */
#define vcpu_reg(_vcpu, _reg_num) \
	(*kvm_vcpu_reg((_vcpu), _reg_num, VCPU_MODE(_vcpu)))

/* Get vcpu register for specific mode */
#define vcpu_reg_m(_vcpu, _reg_num, _mode) \
	(*kvm_vcpu_reg(_vcpu, _reg_num, _mode))

#define vcpu_cpsr(_vcpu) \
	(_vcpu->arch.regs.cpsr)

/* Get vcpu SPSR for current mode */
#define vcpu_spsr(_vcpu) \
	kvm_vcpu_spsr(_vcpu, VCPU_MODE(_vcpu))

/* Get vcpu SPSR for specific mode */
#define vcpu_spsr_m(_vcpu, _mode) \
	kvm_vcpu_spsr(_vcpu, _mode)

#define MODE_HAS_SPSR(_vcpu) \
	 ((VCPU_MODE(_vcpu)) < MODE_USR)

#define VCPU_MODE_PRIV(_vcpu) \
	(((VCPU_MODE(_vcpu)) == MODE_USR) ? 0 : 1)

u32* kvm_vcpu_reg(struct kvm_vcpu *vcpu, u8 reg_num, u32 mode);

int kvm_handle_cp10_id(struct kvm_vcpu *vcpu, struct kvm_run *run);
int kvm_handle_cp_0_13_access(struct kvm_vcpu *vcpu, struct kvm_run *run);
int kvm_handle_cp14_load_store(struct kvm_vcpu *vcpu, struct kvm_run *run);
int kvm_handle_cp14_access(struct kvm_vcpu *vcpu, struct kvm_run *run);
int kvm_handle_cp15_access(struct kvm_vcpu *vcpu, struct kvm_run *run);
int kvm_handle_wfi(struct kvm_vcpu *vcpu, struct kvm_run *run);

/*
 * Return the SPSR for the specified mode of the virtual CPU.
 */
static inline u32 kvm_vcpu_spsr(struct kvm_vcpu *vcpu, u32 mode)
{
	switch (mode) {
	case MODE_SVC:
		return vcpu->arch.regs.svc_regs[2];
	case MODE_ABT:
		return vcpu->arch.regs.svc_regs[2];
	case MODE_UND:
		return vcpu->arch.regs.svc_regs[2];
	case MODE_IRQ:
		return vcpu->arch.regs.svc_regs[2];
	case MODE_FIQ:
		return vcpu->arch.regs.fiq_regs[7];
	default:
		BUG();
	}
}

/*
 * Helper function to do what's needed when switching modes
 */
static inline int kvm_switch_mode(struct kvm_vcpu *vcpu, u8 new_cpsr)
{
	u8 new_mode;
	u8 old_mode = VCPU_MODE(vcpu);
	int ret = 0;

	u8 modes_table[16] = {
		MODE_USR,	// 0x0
		MODE_FIQ,	// 0x1
		MODE_IRQ,	// 0x2
		MODE_SVC,	// 0x3
		0xf, 0xf, 0xf,
		MODE_ABT,	// 0x7
		0xf, 0xf, 0xf,
		MODE_UND,	// 0xb
		0xf, 0xf, 0xf,
		MODE_SYS};	// 0xf

	new_mode = modes_table[new_cpsr & 0xf];
	BUG_ON(new_mode == 0xf);

	if (new_mode == old_mode)
		return 0;

	// TODO: Check this for Virt-Ext implementation
	if (new_mode == MODE_USR || old_mode == MODE_USR) {
		/* Switch btw. priv. and non-priv. */
		//ret = kvm_init_l1_shadow(vcpu, vcpu->arch.shadow_pgtable->pgd);
	}
	//vcpu->arch.shared_page->vcpu_mode = new_mode;

	return ret;
}

/*
 * Write to the virtual CPSR.
 * The CPSR should NEVER be written directly!
 */
static inline void kvm_cpsr_write(struct kvm_vcpu *vcpu, u32 new_cpsr)
{
	if ((new_cpsr & MODE_MASK) != (vcpu->arch.regs.cpsr & MODE_MASK)) {
		BUG_ON(kvm_switch_mode(vcpu, new_cpsr));
	}

	BUG_ON((new_cpsr & PSR_N_BIT) && (new_cpsr & PSR_Z_BIT));

	vcpu->arch.regs.cpsr = new_cpsr;
}

#endif /* __ARM_KVM_EMULATE_H__ */
