use core::arch::asm;

use wdk_sys::{CCHAR, PUINT_PTR, PVOID, UINT_PTR, ULONG, USHORT};
use wdk_sys::ntddk::KeSetSystemAffinityThreadEx;

pub fn make_long(a: USHORT, b: USHORT) -> ULONG {
	((a as ULONG) & 0xffff) | ((b as ULONG) & 0xffff) << 16
}

/// The Interrupt Descriptor Table layout of data struct retrieved from sidt instruction
#[repr(C)]
#[derive(Clone, Debug, Copy, Default)]
pub struct IdtInfo {
	pub limit: USHORT,
	pub low_base: USHORT,
	pub high_base: USHORT,
}

/// A simplified layout of an IDT entry
/// (all the flag details have been omitted, we don't change them anyway)
#[repr(C)]
#[derive(Clone, Debug, Copy, Default)]
pub struct IdtEntry {
	pub low_offset: USHORT,
	pub seg_selector: USHORT,
	pub flags: USHORT,
	pub high_offset: USHORT,
}

/// Get the info from the Store Interrupt Descriptor Table Register
pub unsafe extern "C" fn get_idt_info() -> IdtInfo {
	let ret_val: *const IdtInfo;
	asm!("sidt {}", out(reg) ret_val);
	*ret_val
}

pub unsafe extern "C" fn hook_interrupt(new_handler: PVOID, number: ULONG, old_handler: PUINT_PTR) {
	let info: *const IdtInfo;
	asm!("sidt {}", out(reg) info);
	let idt = make_long((*info).low_base, (*info).high_base) as *mut IdtEntry;
	asm!(
	"pushfd",
	"cli",
	);

	let next_idt = idt.add(number as usize);
	let orig_handler = ((((*next_idt).high_offset as ULONG) << 16) | (*next_idt).low_offset as ULONG) as UINT_PTR;

	(*next_idt).low_offset = new_handler as USHORT;
	(*next_idt).high_offset = ((new_handler as ULONG) >> 16) as USHORT;
	if (old_handler as UINT_PTR) != 0 {
		*old_handler = orig_handler;
	}

	// CLI just clears the IF in EFLAGS so we don't need to execute STI here
	// by popping the previously pushed EFLAGS we revert to the original state
	asm!("popfd");
}

pub unsafe extern "C" fn switch_to_cpu(cpu: CCHAR) {
	KeSetSystemAffinityThreadEx(1 << cpu);
}
