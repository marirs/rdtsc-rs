use wdk_sys::{PVOID, ULONG};

pub const FILE_DEVICE_RDTSC: u32 = 0x8000;

pub const MAX_CPUS: usize = 32;

pub const MAX_INSTR: usize = 15;

pub enum RDTSCMode {
	Constant,
	Increasing,
}

// valid for all exceptions with an associated error code (see Intel manuals Vol.3A, 5.13)
#[repr(C)]
#[derive(Clone, Debug, Copy, Default)]
pub struct StackWithErr {
	pub error_code: ULONG,
	pub eip: ULONG,
	pub cs: ULONG,
	pub eflags: ULONG,
	pub esp: ULONG,
	pub ss: ULONG,
}

// integer register context and segment selectors
#[repr(C)]
#[derive(Clone, Debug, Copy, Default)]
pub struct CtxSelector {
	pub gs: ULONG,
	pub fs: ULONG,
	pub es: ULONG,
	pub ds: ULONG,
	pub edi: ULONG,
	pub esi: ULONG,
	pub ebp: ULONG,
	pub esp: ULONG,
	pub ebx: ULONG,
	pub edx: ULONG,
	pub ecx: ULONG,
	pub eax: ULONG,
}

// represents the stack layout at interrupt handler entry after all registers and segment
// selectors have been saved
#[repr(C)]
#[derive(Clone, Debug, Copy, Default)]
pub struct StackWithCtx {
	pub ctx: CtxSelector,
	pub orig_handler_stack: StackWithErr,
}

// const ORIG_HANDLERS: UINT_PTR = *const (Vec::with_capacity(MAX_CPUS));

pub unsafe extern "C" fn is_rdtsc(address: PVOID) -> ULONG {
	let mut instr: [u8; MAX_INSTR] = [0; MAX_INSTR];
	let mut i = 0;
	while i < MAX_INSTR {
		instr[i] = *(address as *const u8).add(i);
		i += 1;
	}
	if instr[0] == 0x0f && instr[1] == 0x31 {
		return 1;
	}
	0
}
