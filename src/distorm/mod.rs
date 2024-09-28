use wdk_sys::{PUINT8, UINT8};

mod wstring;
mod config;
mod mnemonics;
mod x86defs;
mod text_defs;
mod operands;
mod prefix;
mod decoder;
mod insts;
mod instructions;

pub const OPCODE_ID_NONE: UINT8 = 0;
/// The instruction could not be disassembled.
pub const FLAG_NOT_DECODABLE: u16 = 0xFFFF;
/// The instruction locks memory access.
pub const FLAG_LOCK: u32 = 1 << 0;
/// The instruction is prefixed with a REPNZ.
pub const FLAG_REPNZ: u32 = 1 << 1;
/// The instruction is prefixed with a REP, this can be a REPZ, it depends on the specific instruction.
pub const FLAG_REP: u32 = 1 << 2;
///Indicates there is a hint taken for Jcc instructions only.
pub const FLAG_HINT_TAKEN: u32 = 1 << 3;
/// Indicates there is a hint non-taken for Jcc instructions only.
pub const FLAG_HINT_NOT_TAKEN: u32 = 1 << 4;
/// The Imm value is signed extended (E.G in 64 bit decoding mode, a 32 bit imm is usually sign extended into 64 bit imm).
pub const FLAG_IMM_SIGNED: u32 = 1 << 5;
/// The destination operand is writable.
pub const FLAG_DST_WR: u32 = 1 << 6;
/// The instruction uses RIP-relative indirection.
pub const FLAG_RIP_RELATIVE: u32 = 1 << 7;
/// The instruction is privileged and can only be used from Ring0.
pub const FLAG_PRIVILEGED_INSTRUCTION: u32 = 1 << 15;

/// No register was defined.
pub const R_NONE: UINT8 = 0xFF;

pub const REGS64_BASE: u32 = 0;
pub const REGS32_BASE: u32 = 16;
pub const REGS16_BASE: u32 = 32;
pub const REGS8_BASE: u32 = 48;
pub const REGS8_REX_BASE: u32 = 64;
pub const SREGS_BASE: u32 = 68;
pub const FPUREGS_BASE: u32 = 75;
pub const MMXREGS_BASE: u32 = 83;
pub const SSEREGS_BASE: u32 = 91;
pub const AVXREGS_BASE: u32 = 107;
pub const CREGS_BASE: u32 = 123;
pub const DREGS_BASE: u32 = 132;
pub const OPERANDS_NO: u8 = 4;
/// Static size of strings. Do not change this value. Keep Python wrapper in sync.
pub const MAX_TEXT_SIZE: u8 = 48;
pub const RM_AX: u32 = 1;  // AL, AH, AX, EAX, RAX
pub const RM_CX: u32 = 2;  // CL, CH, CX, ECX, RCX
pub const RM_DX: u32 = 4;  // DL, DH, DX, EDX, RDX
pub const RM_BX: u32 = 8;  // BL, BH, BX, EBX, RBX
pub const RM_SP: u32 = 0x10;  // SPL, SP, ESP, RSP
pub const RM_BP: u32 = 0x20;  // BPL, BP, EBP, RBP
pub const RM_SI: u32 = 0x40;  // SIL, SI, ESI, RSI
pub const RM_DI: u32 = 0x80;  // DIL, DI, EDI, RDI
pub const RM_FPU: u32 = 0x100; // ST(0) - ST(7)
pub const RM_MMX: u32 = 0x200; // MM0 - MM7
pub const RM_SSE: u32 = 0x400; // XMM0 - XMM15
pub const RM_AVX: u32 = 0x800; // YMM0 - YMM15
pub const RM_CR: u32 = 0x1000; // CR0, CR2, CR3, CR4, CR8
pub const RM_DR: u32 = 0x2000; // DR0, DR1, DR2, DR3, DR6, DR7
pub const RM_R8: u32 = 0x4000; // R8B, R8W, R8D, R8
pub const RM_R9: u32 = 0x8000; // R9B, R9W, R9D, R9
pub const RM_R10: u32 = 0x10000; // R10B, R10W, R10D, R10
pub const RM_R11: u32 = 0x20000; // R11B, R11W, R11D, R11
pub const RM_R12: u32 = 0x40000; // R12B, R12W, R12D, R12
pub const RM_R13: u32 = 0x80000; // R13B, R13W, R13D, R13
pub const RM_R14: u32 = 0x0010_0000; // R14B, R14W, R14D, R14
pub const RM_R15: u32 = 0x0020_0000; // R15B, R15W, R15D, R15
pub const RM_SEG: u32 = 0x0040_0000; // CS, SS, DS, ES, FS, GS

// region: -- Cpu flags that instructions modify, test or undefine (are EFLAGS compatible!). --
pub const D_CF: u16 = 1;  // Carry
pub const D_PF: u16 = 4;  // Parity
pub const D_AF: u16 = 0x10;  // Auxiliary
pub const D_ZF: u16 = 0x40;  // Zero
pub const D_SF: u16 = 0x80;  // Sign
pub const D_IF: u16 = 0x200;  // Interrupt
pub const D_DF: u16 = 0x400;  // Direction
pub const D_OF: u16 = 0x800;  // Overflow
// endregion

// region: -- Instructions Set classes --
pub const ISC_INTEGER: u32 = 1;  // Indicates the instruction belongs to the General Integer set.
pub const ISC_FPU: u32 = 2;  // Indicates the instruction belongs to the 387 FPU set.
pub const ISC_P6: u32 = 3;  // Indicates the instruction belongs to the P6 set.
pub const ISC_MMX: u32 = 4;  // Indicates the instruction belongs to the MMX set.
pub const ISC_SSE: u32 = 5;  // Indicates the instruction belongs to the SSE set.
pub const ISC_SSE2: u32 = 6;  // Indicates the instruction belongs to the SSE2 set.
pub const ISC_SSE3: u32 = 7;  // Indicates the instruction belongs to the SSE3 set.
pub const ISC_SSSE3: u32 = 8;  // Indicates the instruction belongs to the SSSE3 set.
pub const ISC_SSE4_1: u32 = 9;  // Indicates the instruction belongs to the SSE4.1 set.
pub const ISC_SSE4_2: u32 = 10;  // Indicates the instruction belongs to the SSE4.2 set.
pub const ISC_SSE4_A: u32 = 11;  // Indicates the instruction belongs to the AMD's SSE4.A set.
pub const ISC_3DNOW: u32 = 12;  // Indicates the instruction belongs to the 3DNow! set.
pub const ISC_3DNOWEXT: u32 = 13;  // Indicates the instruction belongs to the 3DNow! Extensions set.
pub const ISC_VMX: u32 = 14;  // Indicates the instruction belongs to the VMX (Intel) set.
pub const ISC_SVM: u32 = 15;  // Indicates the instruction belongs to the SVM (AMD) set.
pub const ISC_AVX: u32 = 16;  // Indicates the instruction belongs to the AVX (Intel) set.
pub const ISC_FMA: u32 = 17;  // Indicates the instruction belongs to the FMA (Intel) set.
pub const ISC_AES: u32 = 18;  // Indicates the instruction belongs to the AES/AVX (Intel) set.
pub const ISC_CLMUL: u32 = 19;  // Indicates the instruction belongs to the CLMUL (Intel) set.
// endregion

// region: -- Features for decompose --
pub const DF_NONE: u32 = 0;
pub const DF_MAXIMUM_ADDR16: u32 = 1;  // The decoder will limit addresses to a maximum of 16 bits.
pub const DF_MAXIMUM_ADDR32: u32 = 2;  // The decoder will limit addresses to a maximum of 32 bits.
pub const DF_RETURN_FC_ONLY: u32 = 4;  // The decoder will return only flow control instructions (and filter the others internally).
pub const DF_STOP_ON_CALL: u32 = 8;  // The decoder will stop and return to the caller when the instruction 'CALL' (near and far) was decoded.
pub const DF_STOP_ON_RET: u32 = 0x10;  // The decoder will stop and return to the caller when the instruction 'RET' (near and far) was decoded.
pub const DF_STOP_ON_SYS: u32 = 0x20;  // The decoder will stop and return to the caller when the instruction system-call/ret was decoded.
pub const DF_STOP_ON_UNC_BRANCH: u32 = 0x40;  // The decoder will stop and return to the caller when any of the branch 'JMP', (near and far) instructions were decoded.
pub const DF_STOP_ON_CND_BRANCH: u32 = 0x80;  // The decoder will stop and return to the caller when any of the conditional branch instruction were decoded.
pub const DF_STOP_ON_INT: u32 = 0x100;  // The decoder will stop and return to the caller when the instruction 'INT' (INT, INT1, INTO, INT 3) was decoded.
pub const DF_STOP_ON_CMOV: u32 = 0x200;  // The decoder will stop and return to the caller when any of the 'CMOVxx' instruction was decoded.
pub const DF_STOP_ON_HLT: u32 = 0x400;  // The decoder will stop and return to the caller when it encounters the HLT instruction.
pub const DF_STOP_ON_PRIVILEGED: u32 = 0x800;  // The decoder will stop and return to the caller when it encounters a privileged instruction.
pub const DF_STOP_ON_UNDECODEABLE: u32 = 0x1000;  // The decoder will stop and return to the caller when an instruction couldn't be decoded.
pub const DF_SINGLE_BYTE_STEP: u32 = 0x2000;  // The decoder will not synchronize to the next byte after the previosuly decoded instruction, instead it will start decoding at the next byte.
pub const DF_FILL_EFLAGS: u32 = 0x4000;  // The decoder will fill in the eflags fields for the decoded instruction.
pub const DF_USE_ADDR_MASK: u32 = 0x8000;  // The decoder will use the addrMask in CodeInfo structure instead of DF_MAXIMUM_ADDR16/32.
pub const DF_STOP_ON_FLOW_CONTROL: u32 = DF_STOP_ON_CALL | DF_STOP_ON_RET | DF_STOP_ON_SYS | DF_STOP_ON_UNC_BRANCH | DF_STOP_ON_CND_BRANCH | DF_STOP_ON_INT | DF_STOP_ON_CMOV | DF_STOP_ON_HLT;
// endregion

// region: -- Flow control instructions --
pub const FC_NONE: u8 = 0;  // Indicates the instruction is not a flow-control instruction.
pub const FC_CALL: u8 = 1;  // Indicates the instruction is one of: CALL, CALL FAR.
pub const FC_RET: u8 = 2;  // Indicates the instruction is one of: RET, IRET, RETF.
pub const FC_SYS: u8 = 3;  // Indicates the instruction is one of: SYSCALL, SYSRET, SYSENTER, SYSEXIT.
pub const FC_UNC_BRANCH: u8 = 4;  // Indicates the instruction is one of: JMP, JMP FAR.
pub const FC_CND_BRANCH: u8 = 5;  // Indicates the instruction is one of: JCXZ, JO, JNO, JB, JAE, JZ, JNZ, JBE, JA, JS, JNS, JP, JNP, JL, JGE, JLE, JG, LOOP, LOOPZ, LOOPNZ.
pub const FC_INT: u8 = 6;  // Indiciates the instruction is one of: INT, INT1, INT 3, INTO, UD2.
pub const FC_CMOV: u8 = 7;  // Indicates the instruction is one of: CMOVxx.
pub const FC_HLT: u8 = 8;  // Indicates the instruction is HLT.
// endregion

#[cfg(feature = "supports_64bit_offset")]
pub type OffsetInteger = u64;

#[cfg(not(feature = "supports_64bit_offset"))]
pub type OffsetInteger = ULONG;

pub type OffsetType = OffsetInteger;

#[repr(C)]
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum DecodeType {
	Decode16Bits,
	Decode32Bits,
	Decode64Bits,
}

#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub struct CodeInfo {
	pub code_offset: OffsetType,
	pub addr_mask: OffsetType,
	pub next_offset: OffsetType,
	pub code: PUINT8,
	pub code_len: i32,
	pub dt: DecodeType,
	pub features: u32,
}

#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub enum OperandType {
	None,
	Reg,
	Imm,
	Imm1,
	Imm2,
	Disp,
	Smem,
	Mem,
	Pc,
	Ptr,
}

#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub struct Operand {
	/// Type of operand:
	/// NONE: operand is to be ignored.
	/// REG: index holds global register index.
	/// IMM: instruction.imm.
	/// IMM1: instruction.imm.ex.i1.
	/// IMM2: instruction.imm.ex.i2.
	/// DISP: memory dereference with displacement only, instruction.disp.
	/// SMEM: simple memory dereference with optional displacement (a single register memory dereference).
	/// MEM: complex memory dereference (optional fields: s/i/b/disp).
	/// PC: the relative address of a branch instruction (instruction.imm.addr).
	/// PTR: the absolute target address of a far branch instruction (instruction.imm.ptr.seg/off).
	pub r#type: OperandType,
	/// Index of:
	/// REG: holds global register index
	/// SMEM: holds the 'base' register. E.G: [ECX], [EBX+0x1234] are both in operand.index.
	/// MEM: holds the 'index' register. E.G: [EAX*4] is in operand.index.
	pub index: UINT8,
	///  Size in bits of:
	/// REG: register
	/// IMM: instruction.imm
	/// IMM1: instruction.imm.ex.i1
	/// IMM2: instruction.imm.ex.i2
	/// DISP: instruction.disp
	/// SMEM: size of indirection.
	/// MEM: size of indirection.
	/// PC: size of the relative offset
	/// PTR: size of instruction.imm.ptr.off (16 or 32)
	pub size: UINT8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union Value {
	pub sbyte: i8,
	pub byte: u8,
	pub sword: i16,
	pub word: u16,
	pub sdword: i32,
	pub dword: u32,
	pub sqword: i64,
	pub qword: u64,
	/// Used by `OperandType::Pc`
	pub addr: OffsetType,
	pub ptr: Ptr,
	pub ex: Ex,
}

/// Used by `OperandType::Ptr`
#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub struct Ptr {
	pub seg: u16,
	/// Can be 16 or 32 bits, size is in ops[n].size.
	pub off: u32,
}

/// Used by `OperandType::Imm1` (i1) and `OperandType::Imm2` (i2). ENTER instruction only.
#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub struct Ex {
	pub i1: u32,
	pub i2: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DInst {
	pub imm: Value,
	pub disp: u64,
	pub addr: OffsetType,
	pub flags: u16,
	pub unused_prefixes_mask: u16,
	pub used_registers_mask: u32,
	pub opcode: u16,
	pub ops: [Operand; OPERANDS_NO as usize],
	pub ops_no: u8,
	pub size: u8,
	pub segment: u8,
	pub base: u8,
	pub scale: u8,
	pub disp_size: u8,
	pub meta: u16,
	/// The CPU flags that the instruction operates upon, set only with `DF_FILL_EFLAGS` enabled, otherwise 0.
	pub modified_flags_mask: u16,
	pub tested_flags_mask: u16,
	pub undefined_flags_mask: u16,
}

#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub struct WString {
	pub length: u8,
	pub p: [char; MAX_TEXT_SIZE as usize],
}

/// Old decoded instruction structure in text format.
/// This structure holds all information the disassembler generates per instruction.
/// Used only for backward compatibility with diStorm64.
#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub struct DecodedInst {
	/// Start offset of the decoded instruction.
	pub offset: OffsetType,
	/// The size of the decoded instruction in bytes.
	pub size: u8,
	/// The mnemonic of the instruction, prefixed if required by REP, LOCK, etc.
	pub mnemonic: WString,
	/// The operands of the instruction, up to 3 operands, comma-separated.
	pub operands: WString,
	/// The Hex dump, little endian, including prefixes.
	pub instruction_hex: WString,
}

#[repr(C)]
#[no_mangle]
#[derive(Clone, Debug, Copy)]
pub enum DecodeResult {
	None,
	Success,
	MemoryErr,
	InputErr,
	Filtered,
}

const fn distorm_decompose(code: &CodeInfo, decoded: &[DInst], max_instructions: u32, used_instructions_count: *const u32) -> DecodeResult {
	DecodeResult::None
}

#[cfg(not(feature = "distorm_light"))]
const fn distorm_decode(code_offset: OffsetType, code: *const char, code_len: u32, dt: DecodeType, result: &[DecodedInst], max_instructions: u32, used_instructions_count: *const u32) -> DecodeResult {
	DecodeResult::None
}

#[cfg(not(feature = "distorm_light"))]
const fn distorm_format(code_info: &CodeInfo, di: &DInst, result: &DecodedInst) {}


