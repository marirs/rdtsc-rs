use crate::distorm::decoder::IFlags;
use crate::distorm::insts::{FLAGS_TABLE, INST_INFOS, INST_INFOS_EX, INST_SHARED_INFO_TABLE, INSTRUCTIONS_TREE};
use crate::distorm::prefix::PrefixState;

// /* REP prefix for string instructions only - means an instruction can follow it. */
// #define INST_PRE_REP (1 << 6)
// /* CS override prefix. */
// #define INST_PRE_CS (1 << 7)
// /* SS override prefix. */
// #define INST_PRE_SS (1 << 8)
// /* DS override prefix. */
// #define INST_PRE_DS (1 << 9)
// /* ES override prefix. */
// #define INST_PRE_ES (1 << 10)
// /* FS override prefix. Funky Segment :) */
// #define INST_PRE_FS (1 << 11)
// /* GS override prefix. Groovy Segment, of course not, duh ! */
// #define INST_PRE_GS (1 << 12)
// /* Switch operand size from 32 to 16 and vice versa. */
// #define INST_PRE_OP_SIZE (1 << 13)
// /* Switch address size from 32 to 16 and vice versa. */
// #define INST_PRE_ADDR_SIZE (1 << 14)
// /* Native instructions which needs suffix letter to indicate their operation-size (and don't depend on operands). */
// #define INST_NATIVE (1 << 15)
// /* Use extended mnemonic, means it's an _InstInfoEx structure, which contains another mnemonic for 32 bits specifically. */
// #define INST_USE_EXMNEMONIC (1 << 16)
// /* Use third operand, means it's an _InstInfoEx structure, which contains another operand for special instructions. */
// #define INST_USE_OP3 (1 << 17)
// /* Use fourth operand, means it's an _InstInfoEx structure, which contains another operand for special instructions. */
// #define INST_USE_OP4 (1 << 18)
// /* The instruction's mnemonic depends on the mod value of the ModR/M byte (mod=11, mod!=11). */
// #define INST_MNEMONIC_MODRM_BASED (1 << 19)
// /* The instruction uses a ModR/M byte which the MOD must be 11 (for registers operands only). */
// #define INST_MODRR_REQUIRED (1 << 20)
// /* The way of 3DNow! instructions are built, we have to handle their locating specially. Suffix imm8 tells which instruction it is. */
// #define INST_3DNOW_FETCH (1 << 21)
// /* The instruction needs two suffixes, one for the comparison type (imm8) and the second for its operation size indication (second mnemonic). */
// #define INST_PSEUDO_OPCODE (1 << 22)
// /* Invalid instruction at 64 bits decoding mode. */
// #define INST_INVALID_64BITS (1 << 23)
// /* Specific instruction can be promoted to 64 bits (without REX, it is promoted automatically). */
// #define INST_64BITS (1 << 24)
// /* Indicates the instruction must be REX prefixed in order to use 64 bits operands. */
// #define INST_PRE_REX (1 << 25)
// /* Third mnemonic is set. */
// #define INST_USE_EXMNEMONIC2 (1 << 26)
// /* Instruction is only valid in 64 bits decoding mode. */
// #define INST_64BITS_FETCH (1 << 27)
// /* Forces that the ModRM-REG/Opcode field will be 0. (For EXTRQ). */
// #define INST_FORCE_REG0 (1 << 28)
// /* Indicates that instruction is encoded with a VEX prefix. */
// #define INST_PRE_VEX (1 << 29)
// /* Indicates that the instruction is encoded with a ModRM byte (REG field specifically). */
// #define INST_MODRM_INCLUDED (1 << 30)
// /* Indicates that the first (/destination) operand of the instruction is writable. */
// #define INST_DST_WR (1 << 31)
//
// #define INST_PRE_REPS (INST_PRE_REPNZ | INST_PRE_REP)
// #define INST_PRE_LOKREP_MASK (INST_PRE_LOCK | INST_PRE_REPNZ | INST_PRE_REP)
// #define INST_PRE_SEGOVRD_MASK32 (INST_PRE_CS | INST_PRE_SS | INST_PRE_DS | INST_PRE_ES)
// #define INST_PRE_SEGOVRD_MASK64 (INST_PRE_FS | INST_PRE_GS)
// #define INST_PRE_SEGOVRD_MASK (INST_PRE_SEGOVRD_MASK32 | INST_PRE_SEGOVRD_MASK64)
//
// /* Extended flags for VEX: */
// /* Indicates that the instruction might have VEX.L encoded. */
// #define INST_VEX_L (1)
// /* Indicates that the instruction might have VEX.W encoded. */
// #define INST_VEX_W (1 << 1)
// /* Indicates that the mnemonic of the instruction is based on the VEX.W bit. */
// #define INST_MNEMONIC_VEXW_BASED (1 << 2)
// /* Indicates that the mnemonic of the instruction is based on the VEX.L bit. */
// #define INST_MNEMONIC_VEXL_BASED (1 << 3)
// /* Forces the instruction to be encoded with VEX.L, otherwise it's undefined. */
// #define INST_FORCE_VEXL (1 << 4)
// /*
//  * Indicates that the instruction is based on the MOD field of the ModRM byte.
//  * (MOD==11: got the right instruction, else skip +4 in prefixed table for the correct instruction).
//  */
// #define INST_MODRR_BASED (1 << 5)
// /* Indicates that the instruction doesn't use the VVVV field of the VEX prefix, if it does then it's undecodable. */
// #define INST_VEX_V_UNUSED (1 << 6)
//
// /* Indication that the instruction is privileged (Ring 0), this should be checked on the opcodeId field. */
// #define META_INST_PRIVILEGED ((uint16_t)0x8000)
//
// /*
//  * Indicates which operand is being decoded.
//  * Destination (1st), Source (2nd), op3 (3rd), op4 (4th).
//  * Used to set the operands' fields in the _DInst structure!
//  */
// typedef enum {ONT_NONE = -1, ONT_1 = 0, ONT_2 = 1, ONT_3 = 2, ONT_4 = 3} _OperandNumberType;
//
// /* CPU Flags that instructions modify, test or undefine, in compacted form (CF,PF,AF,ZF,SF are 1:1 map to EFLAGS). */
// #define D_COMPACT_CF 1		/* Carry */
// #define D_COMPACT_PF 4		/* Parity */
// #define D_COMPACT_AF 0x10	/* Auxiliary */
// #define D_COMPACT_ZF 0x40	/* Zero */
// #define D_COMPACT_SF 0x80	/* Sign */
// /* The following flags have to be translated to EFLAGS. */
// #define D_COMPACT_IF 2		/* Interrupt */
// #define D_COMPACT_DF 8		/* Direction */
// #define D_COMPACT_OF 0x20	/* Overflow */
//
// /* The mask of flags that are already compatible with EFLAGS. */
// #define D_COMPACT_SAME_FLAGS (D_COMPACT_CF | D_COMPACT_PF | D_COMPACT_AF | D_COMPACT_ZF | D_COMPACT_SF)
//
// /*
//  * In order to save more space for storing the DB statically,
//  * I came up with another level of shared info.
//  * Because I saw that most of the information that instructions use repeats itself.
//  *
//  * Info about the instruction, source/dest types, meta and flags.
//  * _InstInfo points to a table of _InstSharedInfo.
//  */
// typedef struct {
// 	uint8_t flagsIndex; /* An index into FlagsTables */
// 	uint8_t s, d; /* OpType. */
// 	/*
// 	 * The following are CPU flag masks that the instruction changes.
// 	 * The flags are compacted so 8 bits representation is enough.
// 	 * They will be expanded in runtime to be compatible to EFLAGS.
// 	 */
// 	uint8_t modifiedFlagsMask;
// 	uint8_t testedFlagsMask;
// 	uint8_t undefinedFlagsMask;
// 	uint16_t meta; /* High byte = Instruction set class | Low byte = flow control flags. */
// } _InstSharedInfo;
//
// /*
//  * This structure is used for the instructions DB and NOT for the disassembled result code!
//  * This is the BASE structure, there are extensions to this structure below.
//  */
// typedef struct {
// 	uint16_t sharedIndex; /* An index into the SharedInfoTable. */
// 	uint16_t opcodeId; /* The opcodeId is really a byte-offset into the mnemonics table. MSB is a privileged indication. */
// } _InstInfo;
//
// /*
//  * There are merely few instructions which need a second mnemonic for 32 bits.
//  * Or a third for 64 bits. Therefore sometimes the second mnemonic is empty but not the third.
//  * In all decoding modes the first mnemonic is the default.
//  * A flag will indicate it uses another mnemonic.
//  *
//  * There are a couple of (SSE4) instructions in the whole DB which need both op3 and 3rd mnemonic for 64bits,
//  * therefore, I decided to make the extended structure contain all extra info in the same structure.
//  * There are a few instructions (SHLD/SHRD/IMUL and SSE too) which use third operand (or a fourth).
//  * A flag will indicate it uses a third/fourth operand.
//  */
// typedef struct {
// 	/* Base structure (doesn't get accessed directly from code). */
// 	_InstInfo BASE;
//
// 	/* Extended starts here. */
// 	uint8_t flagsEx; /* 8 bits are enough, in the future we might make it a bigger integer. */
// 	uint8_t op3, op4; /* OpType. */
// 	uint16_t opcodeId2, opcodeId3;
// } _InstInfoEx;
//
// /* Trie data structure node type: */
// typedef enum {
// 	INT_NOTEXISTS = 0, /* Not exists. */
// 	INT_INFO = 1, /* It's an instruction info. */
// 	INT_INFOEX,
// 	INT_INFO_TREAT, /* Extra intervention is required by inst_lookup. */
// 	INT_LIST_GROUP,
// 	INT_LIST_FULL,
// 	INT_LIST_DIVIDED,
// 	INT_LIST_PREFIXED
// } _InstNodeType;
//
// /* Used to check instType < INT_INFOS, means we got an inst-info. Cause it has to be only one of them. */
// #define INT_INFOS (INT_LIST_GROUP)
//
// /* Instruction node is treated as { int index:13;  int type:3; } */
// typedef uint16_t _InstNode;
//
// _InstInfo* inst_lookup(_CodeInfo* ci, _PrefixState* ps, int* isPrefixed);
// _InstInfo* inst_lookup_3dnow(_CodeInfo* ci);
//
// #endif /* INSTRUCTIONS_H */
pub const INST_FLAGS_NONE: i32 = 0;
pub const INST_MODRM_REQUIRED: i32 = 1;
pub const INST_NOT_DIVIDED: i32 = 1 << 1;
pub const INST_16BITS: i32 = 1 << 2;
pub const INST_32BITS: i32 = 1 << 3;
pub const INST_PRE_LOCK: i32 = 1 << 4;
pub const INST_PRE_REPNZ: i32 = 1 << 5;
pub const INST_PRE_REP: i32 = 1 << 6;
pub const INST_PRE_CS: i32 = 1 << 7;
pub const INST_PRE_SS: i32 = 1 << 8;
pub const INST_PRE_DS: i32 = 1 << 9;
pub const INST_PRE_ES: i32 = 1 << 10;
pub const INST_PRE_FS: i32 = 1 << 11;
pub const INST_PRE_GS: i32 = 1 << 12;
pub const INST_PRE_OP_SIZE: i32 = 1 << 13;
pub const INST_PRE_ADDR_SIZE: i32 = 1 << 14;
pub const INST_NATIVE: i32 = 1 << 15;
pub const INST_USE_EXMNEMONIC: i32 = 1 << 16;
pub const INST_USE_OP3: i32 = 1 << 17;
pub const INST_USE_OP4: i32 = 1 << 18;
pub const INST_MNEMONIC_MODRM_BASED: i32 = 1 << 19;
pub const INST_MODRR_REQUIRED: i32 = 1 << 20;
pub const INST_3DNOW_FETCH: i32 = 1 << 21;
pub const INST_PSEUDO_OPCODE: i32 = 1 << 22;
pub const INST_INVALID_64BITS: i32 = 1 << 23;
pub const INST_64BITS: i32 = 1 << 24;
pub const INST_PRE_REX: i32 = 1 << 25;
pub const INST_USE_EXMNEMONIC2: i32 = 1 << 26;
pub const INST_64BITS_FETCH: i32 = 1 << 27;
pub const INST_FORCE_REG0: i32 = 1 << 28;
pub const INST_PRE_VEX: i32 = 1 << 29;
pub const INST_MODRM_INCLUDED: i32 = 1 << 30;
pub const INST_DST_WR: i32 = 1 << 31;
pub const INST_PRE_REPS: i32 = INST_PRE_REPNZ | INST_PRE_REP;
pub const INST_PRE_LOKREP_MASK: i32 = INST_PRE_LOCK | INST_PRE_REPNZ | INST_PRE_REP;
pub const INST_PRE_SEGOVRD_MASK32: i32 = INST_PRE_CS | INST_PRE_SS | INST_PRE_DS | INST_PRE_ES;
pub const INST_PRE_SEGOVRD_MASK64: i32 = INST_PRE_FS | INST_PRE_GS;
pub const INST_PRE_SEGOVRD_MASK: i32 = INST_PRE_SEGOVRD_MASK32 | INST_PRE_SEGOVRD_MASK64;
pub const INST_VEX_L: i32 = 1;
pub const INST_VEX_W: i32 = 1 << 1;
pub const INST_MNEMONIC_VEXW_BASED: i32 = 1 << 2;
pub const INST_MNEMONIC_VEXL_BASED: i32 = 1 << 3;
pub const INST_FORCE_VEXL: i32 = 1 << 4;
pub const INST_MODRR_BASED: i32 = 1 << 5;
pub const INST_VEX_V_UNUSED: i32 = 1 << 6;
pub const META_INST_PRIVILEGED: u16 = 0x8000;

pub enum OperandNumberType {
	OntNone = -1,
	Ont1 = 0,
	Ont2 = 1,
	Ont3 = 2,
	Ont4 = 3,
}

pub const D_COMPACT_CF: u8 = 1;
pub const D_COMPACT_PF: u8 = 4;
pub const D_COMPACT_AF: u8 = 0x10;
pub const D_COMPACT_ZF: u8 = 0x40;
pub const D_COMPACT_SF: u8 = 0x80;
pub const D_COMPACT_IF: u8 = 2;
pub const D_COMPACT_DF: u8 = 8;
pub const D_COMPACT_OF: u8 = 0x20;
pub const D_COMPACT_SAME_FLAGS: u8 = D_COMPACT_CF | D_COMPACT_PF | D_COMPACT_AF | D_COMPACT_ZF | D_COMPACT_SF;

#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub struct InstSharedInfo {
	pub flags_index: u8,
	pub s: u8,
	pub d: u8,
	pub modified_flags_mask: u8,
	pub tested_flags_mask: u8,
	pub undefined_flags_mask: u8,
	pub meta: u16,
}

/// This structure is used for the instructions DB and NOT for the disassembled result code!
/// This is the BASE structure, there are extensions to this structure below.
#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub struct InstInfo {
	/// An index into the SharedInfoTable.
	pub shared_index: u16,
	pub opcode_id: u16,
}

/// There are merely few instructions which need a second mnemonic for 32 bits.
/// Or a third for 64 bits. Therefore sometimes the second mnemonic is empty but not the third.
/// In all decoding modes the first mnemonic is the default.
/// A flag will indicate it uses another mnemonic.
///
/// There are a couple of (SSE4) instructions in the whole DB which need both op3 and 3rd mnemonic for 64bits,
/// therefore, I decided to make the extended structure contain all extra info in the same structure.
/// There are a few instructions (SHLD/SHRD/IMUL and SSE too) which use third operand (or a fourth).
/// A flag will indicate it uses a third/fourth operand.
#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub struct InstInfoEx {
	pub base: InstInfo,
	pub flags_ex: u8,
	pub op3: u8,
	pub op4: u8,
	pub opcode_id2: u16,
	pub opcode_id3: u16,
}

/// Trie data structure node type
#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub enum InstNodeType {
	IntNotExists = 0,
	IntInfo = 1,
	IntInfoEx,
	IntInfoTreat,
	IntListGroup,
	IntListFull,
	IntListDivided,
	IntListPrefixed,
}

pub const INT_INFOS: InstNodeType = InstNodeType::IntListGroup;

pub type InstNode = u16;

pub const fn inst_node_index(n: InstNode) -> InstNode {
	n & 0x1fff
}

pub const fn inst_node_type(n: InstNode) -> InstNode {
	n >> 13
}

pub const fn inst_info_flags(ii: InstInfo) -> IFlags {
	FLAGS_TABLE[INST_SHARED_INFO_TABLE[ii.shared_index as usize].flags_index as usize]
}

pub const fn inst_get_info(mut inst_node: InstNode, index: i32) -> Option<InstInfo> {
	let mut inst_index = 0;
	inst_node = INSTRUCTIONS_TREE[(inst_node_index(inst_node) as i32 + index) as usize];
	if inst_node == InstNodeType::IntNotExists as InstNode {
		return None;
	}
	inst_index = inst_node_index(inst_node) as usize;
	if inst_node_type(inst_node) == InstNodeType::IntInfo as InstNode {
		return Some(INST_INFOS[inst_index]);
	}
	Some(INST_INFOS_EX[inst_index].base)
}

pub const fn inst_lookup_prefixed(inst_node: InstNode, prefix_state: PrefixState) {}
