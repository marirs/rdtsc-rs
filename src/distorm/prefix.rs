use crate::distorm::{CodeInfo, DecodeType, DInst};
use crate::distorm::decoder::IFlags;
use crate::distorm::instructions::{INST_PRE_ADDR_SIZE, INST_PRE_LOKREP_MASK, INST_PRE_OP_SIZE, INST_PRE_REX, INST_PRE_SEGOVRD_MASK};
use crate::distorm::prefix::PrefixIndexer::{PfxIdxAdrs, PfxIdxLorep, PfxIdxMax, PfxIdxOpSize, PfxIdxRex, PfxIdxSeg};

#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub enum PrefixExtType {
	PetNone = 0,
	PetRex,
	PetVex2Bytes,
	PetVex3Bytes,
}

#[allow(clippy::enum_variant_names)]
#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub enum PrefixIndexer {
	PfxIdxNone = -1,
	PfxIdxRex,
	PfxIdxLorep,
	PfxIdxSeg,
	PfxIdxOpSize,
	PfxIdxAdrs,
	PfxIdxMax,
}

#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub struct PrefixState {
	pub decoded_prefixes: IFlags,
	pub used_prefixes: IFlags,
	pub count: i32,
	pub unused_prefixes_mask: u16,
	pub pfx_indexer: [u16; PfxIdxMax as usize],
	pub prefix_ext_type: PrefixExtType,
	pub is_op_size_mandatory: i32,
	pub vex_v: i32,
	pub vrex: u32,
	pub vex_pos: *const u8,
}

pub const MAX_PREFIXES: usize = 5;


pub const PREFIX_TABLES: [u8; 512] = [
	/* Decode 16/32 Bits */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, /* ES (0x26) CS (0x2e) */
	0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, /* DS (0x3e) SS (0x36) */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, /* FS(0x64) GS(0x65) OP_SIZE(0x66) ADDR_SIZE(0x67) */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* VEX2b (0xc5) VEX3b (0xc4) */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* LOCK (0xf0) REPNZ (0xf2) REP (0xf3) */
	/* Decode64Bits */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0,
	0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0,
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* REX: 0x40 - 0x4f */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
];

pub const fn prefixes_is_valid(ch: u8, decode_type: DecodeType) -> i32 {
	PREFIX_TABLES[ch as usize + ((decode_type as usize >> 1) << 8)] as i32
}

pub const fn prefixes_ignore(mut prefix_state: PrefixState, prefix_indexer: usize) {
	prefix_state.unused_prefixes_mask |= prefix_state.pfx_indexer[prefix_indexer];
}

pub fn prefixes_ignore_all(prefix_state: PrefixState) {
	for i in 0..PfxIdxMax as usize {
		prefixes_ignore(prefix_state, i);
	}
}

pub const fn prefixes_set_unused_mask(prefix_state: PrefixState) -> u16 {
	let unused_prefixes_diff = prefix_state.decoded_prefixes ^ prefix_state.used_prefixes;
	let mut unused_prefixes_mask = prefix_state.unused_prefixes_mask;
	if unused_prefixes_diff != 0 {
		if (unused_prefixes_diff & INST_PRE_REX as u32) != 0 {
			unused_prefixes_mask |= prefix_state.pfx_indexer[PfxIdxRex as usize];
		}
		if (unused_prefixes_diff & INST_PRE_SEGOVRD_MASK as u32) != 0 {
			unused_prefixes_mask |= prefix_state.pfx_indexer[PfxIdxSeg as usize];
		}
		if (unused_prefixes_diff & INST_PRE_LOKREP_MASK as u32) != 0 {
			unused_prefixes_mask |= prefix_state.pfx_indexer[PfxIdxLorep as usize];
		}
		if (unused_prefixes_diff & INST_PRE_OP_SIZE as u32) != 0 {
			unused_prefixes_mask |= prefix_state.pfx_indexer[PfxIdxOpSize as usize];
		}
		if (unused_prefixes_diff & INST_PRE_ADDR_SIZE as u32) != 0 {
			unused_prefixes_mask |= prefix_state.pfx_indexer[PfxIdxAdrs as usize];
		}
	}
	unused_prefixes_mask
}

pub const fn prefixes_track_unused(mut prefix_state: PrefixState, index: i32, prefix_indexer: PrefixIndexer) {
	prefixes_ignore(prefix_state, prefix_indexer as usize);
	prefix_state.pfx_indexer[prefix_indexer as usize] = 1 << index;
}

// void prefixes_decode(_CodeInfo* ci, _PrefixState* ps)
// {
// 	const uint8_t* rexPos = NULL;
// 	const uint8_t* start = ci->code;
// 	uint8_t byte, vex;
// 	/*
// 	 * First thing to do, scan for prefixes, there are six types of prefixes.
// 	 * There may be up to six prefixes before a single instruction, not the same type, no special order,
// 	 * except REX/VEX must precede immediately the first opcode byte.
// 	 * BTW - This is the reason why I didn't make the REP prefixes part of the instructions (STOS/SCAS/etc).
// 	 *
// 	 * Another thing, the instruction maximum size is 15 bytes, thus if we read more than 15 bytes, we will halt.
// 	 *
// 	 * We attach all prefixes to the next instruction, there might be two or more occurrences from the same prefix.
// 	 * Also, since VEX can be allowed only once we will test it separately.
// 	 */
// 	for (unsigned int index = 0;
// 		(ci->codeLen > 0) && (index < INST_MAXIMUM_SIZE);
// 		ci->code++, ci->codeLen--, index++) {
// 		/*
// 		NOTE: AMD treat lock/rep as two different groups... But I am based on Intel.
//
// 			- Lock and Repeat:
// 				- 0xF0 � LOCK
// 				- 0xF2 � REPNE/REPNZ
// 				- 0xF3 - REP/REPE/REPZ
// 			- Segment Override:
// 				- 0x2E - CS
// 				- 0x36 - SS
// 				- 0x3E - DS
// 				- 0x26 - ES
// 				- 0x64 - FS
// 				- 0x65 - GS
// 			- Operand-Size Override: 0x66, switching default size.
// 			- Address-Size Override: 0x67, switching default size.
//
// 		64 Bits:
// 			- REX: 0x40 - 0x4f, extends register access.
// 			- 2 Bytes VEX: 0xc4
// 			- 3 Bytes VEX: 0xc5
// 		32 Bits:
// 			- 2 Bytes VEX: 0xc4 11xx-xxxx
// 			- 3 Bytes VEX: 0xc5 11xx-xxxx
// 		*/
//
// 		/* Examine what type of prefix we got. */
// 		byte = *ci->code;
// 		switch (byte)
// 		{
// 		case PREFIX_OP_SIZE: {/* Op Size type: */
// 			ps->decodedPrefixes |= INST_PRE_OP_SIZE;
// 			prefixes_track_unused(ps, index, PFXIDX_OP_SIZE);
// 		} break;
// 			/* Look for both common arch prefixes. */
// 		case PREFIX_LOCK: {
// 			/* LOCK and REPx type: */
// 			ps->decodedPrefixes |= INST_PRE_LOCK;
// 			prefixes_track_unused(ps, index, PFXIDX_LOREP);
// 		} break;
// 		case PREFIX_REPNZ: {
// 			ps->decodedPrefixes |= INST_PRE_REPNZ;
// 			prefixes_track_unused(ps, index, PFXIDX_LOREP);
// 		} break;
// 		case PREFIX_REP: {
// 			ps->decodedPrefixes |= INST_PRE_REP;
// 			prefixes_track_unused(ps, index, PFXIDX_LOREP);
// 		} break;
// 		case PREFIX_CS: {
// 			/* Seg Overide type: */
// 			ps->decodedPrefixes &= ~INST_PRE_SEGOVRD_MASK;
// 			ps->decodedPrefixes |= INST_PRE_CS;
// 			prefixes_track_unused(ps, index, PFXIDX_SEG);
// 		} break;
// 		case PREFIX_SS: {
// 			ps->decodedPrefixes &= ~INST_PRE_SEGOVRD_MASK;
// 			ps->decodedPrefixes |= INST_PRE_SS;
// 			prefixes_track_unused(ps, index, PFXIDX_SEG);
// 		} break;
// 		case PREFIX_DS: {
// 			ps->decodedPrefixes &= ~INST_PRE_SEGOVRD_MASK;
// 			ps->decodedPrefixes |= INST_PRE_DS;
// 			prefixes_track_unused(ps, index, PFXIDX_SEG);
// 		} break;
// 		case PREFIX_ES: {
// 			ps->decodedPrefixes &= ~INST_PRE_SEGOVRD_MASK;
// 			ps->decodedPrefixes |= INST_PRE_ES;
// 			prefixes_track_unused(ps, index, PFXIDX_SEG);
// 		} break;
// 		case PREFIX_FS: {
// 			ps->decodedPrefixes &= ~INST_PRE_SEGOVRD_MASK;
// 			ps->decodedPrefixes |= INST_PRE_FS;
// 			prefixes_track_unused(ps, index, PFXIDX_SEG);
// 		} break;
// 		case PREFIX_GS: {
// 			ps->decodedPrefixes &= ~INST_PRE_SEGOVRD_MASK;
// 			ps->decodedPrefixes |= INST_PRE_GS;
// 			prefixes_track_unused(ps, index, PFXIDX_SEG);
// 		} break;
// 		case PREFIX_ADDR_SIZE: {
// 			/* Addr Size type: */
// 			ps->decodedPrefixes |= INST_PRE_ADDR_SIZE;
// 			prefixes_track_unused(ps, index, PFXIDX_ADRS);
// 		} break;
// 		default:
// 			if (ci->dt == Decode64Bits) {
// 				/* REX type, 64 bits decoding mode only: */
// 				if ((byte & 0xf0) == 0x40) {
// 					ps->decodedPrefixes |= INST_PRE_REX;
// 					rexPos = ci->code;
// 					ps->vrex = byte & 0xf; /* Keep only BXRW. */
// 					ps->prefixExtType = PET_REX;
// 					prefixes_track_unused(ps, index, PFXIDX_REX);
// 					continue;
// 				}
// 			}
// 			goto _Break2;
// 		}
// 	}
// _Break2:
//
// 	/* 2 Bytes VEX: */
// 	if ((ci->codeLen >= 2) &&
// 		(*ci->code == PREFIX_VEX2b) &&
// 		((ci->code - start) <= INST_MAXIMUM_SIZE - 2)) {
// 		/*
// 		 * In 32 bits the second byte has to be in the special range of Mod=11.
// 		 * Otherwise it might be a normal LDS instruction.
// 		 */
// 		if ((ci->dt == Decode64Bits) || (*(ci->code + 1) >= INST_DIVIDED_MODRM)) {
// 			ps->vexPos = ci->code + 1;
// 			ps->decodedPrefixes |= INST_PRE_VEX;
// 			ps->prefixExtType = PET_VEX2BYTES;
//
// 			/*
// 			 * VEX 1 byte bits:
// 			 * |7-6--3-2-10|
// 			 * |R|vvvv|L|pp|
// 			 * |-----------|
// 			 */
//
// 			/* -- Convert from VEX prefix to VREX flags -- */
// 			vex = *ps->vexPos;
// 			if (!(vex & 0x80) && (ci->dt == Decode64Bits)) ps->vrex |= PREFIX_EX_R; /* Convert VEX.R. */
// 			if (vex & 4) ps->vrex |= PREFIX_EX_L; /* Convert VEX.L. */
//
// 			ci->code += 2;
// 			ci->codeLen -= 2;
// 		}
// 	}
//
// 	/* 3 Bytes VEX: */
// 	if ((ci->codeLen >= 3) &&
// 		(*ci->code == PREFIX_VEX3b) &&
// 		((ci->code - start) <= INST_MAXIMUM_SIZE - 3) &&
// 		(!(ps->decodedPrefixes & INST_PRE_VEX))) {
// 		/*
// 		 * In 32 bits the second byte has to be in the special range of Mod=11.
// 		 * Otherwise it might be a normal LES instruction.
// 		 * And we don't care now about the 3rd byte.
// 		 */
// 		if ((ci->dt == Decode64Bits) || (*(ci->code + 1) >= INST_DIVIDED_MODRM)) {
// 			ps->vexPos = ci->code + 1;
// 			ps->decodedPrefixes |= INST_PRE_VEX;
// 			ps->prefixExtType = PET_VEX3BYTES;
//
// 			/*
// 			 * VEX first and second bytes:
// 			 * |7-6-5-4----0|  |7-6--3-2-10|
// 			 * |R|X|B|m-mmmm|  |W|vvvv|L|pp|
// 			 * |------------|  |-----------|
// 			 */
//
// 			/* -- Convert from VEX prefix to VREX flags -- */
// 			vex = *ps->vexPos;
// 			ps->vrex |= ((~vex >> 5) & 0x7); /* Shift and invert VEX.R/X/B to their place */
// 			vex = *(ps->vexPos + 1);
// 			if (vex & 4) ps->vrex |= PREFIX_EX_L; /* Convert VEX.L. */
// 			if (vex & 0x80) ps->vrex |= PREFIX_EX_W; /* Convert VEX.W. */
//
// 			/* Clear some flags if the mode isn't 64 bits. */
// 			if (ci->dt != Decode64Bits) ps->vrex &= ~(PREFIX_EX_B | PREFIX_EX_X | PREFIX_EX_R | PREFIX_EX_W);
//
// 			ci->code += 3;
// 			ci->codeLen -= 3;
// 		}
// 	}
//
// 	if (ci->dt == Decode64Bits) {
// 		if (ps->decodedPrefixes & INST_PRE_REX) {
// 			/* REX prefix must precede first byte of instruction. */
// 			if (rexPos != (ci->code - 1)) {
// 				ps->decodedPrefixes &= ~INST_PRE_REX;
// 				if (ps->prefixExtType == PET_REX) ps->prefixExtType = PET_NONE; /* It might be a VEX by now, keep it that way. */
// 				prefixes_ignore(ps, PFXIDX_REX);
// 			}
// 			/*
// 			 * We will disable operand size prefix,
// 			 * if it exists only after decoding the instruction, since it might be a mandatory prefix.
// 			 * This will be done after calling inst_lookup in decode_inst.
// 			 */
// 		}
// 		/* In 64 bits, segment overrides of CS, DS, ES and SS are ignored. So don't take'em into account. */
// 		if (ps->decodedPrefixes & INST_PRE_SEGOVRD_MASK32) {
// 			ps->decodedPrefixes &= ~INST_PRE_SEGOVRD_MASK32;
// 			prefixes_ignore(ps, PFXIDX_SEG);
// 		}
// 	}
//
// 	/* Store number of prefixes scanned. */
// 	ps->count = (uint8_t)(ci->code - start);
// }
pub const fn prefixes_decode(code_info: &CodeInfo, prefix_state: &PrefixState) {
	let rex_pos: *const u8;
	let start: *const u8 = code_info.code;
	let mut byte: u8;
	let mut vex: u8;
	/*
	 * First thing to do, scan for prefixes, there are six types of prefixes.
	 * There may be up to six prefixes before a single instruction, not the same type, no special order,
	 * except REX/VEX must precede immediately the first opcode byte.
	 * BTW - This is the reason why I didn't make the REP prefixes part of the instructions (STOS/SCAS/etc).
	 *
	 * Another thing, the instruction maximum size is 15 bytes, thus if we read more than 15 bytes, we will halt.
	 *
	 * We attach all prefixes to the next instruction, there might be two or more occurrences from the same prefix.
	 * Also, since VEX can be allowed only once we will test it separately.
	 */
}

pub const fn prefixes_use_segment(default_seg: IFlags, prefix_state: PrefixState, decode_type: DecodeType, di: DInst) {}
