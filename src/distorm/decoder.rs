use crate::distorm::DecodeType;
use crate::distorm::instructions::INST_PRE_ADDR_SIZE;

pub type IFlags = u32;

pub fn decode_get_effective_addr_size(dt: DecodeType, decoded_prefixes: IFlags) -> DecodeType {
	if decoded_prefixes & INST_PRE_ADDR_SIZE as IFlags == 0 {
		if dt == DecodeType::Decode32Bits {
			return DecodeType::Decode16Bits;
		}
		return DecodeType::Decode32Bits;
	}
	dt
}
