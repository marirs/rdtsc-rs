#[cfg(target_endian = "big")]
pub const unsafe fn r_short(s: *const u8) -> i16 {
	let mut ret: i16 = 0;
	ret |= *s as i16;
	ret |= (*s.add(1) as i16) << 8;
	ret
}

#[cfg(target_endian = "big")]
pub const unsafe fn r_u_short(s: *const u8) -> u16 {
	let mut ret: u16 = 0;
	ret |= *s as u16;
	ret |= (*s.add(1) as u16) << 8;
	ret
}

#[cfg(target_endian = "big")]
pub const unsafe fn r_long(s: *const u8) -> i32 {
	let mut ret: i32 = 0;
	ret |= *s as i32;
	ret |= (*s.add(1) as i32) << 8;
	ret |= (*s.add(2) as i32) << 16;
	ret |= (*s.add(3) as i32) << 24;
	ret
}

#[cfg(target_endian = "big")]
pub const unsafe fn r_u_long(s: *const u8) -> u32 {
	let mut ret: u32 = 0;
	ret |= *s as u32;
	ret |= (*s.add(1) as u32) << 8;
	ret |= (*s.add(2) as u32) << 16;
	ret |= (*s.add(3) as u32) << 24;
	ret
}

#[cfg(target_endian = "big")]
pub const unsafe fn r_llong(s: *const u8) -> i64 {
	let mut ret: i64 = 0;
	ret |= *s as i64;
	ret |= (*s.add(1) as i64) << 8;
	ret |= (*s.add(2) as i64) << 16;
	ret |= (*s.add(3) as i64) << 24;
	ret |= (*s.add(4) as i64) << 32;
	ret |= (*s.add(5) as i64) << 40;
	ret |= (*s.add(6) as i64) << 48;
	ret |= (*s.add(7) as i64) << 56;
	ret
}

#[cfg(target_endian = "big")]
pub const unsafe fn r_u_llong(s: *const u8) -> u64 {
	let mut ret: u64 = 0;
	ret |= *s as u64;
	ret |= (*s.add(1) as u64) << 8;
	ret |= (*s.add(2) as u64) << 16;
	ret |= (*s.add(3) as u64) << 24;
	ret |= (*s.add(4) as u64) << 32;
	ret |= (*s.add(5) as u64) << 40;
	ret |= (*s.add(6) as u64) << 48;
	ret |= (*s.add(7) as u64) << 56;
	ret
}

#[cfg(target_endian = "little")]
#[allow(clippy::cast_ptr_alignment)]
pub const unsafe fn r_short(s: *const u8) -> i16 {
	*s.cast::<i16>()
}

#[cfg(target_endian = "little")]
#[allow(clippy::cast_ptr_alignment)]
pub const unsafe fn r_u_short(s: *const u8) -> u16 {
	*s.cast::<u16>()
}

#[cfg(target_endian = "little")]
#[allow(clippy::cast_ptr_alignment)]
pub const unsafe fn r_long(s: *const u8) -> i32 {
	*s.cast::<i32>()
}

#[cfg(target_endian = "little")]
#[allow(clippy::cast_ptr_alignment)]
pub const unsafe fn r_u_long(s: *const u8) -> u32 {
	*s.cast::<u32>()
}

#[cfg(target_endian = "little")]
#[allow(clippy::cast_ptr_alignment)]
pub const unsafe fn r_llong(s: *const u8) -> i64 {
	*s.cast::<i64>()
}

#[cfg(target_endian = "little")]
#[allow(clippy::cast_ptr_alignment)]
pub const unsafe fn r_u_llong(s: *const u8) -> u64 {
	*s.cast::<u64>()
}
