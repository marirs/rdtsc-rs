use crate::distorm::mnemonics::WRegister;

// #[cfg(feature = "distorm_light")]
pub unsafe fn strcat_wsr(str: &mut *mut [u8; 6], reg: &WRegister) {
	// Longest register name is YMM15 - 5 characters,
	// Copy 8 so compiler can do a QWORD move.
	// We copy nul termination and fix the length, so it's okay to copy more to the output buffer.
	// There's a sentinel register to make sure we don't read past the end of the registers table.
	core::ptr::copy_nonoverlapping(core::ptr::addr_of!(reg.p), *str, 8);
	*str = (*str).add(reg.length as usize);
}

pub unsafe fn strfinalize_ws(s: &mut [u8; 6], end: *mut u8) {
	*end = 0;
	s[5] = u8::try_from(end as usize - s.as_ptr() as usize).unwrap();
}

#[allow(clippy::missing_const_for_fn)]
pub unsafe fn chrcat_ws(s: *mut u8, ch: u8) {
	*s = ch;
	*s = *s.add(1);
}

pub unsafe fn strcat_ws(s: *mut u8, buf: *const u8, copylen: usize, advancelen: usize) {
	core::ptr::copy_nonoverlapping(buf, s, copylen);
	*s = *s.add(advancelen);
}