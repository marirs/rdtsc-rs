use alloc::boxed::Box;
use alloc::format;

use lazy_static::lazy_static;

/// The author of the driver.
pub const TEXT_AUTHOR: &str = "SGP";
/// The major product version.
pub const PRD_MAJ_VER: u32 = 24;
/// The minor product version.
pub const PRD_MIN_VER: u32 = 0;
/// The product build number.
pub const PRD_BUILD: u32 = 1;
/// The major file version.
pub const FILE_MAJ_VER: u32 = 24;
/// The minor file version.
pub const FILE_MIN_VER: u32 = 0;
/// The file build number.
pub const FILE_BUILD: u32 = 1;
/// The year the driver was created.
pub const DRIVER_YEAR: u32 = 2024;
/// The website of the driver.
pub const TEXT_WEBSITE: &str = "";
/// The name of the product.
pub const TEXT_PRODUCT_NAME: &str = "RDTSC Emulator";
/// The file description.
pub const TEXT_FILE_DESCRIPTION: &str = "RDTSC Emulator Driver";
/// The company.
pub const TEXT_COMPANY: &str = "";
/// The module.
pub const TEXT_MODULE: &str = "RDTSC_RS";

lazy_static! {
	/// The legal copyright.
	static ref TEXT_COPYRIGHT: &'static str = {
		let copyright = format!("Copyright (c) {} {}", DRIVER_YEAR, TEXT_COMPANY);
		Box::leak(Box::new(copyright))
	};
}
/// The internal name.
pub const TEXT_INTERNAL_NAME: &str = "rdtsc_rs.sys";
