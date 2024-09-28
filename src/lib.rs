#![no_std]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(clippy::cargo)]
#![allow(clippy::missing_safety_doc)]
#![allow(unused)]

extern crate alloc;
#[cfg(not(test))]
extern crate wdk_panic;

use core::arch::asm;
use core::mem::{size_of, size_of_val};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use lazy_static::lazy_static;
use wdk::{nt_success, println};
#[cfg(not(test))]
use wdk_alloc::WDKAllocator;
use wdk_sys::{CCHAR, DRIVER_OBJECT, HANDLE, IO_NO_INCREMENT, KeNumberProcessors, KEY_READ, macros, NTSTATUS, OBJ_KERNEL_HANDLE, OBJECT_ATTRIBUTES, PCUNICODE_STRING, PCWSTR, PDEVICE_OBJECT, PDRIVER_OBJECT, PHANDLE, PIO_STACK_LOCATION, PIRP, PKEY_VALUE_PARTIAL_INFORMATION, POBJECT_ATTRIBUTES, PUINT_PTR, PULONG, PUNICODE_STRING, PVOID, PWCH, PWSTR, SIZE_T, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_DEVICE_REQUEST, STATUS_INVALID_PARAMETER, STATUS_SUCCESS, STATUS_UNSUCCESSFUL, UINT_PTR, ULONG, UNICODE_STRING, USHORT, WCHAR, WDF_DRIVER_CONFIG, WDF_NO_HANDLE, WDF_NO_OBJECT_ATTRIBUTES, WDFDRIVER};
use wdk_sys::_KEY_VALUE_INFORMATION_CLASS::KeyValuePartialInformation;
use wdk_sys::_POOL_TYPE::PagedPool;
use wdk_sys::ntddk::{ExAllocatePool, ExFreePool, IoDeleteDevice, IoDeleteSymbolicLink, IofCompleteRequest, MmIsAddressValid, RtlInitUnicodeString, RtlRandomEx, wcslen, ZwClose, ZwOpenKey, ZwQueryValueKey};

use crate::bindings::{InitializeObjectAttributes, IoGetCurrentIrpStackLocation, RtlStringCbCatW, RtlStringCbCopyW, WdfDriverWdmGetDriverObject};
use crate::hoot_int::{hook_interrupt, switch_to_cpu};
use crate::rdtsc_emu::{is_rdtsc, StackWithCtx};

mod rdtsc_emu;
mod driver_version;
mod hoot_int;
mod distorm;
mod bindings;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WDKAllocator = WDKAllocator;


pub const MAX_CPUS: usize = 32;
pub const MAX_INSTR: usize = 15;

pub const DEV_NAME: &str = "\\Device\\";
pub const SYMLINK_NAME: &str = "\\DosDevices\\";

// pub static DEVICE_NAME: UNICODE_STRING = UNICODE_STRING { Length: 0, MaximumLength: 0, Buffer: 0 as PWCH };
// pub static DOS_DEVICE_NAME: UNICODE_STRING = UNICODE_STRING { Length: 0, MaximumLength: 0, Buffer: 0 as PWCH };

lazy_static! {
	pub static ref CR4_TO_EAX: () = {
		unsafe {
			asm!("_emit 0x0f", " _emit 0x20", " _emit 0xe0")
		}
	};
	pub static ref EAX_TO_CR4: () = {
		unsafe {
			asm!("_emit 0x0f", " _emit 0x22", " _emit 0xe0")
		}
	};
	pub static ref SET_TSD_EAX: () = {
		unsafe {
			asm!("or eax, 0x4")
		}
	};
	pub static ref CLEAR_TSD_EAX: () = {
		unsafe {
			asm!("and eax, 0xfffffffb")
		}
	};
	pub static ref ENABLE_TSD: () = {
		let _ = &CR4_TO_EAX;
		let _ = &SET_TSD_EAX;
		let _ = &EAX_TO_CR4;
	};
	pub static ref CLEAR_TSD: () = {
		let _ = &CR4_TO_EAX;
		let _ = &CLEAR_TSD_EAX;
		let _ = &EAX_TO_CR4;
	};  
	pub static ref METHOD_INCREASING: AtomicBool = AtomicBool::new(false);
	pub static ref DELTA: AtomicUsize = AtomicUsize::new(0);
	pub static ref RDTSC_VALUE: AtomicUsize = AtomicUsize::new(0);
	pub static ref CONST_VALUE: AtomicUsize = AtomicUsize::new(0);
	pub static ref ORIG_HANDLERS: [UINT_PTR; MAX_CPUS] = [0; MAX_CPUS];
	pub static ref DEVICE_NAME: (AtomicUsize, AtomicUsize, AtomicUsize) = (AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0));
	pub static ref DOS_DEVICE_NAME: (AtomicUsize, AtomicUsize, AtomicUsize) = (AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0));

	// pub static ref DEVICE_NAME: UNICODE_STRING = UNICODE_STRING { Length: 0, MaximumLength: 0, Buffer: 0 as PWCH };
	// pub static DOS_DEVICE_NAME: UNICODE_STRING = UNICODE_STRING { Length: 0, MaximumLength: 0, Buffer: 0 as PWCH };
}


/// `DriverEntry` initializes the driver and is the first routine called by the
/// system after the driver is loaded. `DriverEntry` specifies the other entry
/// points in the function driver, such as `EvtDevice` and `DriverUnload`.
///
/// # Arguments
///
/// * `driver` - represents the instance of the function driver that is loaded
///   into memory. `DriverEntry` must initialize members of `DriverObject`
///   before it returns to the caller. `DriverObject` is allocated by the system
///   before the driver is loaded, and it is released by the system after the
///   system unloads the function driver from memory.
/// * `registry_path` - represents the driver specific path in the Registry. The
///   function driver can use the path to store driver related data between
///   reboots. The path does not store hardware instance specific data.
///
/// # Return value:
///
/// * `STATUS_SUCCESS` - if successful,
/// * `STATUS_UNSUCCESSFUL` - otherwise.
#[link_section = "INIT"]
#[export_name = "DriverEntry"] // WDF expects a symbol with the name DriverEntry
pub unsafe extern "system" fn driver_entry(
	driver: &mut DRIVER_OBJECT,
	registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
	let mut driver_config = WDF_DRIVER_CONFIG {
		// Set the size of the structure
		Size: ULONG::try_from(core::mem::size_of::<WDF_DRIVER_CONFIG>()).unwrap(),
		// Set the EvtDriverDeviceAdd callback
		// EvtDriverDeviceAdd: Some(),
		EvtDriverUnload: Some(unload_driver),
		..Default::default()
	};
	let driver_handle_output = WDF_NO_HANDLE.cast::<WDFDRIVER>();
	if !init_device_strings(registry_path) {
		return STATUS_UNSUCCESSFUL;
	}

	let nt_status = unsafe {
		macros::call_unsafe_wdf_function_binding!(
			WdfDriverCreate,
			driver as PDRIVER_OBJECT,
			registry_path,
			WDF_NO_OBJECT_ATTRIBUTES,
			&mut driver_config,
			driver_handle_output
		)
	};
	if !nt_success(nt_status) {
		println!("Error: WdfDriverCreate failed {nt_status:#010x}");
		return nt_status;
	}
	initialize_hooks();

	nt_status
}

pub unsafe fn hook_implementation(mut stack_layout: StackWithCtx) -> bool {
	if MmIsAddressValid(stack_layout.orig_handler_stack.eip as PVOID) > 0 {
		let length = is_rdtsc(stack_layout.orig_handler_stack.eip as PVOID);
		if METHOD_INCREASING.load(Ordering::SeqCst) {
			let mut seed: ULONG = 0x666;
			if DELTA.load(Ordering::SeqCst) > 0 {
				RDTSC_VALUE.fetch_add((RtlRandomEx(ptr::addr_of_mut!(seed)) as usize % DELTA.load(Ordering::SeqCst)), Ordering::SeqCst);
			}
			stack_layout.ctx.eax = RDTSC_VALUE.load(Ordering::SeqCst) as ULONG;
			stack_layout.ctx.edx = (RDTSC_VALUE.load(Ordering::SeqCst) >> 32) as ULONG;
		} else {
			stack_layout.ctx.eax = CONST_VALUE.load(Ordering::SeqCst) as ULONG;
			stack_layout.ctx.edx = CONST_VALUE.load(Ordering::SeqCst) as ULONG;
		}
		stack_layout.orig_handler_stack.eip += length;
	}
	false
}

pub unsafe fn remove_hooks() {
	for i in 0..KeNumberProcessors {
		switch_to_cpu(i);
		let _ = CLEAR_TSD;
		hook_interrupt(ORIG_HANDLERS[i as usize] as PVOID, 0xD, WDF_NO_HANDLE.cast());
	}
}

pub unsafe fn init_device_strings(registry_path: PCUNICODE_STRING) -> bool {
	let rand_name: PWSTR = get_randomized_name(registry_path as PUNICODE_STRING);
	if rand_name.is_null() { return false; }
	let mut ret_val = false;
	let device_name = UNICODE_STRING {
		Length: DEVICE_NAME.0.load(Ordering::SeqCst) as USHORT,
		MaximumLength: DEVICE_NAME.1.load(Ordering::SeqCst) as USHORT,
		Buffer: DEVICE_NAME.2.load(Ordering::SeqCst) as PWCH,
	};
	if build_device_name(ptr::from_ref(&device_name).cast_mut(), ptr::from_ref(DEV_NAME) as PCWSTR, rand_name) &&
		build_device_name(ptr::from_ref(&DOS_DEVICE_NAME) as PUNICODE_STRING, ptr::from_ref(SYMLINK_NAME) as PCWSTR, rand_name) {
		ret_val = true;
	}
	ExFreePool(rand_name as PVOID);
	ret_val
}

pub unsafe fn initialize_hooks() {
	for i in 0..KeNumberProcessors {
		switch_to_cpu(i);
		hook_interrupt(hook_stub as PVOID, 0xD, ORIG_HANDLERS[i as usize] as PUINT_PTR);
		let _ = ENABLE_TSD;
	}
}

pub unsafe fn hook_stub() {
	asm!(
	"pushad",
	"push ds",
	"push es",
	"push fs",
	"push gs",
	// set kernel mode selectors
	"mov     ax, 0x23",
	"mov     ds, ax",
	"mov     es, ax",
	"mov     gs, ax",
	"mov     ax, 0x30",
	"mov     fs, ax",
	"push	esp",
	"call	hookImplementation",
	"cmp		al, 0",
	"jz		oldHandler",
	"pop		gs",
	"pop		fs",
	"pop		es",
	"pop		ds",
	"popad",
	// we need to remove the error code manually (see Intel manuals Vol.3A, 5.13)
	"add		esp, 4",
	"iretd",

	// just call first original handler
	//"oldHandler :",
	"pop		gs",
	"pop		fs",
	"pop		es",
	"pop		ds",
	"popad",
	"jmp		dword ptr[origHandlers]"
	);
}

pub unsafe fn free_strings() {
	if !(DEVICE_NAME.2.load(Ordering::SeqCst) as PWCH).is_null() {
		ExFreePool(DEVICE_NAME.2.load(Ordering::SeqCst) as PVOID);
	}
	if !(DOS_DEVICE_NAME.2.load(Ordering::SeqCst) as PWCH).is_null() {
		ExFreePool(DOS_DEVICE_NAME.2.load(Ordering::SeqCst) as PVOID);
	}
	DEVICE_NAME.2.fetch_and(*WDF_NO_HANDLE.cast(), Ordering::SeqCst);
	DOS_DEVICE_NAME.2.fetch_and(*WDF_NO_HANDLE.cast(), Ordering::SeqCst);
}

pub unsafe fn vmrdsc_dispatch_create_close(device_object: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
	let mut status = STATUS_SUCCESS;
	(*irp).IoStatus.__bindgen_anon_1.Status = status;
	(*irp).IoStatus.Information = 0;
	IofCompleteRequest(irp, IO_NO_INCREMENT as CCHAR);
	status
}

pub unsafe fn vmrdtsc_dispatch_device_control(_device_object: PDEVICE_OBJECT, irp: PIRP) -> NTSTATUS {
	let mut status = STATUS_SUCCESS;
	let irp_sp: PIO_STACK_LOCATION = IoGetCurrentIrpStackLocation(irp);
	match (*irp_sp).Parameters.DeviceIoControl.IoControlCode {
		IOCTL_VMRDTSC_METHOD_ALWAYS_CONST => {
			if (*irp_sp).Parameters.DeviceIoControl.InputBufferLength == size_of_val::<ULONG>(&0) as u32 {
				METHOD_INCREASING.fetch_and(false, Ordering::SeqCst);
				CONST_VALUE.fetch_and(*((*irp).AssociatedIrp.SystemBuffer as PULONG) as usize, Ordering::SeqCst);
			} else {
				status = STATUS_INVALID_PARAMETER;
			}
		}
		IOCTL_VMRDTSC_METHOD_INCREASING => {
			if (*irp_sp).Parameters.DeviceIoControl.InputBufferLength == size_of_val::<ULONG>(&0) as u32 {
				asm!(
				"push eax",
				"push ecx",
				"push edx",
				"rdtsc",
				"lea ecx, {}",
				"mov dword ptr[ecx], eax",
				"mov dword ptr[ecx + 4], edx",
				"pop edx",
				"pop ecx",
				"pop eax",
				in(reg) RDTSC_VALUE.load(Ordering::SeqCst),
				);
				DELTA.fetch_and(*((*irp).AssociatedIrp.SystemBuffer as PULONG) as usize, Ordering::SeqCst);
				METHOD_INCREASING.fetch_and(true, Ordering::SeqCst);
				(*irp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
			} else {
				status = STATUS_INVALID_PARAMETER;
			}
		}
		_ => {
			(*irp).IoStatus.__bindgen_anon_1.Status = STATUS_INVALID_DEVICE_REQUEST;
			(*irp).IoStatus.Information = 0;
		}
	}
	status = (*irp).IoStatus.__bindgen_anon_1.Status;
	IofCompleteRequest(irp, IO_NO_INCREMENT as CCHAR);
	status
}

pub unsafe extern "C" fn unload_driver(driver: WDFDRIVER) {
	let mut driver_object = WdfDriverWdmGetDriverObject(driver);
	let mut pdo_next_device_obj = (*driver_object).DeviceObject;
	let mut dos_device_name = UNICODE_STRING {
		Length: DOS_DEVICE_NAME.0.load(Ordering::SeqCst) as USHORT,
		MaximumLength: DOS_DEVICE_NAME.1.load(Ordering::SeqCst) as USHORT,
		Buffer: DOS_DEVICE_NAME.2.load(Ordering::SeqCst) as PWCH,
	};
	IoDeleteSymbolicLink(ptr::addr_of_mut!(dos_device_name) as PUNICODE_STRING);
	while !pdo_next_device_obj.is_null() {
		let pdo_this_device_obj = pdo_next_device_obj;
		pdo_next_device_obj = (*pdo_this_device_obj).NextDevice as PDEVICE_OBJECT;
		IoDeleteDevice(pdo_this_device_obj);
	}
	remove_hooks();
	free_strings();
}


pub unsafe fn get_randomized_name(registry_path: PUNICODE_STRING) -> PWSTR {
	let registry_key: UNICODE_STRING;
	let mut value_name: UNICODE_STRING = UNICODE_STRING {
		Length: 0,
		MaximumLength: 0,
		Buffer: 0 as PWCH,
	};
	let obj_attr: OBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES {
		Length: 0,
		RootDirectory: 0 as HANDLE,
		ObjectName: 0 as PUNICODE_STRING,
		Attributes: 0,
		SecurityDescriptor: 0 as PVOID,
		SecurityQualityOfService: 0 as PVOID,
	};
	let hkey: HANDLE = WDF_NO_HANDLE.cast();
	RtlInitUnicodeString(ptr::from_mut(&mut value_name), ptr::from_ref("DisplayName") as PCWSTR);
	InitializeObjectAttributes(ptr::from_ref(&obj_attr) as POBJECT_ATTRIBUTES, registry_path, OBJ_KERNEL_HANDLE, WDF_NO_HANDLE.cast(), WDF_NO_HANDLE.cast());
	let mut result: PWSTR = WDF_NO_HANDLE.cast();
	let mut status: NTSTATUS = ZwOpenKey(ptr::from_ref(&hkey) as PHANDLE, KEY_READ, ptr::from_ref(&obj_attr) as POBJECT_ATTRIBUTES);
	if nt_success(status) {
		let mut size: ULONG = 0;
		status = ZwQueryValueKey(hkey, ptr::from_ref(&value_name) as PUNICODE_STRING, KeyValuePartialInformation, WDF_NO_HANDLE.cast(), 0, ptr::from_ref(&size) as PULONG);
		if status == STATUS_BUFFER_TOO_SMALL && size > 0 {
			let vpip: PKEY_VALUE_PARTIAL_INFORMATION = ExAllocatePool(PagedPool, size as SIZE_T) as PKEY_VALUE_PARTIAL_INFORMATION;
			if !vpip.is_null() {
				status = ZwQueryValueKey(hkey, ptr::from_ref(&value_name) as PUNICODE_STRING, KeyValuePartialInformation, vpip as PVOID, size, ptr::from_ref(&size) as PULONG);
				if nt_success(status) {
					result = ExAllocatePool(PagedPool, (*vpip).DataLength as SIZE_T) as PWSTR;
					RtlStringCbCopyW(result, (*vpip).DataLength as SIZE_T, ptr::from_mut(&mut (*vpip).Data) as PCWSTR);
					ExFreePool(vpip as PVOID);
				}
			}
		}
		ZwClose(hkey);
	}
	result
}

pub unsafe fn build_device_name(dest: PUNICODE_STRING, dev_name: PCWSTR, random_part: PCWSTR) -> bool {
	let buf_len = ((wcslen(dev_name) + wcslen(random_part) + 1) as usize * size_of::<WCHAR>()) as SIZE_T;
	let dev_name_buf = ExAllocatePool(PagedPool, buf_len as SIZE_T) as PWSTR;
	if dev_name_buf.is_null() {
		return false;
	}
	RtlStringCbCopyW(dev_name_buf, buf_len, dev_name);
	RtlStringCbCatW(dev_name_buf, buf_len, random_part);
	RtlInitUnicodeString(dest, dev_name_buf);
	true
}


