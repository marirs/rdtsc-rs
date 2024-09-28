use wdk_sys::{HANDLE, NTSTATUS, PCWSTR, PDRIVER_OBJECT, PIO_STACK_LOCATION, PIRP, POBJECT_ATTRIBUTES, PSECURITY_DESCRIPTOR, PUNICODE_STRING, PWSTR, SIZE_T, ULONG, WDFDRIVER};

extern "C" {
	pub fn WdfDriverWdmGetDriverObject(driver: WDFDRIVER) -> PDRIVER_OBJECT;

	pub fn RtlStringCbCopyW(pszDest: PWSTR, cbDest: SIZE_T, pszSrc: PCWSTR) -> NTSTATUS;

	pub fn RtlStringCbCatW(pszDest: PWSTR, cbDest: SIZE_T, pszSrc: PCWSTR) -> NTSTATUS;

	pub fn InitializeObjectAttributes(p: POBJECT_ATTRIBUTES, n: PUNICODE_STRING, a: ULONG, r: HANDLE, s: PSECURITY_DESCRIPTOR);

	pub fn IoGetCurrentIrpStackLocation(Irp: PIRP) -> PIO_STACK_LOCATION;
}
