//! Measures how long creating, enabling and disabling many detours takes
//! (Windows, x86-64).
//!
//! A hooking library typically detours dozens of exports while its host
//! process starts, so this cost is paid once per process. Each run creates
//! (without enabling) a detour of each export in `EXPORTS`, the file and
//! process functions a file-system virtualization layer detours. It then
//! creates detours of the same number of functions in a fresh mapping, spread
//! over a similar number of pages, and enables and disables them in one
//! transaction each.
//!
//! A run prints one line of timings in microseconds. Run it several times,
//! each a fresh process, since the first detour also pays for initializing
//! the decoder & encoder:
//!
//! ```text
//! cargo run --release --example many_detours
//! ```

#[cfg(all(windows, target_arch = "x86_64"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
  use detour::{RawDetour, Threads, Transaction};
  use std::time::Instant;
  use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};

  /// The prolog & epilog of a typical x86-64 function, which is relocatable.
  const FUNCTION: [u8; 16] = [
    0x48, 0x89, 0x5C, 0x24, 0x08, // mov [rsp+8], rbx
    0x57, // push rdi
    0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
    0x48, 0x83, 0xC4, 0x20, // add rsp, 0x20
    0x5F, // pop rdi
    0xC3, // ret
  ];
  /// The distance between the synthetic functions, which places the 109
  /// functions on 61 pages, as the exports below are on Windows 11 24H2.
  const STRIDE: usize = 2304;

  extern "system" fn replacement() {}

  // SAFETY: The name is NUL-terminated.
  unsafe { LoadLibraryA(c"ucrtbase.dll".as_ptr().cast()) };

  // Detours of the exports, not enabled
  let start = Instant::now();
  let mut exports = Vec::new();
  for (modules, name) in EXPORTS {
    let target = modules.iter().find_map(|module| {
      let module = std::ffi::CString::new(*module).ok()?;
      // SAFETY: Both names are NUL-terminated.
      unsafe {
        let handle = GetModuleHandleA(module.as_ptr().cast());
        GetProcAddress(handle, name.as_ptr().cast())
      }
    });
    let Some(target) = target else { continue };
    // SAFETY: The detour is never enabled.
    exports.push(unsafe { RawDetour::new(target as *const (), replacement as *const ())? });
  }
  let create_exports = start.elapsed();

  // Synthetic functions, in a mapping of their own
  let count = exports.len();
  let mut mapping = region::alloc(count * STRIDE, region::Protection::READ_WRITE)?;
  let base = mapping.as_mut_ptr::<u8>();
  for index in 0..count {
    // SAFETY: Each function lies within the mapping.
    unsafe {
      let function = base.add(index * STRIDE);
      core::ptr::write_bytes(function, 0xCC, STRIDE);
      core::ptr::copy_nonoverlapping(FUNCTION.as_ptr(), function, FUNCTION.len());
    }
  }
  // SAFETY: The mapping is owned, and nothing executes it yet.
  unsafe { region::protect(base, count * STRIDE, region::Protection::READ_EXECUTE)? };

  let start = Instant::now();
  let synthetic = (0..count)
    // SAFETY: Each target is a complete function.
    .map(|index| unsafe { RawDetour::new(base.add(index * STRIDE) as *const (), replacement as *const ()) })
    .collect::<detour::Result<Vec<_>>>()?;
  let create_synthetic = start.elapsed();

  let mut transaction = Transaction::new();
  synthetic
    .iter()
    .for_each(|detour| _ = transaction.enable(detour));
  let start = Instant::now();
  // SAFETY: No other thread executes the synthetic functions.
  unsafe { transaction.commit(Threads::None)? };
  let enable = start.elapsed();

  let mut transaction = Transaction::new();
  synthetic
    .iter()
    .for_each(|detour| _ = transaction.disable(detour));
  let start = Instant::now();
  // SAFETY: As above.
  unsafe { transaction.commit(Threads::None)? };
  let disable = start.elapsed();

  println!(
    "detours={count} create_exports_us={} create_synthetic_us={} enable_us={} disable_us={}",
    create_exports.as_micros(),
    create_synthetic.as_micros(),
    enable.as_micros(),
    disable.as_micros(),
  );
  drop(synthetic);
  drop(exports);
  Ok(())
}

/// The exports of a file-system virtualization layer, each with the modules
/// that may export it, in order of preference.
#[cfg(all(windows, target_arch = "x86_64"))]
const EXPORTS: &[(&[&str], &core::ffi::CStr)] = &[
  (&["ntdll.dll"], c"RtlExitUserProcess"),
  (&["ntdll.dll"], c"NtTerminateProcess"),
  (&["kernelbase.dll", "kernel32.dll"], c"CreateProcessW"),
  (&["kernelbase.dll", "kernel32.dll"], c"CreateProcessA"),
  (&["ntdll.dll"], c"NtCreateUserProcess"),
  (&["ntdll.dll"], c"NtSetInformationJobObject"),
  (&["ntdll.dll"], c"NtAssignProcessToJobObject"),
  (&["ntdll.dll"], c"NtClose"),
  (&["ntdll.dll"], c"NtWriteFile"),
  (&["kernelbase.dll", "kernel32.dll"], c"SetStdHandle"),
  (&["kernelbase.dll", "kernel32.dll"], c"WriteConsoleA"),
  (&["kernelbase.dll", "kernel32.dll"], c"WriteConsoleW"),
  (&["kernelbase.dll", "kernel32.dll"], c"VirtualAlloc"),
  (&["ntdll.dll"], c"RtlDosPathNameToNtPathName_U_WithStatus"),
  (
    &["ntdll.dll"],
    c"RtlDosPathNameToRelativeNtPathName_U_WithStatus",
  ),
  (&["ntdll.dll"], c"RtlDosPathNameToRelativeNtPathName_U"),
  (&["ntdll.dll"], c"RtlGetFullPathName_U"),
  (&["ntdll.dll"], c"RtlGetFullPathName_UEx"),
  (&["ntdll.dll"], c"NtCreateFile"),
  (&["ntdll.dll"], c"NtOpenFile"),
  (&["ntdll.dll"], c"NtQueryFullAttributesFile"),
  (&["ntdll.dll"], c"NtQueryAttributesFile"),
  (&["ntdll.dll"], c"NtSetInformationFile"),
  (&["kernelbase.dll", "kernel32.dll"], c"GetCurrentDirectoryW"),
  (&["kernelbase.dll", "kernel32.dll"], c"GetCurrentDirectoryA"),
  (&["kernelbase.dll", "kernel32.dll"], c"SetCurrentDirectoryW"),
  (&["kernelbase.dll", "kernel32.dll"], c"CreateDirectoryW"),
  (&["kernelbase.dll", "kernel32.dll"], c"RemoveDirectoryW"),
  (&["kernelbase.dll", "kernel32.dll"], c"GetLongPathNameW"),
  (&["kernelbase.dll", "kernel32.dll"], c"GetFullPathNameW"),
  (&["kernelbase.dll", "kernel32.dll"], c"GetFullPathNameA"),
  (&["kernelbase.dll", "kernel32.dll"], c"GetVolumePathNameW"),
  (&["kernelbase.dll", "kernel32.dll"], c"GetModuleFileNameW"),
  (&["kernelbase.dll", "kernel32.dll"], c"GetModuleFileNameExW"),
  (&["kernelbase.dll", "kernel32.dll"], c"GetModuleFileNameA"),
  (&["kernelbase.dll", "kernel32.dll"], c"GetModuleFileNameExA"),
  (&["kernelbase.dll", "kernel32.dll"], c"GetModuleHandleExW"),
  (&["kernelbase.dll", "kernel32.dll"], c"GetFileAttributesW"),
  (&["kernelbase.dll", "kernel32.dll"], c"SetFileAttributesW"),
  (&["kernelbase.dll", "kernel32.dll"], c"GetFileAttributesExW"),
  (&["kernelbase.dll", "kernel32.dll"], c"CopyFileW"),
  (&["kernelbase.dll", "kernel32.dll"], c"CopyFileExW"),
  (&["kernelbase.dll", "kernel32.dll"], c"CreateHardLinkW"),
  (&["kernelbase.dll", "kernel32.dll"], c"DeleteFileW"),
  (
    &["kernelbase.dll", "kernel32.dll"],
    c"MoveFileWithProgressW",
  ),
  (&["kernelbase.dll", "kernel32.dll"], c"MoveFileExW"),
  (&["kernelbase.dll", "kernel32.dll"], c"FindFirstFileW"),
  (&["kernelbase.dll", "kernel32.dll"], c"FindFirstFileExW"),
  (&["kernelbase.dll", "kernel32.dll"], c"FindFirstFileA"),
  (&["kernelbase.dll", "kernel32.dll"], c"FindFirstFileExA"),
  (&["kernelbase.dll", "kernel32.dll"], c"FindNextFileW"),
  (&["kernelbase.dll", "kernel32.dll"], c"FindNextFileA"),
  (&["kernelbase.dll", "kernel32.dll"], c"FindClose"),
  (
    &["kernelbase.dll", "kernel32.dll"],
    c"GetFinalPathNameByHandleW",
  ),
  (&["kernelbase.dll", "kernel32.dll"], c"SearchPathW"),
  (&["kernelbase.dll", "kernel32.dll"], c"LoadLibraryExW"),
  (&["kernelbase.dll", "kernel32.dll"], c"GetDriveTypeW"),
  (&["kernelbase.dll", "kernel32.dll"], c"GetDiskFreeSpaceExW"),
  (
    &["kernelbase.dll", "kernel32.dll"],
    c"GetVolumeInformationW",
  ),
  (&["ntdll.dll"], c"NtReadFile"),
  (&["ntdll.dll"], c"NtQueryInformationFile"),
  (&["ntdll.dll"], c"NtQueryVolumeInformationFile"),
  (&["ntdll.dll"], c"NtQueryDirectoryFile"),
  (&["ntdll.dll"], c"NtFsControlFile"),
  (&["ntdll.dll"], c"NtDeviceIoControlFile"),
  (&["ntdll.dll"], c"NtQueryObject"),
  (&["ntdll.dll"], c"NtQuerySecurityObject"),
  (&["ntdll.dll"], c"NtSetInformationObject"),
  (&["ntdll.dll"], c"NtCreateSection"),
  (&["ntdll.dll"], c"NtFlushBuffersFile"),
  (&["kernelbase.dll", "kernel32.dll"], c"DuplicateHandle"),
  (&["kernelbase.dll", "kernel32.dll"], c"LockFile"),
  (&["kernelbase.dll", "kernel32.dll"], c"LockFileEx"),
  (&["kernelbase.dll", "kernel32.dll"], c"UnlockFile"),
  (&["kernelbase.dll", "kernel32.dll"], c"UnlockFileEx"),
  (&["kernelbase.dll", "kernel32.dll"], c"FlushFileBuffers"),
  (&["kernelbase.dll", "kernel32.dll"], c"SetFileTime"),
  (&["kernelbase.dll", "kernel32.dll"], c"GetFileType"),
  (
    &["kernelbase.dll", "kernel32.dll"],
    c"GetFileInformationByHandle",
  ),
  (
    &["kernelbase.dll", "kernel32.dll"],
    c"GetFileInformationByHandleEx",
  ),
  (
    &["kernelbase.dll", "kernel32.dll"],
    c"GetVolumeInformationByHandleW",
  ),
  (&["kernelbase.dll", "kernel32.dll"], c"CreateFileMappingW"),
  (&["kernel32.dll", "kernelbase.dll"], c"CreateFileMappingA"),
  (&["kernelbase.dll", "kernel32.dll"], c"OpenFileMappingW"),
  (&["kernelbase.dll", "kernel32.dll"], c"MapViewOfFile"),
  (&["kernelbase.dll", "kernel32.dll"], c"MapViewOfFileEx"),
  (&["kernelbase.dll", "kernel32.dll"], c"UnmapViewOfFile"),
  (&["kernelbase.dll", "kernel32.dll"], c"UnmapViewOfFileEx"),
  (&["kernelbase.dll", "kernel32.dll"], c"FlushViewOfFile"),
  (&["kernelbase.dll", "kernel32.dll"], c"GetConsoleMode"),
  (&["kernelbase.dll", "kernel32.dll"], c"SetConsoleMode"),
  (&["kernelbase.dll", "kernel32.dll"], c"ReadConsoleW"),
  (&["kernelbase.dll", "kernel32.dll"], c"WaitForSingleObject"),
  (
    &["kernelbase.dll", "kernel32.dll"],
    c"WaitForSingleObjectEx",
  ),
  (
    &["kernelbase.dll", "kernel32.dll"],
    c"WaitForMultipleObjects",
  ),
  (
    &["kernelbase.dll", "kernel32.dll"],
    c"WaitForMultipleObjectsEx",
  ),
  (
    &["kernel32.dll", "kernelbase.dll"],
    c"RegisterWaitForSingleObject",
  ),
  (&["kernel32.dll", "kernelbase.dll"], c"GetExitCodeProcess"),
  (&["kernelbase.dll"], c"PathSearchAndQualifyW"),
  (&["kernelbase.dll"], c"GetFileInformationByName"),
  (&["ucrtbase.dll"], c"_wgetcwd"),
  (&["ucrtbase.dll"], c"_wfullpath"),
  (&["ucrtbase.dll"], c"_fullpath"),
  (&["ucrtbase.dll"], c"_get_wpgmptr"),
  (&["ucrtbase.dll"], c"__p__wpgmptr"),
  (&["ucrtbase.dll"], c"_waccess_s"),
  (&["ntdll.dll"], c"NtCopyFileChunk"),
  (&["kernelbase.dll"], c"MapViewOfFile3"),
  (&["ntdll.dll"], c"NtQueryDirectoryFileEx"),
];

#[cfg(not(all(windows, target_arch = "x86_64")))]
fn main() {
  eprintln!("This example only runs on Windows x86-64");
}
