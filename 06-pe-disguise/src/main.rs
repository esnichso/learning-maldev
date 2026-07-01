use std::env;
use std::ffi::c_void;
use windows::Win32::System::Diagnostics::Debug::{
    CheckSumMappedFile, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: pe-disguise.exe <input.exe> [output.exe]");
        std::process::exit(1);
    }
    let input_path = &args[1];
    let output_path = args.get(2).unwrap_or(input_path);

    let mut bytes = std::fs::read(input_path).expect("failed to read input file");

    unsafe {
        // Step 1 — Parse and validate the PE headers.
        // Hint: cast bytes.as_ptr() to *const IMAGE_DOS_HEADER
        //       check (*dos).e_Magic == 0x5A4D (MZ)
        //       follow (*dos).e_lfanew to IMAGE_NT_HEADERS64
        //       check (*nt).Signature == 0x00004550 (PE\0\0)
        let dos: *mut IMAGE_DOS_HEADER = todo!("parse DOS header");
        let nt: *mut IMAGE_NT_HEADERS64 = todo!("follow e_lfanew to NT headers");

        // Step 2 — Stomp the timestamp.
        // Hint: (*nt).FileHeader.TimeDateStamp = <some plausible u32 value>
        todo!("write new timestamp into FileHeader.TimeDateStamp");

        // Step 3 — Normalize section names.
        // Hint: section headers start at:
        //   nt_ptr + size_of::<u32>() + size_of::<IMAGE_FILE_HEADER>() + SizeOfOptionalHeader
        // There are (*nt).FileHeader.NumberOfSections of them.
        // Each IMAGE_SECTION_HEADER.Name is [u8; 8] — overwrite in place.
        todo!("walk sections and normalize names");

        // Step 4 — Recalculate the checksum.
        // Hint: call CheckSumMappedFile(bytes.as_mut_ptr() as *mut c_void, bytes.len() as u32, ...)
        //       then write the output into (*nt).OptionalHeader.CheckSum
        todo!("recompute and write checksum");
    }

    std::fs::write(output_path, &bytes).expect("failed to write output file");
    println!("wrote {}", output_path);
}
