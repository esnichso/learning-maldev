use std::ffi::c_void;
use windows::Win32::System::Diagnostics::Debug::{
    CaptureStackBackTrace, RtlCaptureContext, CONTEXT, CONTEXT_FULL,
    IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc,
};
use windows::core::PCSTR;

// Function pointer types for the NT functions we resolve at runtime.
// These are not in the windows crate's safe wrappers.
type FnRtlCaptureContext = unsafe extern "system" fn(context: *mut CONTEXT);
type FnRtlRestoreContext = unsafe extern "system" fn(context: *const CONTEXT, exception: *mut c_void) -> !;

fn main() {
    unsafe {
        // Step 1 — Print the unmodified call stack so we have a baseline.
        //
        // CaptureStackBackTrace walks the current thread's call stack and fills
        // an array of return-address pointers (void*). We'll call it here and
        // again after spoofing to compare.
        //
        // Hint: CaptureStackBackTrace(
        //     FramesToSkip: u32,           // 0 — start from the current frame
        //     FramesToCapture: u32,        // 16 — capture up to 16 frames
        //     BackTrace: *mut *mut c_void, // pointer to your frame pointer array
        //     BackTraceHash: *mut u32,     // pointer to a u32 for the hash, or null
        // ) -> u16                         // number of frames actually captured
        let mut frames_before = [std::ptr::null_mut::<c_void>(); 16];
        let count_before: u16 = todo!(
            "CaptureStackBackTrace(0, 16, frames_before.as_mut_ptr(), std::ptr::null_mut())"
        );
        println!("=== Stack BEFORE spoofing ({} frames) ===", count_before);
        for i in 0..count_before as usize {
            println!("  [{:02}] {:p}", i, frames_before[i]);
        }

        // Step 2 — Resolve RtlCaptureContext and RtlRestoreContext from ntdll.
        //
        // These functions are exported by ntdll.dll but are not wrapped by the
        // windows crate as safe APIs, so we resolve them manually.
        //
        // Hint: GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr())) -> HMODULE
        //       GetProcAddress(hmod, PCSTR(b"RtlCaptureContext\0".as_ptr())) -> Option<unsafe extern "system" fn()>
        //       Transmute the fn pointer to FnRtlCaptureContext / FnRtlRestoreContext.
        let hntdll = todo!("GetModuleHandleA(\"ntdll.dll\")") as *mut c_void;
        assert!(!hntdll.is_null(), "GetModuleHandleA failed");

        let rtl_capture: FnRtlCaptureContext = todo!("GetProcAddress + transmute for RtlCaptureContext");
        let rtl_restore: FnRtlRestoreContext = todo!("GetProcAddress + transmute for RtlRestoreContext");

        // Step 3 — Find a legitimate-looking return address inside ntdll's .text section.
        //
        // We need an address that, when a stack-walker inspects it, looks like it belongs
        // to ntdll code. Parse ntdll's in-memory PE headers to locate .text and pick an
        // offset inside it. Any address inside .text works for this demo.
        //
        // Hint: cast hntdll to *const IMAGE_DOS_HEADER to get e_lfanew.
        //       Then cast (hntdll as usize + e_lfanew as usize) to *const IMAGE_NT_HEADERS64.
        //       Iterate section headers (pointer after IMAGE_NT_HEADERS64) to find the one
        //       named ".text" — its VirtualAddress gives the RVA. Add to hntdll base.
        //       Pick offset 0x1000 into .text as your fake return address.
        let fake_ret_addr: usize = todo!(
            "parse ntdll PE headers to get hntdll + .text.VirtualAddress + 0x1000"
        );
        println!("Using fake return address: {:#x}", fake_ret_addr);

        // Step 4 — Capture the current register context (needed for restoration later).
        //
        // RtlCaptureContext fills a CONTEXT with all register values at the moment of
        // the call. We'll use this saved context to restore execution after the spoofed call.
        //
        // ContextFlags must be set before calling RtlCaptureContext.
        let mut saved_ctx = CONTEXT {
            ContextFlags: CONTEXT_FULL,
            ..Default::default()
        };
        todo!("rtl_capture(&mut saved_ctx)");

        // Step 5 — Call VirtualAlloc with a spoofed return address on the stack.
        //
        // The idea: before calling VirtualAlloc, we manipulate RSP so that the
        // "return address" that VirtualAlloc would push-back-to is our fake_ret_addr
        // rather than the real next instruction in this function.
        //
        // Inline assembly approach:
        //   1. Save current RSP in a register (e.g. r11)
        //   2. Subtract 8 from RSP to make room for our fake return address
        //   3. Write fake_ret_addr to [RSP]
        //   4. Subtract 32 more bytes for shadow space (required by x64 calling convention)
        //   5. Call VirtualAlloc — it will see our fake address as its caller
        //   6. Add 40 to RSP to undo steps 2+4, restore
        //   7. Move the return value (RAX) into a Rust variable
        //
        // Hint: asm!(
        //     "sub rsp, 8",          // make room for fake return address
        //     "mov [{rsp}], {ret}",  // write fake_ret_addr to [RSP]
        //     "sub rsp, 32",         // shadow space for the call
        //     // set up args: rcx=null, rdx=0x1000, r8=MEM_COMMIT|MEM_RESERVE, r9=PAGE_EXECUTE_READWRITE
        //     "call {fn}",           // call VirtualAlloc
        //     "add rsp, 40",         // undo shadow + fake-ret slot
        //     ...
        // )
        //
        // For a simpler first attempt: call VirtualAlloc normally but insert the fake
        // address as a test — just push/pop around a normal call and observe CaptureStackBackTrace.
        //
        // x64 calling convention for VirtualAlloc:
        //   rcx = lpAddress (null = OS chooses)
        //   rdx = dwSize    (0x1000)
        //   r8  = flAllocationType (MEM_COMMIT | MEM_RESERVE = 0x3000)
        //   r9  = flProtect (PAGE_EXECUTE_READWRITE = 0x40)
        //   returns: rax = allocated pointer (null on failure)
        let alloc_ptr: *mut c_void;
        todo!(
            r#"
            use core::arch::asm;
            asm!(
                // spoofed-frame setup here
                // call VirtualAlloc
                // teardown
                ...
            );
            "#
        );
        println!("VirtualAlloc returned: {:p}", alloc_ptr);

        // Step 6 — Capture stack after the spoofed call and compare.
        //
        // At this point the call has returned, so the stack is restored. But during
        // the call, a stack-walker would have seen fake_ret_addr at the top.
        // For verification, capture the trace again and confirm the frames changed.
        let mut frames_after = [std::ptr::null_mut::<c_void>(); 16];
        let count_after: u16 = todo!(
            "CaptureStackBackTrace(0, 16, frames_after.as_mut_ptr(), std::ptr::null_mut())"
        );
        println!("\n=== Stack AFTER spoofed call ({} frames) ===", count_after);
        for i in 0..count_after as usize {
            println!("  [{:02}] {:p}", i, frames_after[i]);
        }

        println!("\nFake return address used: {:#x}", fake_ret_addr);
        println!("ntdll base: {:p}", hntdll);
    }
}
