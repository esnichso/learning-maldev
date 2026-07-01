// Module 30 — Proc Macro Obfuscation
//
// Build 30-encrypt-macro first (it's a proc-macro crate, which the compiler
// invokes as a host binary at compile time):
//   cargo build -p encrypt-macro           # host target, not cross-compiled
//   cargo build --target x86_64-pc-windows-gnu -p proc-macro-obfuscation
//
// After building in release mode, verify the plaintext string is absent:
//   strings target/x86_64-pc-windows-gnu/release/proc-macro-obfuscation.exe \
//       | grep -i maldev
//   (should print nothing)

use encrypt_macro::xor_string;
use windows::core::PCSTR;
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_OK};

// Step 1 — Apply the #[xor_string] attribute to a static string declaration.
//
// The proc macro will run at compile time and replace this static with an
// encrypted byte array + a runtime decode expression. The string must NOT
// appear as plaintext in the compiled binary.
//
// Hint: add #[xor_string] on the line above the static declaration below.
//       The macro expects a `static NAME: &str = "...";` declaration.
#[xor_string]
static SECRET: &str = "MaldevObfuscated\0";

// Step 2 — After the macro is implemented, call the decode function produced
// by the macro (or use SECRET directly if the macro emits a runtime expression)
// and pass it to MessageBoxA as the caption.
//
// The goal: MessageBoxA shows "MaldevObfuscated" but the string is not present
// as plaintext anywhere in the binary.
//
// Hint: MessageBoxA(
//     hwnd: HWND,           // None for no owner window
//     lptext: PCSTR,        // "Hello from proc macro\0" — the message body
//     lpcaption: PCSTR,     // decoded SECRET bytes as PCSTR
//     utype: MESSAGEBOX_STYLE, // MB_OK
// ) -> MESSAGEBOX_RESULT

fn main() {
    // Step 3 — Get the decoded bytes from SECRET (after the macro is working).
    //
    // If your macro emits a decode function, call it here.
    // If it emits a runtime-decoded &str directly, use SECRET.as_ptr().
    //
    // Hint: let decoded_ptr = SECRET.as_ptr(); // works if macro returns &str
    let decoded_ptr: *const u8 = todo!(
        "get a *const u8 pointer to the decoded string — SECRET.as_ptr() once the macro works"
    );

    unsafe {
        // Step 4 — Call MessageBoxA with the decoded secret as the caption.
        //
        // Hint: MessageBoxA(
        //     None,
        //     PCSTR(b"Proc macro obfuscation works!\0".as_ptr()),
        //     PCSTR(decoded_ptr),
        //     MB_OK,
        // );
        todo!("call MessageBoxA(None, body_pcstr, caption_pcstr, MB_OK)");
    }

    // Step 5 — Build in release mode and verify:
    //   cargo build --target x86_64-pc-windows-gnu -p proc-macro-obfuscation --release
    //   strings .../release/proc-macro-obfuscation.exe | grep -i maldev
    // Expected: no output (the plaintext "MaldevObfuscated" is absent).
    let _ = decoded_ptr;
}
