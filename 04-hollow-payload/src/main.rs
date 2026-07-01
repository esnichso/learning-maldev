#![windows_subsystem = "windows"]
// Hollow payload — this binary exists only to be embedded by 04-process-hollowing
// and hollowed into a suspended notepad.exe process. You do not implement this crate.
//
// Build first, then build 04-process-hollowing:
//   cargo build --target x86_64-pc-windows-gnu -p hollow-payload

fn main() {
    std::process::Command::new("calc.exe")
        .spawn()
        .ok();
}
