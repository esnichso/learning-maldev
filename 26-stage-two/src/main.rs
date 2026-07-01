// Stage-two payload for Module 26 — Staged Payloads.
//
// This binary is the "agent" that the stager downloads at runtime and
// reflectively executes in memory. It never touches disk on the target.
//
// Build this crate first, then serve the resulting EXE over HTTP:
//   cargo build --target x86_64-pc-windows-gnu -p stage-two-payload
//   python3 -m http.server 8080   (from the directory containing stage_two_payload.exe)
//
// The stager in 26-staged-payloads downloads this binary, maps it like a
// reflective loader (Module 07 skills), and jumps to its entry point.

fn main() {
    std::process::Command::new("calc.exe")
        .spawn()
        .ok();
}
