// Stage-two payload — embedded by 13-payload-staging as a PE binary.
// Its only job is to produce a visible effect so you can confirm execution.
//
// Build first:
//   cargo build --target x86_64-pc-windows-gnu -p stage-two

fn main() {
    std::process::Command::new("calc.exe").spawn().ok();
}
