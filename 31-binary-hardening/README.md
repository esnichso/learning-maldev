# Module 31 — Binary Hardening

## Concept

Every byte of a malware binary is a potential detection surface. Size matters for three reasons:

1. **Signature matching** — AV products match byte patterns and section metadata. Bloated binaries carry more identifiable patterns.
2. **Transfer time** — a 5 MB stager is far more conspicuous than a 50 KB one, especially for in-memory staging.
3. **Static analysis** — debug symbols, RTTI, and Rust's standard library add recognizable patterns that analysts use to understand the binary quickly.

This module applies a systematic set of hardening steps to module 01's shellcode runner, measuring size after each. The goal is to understand *what* contributes to binary size and *why* each optimization helps.

### What's inside a typical Rust Windows binary

| Component | Rough contribution |
|---|---|
| Debug symbols (`.pdata`, `.debug_*`) | 30-60% in debug builds |
| Rust standard library (allocator, panic, fmt) | 50-200 KB |
| CRT startup code (mingw runtime) | 10-30 KB |
| Your actual code | Often under 10 KB |
| windows crate feature code | Varies by features |

In a debug build, most of the binary is symbols and unoptimized codegen. In release with all settings applied, only your code and the minimum runtime remain.

---

## Task

The `src/main.rs` in this module is module 01's shellcode runner — do **not** change the code. Your task is entirely in `Cargo.toml` and optionally `.cargo/config.toml`.

### Step 1 — Establish the debug baseline

```bash
cargo build --target x86_64-pc-windows-gnu -p binary-hardening
ls -lh target/x86_64-pc-windows-gnu/debug/binary-hardening.exe
```

Record the size in the table below.

### Step 2 — Release baseline (no extra settings)

Temporarily set `[profile.release]` to empty (or comment out all settings) and build:

```bash
cargo build --target x86_64-pc-windows-gnu -p binary-hardening --release
ls -lh target/x86_64-pc-windows-gnu/release/binary-hardening.exe
```

### Step 3 — Apply settings one at a time

Add each setting to `[profile.release]` in `Cargo.toml`, rebuild, and record the size:

| Setting | What it does | Expected savings |
|---|---|---|
| `opt-level = "z"` | Optimize for size over speed | 10-30% vs `opt-level = 3` |
| `lto = true` | Link-time optimization: remove dead code across crate boundaries | 15-40% |
| `codegen-units = 1` | Single codegen unit: better whole-program optimization | 5-15% |
| `panic = "abort"` | No stack-unwinding machinery | 5-20 KB |
| `strip = true` | Remove debug symbols and section names from the PE | 30-60% in release |

Fill in your measured sizes:

| Configuration | Size (KB) |
|---|---|
| Debug build | ___ |
| Release (no extra settings) | ___ |
| + `opt-level = "z"` | ___ |
| + `lto = true` | ___ |
| + `codegen-units = 1` | ___ |
| + `panic = "abort"` | ___ |
| + `strip = true` | ___ |
| + linker flags (step 5) | ___ |

### Step 4 — Analyze with `cargo bloat`

Install cargo-bloat if not present (`cargo install cargo-bloat`), then run:

```bash
cargo bloat --target x86_64-pc-windows-gnu --release -p binary-hardening
cargo bloat --target x86_64-pc-windows-gnu --release -p binary-hardening --crates
```

The first command shows the largest individual functions. The second shows which crates contribute the most code. Look for:

- `std::` functions that you don't explicitly call (pulled in transitively)
- `core::fmt` machinery (formatting/panic infrastructure)
- `alloc::` items if you use `String` or `Vec`

### Step 5 — Additional linker flags (optional)

Add a `.cargo/config.toml` in the workspace root (or modify the existing one) with extra linker arguments. These are passed to `x86_64-w64-mingw32-gcc`:

```toml
[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"
rustflags = [
    "-C", "link-args=-s",          # strip via linker (redundant with strip=true but belt+braces)
    "-C", "link-args=-Wl,--gc-sections", # garbage-collect unreferenced sections
]
```

Measure the size again after adding these.

### Step 6 — Compare against `no_std` (module 29)

Build module 29's `no-std-malware` in release and compare:

```bash
cargo build --target x86_64-pc-windows-gnu -p no-std-malware --release
ls -lh target/x86_64-pc-windows-gnu/release/no_std_malware.exe
```

Add to your table. This shows the floor — the smallest achievable size for equivalent functionality.

---

## Key concepts

### `opt-level = "z"` vs `"s"` vs `3`

- `"3"` — maximum speed, ignores code size (default for release)
- `"s"` — balance of speed and size
- `"z"` — minimum size, may inline less and use slower code paths

For malware, `"z"` is almost always the right choice. Performance rarely matters.

### LTO (Link-Time Optimization)

Without LTO, each crate is compiled independently and the linker sees only object files. Dead code in dependencies isn't eliminated if the linker can't prove it's unused. With LTO, the compiler has a whole-program view and can remove much more aggressively.

`lto = "thin"` is faster to compile than `lto = true` (which means "fat" LTO) but less effective. For release builds, fat LTO is worth the wait.

### `strip = true`

On GNU targets, this runs `x86_64-w64-mingw32-strip --strip-all` on the output. It removes:
- `.debug_*` sections (DWARF debug info)
- Symbol table entries
- Section name strings

The result: analysts using tools like `readpe` or `dumpbin` see less metadata. The binary also stops carrying Rust source file paths embedded in panic messages.

### `panic = "abort"`

Without this, Rust's default `panic!` triggers stack unwinding — the runtime walks the call stack, running `Drop` implementations and printing a backtrace. This requires significant runtime machinery (`libunwind`, exception tables, RTTI). Setting `panic = "abort"` replaces all of this with a single instruction: `ud2` (undefined instruction), which immediately kills the process. For malware, crashing fast is preferable to printing a backtrace that reveals your code.

---

## Detection implications

A heavily stripped binary is *smaller* but not necessarily *less detectable*. In fact:

- Stripped binaries with no version info, no PDB path, no compile timestamps, and no imports stand out as suspicious because legitimate software always has these.
- The right balance: make the binary look like a legitimate stripped release build — keep some imports, add version info (module 06), use a realistic section layout.

Module 06 (PE disguise) covers the complementary technique: adding convincing metadata rather than stripping everything.

---

## Acceptance Criteria

- [ ] Debug build size recorded in the table
- [ ] Each optimization step applied one at a time and size recorded
- [ ] `cargo bloat` run and interpreted — at least 2 large contributors identified
- [ ] Linker flags tested (step 5)
- [ ] Comparison against module 29's no_std binary made
- [ ] Table in README filled in with your measurements
- [ ] Written explanation in the README: which setting gave the biggest single reduction and why

---

## Submission

Fill in the size table above with your measurements and paste it here along with your final `Cargo.toml` and `.cargo/config.toml`. Explain which optimization gave the biggest impact and what `cargo bloat` showed.
