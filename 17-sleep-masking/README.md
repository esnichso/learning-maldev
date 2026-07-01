# Module 17 — Sleep Masking

## Concept

A beacon that does nothing while idle is still detectable if its memory is visible. Modern EDR products schedule periodic in-memory scans that walk every process's virtual address space looking for:

- RWX memory regions (write + execute is suspicious)
- PE headers in heap/anonymous memory (sign of a reflectively loaded implant)
- Known shellcode byte patterns or strings (YARA rules)

The naive countermeasure — `VirtualProtect` to `PAGE_NOACCESS` before sleeping and back after — is itself detected, because `VirtualProtect` calls are monitored and the pattern (RWX → NOACCESS → RWX around a Sleep) is a known IOC.

**Sleep masking** is the correct approach: *encrypt* the implant's memory before sleeping (so scanners see random bytes even if they bypass the protection change) and orchestrate the encrypt/sleep/decrypt cycle through a mechanism that doesn't look like the implant protecting itself.

### The Ekko technique

Ekko (by C5pider, 2022) uses a timer queue to schedule the encrypt/sleep/decrypt sequence on the Windows thread pool. The implant's own thread never calls `VirtualProtect` or `Sleep` — it simply creates some timers and then blocks on `WaitForSingleObject`. The actual memory operations happen on a system thread pool thread, so the call stack visible at scan time doesn't trace back to suspicious code.

```
Implant thread:
  CreateTimerQueueTimer(cb_encrypt,  delay=0ms)
  CreateTimerQueueTimer(cb_sleep,    delay=500ms)
  CreateTimerQueueTimer(cb_decrypt,  delay=1000ms)
  WaitForSingleObject(event, INFINITE)   ← implant blocks here

Thread pool (system thread):
  t=0ms:    cb_encrypt  → VirtualProtect(NOACCESS) + XOR encrypt
  t=500ms:  cb_sleep    → (nothing; the delay is the sleep)
  t=1000ms: cb_decrypt  → XOR decrypt + VirtualProtect(RWX) + SetEvent
```

The implant's main thread is not executing during the sleep window — it is stuck in `WaitForSingleObject`, which is a perfectly normal state for any thread.

### What this module does vs. full Ekko

Full Ekko also uses `RtlCaptureContext`/`RtlRestoreContext` (and sometimes a ROP chain) to encrypt the *stack* of the sleeping thread and swap it out during the sleep window, so stack scanning also finds nothing. That layer requires inline assembly and is covered in module 18 (call stack spoofing). This module implements the timer-based memory encryption loop, which is the core of the technique.

### Why this builds on prior modules

- Module 01: `VirtualAlloc` / `VirtualProtect` — same APIs
- Module 05: sleep obfuscation concept — this module makes it rigorous
- Module 13: XOR key encoding — same pattern applied to in-memory regions

---

## Key APIs

### `CreateTimerQueue`

Creates an empty timer queue object.

```
CreateTimerQueue() -> Result<HANDLE>   // returns a queue handle; close with DeleteTimerQueueEx
```

### `CreateTimerQueueTimer`

Adds a timer to a queue. The callback fires on a thread-pool thread.

```
CreateTimerQueueTimer(
    phnewtimer: *mut HANDLE,             // out: handle to the created timer
    timerqueue: HANDLE,                  // the queue to add this timer to
    callback: WAITORTIMERCALLBACK,       // fn(lpparameter: *mut c_void, timerorfired: u8)
    parameter: *mut c_void,              // passed as lpparameter to the callback — use this for shared state
    duetime: u32,                        // milliseconds before first fire
    period: u32,                         // repeat interval in ms; 0 = fire once then auto-delete
    flags: WORKER_THREAD_FLAGS,          // WT_EXECUTEDEFAULT for normal thread-pool execution
) -> Result<()>
```

### `WaitForSingleObject`

Blocks the calling thread until an object is signalled or a timeout expires.

```
WaitForSingleObject(
    hhandle: HANDLE,        // the object to wait on (event, mutex, process, thread, ...)
    dwmilliseconds: u32,    // timeout in ms; INFINITE = wait forever
) -> WAIT_EVENT             // WAIT_OBJECT_0 = signalled; WAIT_TIMEOUT = timed out; WAIT_FAILED = error
```

### `CreateEventA`

Creates a synchronization event — an object that can be signalled (`SetEvent`) or waited on.

```
CreateEventA(
    lpeventattributes: Option<*const SECURITY_ATTRIBUTES>, // None for default security
    bmanualreset: bool,    // true: stays signalled until ResetEvent; false: auto-resets after each wait
    binitialstate: bool,   // true: starts signalled; false: starts not-signalled
    lpname: PCSTR,         // optional name for cross-process sharing; PCSTR::null() for anonymous
) -> Result<HANDLE>
```

### `DeleteTimerQueueEx`

Destroys a timer queue and optionally waits for all in-flight callbacks to finish.

```
DeleteTimerQueueEx(
    timerqueue: HANDLE,    // the queue handle from CreateTimerQueue
    completionevent: HANDLE, // HANDLE::default() = don't wait; INVALID_HANDLE_VALUE = wait for callbacks
) -> Result<()>
```

---

## Task

Implement sleep masking in six steps. The skeleton in `src/main.rs` defines the three callbacks and the `xor_region` helper — you must implement the body of each `todo!()`.

### Step 1 — Allocate an RWX region simulating the implant

```
VirtualAlloc(
    lpaddress: Option<*const c_void>,        // None — OS chooses the address
    dwsize: usize,                           // 4096 — one page is enough for the demo
    flallocationtype: VIRTUAL_ALLOCATION_TYPE, // MEM_COMMIT | MEM_RESERVE
    flprotect: PAGE_PROTECTION_FLAGS,        // PAGE_EXECUTE_READWRITE — implant shellcode is RWX
) -> *mut c_void                             // NULL on failure
```

After allocating, write the string `b"IMPLANT_REGION\0"` into the start of the region. This is the "payload" you'll prove survives the encrypt/decrypt round-trip.

### Step 2 — Implement `xor_region`

```rust
fn xor_region(ptr: *mut u8, size: usize, key: u8) {
    // iterate i in 0..size, read *ptr.add(i), XOR with key, write back
}
```

XOR is its own inverse — call this with the same key to encrypt and to decrypt.

### Step 3 — Implement `cb_encrypt`

The first timer callback (fires at `duetime=0`):
1. Call `VirtualProtect` on the region with `PAGE_NOACCESS` — protect before encrypting
2. Call `xor_region` to encrypt
3. Increment `CALLBACKS_DONE`

```
VirtualProtect(
    lpaddress: *const c_void,             // state.region as *const c_void
    dwsize: usize,                        // state.size
    flnewprotect: PAGE_PROTECTION_FLAGS,  // PAGE_NOACCESS
    lpfloldprotect: *mut PAGE_PROTECTION_FLAGS, // &mut dummy — old value; not needed here
) -> Result<()>
```

### Step 4 — Implement `cb_sleep`

The second timer callback (fires at `duetime=500`). The delay *is* the sleep — the callback itself does nothing meaningful except count:
1. Increment `CALLBACKS_DONE`

### Step 5 — Implement `cb_decrypt`

The third timer callback (fires at `duetime=1000`):
1. Call `xor_region` to decrypt
2. Call `VirtualProtect` to restore `PAGE_EXECUTE_READWRITE`
3. Increment `CALLBACKS_DONE`
4. `SetEvent(state.event)` — wake the main thread

```
SetEvent(
    hevent: HANDLE,  // the event created in main
) -> Result<()>
```

### Step 6 — Queue the timers and wait

In `main`:
1. Create a wake event with `CreateEventA(None, true, false, PCSTR::null())`
2. Create a timer queue with `CreateTimerQueue()`
3. Queue all three callbacks with `CreateTimerQueueTimer` (see delays above)
4. Block with `WaitForSingleObject(wake_event, INFINITE)`
5. After returning, assert the region contents match the original marker

---

## Shared State Between Callbacks

Each callback receives `lpparameter: *mut c_void`. This is your `*mut MaskState` cast to `*mut c_void`. Inside the callback, cast back and dereference:

```rust
let state = &*(param as *const MaskState);
// now use state.region, state.size, state.key, state.event
```

The `MaskState` struct is heap-allocated with `Box::new` and converted to a raw pointer with `Box::into_raw`. The callbacks borrow it via a raw pointer — they must not outlive the allocation. In this exercise, the `main` function owns the allocation and lives longer than all callbacks, so this is safe.

---

## Acceptance Criteria

- [ ] `cargo build --target x86_64-pc-windows-gnu -p sleep-masking` succeeds
- [ ] Running the binary prints the marker string before masking, then confirms correct restoration after wake
- [ ] `cb_encrypt` fires first, `cb_sleep` fires second, `cb_decrypt` fires last — observable via print statements or a debugger
- [ ] `xor_region` encrypts and decrypts correctly (round-trip identity)
- [ ] `VirtualProtect` calls are made from the thread-pool callbacks, not from the main thread
- [ ] All three `CALLBACKS_DONE` increments occur before the main thread is released
- [ ] Timer queue is destroyed and handles closed in the cleanup path

---

## Key Types

**`WAITORTIMERCALLBACK`** — the type of a timer callback:
```rust
unsafe extern "system" fn(lpparameter: *mut c_void, timerorfired: u8)
```
Pass `Some(cb_encrypt)` (etc.) to `CreateTimerQueueTimer`. The second argument `timerorfired` is `1` if the callback fired because the timer elapsed (always true here).

**`AtomicU32`** — a Rust atomic integer. Used here as a thread-safe counter shared between the main thread and pool threads. `fetch_add(1, Ordering::SeqCst)` atomically increments and returns the old value.

**`WAIT_OBJECT_0`** — the success return value of `WaitForSingleObject` when the waited handle was signalled.

**`WT_EXECUTEDEFAULT`** — the standard flag for `CreateTimerQueueTimer`. Causes the callback to run on a thread from the default thread pool.

---

## Hints

- `CALLBACKS_DONE` is a global atomic — it doesn't need to be in `MaskState`. But `event` must be in `MaskState` because `cb_decrypt` needs it to signal wake-up.
- The timer delays are **from the moment `CreateTimerQueueTimer` is called**, not from the previous timer. Queue all three timers quickly so the delays are roughly accurate.
- `PAGE_NOACCESS` causes an access violation if anything reads or writes the region during the sleep window. In a real implant, you must make sure no other thread touches the implant's memory while it's encrypted.
- `DeleteTimerQueueEx(queue, HANDLE::default())` does not wait for running callbacks. If you need to guarantee no callbacks are in-flight after deleting, pass `INVALID_HANDLE_VALUE` as the second argument — but then the function blocks until they complete.
- `Box::into_raw` leaks the Box until you call `Box::from_raw` to reclaim it. In this exercise, it's acceptable to skip cleanup since the process exits immediately. In a real implant, track and free it.
- Full Ekko additionally encrypts the implant's stack by using `RtlCaptureContext` to save and restore thread context around the sleep — see module 18 for context manipulation with inline assembly.

---

## Submission

Paste `17-sleep-masking/src/main.rs` and ask for a review.
