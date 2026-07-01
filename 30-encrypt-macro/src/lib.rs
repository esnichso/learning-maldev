// encrypt-macro — compile-time XOR string encryption proc macro.
//
// This crate implements one attribute macro:
//
//   #[xor_string]
//   static SECRET: &str = "MaldevObfuscated\0";
//
// The macro runs at compile time, XOR-encrypts the string literal with a
// randomly-generated key, and replaces the static declaration with code that
// holds the encrypted bytes and decodes them at runtime.
//
// Proc macros run as host-side code during compilation — they are a normal
// Rust binary that the compiler invokes. They can use std, do I/O, generate
// random numbers, and read the filesystem. The student binary they transform
// does not see any of this; it only sees the generated token stream.

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{parse_macro_input, Expr, ItemStatic, Lit};

/// Attribute macro applied to a `static &str` declaration.
/// Encrypts the string literal at compile time with a random XOR key.
///
/// Usage:
/// ```ignore
/// #[xor_string]
/// static SECRET: &str = "hello\0";
/// ```
///
/// Expands to something equivalent to:
/// ```ignore
/// static SECRET_ENC: [u8; N] = [/* XOR-encrypted bytes */];
/// static SECRET_KEY: u8 = /* random key */;
/// static SECRET: &str = /* runtime-decoded string */;
/// ```
///
/// In practice the expansion is a block expression so the static holds the
/// result of the runtime decode, keeping the interface identical for callers.
#[proc_macro_attribute]
pub fn xor_string(_attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse the input as a static item declaration.
    let input = parse_macro_input!(item as ItemStatic);

    // Step 1 — Extract the string literal value from the static's initialiser.
    //
    // The initialiser is `input.expr`. It should be an `Expr::Lit` containing
    // a `Lit::Str`. Anything else is a compile error.
    //
    // Hint:
    //   if let Expr::Lit(expr_lit) = *input.expr.clone() {
    //       if let Lit::Str(lit_str) = expr_lit.lit {
    //           let plaintext = lit_str.value(); // String
    //           ...
    //       }
    //   }
    //   panic!("xor_string requires a string literal as the static value");
    let plaintext: String = todo!(
        "extract the string value from input.expr — match Expr::Lit → Lit::Str → .value()"
    );

    // Step 2 — Generate a random XOR key.
    //
    // Proc macros run as host code, so std is available here.
    // Use std::time::SystemTime to get a pseudo-random seed and derive a byte key.
    //
    // Hint:
    //   use std::time::{SystemTime, UNIX_EPOCH};
    //   let seed = SystemTime::now()
    //       .duration_since(UNIX_EPOCH)
    //       .unwrap()
    //       .subsec_nanos();
    //   let key = (seed ^ (seed >> 8) ^ (seed >> 16)) as u8;
    //   if key == 0 { key = 0x5A; }  // avoid a zero key — XOR with 0 is identity
    let key: u8 = todo!("generate a non-zero random byte using SystemTime");

    // Step 3 — XOR-encrypt each byte of the plaintext.
    //
    // Hint: plaintext.bytes().map(|b| b ^ key).collect::<Vec<u8>>()
    let encrypted: Vec<u8> = todo!("XOR each byte of plaintext with key");

    // Step 4 — Generate the replacement token stream.
    //
    // We need to emit code that:
    //   a) Stores the encrypted bytes as a const array
    //   b) At runtime, XORs each byte back with the key
    //   c) Returns the decoded bytes as a &str (or &[u8])
    //
    // The static's name and visibility come from `input.ident` and `input.vis`.
    // Use `quote!` to construct the output token stream.
    //
    // Hint — emit something like:
    //   {vis} static {ident}: &str = {
    //       const ENCRYPTED: &[u8] = &[b0, b1, ...];
    //       const KEY: u8 = {key};
    //       // runtime decode into a fixed-size array on the stack
    //       // unsafe: from_utf8_unchecked
    //   };
    //
    // A simpler approach: emit a `static` holding a `[u8; N]` of encrypted
    // bytes, and a `fn decode_{ident}() -> [u8; N]` that XORs them back.
    // The caller calls the decode function. Document your choice in the README.

    let name = &input.ident;
    let vis = &input.vis;
    let enc_len = encrypted.len();
    let enc_bytes = encrypted.iter().map(|&b| {
        syn::LitByte::new(b, Span::call_site())
    });

    let expanded = todo!(
        "use quote! {{ ... }} to build a TokenStream that holds the encrypted bytes \
         and produces a runtime-decoded static; convert to proc_macro::TokenStream"
    );

    // Placeholder so the file compiles as a library (remove once Step 4 is done):
    let _ = (name, vis, enc_len, enc_bytes, key);
    expanded
}
