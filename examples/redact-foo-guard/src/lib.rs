//! A trivial example guard: redact the literal token `FOO`.
//!
//! It exports `scan(text) -> verdict` from the `cerberust:guard` world and imports
//! nothing — the guest has no host capability, so it is a pure function over the
//! text it is handed. The host loads the compiled component as a `WasmScanner`.

wit_bindgen::generate!({
    world: "guard",
    path: "../../wit",
});

use exports::cerberust::guard::scanner::{Guest, Verdict};

struct Guard;

impl Guest for Guard {
    fn scan(text: String) -> Verdict {
        let redacted = text.replace("FOO", "[REDACTED]");
        let found = redacted != text;
        Verdict {
            text: redacted,
            valid: !found,
            risk: if found { 1.0 } else { 0.0 },
        }
    }
}

export!(Guard);
