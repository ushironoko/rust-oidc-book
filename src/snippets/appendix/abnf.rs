// RFC 7636 と RFC 6749 付録A の ABNF を、そのまま Rust の判定関数に写す

// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

// code-verifier = 43*128unreserved
fn is_code_verifier(s: &str) -> bool {
    (43..=128).contains(&s.len()) && s.bytes().all(is_unreserved)
}

// VSCHAR = %x20-7E
fn is_vschar(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

// state = 1*VSCHAR
fn is_state(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(is_vschar)
}

// NQCHAR = %x21 / %x23-5B / %x5D-7E (空白・二重引用符・バックスラッシュ以外)
fn is_nqchar(b: u8) -> bool {
    b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b)
}

// scope = scope-token *( SP scope-token ) / scope-token = 1*NQCHAR
fn is_scope(s: &str) -> bool {
    s.split(' ').all(|t| !t.is_empty() && t.bytes().all(is_nqchar))
}

fn main() {
    let verifiers = [
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        "too-short",
        "dBjftJeZ4CVP+mB92K27uhbUJU1p1r/wW1gFWFOEjXk",
    ];
    for v in verifiers {
        println!("code_verifier {v:?} => {}", is_code_verifier(v));
    }
    for s in ["af0ifjsldkj", "", "日本語"] {
        println!("state {s:?} => {}", is_state(s));
    }
    for s in ["openid profile email", "openid  profile", "openid \"profile\""] {
        println!("scope {s:?} => {}", is_scope(s));
    }
}
