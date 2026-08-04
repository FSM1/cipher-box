//! Lowercase hex encoding — a neutral wire/diagnostic helper.
//!
//! Not crypto: a byte-to-hex encoding of already-public bytes (a SEC1 public
//! key, a compact signature, a scope id). Secret material is never formatted —
//! it redacts instead ([`crate::suite::secret::SecretBytes`]).

/// Lowercase hex encoding of `bytes`.
pub fn lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).expect("high nibble is < 16"));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).expect("low nibble is < 16"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_pads_each_byte() {
        assert_eq!(lower(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    }
}
