//! Shared secret-comparison helpers (blueprint/engine.md "Grants and ledger").
//!
//! Constant-time equality over 32-byte secret material, used wherever a seed or
//! a derived key is compared so a mismatch is never a timing oracle. The engine
//! holds no crypto; this is a hardened byte compare, not a primitive.

/// Constant-time 32-byte equality: no data-dependent early exit, so a mismatch
/// between two secret 32-byte values (a seed or a derived read key) is never a
/// timing oracle over the secret.
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
}
