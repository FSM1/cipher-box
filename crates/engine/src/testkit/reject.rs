//! The shape every reject family shares: one refusal the live code produced,
//! and the surface it must sit on.
//!
//! A vector's `check` and `class` are read off an error value a real call
//! returned, never written down — so a verdict that quietly moves surfaces or
//! classes shows up as a diff against the committed vectors under
//! `crates/engine/kat`, written by `examples/kat_gen.rs`.

use std::collections::BTreeSet;

/// One refusal the live code produced, and the verdict it must keep.
pub struct RejectVector {
    /// A short description of the fixture that provoked the refusal.
    pub name: &'static str,
    /// The check the returned error named.
    pub check: &'static str,
    /// The class label the returned error carried.
    pub class: &'static str,
}

/// One error type's reject vectors and the surface they must sit on.
pub struct RejectFamily {
    /// The file stem under the corpus's `vectors/`, e.g. `"reseal"`.
    pub plane: &'static str,
    /// The type's `CHECKS`.
    pub surface: &'static [&'static str],
    /// The refusals this family pins, in build order.
    pub vectors: Vec<RejectVector>,
}

/// Read the verdict pair off an error value. A macro, not a generic function:
/// the engine's error types share `check`/`class` by convention, not by a trait.
macro_rules! refusal {
    ($name:expr, $error:expr $(,)?) => {{
        let error = $error;
        $crate::testkit::reject::RejectVector {
            name: $name,
            check: error.check(),
            class: error.class(),
        }
    }};
}

pub(crate) use refusal;

/// Assemble a family, refusing a duplicate name or an off-surface check. A
/// variant that delegates its verdict to another surface is pinned by that
/// type's order test instead, so it never appears here.
pub fn family(
    plane: &'static str,
    surface: &'static [&'static str],
    vectors: Vec<RejectVector>,
) -> RejectFamily {
    let mut names = BTreeSet::new();
    for vector in &vectors {
        assert!(
            names.insert(vector.name),
            "{plane}: duplicate vector name {}",
            vector.name
        );
        assert!(
            surface.contains(&vector.check),
            "{plane}: {} names off-surface check {}",
            vector.name,
            vector.check
        );
    }
    RejectFamily {
        plane,
        surface,
        vectors,
    }
}
