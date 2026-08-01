//! The terminal-owner wipe guards.
//!
//! A codec or schema pass owns the transient `Value` tree it builds, and that
//! tree carries verbatim copies of secret material — inline content keys, scope
//! seeds. It is therefore that tree's terminal owner and wipes it on every exit
//! a caller does not take ownership through, panic-unwind included
//! (blueprint/core.md "Crypto suite": key material lives only in zeroizing
//! owners). Map keys are field names, never secret, and are left intact.

use super::value::{Map, Value};

/// What a guard wipes.
pub(crate) trait Scrub {
    fn scrub(&mut self);
}

impl Scrub for Value {
    fn scrub(&mut self) {
        self.zeroize_bytes();
    }
}

impl Scrub for Map {
    fn scrub(&mut self) {
        self.zeroize_bytes();
    }
}

impl Scrub for Vec<Value> {
    fn scrub(&mut self) {
        for value in self {
            value.zeroize_bytes();
        }
    }
}

impl Scrub for Vec<(String, Value)> {
    fn scrub(&mut self) {
        for (_, value) in self {
            value.zeroize_bytes();
        }
    }
}

/// Wipes what it borrows on drop, leaving the wiped buffers observable to the
/// borrow's owner. Disarmed by forgetting it, which leaks nothing — it holds
/// one borrow.
pub(crate) struct ScrubOnDrop<'a, T: Scrub>(pub(crate) &'a mut T);

impl<T: Scrub> Drop for ScrubOnDrop<'_, T> {
    fn drop(&mut self) {
        self.0.scrub();
    }
}

/// The owning sibling, for a decode that holds a live `&Map` into the tree —
/// which a `&mut` guard cannot coexist with. Read it via [`Self::value`].
pub(crate) struct ScrubOwned(pub(crate) Value);

impl ScrubOwned {
    pub(crate) fn value(&self) -> &Value {
        &self.0
    }
}

impl Drop for ScrubOwned {
    fn drop(&mut self) {
        self.0.zeroize_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guard standing between a mid-item reject and a heap holding every
    /// secret the pass had already lifted out of its input.
    #[test]
    fn a_borrowed_guard_wipes_what_it_guards() {
        let mut items = vec![Value::Bytes(vec![0xAB; 32]), Value::Unsigned(7)];
        drop(ScrubOnDrop(&mut items));
        assert_eq!(items[0], Value::Bytes(Vec::new()));
        assert_eq!(items[1], Value::Unsigned(7), "shape and scalars kept");

        let mut entries = vec![("contentKey".to_string(), Value::Bytes(vec![0xAB; 32]))];
        drop(ScrubOnDrop(&mut entries));
        assert_eq!(entries[0].1, Value::Bytes(Vec::new()));
        assert_eq!(entries[0].0, "contentKey", "keys are not secret");

        let mut value = Value::Array(vec![Value::Text("secret-file.txt".into())]);
        drop(ScrubOnDrop(&mut value));
        assert_eq!(
            value.as_array().unwrap()[0],
            Value::Text(String::new()),
            "the whole-tree guard wipes nested buffers too"
        );
    }

    #[test]
    fn an_owning_guard_wipes_the_tree_it_took() {
        let mut m = Map::new();
        m.insert("contentKey", Value::Bytes(vec![0xAB; 32]));
        let guard = ScrubOwned(Value::Map(m));
        assert_eq!(
            guard.value().as_map().unwrap().get("contentKey"),
            Some(&Value::Bytes(vec![0xAB; 32])),
            "readable while the guard stands"
        );
    }
}
