//! The frozen node-name law vectors, shared by every layer that answers for a
//! name: the engine law, the desktop projection, and the TypeScript client.
//!
//! One committed file, three consumers — a row edited here fails all of them,
//! which is the only way a divergence between the layers stays visible.

use serde::Deserialize;

use crate::name::NameError;

/// The committed vector file.
const VECTOR_JSON: &str = include_str!("../../name-law/vectors.json");

/// One name and the verdict the law owes it.
#[derive(Debug, Deserialize)]
pub struct NameRow {
    /// The name under test.
    pub name: String,
    /// `accept`, or the refusal's check label without its `node-name-` prefix.
    pub verdict: String,
    /// Whether the narrow tier can hand the name to a kernel.
    pub emittable: bool,
}

/// One folder's colliding children, in node id order, and the names a read
/// plane renders them under.
#[derive(Debug, Deserialize)]
pub struct CollisionRow {
    /// The stored names, in ascending node id order.
    pub names: Vec<String>,
    /// The name each of those children renders under.
    pub rendered: Vec<String>,
}

/// The whole vector set.
#[derive(Debug, Deserialize)]
pub struct NameLawVectors {
    /// Name-to-verdict rows.
    pub names: Vec<NameRow>,
    /// Sibling-collision rows.
    pub collisions: Vec<CollisionRow>,
}

/// Parse the committed vectors.
pub fn name_law_vectors() -> NameLawVectors {
    serde_json::from_str(VECTOR_JSON).expect("the committed name-law vectors parse")
}

/// The vector file's spelling of a verdict.
pub fn verdict(result: Result<(), NameError>) -> &'static str {
    match result {
        Ok(()) => "accept",
        Err(error) => error
            .check()
            .strip_prefix("node-name-")
            .unwrap_or_else(|| error.check()),
    }
}
