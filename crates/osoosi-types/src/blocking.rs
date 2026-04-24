use serde::{Deserialize, Serialize};

/// Recommended autonomous response action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockingRule {
    pub path: String,
    pub kind: BlockingKind,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BlockingKind {
    Executable,
    Shredding,
}
