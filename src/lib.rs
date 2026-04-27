//! prompto — homelab power/virt/exec MCP.
//!
//! Library surface so integration tests can drive the same code paths the
//! binary uses.

pub mod baselines;
pub mod claudemgr;
pub mod diagnose;
pub mod files;
pub mod filters;
pub mod host;
pub mod inventory;
pub mod mcp;
pub mod mcpprobe;
pub mod script;
pub mod ssh;
pub mod virt;
pub mod wol;

// Token-savings analytics live in the standalone `mcp-gain` crate so the
// siblings (memqdrant, bucciarati) can share the same shape. Re-export the
// types prompto's call sites need so they read uniformly.
pub use inventory::{Capability, HostConfig, Inventory, InventoryStore};
pub use mcp_gain::{Summary, ToolSummary, Tracker};
pub use ssh::{ExecOutput, SshClient};
