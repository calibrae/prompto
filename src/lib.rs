//! prompto — homelab power/virt/exec MCP.
//!
//! Library surface so integration tests can drive the same code paths the
//! binary uses.

pub mod advisor;
pub mod agent;
pub mod agent_api;
pub mod approval;
pub mod approvers;
pub mod audit;
pub mod authz;
pub mod baselines;
pub mod batch;
pub mod caller;
pub mod canon;
pub mod ctx;
pub mod diagnose;
pub mod drain;
pub mod error_class;
pub mod files;
pub mod filters;
pub mod handover;
pub mod host;
pub mod inventory;
pub mod kill;
pub mod mcp;
pub mod policy;
pub mod portscan;
pub mod precheck;
pub mod rsync;
pub mod script;
pub mod server;
pub mod sessions;
pub mod ssh;
pub mod stamp;
pub mod systemd;
pub mod ticket;
pub mod totp;
pub mod vault;
pub mod virt;
pub mod wol;

// Token-savings analytics live in the standalone `mcp-gain` crate so the
// siblings (memqdrant, bucciarati) can share the same shape. Re-export the
// types prompto's call sites need so they read uniformly.
pub use inventory::{Capability, HostConfig, Inventory, InventoryStore};
pub use mcp_gain::{Summary, ToolSummary, Tracker};
pub use ssh::{ExecOutput, SshClient};
