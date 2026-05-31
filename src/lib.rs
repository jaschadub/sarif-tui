//! sarif-tui: a terminal UI for exploring SARIF static-analysis reports.
//!
//! Modules are enabled incrementally as the implementation milestones land.

pub mod actions;
pub mod app;
pub mod cli;
pub mod event;
pub mod filter;
pub mod sarif;
pub mod triage;
pub mod ui;
