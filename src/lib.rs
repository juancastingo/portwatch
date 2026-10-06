pub mod cli;
pub mod model;
pub mod printer;
pub mod rules;
pub mod scanner;
pub mod snapshot;

pub use model::{
    Exposure, ListeningSocket, Protocol, RuleFinding, ScanReport, Severity, SnapshotDiff,
};
pub use printer::{print_diff, print_scan_report};
pub use scanner::scan_listening_sockets;
pub use snapshot::{diff_snapshots, load_snapshot, save_snapshot};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
