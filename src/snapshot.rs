use anyhow::{anyhow, Result};
use std::fs;
use std::path::Path;

use crate::model::{ListeningSocket, SnapshotDiff};

pub fn save_snapshot(path: &str, sockets: &[ListeningSocket]) -> Result<()> {
    let json_str = serde_json::to_string_pretty(sockets)
        .map_err(|e| anyhow!("Failed to serialize snapshot: {}", e))?;
    fs::write(Path::new(path), json_str)
        .map_err(|e| anyhow!("Failed to write snapshot to '{}': {}", path, e))?;
    Ok(())
}

pub fn load_snapshot(path: &str) -> Result<Vec<ListeningSocket>> {
    let content = fs::read_to_string(Path::new(path))
        .map_err(|e| anyhow!("Failed to read snapshot file '{}': {}", path, e))?;
    let sockets: Vec<ListeningSocket> = serde_json::from_str(&content)
        .map_err(|e| anyhow!("Failed to parse snapshot JSON in '{}': {}", path, e))?;
    Ok(sockets)
}

pub fn diff_snapshots(baseline: &[ListeningSocket], current: &[ListeningSocket]) -> SnapshotDiff {
    let mut new_sockets = Vec::new();
    let mut closed_sockets = Vec::new();

    for cur in current {
        let exists = baseline
            .iter()
            .any(|b| b.protocol == cur.protocol && b.port == cur.port);
        if !exists {
            new_sockets.push(cur.clone());
        }
    }

    for base in baseline {
        let exists = current
            .iter()
            .any(|c| c.protocol == base.protocol && c.port == base.port);
        if !exists {
            closed_sockets.push(base.clone());
        }
    }

    SnapshotDiff {
        new_sockets,
        closed_sockets,
    }
}
