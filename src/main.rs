use clap::Parser;
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

use portwatch::cli::CliArgs;
use portwatch::{
    diff_snapshots, load_snapshot, print_diff, print_scan_report, save_snapshot,
    scan_listening_sockets, Exposure, Protocol, ScanReport, Severity,
};

fn main() {
    let args = CliArgs::parse();

    let mut sockets = scan_listening_sockets();

    // Filters
    if args.all_interfaces_only {
        sockets.retain(|s| s.exposure == Exposure::AllInterfaces);
    }
    if args.tcp_only {
        sockets.retain(|s| s.protocol == Protocol::Tcp);
    }
    if args.udp_only {
        sockets.retain(|s| s.protocol == Protocol::Udp);
    }

    let localhost_count = sockets
        .iter()
        .filter(|s| s.exposure == Exposure::Loopback)
        .count();
    let lan_count = sockets
        .iter()
        .filter(|s| s.exposure == Exposure::LanPrivate)
        .count();
    let all_interfaces_count = sockets
        .iter()
        .filter(|s| s.exposure == Exposure::AllInterfaces)
        .count();

    let mut warning_count = 0;
    let mut critical_count = 0;

    for s in &sockets {
        for f in &s.findings {
            match f.severity {
                Severity::Warning => warning_count += 1,
                Severity::Critical => critical_count += 1,
                _ => {}
            }
        }
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let report = ScanReport {
        timestamp,
        total_sockets: sockets.len(),
        localhost_count,
        lan_count,
        all_interfaces_count,
        warning_count,
        critical_count,
        sockets: sockets.clone(),
    };

    // Save snapshot if requested
    if let Some(ref save_path) = args.save_path {
        if let Err(e) = save_snapshot(save_path, &sockets) {
            eprintln!("Failed to save snapshot to '{}': {}", save_path, e);
            exit(2);
        }
        if !args.json {
            println!(
                "✓ Saved baseline snapshot of {} listening sockets to '{}'",
                sockets.len(),
                save_path
            );
        }
    }

    // Compare with baseline diff if requested
    if let Some(ref diff_path) = args.diff_path {
        match load_snapshot(diff_path) {
            Ok(baseline) => {
                let diff = diff_snapshots(&baseline, &sockets);
                if !args.json {
                    print_diff(&diff);
                }
            }
            Err(e) => {
                eprintln!(
                    "Failed to load baseline snapshot from '{}': {}",
                    diff_path, e
                );
                exit(2);
            }
        }
    }

    print_scan_report(&report, args.json);

    if args.fail_on_risk && (warning_count > 0 || critical_count > 0) {
        exit(1);
    }
}
