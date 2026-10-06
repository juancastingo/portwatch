use crate::model::{Exposure, ListeningSocket, ScanReport, Severity, SnapshotDiff};
use colored::*;

pub fn print_scan_report(report: &ScanReport, as_json: bool) {
    if as_json {
        let json_str = serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string());
        println!("{}", json_str);
        return;
    }

    println!();
    println!("{}", "═".repeat(82).cyan());
    println!(
        " {} {}",
        "🛡️  PortWatch:".bold().white(),
        "Local Exposure & Network Hygiene Audit".bold().cyan()
    );
    println!("{}", "═".repeat(82).cyan());

    // Overview Stats
    println!(
        " Sockets: {} | Localhost: {} | LAN: {} | All Interfaces: {}",
        report.total_sockets.to_string().bold().white(),
        report.localhost_count.to_string().green(),
        report.lan_count.to_string().yellow(),
        report.all_interfaces_count.to_string().bold().red()
    );

    let status_summary = if report.critical_count > 0 {
        format!("{} CRITICAL RISKS DETECTED", report.critical_count)
            .bold()
            .red()
    } else if report.warning_count > 0 {
        format!("{} Warnings flagged", report.warning_count)
            .bold()
            .yellow()
    } else {
        "All exposed ports conform to standard hygiene".green()
    };
    println!(" Posture: {}", status_summary);
    println!("{}", "─".repeat(82).cyan());

    // Header row
    println!(
        " {:<5} {:<6} {:<16} {:<15} {:<8} {:<15} {}",
        "PROTO".bold(),
        "PORT".bold(),
        "BIND ADDRESS".bold(),
        "EXPOSURE".bold(),
        "PID".bold(),
        "PROCESS".bold(),
        "SECURITY STATUS".bold()
    );
    println!("{}", "─".repeat(82).dimmed());

    for s in &report.sockets {
        print_socket_row(s);
    }

    // Explanations for flagged ports
    let flagged: Vec<&ListeningSocket> = report
        .sockets
        .iter()
        .filter(|s| !s.findings.is_empty())
        .collect();

    if !flagged.is_empty() {
        println!("{}", "─".repeat(82).cyan());
        println!("{}", " DEFENSIVE RULE FINDINGS & REMEDIATIONS:".bold());

        for s in flagged {
            for f in &s.findings {
                let sev_badge = match f.severity {
                    Severity::Critical => "[CRITICAL]".bold().red(),
                    Severity::Warning => "[WARNING]".bold().yellow(),
                    Severity::Info => "[INFO]".bold().cyan(),
                    Severity::Safe => "[OK]".green(),
                };

                let proc = s.process_name.as_deref().unwrap_or("unknown");
                println!();
                println!(
                    "  {} {} (Port {} / {} - {})",
                    sev_badge,
                    f.title.bold().white(),
                    s.port.to_string().yellow(),
                    s.protocol,
                    proc.bold()
                );
                println!("    Rule:           {}", f.rule_id.dimmed());
                println!("    Explanation:    {}", f.explanation.white());
                println!(
                    "    Remediation:    {} {}",
                    "→".cyan(),
                    f.recommendation.cyan()
                );
            }
        }
    }

    println!("{}", "═".repeat(82).cyan());
    println!();
}

fn print_socket_row(s: &ListeningSocket) {
    let exposure_badge = match s.exposure {
        Exposure::Loopback => "Localhost".green(),
        Exposure::LanPrivate => "LAN".yellow(),
        Exposure::AllInterfaces => "ALL (0.0.0.0)".bold().red(),
    };

    let severity_badge = match s.max_severity() {
        Severity::Critical => "CRITICAL".bold().red(),
        Severity::Warning => "WARNING".bold().yellow(),
        Severity::Info => "INFO".cyan(),
        Severity::Safe => "SECURE".green(),
    };

    let pid_str = s
        .pid
        .map(|p| p.to_string())
        .unwrap_or_else(|| "-".to_string());
    let proc_str = s.process_name.as_deref().unwrap_or("-");
    let ip_str = if s.ip.is_ipv6() {
        format!("[{}]:{}", s.ip, s.port)
    } else {
        format!("{}:{}", s.ip, s.port)
    };

    println!(
        " {:<5} {:<6} {:<16} {:<15} {:<8} {:<15} {}",
        s.protocol.to_string().cyan(),
        s.port.to_string().bold().white(),
        ip_str.dimmed(),
        exposure_badge,
        pid_str.dimmed(),
        proc_str.bold(),
        severity_badge
    );
}

pub fn print_diff(diff: &SnapshotDiff) {
    println!();
    println!("{}", "═".repeat(82).cyan());
    println!(
        " {} {}",
        "🔍 PortWatch:".bold().white(),
        "Snapshot Comparison".bold().cyan()
    );
    println!("{}", "═".repeat(82).cyan());

    if diff.new_sockets.is_empty() && diff.closed_sockets.is_empty() {
        println!(
            " {}",
            "✓ No listening port changes detected since baseline snapshot."
                .bold()
                .green()
        );
    } else {
        if !diff.new_sockets.is_empty() {
            println!(" {}", "NEWLY EXPOSED PORTS:".bold().red());
            for s in &diff.new_sockets {
                let proc = s.process_name.as_deref().unwrap_or("unknown");
                println!(
                    "   {} {} port {} ({}) bound to {} ({})",
                    "+".bold().red(),
                    s.protocol,
                    s.port.to_string().bold().yellow(),
                    proc.bold(),
                    s.ip,
                    s.exposure.label().bold().red()
                );
            }
        }

        if !diff.closed_sockets.is_empty() {
            println!(" {}", "CLOSED / TERMINATED PORTS:".bold().dimmed());
            for s in &diff.closed_sockets {
                let proc = s.process_name.as_deref().unwrap_or("unknown");
                println!(
                    "   {} {} port {} ({})",
                    "-".dimmed(),
                    s.protocol,
                    s.port,
                    proc
                );
            }
        }
    }

    println!("{}", "═".repeat(82).cyan());
    println!();
}
