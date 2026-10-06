use std::net::IpAddr;

use crate::model::{Exposure, RuleFinding, Severity};

pub fn classify_exposure(ip: &IpAddr) -> Exposure {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                Exposure::Loopback
            } else if v4.is_unspecified() {
                Exposure::AllInterfaces
            } else if v4.is_private() {
                Exposure::LanPrivate
            } else {
                Exposure::AllInterfaces
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                Exposure::Loopback
            } else if v6.is_unspecified() {
                Exposure::AllInterfaces
            } else {
                // Check unique local (fc00::/7) or link local (fe80::/10)
                let segments = v6.segments();
                if (segments[0] & 0xfe00) == 0xfc00 || (segments[0] & 0xffc0) == 0xfe80 {
                    Exposure::LanPrivate
                } else {
                    Exposure::AllInterfaces
                }
            }
        }
    }
}

pub fn guess_service_name(port: u16) -> Option<&'static str> {
    match port {
        21 => Some("FTP (File Transfer)"),
        22 => Some("SSH (Secure Shell)"),
        23 => Some("Telnet (Cleartext Remote Shell)"),
        25 => Some("SMTP (Mail Delivery)"),
        53 => Some("DNS (Domain Name System)"),
        80 => Some("HTTP (Web Server)"),
        443 => Some("HTTPS (Encrypted Web Server)"),
        1433 => Some("Microsoft SQL Server"),
        3000 => Some("Node / React / Rails Dev Server"),
        3306 => Some("MySQL / MariaDB Database"),
        4200 => Some("Angular Dev Server"),
        5000 => Some("Flask / Dev Web Server"),
        5173 => Some("Vite Dev Server"),
        5432 => Some("PostgreSQL Database"),
        5678 => Some("Python Debugger (debugpy)"),
        6379 => Some("Redis In-Memory Store"),
        8000 => Some("HTTP Alternate / Django Dev Server"),
        8080 => Some("HTTP Alternate / Proxy"),
        8086 => Some("InfluxDB Time Series Database"),
        8443 => Some("HTTPS Alternate"),
        9000 => Some("PHP-FPM / MinIO"),
        9200 => Some("Elasticsearch Cluster API"),
        9229 => Some("Node.js V8 Debugger / Inspector"),
        27017 => Some("MongoDB NoSQL Database"),
        _ => None,
    }
}

pub fn evaluate_hygiene_rules(
    port: u16,
    exposure: Exposure,
    process_name: Option<&str>,
) -> Vec<RuleFinding> {
    let mut findings = Vec::new();

    // Rule 1: Database exposed outside localhost
    let db_ports = [3306, 5432, 6379, 27017, 9200, 1433, 8086];
    if db_ports.contains(&port) && exposure != Exposure::Loopback {
        let db_name = guess_service_name(port).unwrap_or("Database");
        findings.push(RuleFinding {
            rule_id: "RULE-DB-001".to_string(),
            severity: Severity::Critical,
            title: format!("{} Exposed Beyond Localhost", db_name),
            explanation: format!(
                "Port {} is listening on a non-loopback interface ({}). Databases exposed to the local network or internet are prime targets for automated credential brute-forcing, ransomware, and unauthenticated data exfiltration.",
                port,
                exposure.label()
            ),
            recommendation: "Bind the database strictly to 127.0.0.1 (e.g. in redis.conf, my.cnf, postgresql.conf) or restrict access with host firewall rules (UFW/iptables).".to_string(),
        });
    }

    // Rule 2: Developer server / debugger exposed outside localhost
    let dev_ports = [3000, 4200, 5000, 5173, 8000, 8080, 5678, 9229];
    if dev_ports.contains(&port) && exposure != Exposure::Loopback {
        let is_debugger = port == 9229 || port == 5678;
        let severity = if is_debugger {
            Severity::Critical
        } else {
            Severity::Warning
        };
        findings.push(RuleFinding {
            rule_id: "RULE-DEV-001".to_string(),
            severity,
            title: if is_debugger { "Active Code Debugger Exposed to Network" } else { "Development Server Bound to External Interface" }.to_string(),
            explanation: if is_debugger {
                format!("Debug port {} allows remote process execution and code inspection without authentication.", port)
            } else {
                format!("Port {} is commonly used by development web servers (Vite, React, Flask). Dev servers often lack production security hardening, rate limiting, and CSRF protection.", port)
            },
            recommendation: "Configure dev server host to 127.0.0.1 or localhost rather than 0.0.0.0 (e.g. `vite --host localhost`).".to_string(),
        });
    }

    // Rule 3: Cleartext legacy protocols
    if (port == 21 || port == 23) && exposure != Exposure::Loopback {
        findings.push(RuleFinding {
            rule_id: "RULE-SEC-001".to_string(),
            severity: Severity::Critical,
            title: "Cleartext Protocol Exposed (Telnet / FTP)".to_string(),
            explanation: format!("Port {} transmits credentials and data completely in plaintext across the network.", port),
            recommendation: "Disable legacy service and use SSH (port 22) or SFTP/FTPS instead.".to_string(),
        });
    }

    // Rule 4: Wildcard Listener Notice
    if exposure == Exposure::AllInterfaces && findings.is_empty() {
        let proc = process_name.unwrap_or("unknown process");
        findings.push(RuleFinding {
            rule_id: "RULE-NET-001".to_string(),
            severity: Severity::Info,
            title: "Service Bound to All Interfaces (0.0.0.0 / ::)".to_string(),
            explanation: format!("Process '{}' is listening on all local interfaces. It will accept incoming connections from any network interface.", proc),
            recommendation: "If this service is only needed locally, bind specifically to 127.0.0.1.".to_string(),
        });
    }

    findings
}
