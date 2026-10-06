use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Exposure {
    Loopback,
    LanPrivate,
    AllInterfaces,
}

impl Exposure {
    pub fn label(&self) -> &'static str {
        match self {
            Exposure::Loopback => "Localhost",
            Exposure::LanPrivate => "LAN / Private",
            Exposure::AllInterfaces => "All Interfaces (0.0.0.0 / ::)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Safe,
    Info,
    Warning,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Safe => write!(f, "SAFE"),
            Severity::Info => write!(f, "INFO"),
            Severity::Warning => write!(f, "WARNING"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub explanation: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListeningSocket {
    pub protocol: Protocol,
    pub ip: IpAddr,
    pub port: u16,
    pub inode: u64,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub user_name: Option<String>,
    pub exposure: Exposure,
    pub service_guess: Option<String>,
    pub findings: Vec<RuleFinding>,
}

impl ListeningSocket {
    pub fn max_severity(&self) -> Severity {
        self.findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Safe)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub timestamp: u64,
    pub total_sockets: usize,
    pub localhost_count: usize,
    pub lan_count: usize,
    pub all_interfaces_count: usize,
    pub warning_count: usize,
    pub critical_count: usize,
    pub sockets: Vec<ListeningSocket>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotDiff {
    pub new_sockets: Vec<ListeningSocket>,
    pub closed_sockets: Vec<ListeningSocket>,
}
