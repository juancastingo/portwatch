use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "portwatch",
    author = "Juan Castiñeira <juancastingo@gmail.com>",
    version,
    about = "Defensive local port and exposure security hygiene scanner.",
    long_about = "PortWatch inspects local TCP/UDP listening sockets, identifies processes and exposure interfaces (localhost vs LAN vs 0.0.0.0), detects risky service exposures (unauthenticated databases, dev servers, debuggers), and provides transparent explanations and remediation guidance."
)]
pub struct CliArgs {
    /// Only show sockets listening on all interfaces (0.0.0.0 or ::)
    #[arg(short = 'a', long = "all-interfaces-only")]
    pub all_interfaces_only: bool,

    /// Only scan TCP sockets
    #[arg(long = "tcp-only", conflicts_with = "udp_only")]
    pub tcp_only: bool,

    /// Only scan UDP sockets
    #[arg(long = "udp-only", conflicts_with = "tcp_only")]
    pub udp_only: bool,

    /// Fail with exit code 1 if any Warning or Critical hygiene findings are detected
    #[arg(long = "fail-on-risk")]
    pub fail_on_risk: bool,

    /// Save current scan results as a baseline snapshot JSON file
    #[arg(long = "save", value_name = "FILE")]
    pub save_path: Option<String>,

    /// Compare current scan against a previously saved baseline snapshot
    #[arg(long = "diff", value_name = "FILE")]
    pub diff_path: Option<String>,

    /// Output results as structured JSON
    #[arg(long = "json")]
    pub json: bool,
}
