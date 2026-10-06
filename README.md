# 🛡️ PortWatch

[![CI](https://github.com/juancastingo/portwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/juancastingo/portwatch/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/portwatch.svg)](https://crates.io/crates/portwatch)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://github.com/juancastingo/portwatch)

**PortWatch** is a defensive local port and network exposure hygiene scanner for developers and sysadmins.

Instead of a noisy external port scanner, PortWatch inspects the **local operating system socket tables and process mappings** from the inside. It distinguishes between safe `localhost` bindings, private `LAN` interfaces, and wildcard `0.0.0.0 / ::` public exposure, flagging dangerous misconfigurations with a transparent rule engine.

---

## 📸 Terminal Preview

```text
══════════════════════════════════════════════════════════════════════════════════
 🛡️  PortWatch: Local Exposure & Network Hygiene Audit
══════════════════════════════════════════════════════════════════════════════════
 Sockets: 8 | Localhost: 5 | LAN: 1 | All Interfaces: 2
 Posture: 1 CRITICAL RISKS DETECTED
──────────────────────────────────────────────────────────────────────────────────
 PROTO PORT   BIND ADDRESS     EXPOSURE        PID      PROCESS         SECURITY STATUS
──────────────────────────────────────────────────────────────────────────────────
 TCP   6379   0.0.0.0:6379     ALL (0.0.0.0)   4129     redis-server    CRITICAL
 TCP   5173   0.0.0.0:5173     ALL (0.0.0.0)   3812     node            WARNING
 TCP   3000   127.0.0.1:3000   Localhost       3077     node            SECURE
 TCP   5432   127.0.0.1:5432   Localhost       1290     postgres        SECURE
──────────────────────────────────────────────────────────────────────────────────
 DEFENSIVE RULE FINDINGS & REMEDIATIONS:

  [CRITICAL] Redis In-Memory Store Exposed Beyond Localhost (Port 6379 / TCP - redis-server)
    Rule:           RULE-DB-001
    Explanation:    Port 6379 is listening on all network interfaces (0.0.0.0). Databases exposed
                    beyond loopback are high-priority targets for credential brute-forcing,
                    ransomware, and unauthenticated data exfiltration.
    Remediation:    → Bind the database strictly to 127.0.0.1 or enforce local firewall rules.

  [WARNING] Development Server Bound to External Interface (Port 5173 / TCP - node)
    Rule:           RULE-DEV-001
    Explanation:    Port 5173 is commonly used by development web servers (Vite). Dev servers lack
                    production hardening, rate limiting, and CSRF protection.
    Remediation:    → Configure Vite with `--host localhost` rather than `0.0.0.0`.
══════════════════════════════════════════════════════════════════════════════════
```

---

## ✨ Key Features

- **Local Process & Inode Mapping**: Automatically maps listening sockets to their owning PID, process name, and user account without requiring complex root tools.
- **Interface Exposure Classification**:
  - `Localhost` (`127.0.0.1` / `::1`): Accessible only to processes on the current machine.
  - `LAN / Private`: Bound to RFC 1918 private subnets.
  - `All Interfaces` (`0.0.0.0` / `::`): Wildcard binding reachable from external networks.
- **Defensive Hygiene Rule Engine**:
  - **`RULE-DB-001` (Critical)**: Unprotected databases (Redis, MongoDB, Postgres, MySQL, Elasticsearch, Memcached) bound beyond loopback.
  - **`RULE-DEV-001` (Warning/Critical)**: Dev servers (Vite, React, Rails, Flask) and debuggers (Node Inspector `9229`, Python debugpy `5678`) exposed publicly.
  - **`RULE-SEC-001` (Critical)**: Legacy plaintext protocols (Telnet `23`, FTP `21`).
  - **`RULE-NET-001` (Info)**: Wildcard public listener notices.
- **Port Exposure Drift Tracking (Snapshots)**:
  - Save baseline snapshots: `portwatch --save baseline.json`
  - Detect newly opened ports: `portwatch --diff baseline.json`
- **CI/CD & Hardening Gate**:
  - `--fail-on-risk`: Exit with code 1 if any warning or critical risks are present.
  - `--json`: Emit structured JSON for compliance audits and automated monitoring.

---

## 🚀 Installation

### Using Cargo
```bash
cargo install portwatch
```

### Pre-compiled Binaries
Download pre-built standalone binaries from the [Releases](https://github.com/juancastingo/portwatch/releases) page.

### From Source
```bash
git clone https://github.com/juancastingo/portwatch.git
cd portwatch
cargo build --release
./target/release/portwatch --help
```

---

## 📖 Usage Examples

### 1. Run Standard Hygiene Audit
```bash
portwatch
```

### 2. Audit Only Wildcard/Publicly Exposed Ports
```bash
portwatch -a
```

### 3. Track Exposure Drift (Baseline Snapshots)
```bash
# Capture clean machine baseline
portwatch --save baseline.json

# Later (e.g. after starting docker containers or new services)
portwatch --diff baseline.json
```

### 4. CI/CD Pre-flight Hardening Gate
Fail the build if unauthenticated services or debuggers are listening on public interfaces:
```bash
portwatch --fail-on-risk
```

### 5. Machine-Readable JSON Export
```bash
portwatch --json | jq '.sockets[] | select(.exposure == "AllInterfaces")'
```

---

## ⚙️ CLI Options

| Flag | Short | Description |
|---|---|---|
| `--all-interfaces-only` | `-a` | Only show sockets listening on `0.0.0.0` or `::` |
| `--tcp-only` | | Only scan TCP listening sockets |
| `--udp-only` | | Only scan UDP listening sockets |
| `--fail-on-risk` | | Exit with code 1 if Warning or Critical findings are present |
| `--save <FILE>` | | Save current listening sockets to a baseline JSON snapshot |
| `--diff <FILE>` | | Compare current sockets against a baseline snapshot |
| `--json` | | Output report in structured JSON format |

---

## 📄 License

Licensed under either the [MIT License](LICENSE) or the Apache License 2.0 at your option.
