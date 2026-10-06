# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-06

### Added
- Initial release of **PortWatch** local socket & hygiene scanner.
- Kernel socket inspection via `/proc/net/{tcp,tcp6,udp,udp6}`.
- Process mapping via `/proc/*/fd/*` linking socket inodes to owning PID, name, and user account.
- Exposure classification: Localhost (`127.0.0.1` / `::1`), Private LAN, and All Interfaces (`0.0.0.0` / `::`).
- Defensive hygiene rule engine detecting unauthenticated exposed databases (Redis, Postgres, Mongo, MySQL, Elasticsearch), exposed debuggers (Node inspector, debugpy), and dev servers (Vite, React, Rails, Flask).
- Snapshot baseline recording and drift diffing (`--save` and `--diff`).
- Full `--json` export and `--fail-on-risk` CI gate.
