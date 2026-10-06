use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::model::{ListeningSocket, Protocol};
use crate::rules::{classify_exposure, evaluate_hygiene_rules, guess_service_name};

#[derive(Debug, Clone)]
struct ProcessInfo {
    pid: u32,
    name: String,
    user: String,
}

pub fn scan_listening_sockets() -> Vec<ListeningSocket> {
    let inode_map = build_socket_inode_map();
    let mut sockets = Vec::new();

    // Scan TCP v4
    if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
        parse_proc_net(&content, Protocol::Tcp, false, &inode_map, &mut sockets);
    }

    // Scan TCP v6
    if let Ok(content) = fs::read_to_string("/proc/net/tcp6") {
        parse_proc_net(&content, Protocol::Tcp, true, &inode_map, &mut sockets);
    }

    // Scan UDP v4
    if let Ok(content) = fs::read_to_string("/proc/net/udp") {
        parse_proc_net(&content, Protocol::Udp, false, &inode_map, &mut sockets);
    }

    // Scan UDP v6
    if let Ok(content) = fs::read_to_string("/proc/net/udp6") {
        parse_proc_net(&content, Protocol::Udp, true, &inode_map, &mut sockets);
    }

    // Sort by exposure priority (AllInterfaces > LanPrivate > Loopback), then port
    sockets.sort_by(|a, b| {
        b.exposure
            .cmp(&a.exposure)
            .then_with(|| a.port.cmp(&b.port))
            .then_with(|| a.protocol.to_string().cmp(&b.protocol.to_string()))
    });

    sockets
}

fn parse_proc_net(
    content: &str,
    protocol: Protocol,
    is_ipv6: bool,
    inode_map: &HashMap<u64, ProcessInfo>,
    sockets: &mut Vec<ListeningSocket>,
) {
    for (i, line) in content.lines().enumerate() {
        if i == 0 {
            continue; // Skip header
        }

        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        let local_addr_str = fields[1];
        let state_str = fields[3];
        let inode_str = fields[9];

        // For TCP, 0A is TCP_LISTEN
        // For UDP, 07 is listening state
        let is_listening = match protocol {
            Protocol::Tcp => state_str.eq_ignore_ascii_case("0A"),
            Protocol::Udp => state_str.eq_ignore_ascii_case("07"),
        };

        if !is_listening {
            continue;
        }

        let (ip_hex, port_hex) = match local_addr_str.split_once(':') {
            Some(pair) => pair,
            None => continue,
        };

        let port = match u16::from_str_radix(port_hex, 16) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let ip = if is_ipv6 {
            match parse_ipv6_hex(ip_hex) {
                Some(ip) => IpAddr::V6(ip),
                None => continue,
            }
        } else {
            match parse_ipv4_hex(ip_hex) {
                Some(ip) => IpAddr::V4(ip),
                None => continue,
            }
        };

        let inode = inode_str.parse::<u64>().unwrap_or(0);
        let proc_info = inode_map.get(&inode);

        let pid = proc_info.map(|p| p.pid);
        let process_name = proc_info.map(|p| p.name.clone());
        let user_name = proc_info.map(|p| p.user.clone());

        let exposure = classify_exposure(&ip);
        let service_guess = guess_service_name(port).map(|s| s.to_string());
        let findings = evaluate_hygiene_rules(port, exposure, process_name.as_deref());

        sockets.push(ListeningSocket {
            protocol,
            ip,
            port,
            inode,
            pid,
            process_name,
            user_name,
            exposure,
            service_guess,
            findings,
        });
    }
}

fn parse_ipv4_hex(hex_str: &str) -> Option<Ipv4Addr> {
    if hex_str.len() != 8 {
        return None;
    }
    let num = u32::from_str_radix(hex_str, 16).ok()?;
    // Linux stores IPv4 in little-endian order in /proc/net/tcp
    let bytes = num.to_le_bytes();
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

fn parse_ipv6_hex(hex_str: &str) -> Option<Ipv6Addr> {
    if hex_str.len() != 32 {
        return None;
    }
    // Four 32-bit words in little endian
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let chunk = &hex_str[i * 8..(i + 1) * 8];
        let word = u32::from_str_radix(chunk, 16).ok()?;
        let word_bytes = word.to_le_bytes();
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word_bytes);
    }
    Some(Ipv6Addr::from(bytes))
}

fn build_socket_inode_map() -> HashMap<u64, ProcessInfo> {
    let mut map = HashMap::new();
    let uid_user_map = build_uid_user_map();

    let proc_dir = match fs::read_dir("/proc") {
        Ok(dir) => dir,
        Err(_) => return map,
    };

    for entry in proc_dir.flatten() {
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        let pid = match name_str.parse::<u32>() {
            Ok(p) => p,
            Err(_) => continue, // Skip non-numeric entries
        };

        let fd_dir_path = entry.path().join("fd");
        let fd_entries = match fs::read_dir(&fd_dir_path) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        let mut proc_name = None;
        let mut user_name = None;

        for fd_entry in fd_entries.flatten() {
            if let Ok(link_target) = fs::read_link(fd_entry.path()) {
                let target_str = link_target.to_string_lossy();
                if let Some(stripped) = target_str.strip_prefix("socket:[") {
                    if let Some(inode_str) = stripped.strip_suffix(']') {
                        if let Ok(inode) = inode_str.parse::<u64>() {
                            if proc_name.is_none() {
                                proc_name = Some(read_process_name(pid));
                                user_name = Some(read_process_user(pid, &uid_user_map));
                            }

                            map.insert(
                                inode,
                                ProcessInfo {
                                    pid,
                                    name: proc_name.clone().unwrap_or_default(),
                                    user: user_name.clone().unwrap_or_default(),
                                },
                            );
                        }
                    }
                }
            }
        }
    }

    map
}

fn read_process_name(pid: u32) -> String {
    let comm_path = format!("/proc/{}/comm", pid);
    if let Ok(name) = fs::read_to_string(&comm_path) {
        return name.trim().to_string();
    }

    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if let Ok(cmd) = fs::read_to_string(&cmdline_path) {
        if let Some(first) = cmd.split('\0').next() {
            let path_clean = Path::new(first)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| first.to_string());
            if !path_clean.is_empty() {
                return path_clean;
            }
        }
    }

    format!("pid:{}", pid)
}

fn read_process_user(pid: u32, uid_map: &HashMap<u32, String>) -> String {
    let status_path = format!("/proc/{}/status", pid);
    if let Ok(status) = fs::read_to_string(status_path) {
        for line in status.lines() {
            if line.starts_with("Uid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(uid) = parts[1].parse::<u32>() {
                        if let Some(username) = uid_map.get(&uid) {
                            return username.clone();
                        }
                        return uid.to_string();
                    }
                }
            }
        }
    }
    "-".to_string()
}

fn build_uid_user_map() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                let username = parts[0];
                if let Ok(uid) = parts[2].parse::<u32>() {
                    map.insert(uid, username.to_string());
                }
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_hex() {
        let ip = parse_ipv4_hex("0100007F").unwrap();
        assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 1));

        let ip_all = parse_ipv4_hex("00000000").unwrap();
        assert_eq!(ip_all, Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn test_parse_ipv6_hex() {
        let ip = parse_ipv6_hex("00000000000000000000000000000000").unwrap();
        assert_eq!(ip, Ipv6Addr::UNSPECIFIED);
    }
}
