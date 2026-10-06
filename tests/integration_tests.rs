use portwatch::model::{Exposure, ListeningSocket, Protocol, Severity};
use portwatch::rules::{classify_exposure, evaluate_hygiene_rules};
use portwatch::snapshot::{diff_snapshots, load_snapshot, save_snapshot};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tempfile::NamedTempFile;

#[test]
fn test_exposure_classification() {
    assert_eq!(
        classify_exposure(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        Exposure::Loopback
    );
    assert_eq!(
        classify_exposure(&IpAddr::V6(Ipv6Addr::LOCALHOST)),
        Exposure::Loopback
    );
    assert_eq!(
        classify_exposure(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
        Exposure::AllInterfaces
    );
    assert_eq!(
        classify_exposure(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        Exposure::AllInterfaces
    );
    assert_eq!(
        classify_exposure(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
        Exposure::LanPrivate
    );
    assert_eq!(
        classify_exposure(&IpAddr::V4(Ipv4Addr::new(10, 0, 1, 5))),
        Exposure::LanPrivate
    );
}

#[test]
fn test_hygiene_rules_database() {
    // Redis listening on 0.0.0.0 must trigger CRITICAL rule finding
    let findings_exposed =
        evaluate_hygiene_rules(6379, Exposure::AllInterfaces, Some("redis-server"));
    assert!(!findings_exposed.is_empty());
    assert_eq!(findings_exposed[0].rule_id, "RULE-DB-001");
    assert_eq!(findings_exposed[0].severity, Severity::Critical);

    // Redis listening safely on 127.0.0.1 should not trigger critical rule
    let findings_local = evaluate_hygiene_rules(6379, Exposure::Loopback, Some("redis-server"));
    assert!(findings_local.is_empty());
}

#[test]
fn test_hygiene_rules_dev_server_and_debugger() {
    // Vite on 0.0.0.0
    let findings_vite = evaluate_hygiene_rules(5173, Exposure::AllInterfaces, Some("node"));
    assert!(findings_vite.iter().any(|f| f.rule_id == "RULE-DEV-001"));

    // Debugger on 0.0.0.0
    let findings_debug = evaluate_hygiene_rules(9229, Exposure::AllInterfaces, Some("node"));
    assert!(findings_debug
        .iter()
        .any(|f| f.severity == Severity::Critical));
}

#[test]
fn test_snapshot_diffing() {
    let s1 = ListeningSocket {
        protocol: Protocol::Tcp,
        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 8080,
        inode: 1,
        pid: Some(100),
        process_name: Some("test-srv".to_string()),
        user_name: Some("test".to_string()),
        exposure: Exposure::Loopback,
        service_guess: None,
        findings: vec![],
    };

    let s2 = ListeningSocket {
        protocol: Protocol::Tcp,
        ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port: 9000,
        inode: 2,
        pid: Some(200),
        process_name: Some("new-srv".to_string()),
        user_name: Some("test".to_string()),
        exposure: Exposure::AllInterfaces,
        service_guess: None,
        findings: vec![],
    };

    let baseline = vec![s1.clone()];
    let current = vec![s1.clone(), s2.clone()];

    let diff = diff_snapshots(&baseline, &current);
    assert_eq!(diff.new_sockets.len(), 1);
    assert_eq!(diff.new_sockets[0].port, 9000);
    assert_eq!(diff.closed_sockets.len(), 0);
}

#[test]
fn test_snapshot_file_persistence() {
    let tmp = NamedTempFile::new().unwrap();
    let tmp_path = tmp.path().to_str().unwrap();

    let s = ListeningSocket {
        protocol: Protocol::Tcp,
        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 3000,
        inode: 10,
        pid: Some(123),
        process_name: Some("node".to_string()),
        user_name: Some("user".to_string()),
        exposure: Exposure::Loopback,
        service_guess: None,
        findings: vec![],
    };

    save_snapshot(tmp_path, &[s]).unwrap();
    let loaded = load_snapshot(tmp_path).unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].port, 3000);
}
