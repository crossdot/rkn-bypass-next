//! Интеграционный тест admin-cli: add / revoke / rotate-key / list.

use std::fs;
use std::process::Command;

fn run(cmd: &[&str], env: &[(&str, String)]) -> (String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_admin-cli"))
        .args(cmd)
        .envs(env.iter().map(|(k, v)| (*k, v.clone())))
        .output()
        .unwrap();
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn tempdir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("admin-cli-test-{}", std::process::id()));
    fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn add_revoke_rotate_list() {
    let dir = tempdir();
    let clients_path = dir.join("clients.toml").display().to_string();
    let clients_dir = dir.join("clients").display().to_string();
    let ca_cert = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.crt");
    let ca_key = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.key");

    let env = [
        ("CLIENTS_PATH", clients_path.clone()),
        ("CLIENTS_DIR", clients_dir.clone()),
        ("CA_CERT", ca_cert.to_string()),
        ("CA_KEY", ca_key.to_string()),
    ];

    // add
    let (stdout, _) = run(&["client", "add", "alice"], &env);
    assert!(stdout.contains("BEGIN PRIVATE KEY") || stdout.contains("BEGIN EC PRIVATE KEY"));
    assert!(fs::read_to_string(&clients_path).unwrap().contains("alice"));

    // list
    let (list, _) = run(&["client", "list"], &env);
    assert!(list.contains("alice"));
    assert!(list.contains("revoked=false"));

    // revoke
    run(&["client", "revoke", "alice"], &env);
    assert!(fs::read_to_string(&clients_path)
        .unwrap()
        .contains("revoked = true"));

    // rotate
    let (stdout, _) = run(&["client", "rotate-key", "alice"], &env);
    assert!(stdout.contains("BEGIN PRIVATE KEY") || stdout.contains("BEGIN EC PRIVATE KEY"));
    assert!(fs::read_to_string(&clients_path)
        .unwrap()
        .contains("revoked = false"));

    // config remains valid per config::ClientRegistry
    let reg =
        config::ClientRegistry::from_toml(&fs::read_to_string(&clients_path).unwrap()).unwrap();
    assert_eq!(reg.len(), 1);

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn add_with_max_sessions() {
    let dir = std::env::temp_dir().join(format!("admin-cli-max-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let clients_path = dir.join("clients.toml").display().to_string();
    let clients_dir = dir.join("clients").display().to_string();
    let ca_cert = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.crt");
    let ca_key = concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.key");
    let env = [
        ("CLIENTS_PATH", clients_path.clone()),
        ("CLIENTS_DIR", clients_dir.clone()),
        ("CA_CERT", ca_cert.to_string()),
        ("CA_KEY", ca_key.to_string()),
    ];

    // с флагом → max_sessions = 5
    let (stdout, _) = run(&["client", "add", "bob", "--max-sessions", "5"], &env);
    let fp = stdout
        .lines()
        .find_map(|l| l.strip_prefix("# fingerprint: "))
        .unwrap()
        .trim()
        .to_string();
    let toml = fs::read_to_string(&clients_path).unwrap();
    assert!(toml.contains("max_sessions = 5"), "{toml}");
    let reg = config::ClientRegistry::from_toml(&toml).unwrap();
    assert_eq!(reg.find_by_fingerprint(&fp).unwrap().max_sessions, Some(5));

    // без флага → None
    let (stdout, _) = run(&["client", "add", "carol"], &env);
    let fp = stdout
        .lines()
        .find_map(|l| l.strip_prefix("# fingerprint: "))
        .unwrap()
        .trim()
        .to_string();
    let toml = fs::read_to_string(&clients_path).unwrap();
    let reg = config::ClientRegistry::from_toml(&toml).unwrap();
    assert_eq!(reg.find_by_fingerprint(&fp).unwrap().max_sessions, None);

    fs::remove_dir_all(&dir).ok();
}
