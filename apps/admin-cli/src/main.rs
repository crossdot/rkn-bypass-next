//! admin-cli: локальное администрирование клиентов (mTLS).
//!
//! Команды: `client add`, `client revoke`, `client rotate-key`, `client list`.
//! Только локально, без сети. Приватные ключи — только в stdout, не в логах.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

#[derive(Serialize, Deserialize, Default)]
struct ClientsFile {
    #[serde(default)]
    server: ServerClients,
}

#[derive(Serialize, Deserialize, Default)]
struct ServerClients {
    #[serde(default)]
    clients: Vec<ClientRecord>,
}

#[derive(Serialize, Deserialize, Clone)]
struct ClientRecord {
    client_id: String,
    key_material: String,
    #[serde(default)]
    revoked: bool,
    max_sessions: Option<u32>,
}

fn load_file(path: &str) -> ClientsFile {
    match fs::read_to_string(path) {
        Ok(s) => toml::from_str(&s).unwrap_or_default(),
        Err(_) => ClientsFile::default(),
    }
}

fn save_file(path: &str, file: &ClientsFile) -> Result<(), String> {
    let s = toml::to_string_pretty(file).map_err(|e| e.to_string())?;
    fs::write(path, s).map_err(|e| e.to_string())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || args[1] != "client" {
        eprintln!(
            "usage: admin-cli client <add|revoke|rotate-key|list> [client_id] [--max-sessions N]"
        );
        std::process::exit(2);
    }
    let cmd = args.get(2).map(|s| s.as_str()).unwrap_or("");

    let mut id = String::new();
    let mut max_sessions: Option<u32> = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--max-sessions" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("--max-sessions requires <N>");
                    std::process::exit(2);
                };
                max_sessions = Some(v.parse::<u32>().unwrap_or_else(|_| {
                    eprintln!("--max-sessions must be a non-negative integer");
                    std::process::exit(2);
                }));
                i += 2;
            }
            other => {
                if id.is_empty() {
                    id = other.to_string();
                }
                i += 1;
            }
        }
    }

    let clients_path = env_or("CLIENTS_PATH", "configs/clients.toml");
    let clients_dir = env_or("CLIENTS_DIR", "configs/clients");
    let ca_cert = env_or(
        "CA_CERT",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.crt"),
    );
    let ca_key = env_or(
        "CA_KEY",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../certs/dev-ca.key"),
    );

    match cmd {
        "add" => cmd_add(
            &id,
            &clients_path,
            &clients_dir,
            &ca_cert,
            &ca_key,
            max_sessions,
        ),
        "revoke" => cmd_revoke(&id, &clients_path),
        "rotate-key" => cmd_rotate(&id, &clients_path, &clients_dir, &ca_cert, &ca_key),
        "list" => cmd_list(&clients_path),
        _ => {
            eprintln!("unknown command: {cmd}");
            std::process::exit(2);
        }
    }
}

fn cmd_add(
    id: &str,
    path: &str,
    dir: &str,
    ca_cert: &str,
    ca_key: &str,
    max_sessions: Option<u32>,
) {
    if id.is_empty() {
        eprintln!("client_id required");
        std::process::exit(2);
    }
    let ca_cert_pem = fs::read_to_string(ca_cert).unwrap_or_else(|e| fail(&e.to_string()));
    let ca_key_pem = fs::read_to_string(ca_key).unwrap_or_else(|e| fail(&e.to_string()));
    let generated = crypto::generate_client_cert(id, &ca_cert_pem, &ca_key_pem)
        .unwrap_or_else(|e| fail(&e.to_string()));

    let dir_path = PathBuf::from(dir);
    fs::create_dir_all(&dir_path).unwrap_or_else(|e| fail(&e.to_string()));
    let cert_file = dir_path.join(format!("{id}.crt"));
    fs::write(&cert_file, &generated.cert_pem).unwrap_or_else(|e| fail(&e.to_string()));

    let mut file = load_file(path);
    if file.server.clients.iter().any(|c| c.client_id == id) {
        eprintln!("client {id} already exists");
        std::process::exit(1);
    }
    file.server.clients.push(ClientRecord {
        client_id: id.to_string(),
        // inline PEM: конфиг сервера самодостаточен (не зависит от путей).
        key_material: generated.cert_pem.clone(),
        revoked: false,
        max_sessions,
    });
    save_file(path, &file).unwrap_or_else(|e| fail(&e));

    // Приватный ключ — только в stdout, не в логах.
    println!(
        "# client_id: {id}\n# fingerprint: {}\n{}",
        generated.fingerprint,
        String::from_utf8_lossy(generated.key_pem.expose())
    );
}

fn cmd_revoke(id: &str, path: &str) {
    let mut file = load_file(path);
    let Some(entry) = file.server.clients.iter_mut().find(|c| c.client_id == id) else {
        eprintln!("client {id} not found");
        std::process::exit(1);
    };
    entry.revoked = true;
    save_file(path, &file).unwrap_or_else(|e| fail(&e));
    println!("revoked {id}");
}

fn cmd_rotate(id: &str, path: &str, dir: &str, ca_cert: &str, ca_key: &str) {
    let ca_cert_pem = fs::read_to_string(ca_cert).unwrap_or_else(|e| fail(&e.to_string()));
    let ca_key_pem = fs::read_to_string(ca_key).unwrap_or_else(|e| fail(&e.to_string()));
    let generated = crypto::generate_client_cert(id, &ca_cert_pem, &ca_key_pem)
        .unwrap_or_else(|e| fail(&e.to_string()));

    let dir_path = PathBuf::from(dir);
    fs::create_dir_all(&dir_path).unwrap_or_else(|e| fail(&e.to_string()));
    let cert_file = dir_path.join(format!("{id}.crt"));
    fs::write(&cert_file, &generated.cert_pem).unwrap_or_else(|e| fail(&e.to_string()));

    let mut file = load_file(path);
    let Some(entry) = file.server.clients.iter_mut().find(|c| c.client_id == id) else {
        eprintln!("client {id} not found");
        std::process::exit(1);
    };
    // Новый сертификат (inline PEM); старый fingerprint перестаёт быть
    // авторизованным (отсутствует в allow-list).
    entry.key_material = generated.cert_pem.clone();
    entry.revoked = false;
    save_file(path, &file).unwrap_or_else(|e| fail(&e));

    println!(
        "# rotated client_id: {id}\n# fingerprint: {}\n{}",
        generated.fingerprint,
        String::from_utf8_lossy(generated.key_pem.expose())
    );
}

fn cmd_list(path: &str) {
    let file = load_file(path);
    for c in &file.server.clients {
        println!(
            "{}\trevoked={}\tmax_sessions={}",
            c.client_id,
            c.revoked,
            c.max_sessions
                .map(|n| n.to_string())
                .unwrap_or_else(|| "-".into())
        );
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}
