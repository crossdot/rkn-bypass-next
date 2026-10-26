//! CLI-обёртка над диагностикой: `diag check <host>:<port> [--transport tls|quic]`.

use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || args[1] != "check" {
        eprintln!("usage: diag-cli check <host>:<port> [--transport tls|quic]");
        std::process::exit(2);
    }
    let target = match diag_cli::parse_target(&args[2]) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("bad target: {e}");
            std::process::exit(2);
        }
    };

    // `--transport` (иначе `DIAG_TRANSPORT`, иначе TLS).
    let mut transport = std::env::var("DIAG_TRANSPORT").unwrap_or_else(|_| "tls".to_string());
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--transport" => {
                let Some(v) = args.get(i + 1) else {
                    eprintln!("--transport requires a value (tls|quic)");
                    std::process::exit(2);
                };
                transport = v.clone();
                i += 2;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let kind = match transport.parse::<config::TransportKind>() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("bad transport: {e}");
            std::process::exit(2);
        }
    };

    let server_addr: SocketAddr = match std::env::var("DIAG_SERVER") {
        Ok(s) => match s.parse() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("invalid DIAG_SERVER: {e}");
                std::process::exit(2);
            }
        },
        Err(_) => diag_cli::DEFAULT_SERVER_ADDR.parse().unwrap(),
    };

    println!(
        "diag check {} -> server {server_addr} (transport={kind:?})",
        args[2]
    );
    for (i, stage) in diag_cli::run_check_kind(server_addr, &target, kind)
        .await
        .iter()
        .enumerate()
    {
        match &stage.status {
            diag_cli::StageStatus::Ok => println!("[{}] {:<10} OK", i + 1, stage.name),
            diag_cli::StageStatus::Failed(cls) => {
                println!("[{}] {:<10} FAIL: {cls}", i + 1, stage.name)
            }
            diag_cli::StageStatus::Skipped => println!("[{}] {:<10} skipped", i + 1, stage.name),
        }
    }
}
