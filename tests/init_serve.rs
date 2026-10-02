//! End-to-end integration test: run the real `panamax` binary to initialize a
//! mirror, serve it over HTTP, and verify the index page and a crate file are
//! reachable through the full stack (CLI -> warp server -> disk).

use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::Duration;

fn bin() -> std::path::PathBuf {
    std::env::var_os("CARGO_BIN_EXE_panamax")
        .map(std::path::PathBuf::from)
        .expect("CARGO_BIN_EXE_panamax must be set by cargo test")
}

/// Bind an ephemeral port and return it, then release it for the server.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local_addr").port();
    drop(listener);
    port
}

#[tokio::test]
async fn init_then_serve_serves_index_and_crate() {
    let dir = tempfile::tempdir().expect("make tempdir");
    let mirror = dir.path();

    // 1. panamax init
    let out = Command::new(bin())
        .args(["init", mirror.to_str().expect("utf8 path")])
        .output()
        .expect("run panamax init");
    assert!(
        out.status.success(),
        "init failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(mirror.join("mirror.toml").exists(), "mirror.toml created");
    assert!(
        mirror.join("crates.io-index").is_dir(),
        "crates.io-index dir created"
    );
    assert!(mirror.join("crates").is_dir(), "crates dir created");
    assert!(mirror.join("rustup").is_dir(), "rustup dir created");

    // The generated config must parse and carry the documented defaults.
    let toml_text = std::fs::read_to_string(mirror.join("mirror.toml")).expect("read mirror.toml");
    let config: toml::Value = toml::from_str(&toml_text).expect("parse mirror.toml");
    assert_eq!(config["rustup"]["sync"], toml::Value::Boolean(true));
    assert_eq!(config["crates"]["sync"], toml::Value::Boolean(true));

    // 2. Seed a tiny bit of mirror content: one rustup platform + one crate.
    let platform_dir = mirror
        .join("rustup")
        .join("dist")
        .join("x86_64-unknown-linux-gnu");
    std::fs::create_dir_all(&platform_dir).expect("create platform dir");
    std::fs::write(platform_dir.join("rustup-init"), "#!/bin/sh\necho fake\n")
        .expect("write rustup-init");

    let crate_dir = mirror
        .join("crates")
        .join("ri")
        .join("pg")
        .join("ripgrep")
        .join("13.0.0");
    std::fs::create_dir_all(&crate_dir).expect("create crate dir");
    std::fs::write(
        crate_dir.join("ripgrep-13.0.0.crate"),
        b"fake ripgrep crate",
    )
    .expect("write crate file");

    // 3. panamax serve in the background.
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let mut child = Command::new(bin())
        .args([
            "serve",
            mirror.to_str().expect("utf8 path"),
            "--listen",
            "127.0.0.1",
            "--port",
            &port.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run panamax serve");

    let client = reqwest::Client::new();
    let index_url = format!("http://{listen}/");
    let crate_url = format!("http://{listen}/crates/ripgrep/13.0.0/download");

    // 4. Wait for the server, then exercise the index and crate routes.
    let mut index_ok = false;
    let mut last_err = String::new();
    for _ in 0..50 {
        match client.get(&index_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let body = resp.text().await.expect("read index body");
                assert!(
                    body.contains("x86_64-unknown-linux-gnu"),
                    "index page lists the platform"
                );
                assert!(body.contains("Panamax"), "index page rendered");
                index_ok = true;
                break;
            }
            Ok(resp) => last_err = format!("index status {}", resp.status()),
            Err(e) => last_err = e.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    if index_ok {
        let resp = client
            .get(&crate_url)
            .send()
            .await
            .expect("crate request sent");
        assert!(
            resp.status().is_success(),
            "crate status: {}",
            resp.status()
        );
        let bytes = resp.bytes().await.expect("read crate bytes");
        assert_eq!(bytes.as_ref(), b"fake ripgrep crate");
    }

    // 5. Shut the server down and assert it actually started.
    let _ = child.kill();
    let out = child.wait_with_output().expect("wait for serve exit");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        index_ok,
        "server never served the index: {last_err}; stderr: {stderr}"
    );
}
