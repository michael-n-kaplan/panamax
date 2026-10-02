use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    path::PathBuf,
    process::Stdio,
    sync::Arc,
};

use askama::Template;
use bytes::BytesMut;
use futures_util::stream::unfold;
use futures_util::TryStreamExt;
use include_dir::{include_dir, Dir};
use rustls::pki_types::pem::PemObject;
use thiserror::Error;
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::Command,
};
use tokio_stream::StreamExt;
use tokio_util::codec::{BytesCodec, FramedRead};
use warp::{
    host::Authority,
    path::Tail,
    reject::Reject,
    reply::{self, Reply},
    Filter, Rejection,
};

use crate::crates::get_crate_path;

pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct Platform {
    is_exe: bool,
    platform_triple: String,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    platforms: Vec<Platform>,
    host: String,
}

const STATIC_DIR: Dir = include_dir!("static");

#[derive(Error, Debug)]
pub enum ServeError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Hyper error: {0}")]
    Hyper(#[from] warp::hyper::Error),
    #[error("Warp HTTP error: {0}")]
    Warp(#[from] warp::http::Error),
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("PEM error: {0}")]
    Pem(#[from] rustls::pki_types::pem::Error),
    #[error("{0}")]
    Other(String),
}

impl Reject for ServeError {}

pub async fn serve(path: PathBuf, socket_addr: SocketAddr, tls_paths: Option<TlsConfig>) {
    let is_tls = tls_paths.is_some();
    let routes = build_routes(path, is_tls);

    match tls_paths {
        Some(TlsConfig {
            cert_path,
            key_path,
        }) => {
            println!("Running TLS on {socket_addr}");
            serve_tls(routes, socket_addr, &cert_path, &key_path).await;
        }
        None => {
            println!("Running HTTP on {socket_addr}");
            warp::serve(routes).run(socket_addr).await;
        }
    }
}

/// Build all of the mirror's routes.
fn build_routes(
    path: PathBuf,
    is_tls: bool,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone + Send + Sync {
    let index_path = path.clone();

    // Handle the homepage
    let index = warp::path::end().and(warp::host::optional()).and_then(
        move |authority: Option<Authority>| {
            let mirror_path = index_path.clone();
            let protocol = if is_tls { "https://" } else { "http://" };
            async move {
                let platforms = get_rustup_platforms(mirror_path)
                    .await
                    .map_err(|_| {
                        warp::reject::custom(ServeError::Other(
                            "Could not retrieve rustup platforms.".to_string(),
                        ))
                    })?;
                let template = IndexTemplate {
                    platforms,
                    host: authority
                        .map(|a| format!("{}{}", protocol, a.as_str()))
                        .unwrap_or_else(|| "http://panamax.internal".to_string()),
                };
                let html = template.render().map_err(|e| {
                    warp::reject::custom(ServeError::Other(format!(
                        "Failed to render index: {e}"
                    )))
                })?;
                Ok(reply::html(html)) as Result<reply::Html<String>, Rejection>
            }
        },
    );

    // Handle all files baked into the binary with include_dir, at /static
    let static_dir =
        warp::path::path("static")
            .and(warp::path::tail())
            .and_then(|path: Tail| async move {
                STATIC_DIR
                    .get_file(path.as_str())
                    .ok_or_else(warp::reject::not_found)
                    .map(|f| f.contents().to_vec())
            });

    let dist_dir = warp::path::path("dist").and(warp::fs::dir(path.join("dist")));
    let rustup_dir = warp::path::path("rustup").and(warp::fs::dir(path.join("rustup")));

    // Handle crates requests in the format of "/crates/ripgrep/0.1.0/download"
    // This format is the default for cargo, and will be used if an external process rewrites config.json in crates.io-index
    let crates_mirror_path = path.clone();
    let crates_dir_native_format = warp::path!("crates" / String / String / "download").and_then(
        move |name: String, version: String| {
            let mirror_path = crates_mirror_path.clone();
            async move { get_crate_file(mirror_path, &name, &version).await }
        },
    );

    // Handle crates requests in the format of either :
    // - "/crates/1/u/0.2.0/u-0.2.0.crate"
    // - "/crates/2/bm/0.11.0/bm-0.11.0.crate"
    // - "/crates/3/c/cde/0.1.1/cde-0.11.0.crate"
    // - "/crates/se/rd/serde/1.0.130/serde-1.0.130.crate"
    // This format is used by Panamax, and/or is used if config.json contains "/crates/{prefix}/{crate}/{version}/{crate}-{version}.crate"
    let crates_mirror_path_2 = path.clone();
    let crates_dir_condensed_format_1 = warp::path!("crates" / "1" / String / String / String)
        .map(|name: String, version: String, crate_file: String| (name, version, crate_file))
        .untuple_one();
    let crates_dir_condensed_format_2 = warp::path!("crates" / "2" / String / String / String)
        .map(|name: String, version: String, crate_file: String| (name, version, crate_file))
        .untuple_one();
    let crates_dir_condensed_format_3 =
        warp::path!("crates" / "3" / String / String / String / String)
            .map(
                |_: String, name: String, version: String, crate_file: String| {
                    (name, version, crate_file)
                },
            )
            .untuple_one();
    let crates_dir_condensed_format_full =
        warp::path!("crates" / String / String / String / String / String)
            .map(
                |_: String, _: String, name: String, version: String, crate_file: String| {
                    (name, version, crate_file)
                },
            )
            .untuple_one();

    let crates_dir_condensed_format = crates_dir_condensed_format_1
        .or(crates_dir_condensed_format_2)
        .unify()
        .or(crates_dir_condensed_format_3)
        .unify()
        .or(crates_dir_condensed_format_full)
        .unify()
        .and_then(move |name: String, version: String, crate_file: String| {
            let mirror_path = crates_mirror_path_2.clone();
            async move {
                if !crate_file.ends_with(".crate") || !crate_file.starts_with(&name) {
                    return Err(warp::reject::not_found());
                }
                get_crate_file(mirror_path, &name, &version).await
            }
        });

    // Handle git client requests to /git/crates.io-index
    let path_for_git = path.clone();
    let git = warp::path("git")
        .and(warp::path("crates.io-index"))
        .and(warp::path::tail())
        .and(warp::method())
        .and(warp::header::optional::<String>("Content-Type"))
        .and(warp::addr::remote())
        .and(warp::body::stream())
        .and(warp::query::raw().or_else(|_| async { Ok::<(String,), Rejection>((String::new(),)) }))
        .and_then(
            move |path_tail, method, content_type, remote, body, query| {
                let mirror_path = path_for_git.clone();
                async move {
                    handle_git(
                        mirror_path,
                        path_tail,
                        method,
                        content_type,
                        remote,
                        body,
                        query,
                    )
                    .await
                }
            },
        );

    // Handle sparse index requests at /index/
    let sparse_index = warp::path("index").and(warp::fs::dir(path.join("crates.io-index")));

    index
        .or(static_dir)
        .or(dist_dir)
        .or(rustup_dir)
        .or(crates_dir_native_format)
        .or(crates_dir_condensed_format)
        .or(sparse_index)
        .or(git)
}

/// Serve the routes over TLS, using rustls via hyper-util.
///
/// warp 0.4 no longer ships a built-in TLS server (warp 0.3's
/// `.tls().cert_path().key_path()` is gone), so we combine the warp filter
/// service with hyper's HTTP/1 server over a rustls acceptor.
async fn serve_tls(
    routes: impl Filter<Extract = impl Reply, Error = Rejection> + Clone + Send + Sync + 'static,
    addr: SocketAddr,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) {
    let config = match load_tls_config(cert_path, key_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Failed to load TLS configuration: {e}");
            return;
        }
    };
    let acceptor = tokio_rustls::TlsAcceptor::from(config);

    let hyper_service = hyper_util::service::TowerToHyperService::new(warp::service(routes));

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("Failed to bind {addr}: {e}");
            return;
        }
    };

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("Failed to accept connection: {e}");
                continue;
            }
        };
        let service = hyper_service.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp).await {
                Ok(stream) => stream,
                Err(e) => {
                    eprintln!("TLS handshake failed for {peer}: {e}");
                    return;
                }
            };
            let io = hyper_util::rt::TokioIo::new(tls_stream);
            if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                hyper_util::rt::TokioExecutor::new(),
            )
            .http1_only()
            .serve_connection(io, service)
            .await
            {
                eprintln!("Error serving connection for {peer}: {e}");
            }
        });
    }
}

/// Load certificate + key files into a rustls ServerConfig.
fn load_tls_config(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<Arc<rustls::ServerConfig>, ServeError> {
    // Install the default crypto provider (aws-lc-rs) for rustls 0.23.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls::pki_types::CertificateDer::pem_file_iter(cert_path)?
            .collect::<Result<Vec<_>, _>>()?;
    if cert_chain.is_empty() {
        return Err(ServeError::Other(
            "No certificates found in certificate file".to_string(),
        ));
    }

    let key_der = rustls::pki_types::PrivateKeyDer::from_pem_file(key_path)?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Get all rustup platforms available on the mirror.
async fn get_rustup_platforms(path: PathBuf) -> io::Result<Vec<Platform>> {
    let rustup_path = path.join("rustup/dist");

    let mut output = vec![];

    // Look at the rustup/dist directory for all rustup-init and rustup-init.exe files.
    // Also return if the rustup-init file is a .exe or not.
    if let Ok(mut rd) = tokio::fs::read_dir(rustup_path).await {
        while let Some(entry) = rd.next_entry().await? {
            if entry.metadata().await?.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    let platform_triple = name.to_string();
                    if entry.path().join("rustup-init").exists() {
                        output.push(Platform {
                            is_exe: false,
                            platform_triple,
                        });
                    } else if entry.path().join("rustup-init.exe").exists() {
                        output.push(Platform {
                            is_exe: true,
                            platform_triple,
                        });
                    }
                }
            }
        }
    }

    // Sort by name, keeping non-exe versions at the top.
    output.sort();

    Ok(output)
}

/// Return a crate file as an HTTP response, streamed from disk.
async fn get_crate_file(
    mirror_path: PathBuf,
    name: &str,
    version: &str,
) -> Result<impl Reply, Rejection> {
    let full_path =
        get_crate_path(&mirror_path, name, version).ok_or_else(warp::reject::not_found)?;

    let file = File::open(full_path)
        .await
        .map_err(|_| warp::reject::not_found())?;
    let meta = file
        .metadata()
        .await
        .map_err(|_| warp::reject::not_found())?;
    let stream = FramedRead::new(file, BytesCodec::new()).map_ok(|buf: BytesMut| buf.freeze());

    Ok(reply::with_header(
        reply::stream(stream),
        warp::http::header::CONTENT_LENGTH,
        meta.len(),
    ))
}

/// Handle a request from a git client by proxying to `git http-backend`.
async fn handle_git<S, B>(
    mirror_path: PathBuf,
    path_tail: Tail,
    method: warp::http::Method,
    content_type: Option<String>,
    remote: Option<SocketAddr>,
    mut body: S,
    query: String,
) -> Result<impl Reply, Rejection>
where
    S: StreamExt<Item = Result<B, warp::Error>> + Send + Unpin + 'static,
    B: bytes::Buf + Send + 'static,
{
    let remote = remote
        .map(|r| r.ip().to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());

    // Run "git http-backend"
    let mut cmd = Command::new("git");
    cmd.arg("http-backend");

    // Clear environment variables, and set needed variables
    // See: https://git-scm.com/docs/git-http-backend
    cmd.env_clear();
    cmd.env("GIT_PROJECT_ROOT", mirror_path);
    cmd.env(
        "PATH_INFO",
        format!("/crates.io-index/{}", path_tail.as_str()),
    );
    cmd.env("REQUEST_METHOD", method.as_str());
    cmd.env("QUERY_STRING", query);
    cmd.env("REMOTE_USER", "");
    cmd.env("REMOTE_ADDR", remote);
    if let Some(content_type) = content_type {
        cmd.env("CONTENT_TYPE", content_type);
    }
    cmd.env("GIT_HTTP_EXPORT_ALL", "true");
    cmd.stderr(Stdio::inherit());
    cmd.stdout(Stdio::piped());
    cmd.stdin(Stdio::piped());

    let mut p = cmd.spawn().map_err(ServeError::from)?;

    // Handle sending git client body to http-backend, if any
    let mut git_input = p.stdin.take().expect("Process should always have stdin");
    while let Some(Ok(mut buf)) = body.next().await {
        git_input
            .write_all_buf(&mut buf)
            .await
            .map_err(ServeError::from)?;
    }
    // Signal EOF to git http-backend so it knows the request body is complete.
    let _ = git_input.shutdown().await;

    // Collect headers from git CGI output
    let mut git_output = BufReader::new(p.stdout.take().expect("Process should always have stdout"));
    let mut headers = HashMap::new();
    let mut status: Option<u16> = None;
    loop {
        let mut line = String::new();
        git_output
            .read_line(&mut line)
            .await
            .map_err(ServeError::from)?;

        let line = line.trim_end();
        if line.is_empty() {
            break;
        }

        if let Some((key, value)) = line.split_once(": ") {
            if key.eq_ignore_ascii_case("Status") {
                // The Status line is of the form "200 OK"; keep just the code.
                status = value.get(..3).and_then(|s| s.parse().ok());
            } else {
                headers.insert(key.to_string(), value.to_string());
            }
        }
    }

    // Stream the git CGI response body without buffering it fully in memory.
    let stream = unfold(git_output, |mut output| async move {
        let mut bytes_out = BytesMut::new();
        match output.read_buf(&mut bytes_out).await {
            Ok(_) if bytes_out.is_empty() => None,
            Ok(_) => Some((Ok(bytes_out.freeze()), output)),
            Err(e) => Some((Err(e), output)),
        }
    });

    // Wrap the streamed body with the CGI-provided status and headers.
    let mut reply: Box<dyn Reply> = Box::new(reply::stream(stream));
    for (key, value) in headers {
        if let (Ok(name), Ok(val)) = (
            warp::http::HeaderName::from_bytes(key.as_bytes()),
            value.parse::<warp::http::HeaderValue>(),
        ) {
            reply = Box::new(reply::with_header(reply, name, val));
        }
    }
    if let Some(status) = status {
        if let Ok(status) = warp::http::StatusCode::from_u16(status) {
            reply = Box::new(reply::with_status(reply, status));
        }
    }

    Ok(reply)
}
