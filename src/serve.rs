use std::{collections::HashMap, io, net::SocketAddr, path::PathBuf, process::Stdio, sync::Arc};

use askama::Template;
use bytes::{Bytes, BytesMut};
use futures_util::TryStreamExt;
use futures_util::stream::unfold;
use include_dir::{Dir, include_dir};
use rustls::pki_types::pem::PemObject;
use thiserror::Error;
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, SeekFrom},
    process::Command,
};
use tokio_stream::StreamExt;
use tokio_util::codec::{BytesCodec, FramedRead};
use warp::{
    Filter, Rejection,
    host::Authority,
    path::Tail,
    reject::Reject,
    reply::{self, Reply},
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

    // The `git http-backend` push endpoint (POST /<repo>/git-receive-pack) is not
    // authenticated: anyone who can reach the server can push to the local
    // crates.io-index repo. Warn loudly when the server is reachable over plain
    // HTTP, and note it even under TLS.
    if !is_tls {
        eprintln!(
            "SECURITY WARNING: serving over plain HTTP. The git index is writable by \
             anyone who can reach this server (unauthenticated git push). Only expose \
             this on a trusted network, or put it behind a reverse proxy with \
             authentication."
        );
    } else {
        eprintln!(
            "Note: the git index push endpoint is not authenticated; restrict access \
             (reverse proxy auth / firewall) if this server is internet-facing."
        );
    }

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
                let platforms = get_rustup_platforms(mirror_path).await.map_err(|_| {
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
                    warp::reject::custom(ServeError::Other(format!("Failed to render index: {e}")))
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
    let crates_dir_native_format = warp::path!("crates" / String / String / "download")
        .and(warp::header::optional("If-None-Match"))
        .and(warp::header::optional("Range"))
        .and_then(
            move |name: String,
                  version: String,
                  if_none_match: Option<String>,
                  range_header: Option<String>| {
                let mirror_path = crates_mirror_path.clone();
                async move {
                    get_crate_file(mirror_path, &name, &version, if_none_match, range_header).await
                }
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
        .and(warp::header::optional("If-None-Match"))
        .and(warp::header::optional("Range"))
        .and_then(
            move |name: String,
                  version: String,
                  crate_file: String,
                  if_none_match: Option<String>,
                  range_header: Option<String>| {
                let mirror_path = crates_mirror_path_2.clone();
                async move {
                    if !crate_file.ends_with(".crate") || !crate_file.starts_with(&name) {
                        return Err(warp::reject::not_found());
                    }
                    get_crate_file(mirror_path, &name, &version, if_none_match, range_header).await
                }
            },
        );

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
            if let Err(e) =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
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
            if entry.metadata().await?.is_dir()
                && let Some(name) = entry.file_name().to_str()
            {
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

    // Sort by name, keeping non-exe versions at the top.
    output.sort();

    Ok(output)
}

/// A parsed `Range: bytes=...` request (single range, per the issue scope).
enum ParseRange {
    /// No Range header: serve the whole file.
    Full,
    /// Inclusive byte range to serve.
    Partial(u64, u64),
    /// Malformed header or a range with no overlap with the file.
    Unsatisfiable,
}

/// Parse a single-range `Range` header against a file of `total` bytes.
fn parse_range(header: Option<&str>, total: u64) -> ParseRange {
    let Some(header) = header else {
        return ParseRange::Full;
    };
    let Some(header) = header.trim().strip_prefix("bytes=") else {
        return ParseRange::Unsatisfiable;
    };
    // Only a single range is supported (the first one if several are listed).
    let Some(spec) = header.split(',').next() else {
        return ParseRange::Unsatisfiable;
    };
    let spec = spec.trim();
    if total == 0 {
        return ParseRange::Unsatisfiable;
    }
    let (start, end) = match spec.split_once('-') {
        Some((s, e)) => {
            let s = s.trim();
            let e = e.trim();
            if s.is_empty() {
                // Suffix range: the last N bytes ("bytes=-N").
                let n = match e.parse::<u64>() {
                    Ok(n) if n <= total => n,
                    _ => return ParseRange::Unsatisfiable,
                };
                (total - n, total - 1)
            } else {
                let start = match s.parse::<u64>() {
                    Ok(v) if v < total => v,
                    _ => return ParseRange::Unsatisfiable,
                };
                // "start-" (open ended) clamps to the end of the file.
                let end = e
                    .parse::<u64>()
                    .map(|v| v.min(total - 1))
                    .unwrap_or(total - 1);
                (start, end)
            }
        }
        None => return ParseRange::Unsatisfiable,
    };
    ParseRange::Partial(start, end)
}

/// Stream up to `limit` bytes of `file` starting at `start` (206 responses).
fn range_stream(
    file: File,
    start: u64,
    limit: u64,
) -> impl futures_util::Stream<Item = Result<Bytes, io::Error>> {
    const CHUNK: u64 = 64 * 1024;
    futures_util::stream::unfold(
        (file, limit, Some(start)),
        |(mut file, remaining, seek_pending)| async move {
            if remaining == 0 {
                return None;
            }
            if let Some(pos) = seek_pending
                && let Err(e) = file.seek(SeekFrom::Start(pos)).await
            {
                return Some((Err(e), (file, 0, None)));
            }
            let want = remaining.min(CHUNK);
            let mut buf = vec![0u8; want as usize];
            match file.read_exact(&mut buf).await {
                Ok(_) => Some((Ok(Bytes::from(buf)), (file, remaining - want, None))),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => None,
                Err(e) => Some((Err(e), (file, 0, None))),
            }
        },
    )
}

/// Return a crate file as an HTTP response, streamed from disk.
///
/// Supports `If-None-Match` (304), `Last-Modified`, a weak `ETag`, and single
/// `Range` requests (206), so generic HTTP clients and resumable downloads
/// work. `cargo`/`rustup` don't use these headers and are unaffected.
async fn get_crate_file(
    mirror_path: PathBuf,
    name: &str,
    version: &str,
    if_none_match: Option<String>,
    range_header: Option<String>,
) -> Result<impl Reply + use<>, Rejection> {
    // `use<>` (edition 2024 precise capturing): the reply is fully owned
    // (tokio File + codec), so it captures no lifetimes. Without this, the
    // 2024 capture rules reject callers that borrow `name`/`version` from
    // short-lived locals.
    let full_path =
        get_crate_path(&mirror_path, name, version).ok_or_else(warp::reject::not_found)?;

    let file = File::open(full_path)
        .await
        .map_err(|_| warp::reject::not_found())?;
    let meta = file
        .metadata()
        .await
        .map_err(|_| warp::reject::not_found())?;
    let total = meta.len();

    // Weak ETag derived from mtime + size: good enough for a local file store.
    let mtime = meta
        .modified()
        .ok()
        .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let etag = format!("W/\"{}-{}\"", mtime, total);
    let last_modified = meta
        .modified()
        .ok()
        .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| httpdate::fmt_http_date(std::time::UNIX_EPOCH + d));

    // 304 Not Modified?
    if let Some(header) = if_none_match {
        let strong = format!("\"{}-{}\"", mtime, total);
        let matched = header
            .split(',')
            .map(str::trim)
            .any(|v| v == "*" || v == etag || v == strong);
        if matched {
            // Same concrete type (Box<dyn Reply>) as the full/partial arms
            // so the `impl Reply` return type unifies.
            let r: Box<dyn Reply> = Box::new(reply::with_header(
                // `()` doesn't implement Reply in warp 0.4; use an empty Vec.
                reply::with_status(Vec::<u8>::new(), warp::http::StatusCode::NOT_MODIFIED),
                "ETag",
                etag,
            ));
            return Ok(r);
        }
    }

    let reply: Box<dyn Reply> = match parse_range(range_header.as_deref(), total) {
        ParseRange::Unsatisfiable => Box::new(reply::with_header(
            reply::with_status(
                Vec::<u8>::new(),
                warp::http::StatusCode::RANGE_NOT_SATISFIABLE,
            ),
            "Content-Range",
            format!("bytes */{total}"),
        )),
        ParseRange::Partial(start, end) => {
            let stream = range_stream(file, start, end - start + 1);
            let r = reply::with_status(
                reply::stream(stream),
                warp::http::StatusCode::PARTIAL_CONTENT,
            );
            let r = reply::with_header(r, "Content-Range", format!("bytes {start}-{end}/{total}"));
            let r = reply::with_header(r, "ETag", etag);
            if let Some(lm) = last_modified {
                let r = reply::with_header(r, "Last-Modified", lm);
                Box::new(r)
            } else {
                Box::new(r)
            }
        }
        ParseRange::Full => {
            let stream =
                FramedRead::new(file, BytesCodec::new()).map_ok(|buf: BytesMut| buf.freeze());
            let r = reply::with_header(
                reply::stream(stream),
                warp::http::header::CONTENT_LENGTH,
                total,
            );
            let r = reply::with_header(r, "ETag", etag);
            if let Some(lm) = last_modified {
                let r = reply::with_header(r, "Last-Modified", lm);
                Box::new(r)
            } else {
                Box::new(r)
            }
        }
    };

    Ok(reply)
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
    let mut git_output =
        BufReader::new(p.stdout.take().expect("Process should always have stdout"));
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
    if let Some(status) = status
        && let Ok(status) = warp::http::StatusCode::from_u16(status)
    {
        reply = Box::new(reply::with_status(reply, status));
    }

    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Build a small mirror fixture inside `dir`:
    /// a rustup platform, a dist file, one crate (ri/pg/ripgrep 13.0.0),
    /// a sparse-index file, and a git repo for /git/crates.io-index.
    fn make_test_mirror(dir: &Path) {
        use std::fs;

        let platform_dir = dir
            .join("rustup")
            .join("dist")
            .join("x86_64-unknown-linux-gnu");
        fs::create_dir_all(&platform_dir).unwrap();
        fs::write(platform_dir.join("rustup-init"), b"fake-rustup-init").unwrap();

        let dist_dir = dir.join("dist").join("test-tool");
        fs::create_dir_all(&dist_dir).unwrap();
        fs::write(dist_dir.join("toolchain"), b"fake-toolchain").unwrap();

        let crate_dir = dir
            .join("crates")
            .join("ri")
            .join("pg")
            .join("ripgrep")
            .join("13.0.0");
        fs::create_dir_all(&crate_dir).unwrap();
        fs::write(
            crate_dir.join("ripgrep-13.0.0.crate"),
            b"fake-ripgrep-crate",
        )
        .unwrap();

        let index_dir = dir.join("crates.io-index");
        fs::create_dir_all(index_dir.join("ri").join("pg")).unwrap();
        let index_line = b"{\"vers\":\"13.0.0\"}\n";
        fs::write(index_dir.join("ri").join("pg").join("ripgrep"), index_line).unwrap();

        let repo = git2::Repository::init(&index_dir).unwrap();
        let sig = git2::Signature::now("tester", "t@example.com").unwrap();
        // Build the tree bottom-up: ripgrep file -> pg tree -> ri tree -> root.
        // (git2's TreeBuilder does not create intermediate directories.)
        const TREE_MODE: i32 = 0o40000; // directory
        const FILE_MODE: i32 = 0o100644;
        let ripgrep_oid = repo.blob(index_line).unwrap();
        let mut pg_tb = repo.treebuilder(None).unwrap();
        pg_tb.insert("ripgrep", ripgrep_oid, FILE_MODE).unwrap();
        let pg_oid = pg_tb.write().unwrap();

        let mut ri_tb = repo.treebuilder(None).unwrap();
        ri_tb.insert("pg", pg_oid, TREE_MODE).unwrap();
        let ri_oid = ri_tb.write().unwrap();

        let mut tree_builder = repo.treebuilder(None).unwrap();
        tree_builder.insert("ri", ri_oid, TREE_MODE).unwrap();
        let tree_oid = tree_builder.write().unwrap();
        let tree = repo.find_tree(tree_oid).unwrap();
        repo.commit(
            Some("refs/heads/master"),
            &sig,
            &sig,
            "test index",
            &tree,
            &[],
        )
        .unwrap();
        repo.set_head("refs/heads/master").unwrap();
    }

    // Takes an owned PathBuf so the returned `impl Filter` captures no
    // lifetimes (edition 2024 RPIT capture) and satisfies warp::test's 'static bound.
    fn routes(
        mirror: PathBuf,
    ) -> impl warp::Filter<Extract = impl warp::reply::Reply, Error = warp::reject::Rejection>
    + Clone
    + Send
    + Sync {
        build_routes(mirror, false)
    }

    fn body_of(resp: http::Response<bytes::Bytes>) -> Vec<u8> {
        resp.into_body().as_ref().to_vec()
    }

    #[test]
    fn index_template_renders_platforms_and_host() {
        let platforms = vec![
            Platform {
                is_exe: false,
                platform_triple: "x86_64-unknown-linux-gnu".into(),
            },
            Platform {
                is_exe: true,
                platform_triple: "x86_64-pc-windows-msvc".into(),
            },
        ];
        let html = IndexTemplate {
            platforms,
            host: "http://mirror.example.com".into(),
        }
        .render()
        .unwrap();
        assert!(html.contains("x86_64-unknown-linux-gnu"));
        assert!(html.contains("x86_64-pc-windows-msvc"));
        assert!(html.contains("http://mirror.example.com"));
        // The <select> options carry the is_exe flag as their value.
        assert!(html.contains("option value=\"false\""));
        assert!(html.contains("option value=\"true\""));
    }

    #[tokio::test]
    async fn index_route_returns_platform_html() {
        let dir = tempfile::tempdir().unwrap();
        make_test_mirror(dir.path());
        let resp = warp::test::request()
            .path("/")
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        let content_type = resp
            .headers()
            .get(http::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(content_type.starts_with("text/html"));
        let html = String::from_utf8(body_of(resp)).unwrap();
        assert!(html.contains("Panamax"));
        assert!(html.contains("x86_64-unknown-linux-gnu"));
    }

    #[tokio::test]
    async fn static_route_serves_bundled_asset() {
        let dir = tempfile::tempdir().unwrap();
        make_test_mirror(dir.path());
        let resp = warp::test::request()
            .path("/static/css/panamax.css")
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        let served = String::from_utf8(body_of(resp)).unwrap();
        // The bundled file is baked in via include_dir; compare against the source.
        let expected = std::fs::read_to_string("static/css/panamax.css").unwrap();
        assert_eq!(served, expected);
    }

    #[tokio::test]
    async fn static_route_404s_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        make_test_mirror(dir.path());
        let resp = warp::test::request()
            .path("/static/does-not-exist.css")
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn dist_and_rustup_routes_serve_files() {
        let dir = tempfile::tempdir().unwrap();
        make_test_mirror(dir.path());

        let resp = warp::test::request()
            .path("/dist/test-tool/toolchain")
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(body_of(resp), b"fake-toolchain");

        let resp = warp::test::request()
            .path("/rustup/dist/x86_64-unknown-linux-gnu/rustup-init")
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(body_of(resp), b"fake-rustup-init");
    }

    #[tokio::test]
    async fn crate_native_and_condensed_formats_serve_file() {
        let dir = tempfile::tempdir().unwrap();
        make_test_mirror(dir.path());

        // Cargo's default layout: /crates/{name}/{version}/download
        let resp = warp::test::request()
            .path("/crates/ripgrep/13.0.0/download")
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(http::header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap(),
            b"fake-ripgrep-crate".len().to_string()
        );
        assert_eq!(body_of(resp), b"fake-ripgrep-crate");

        // Panamax's condensed layout: /crates/{2}/{2}/{name}/{version}/{file}
        let resp = warp::test::request()
            .path("/crates/ri/pg/ripgrep/13.0.0/ripgrep-13.0.0.crate")
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(body_of(resp), b"fake-ripgrep-crate");
    }

    #[tokio::test]
    async fn crate_routes_404_for_missing_or_mismatched_crate() {
        let dir = tempfile::tempdir().unwrap();
        make_test_mirror(dir.path());

        // Unknown crate (native format).
        let resp = warp::test::request()
            .path("/crates/nope/0.1.0/download")
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        // Condensed format where the crate file doesn't exist on disk.
        let resp = warp::test::request()
            .path("/crates/se/rd/serde/1.0.0/serde-1.0.0.crate")
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn git_route_serves_info_refs() {
        let dir = tempfile::tempdir().unwrap();
        make_test_mirror(dir.path());

        let resp = warp::test::request()
            .path("/git/crates.io-index/info/refs?service=git-upload-pack")
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        let body = body_of(resp);
        let text = String::from_utf8_lossy(&body);
        // pkt-line framing: each line is prefixed with a 4-hex-digit length.
        assert!(text.contains("# service=git-upload-pack"), "body: {text}");
        assert!(text.contains("refs/heads/master"), "body: {text}");
    }

    #[tokio::test]
    async fn sparse_index_route_serves_index_file() {
        let dir = tempfile::tempdir().unwrap();
        make_test_mirror(dir.path());

        let resp = warp::test::request()
            .path("/index/ri/pg/ripgrep")
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert!(String::from_utf8_lossy(&body_of(resp)).contains("\"13.0.0\""));
    }

    #[tokio::test]
    async fn unknown_route_404s() {
        let dir = tempfile::tempdir().unwrap();
        make_test_mirror(dir.path());

        let resp = warp::test::request()
            .path("/definitely-not-a-route")
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn crate_route_etag_and_304() {
        let dir = tempfile::tempdir().unwrap();
        make_test_mirror(dir.path());

        // First request advertises a weak ETag and Last-Modified.
        let resp = warp::test::request()
            .path("/crates/ripgrep/13.0.0/download")
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        let etag = resp
            .headers()
            .get(http::header::ETAG)
            .expect("ETag header present")
            .to_str()
            .unwrap()
            .to_string();
        assert!(etag.starts_with("W/\""), "weak etag: {etag}");
        assert!(resp.headers().get(http::header::LAST_MODIFIED).is_some());
        let body = body_of(resp);
        assert_eq!(body, b"fake-ripgrep-crate");

        // Same ETag back -> 304 with an empty body.
        let resp = warp::test::request()
            .path("/crates/ripgrep/13.0.0/download")
            .header("If-None-Match", &etag)
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::NOT_MODIFIED);
        assert_eq!(body_of(resp), b"");

        // A different ETag -> full 200 again.
        let resp = warp::test::request()
            .path("/crates/ripgrep/13.0.0/download")
            .header("If-None-Match", "W/\"0-1\"")
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(body_of(resp), body);
    }

    #[tokio::test]
    async fn crate_route_range_requests() {
        let dir = tempfile::tempdir().unwrap();
        make_test_mirror(dir.path());
        const BODY: &[u8] = b"fake-ripgrep-crate"; // 18 bytes
        let path = "/crates/ripgrep/13.0.0/download";

        // Explicit range: first 5 bytes.
        let resp = warp::test::request()
            .path(path)
            .header("Range", "bytes=0-4")
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers()
                .get(http::header::CONTENT_RANGE)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes 0-4/18"
        );
        assert_eq!(body_of(resp), &BODY[0..5]);

        // Open-ended: from byte 5 to the end.
        let resp = warp::test::request()
            .path(path)
            .header("Range", "bytes=5-")
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::PARTIAL_CONTENT);
        assert_eq!(body_of(resp), &BODY[5..]);

        // Suffix range: last 4 bytes.
        let resp = warp::test::request()
            .path(path)
            .header("Range", "bytes=-4")
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::PARTIAL_CONTENT);
        assert_eq!(body_of(resp), &BODY[14..]);

        // Range beyond EOF -> 416 with Content-Range: bytes */total.
        let resp = warp::test::request()
            .path(path)
            .header("Range", "bytes=999-")
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            resp.headers()
                .get(http::header::CONTENT_RANGE)
                .unwrap()
                .to_str()
                .unwrap(),
            "bytes */18"
        );

        // Condensed format gets the same treatment.
        let resp = warp::test::request()
            .path("/crates/ri/pg/ripgrep/13.0.0/ripgrep-13.0.0.crate")
            .header("Range", "bytes=0-3")
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::PARTIAL_CONTENT);
        assert_eq!(body_of(resp), &BODY[0..4]);
    }

    #[tokio::test]
    async fn dist_route_range_requests() {
        // /dist is served by warp::fs, which implements Range natively.
        let dir = tempfile::tempdir().unwrap();
        make_test_mirror(dir.path());

        let resp = warp::test::request()
            .path("/dist/test-tool/toolchain")
            .header("Range", "bytes=0-3")
            .reply(&routes(dir.path().to_path_buf()))
            .await;
        assert_eq!(resp.status(), http::StatusCode::PARTIAL_CONTENT);
        // bytes=0-3 is inclusive: 4 bytes.
        assert_eq!(body_of(resp), b"fake");
    }
}
