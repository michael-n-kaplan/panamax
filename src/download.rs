use reqwest::Client;
use reqwest::header::{HeaderValue, USER_AGENT};
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Build a `reqwest::Client` with sane timeouts so a dead peer cannot hang a
/// sync forever:
///
/// * `connect_timeout` (15s): fail fast if the peer won't accept a connection.
/// * `read_timeout` (60s): abort if no bytes arrive for 60s. This is an
///   inactivity timeout that resets on every chunk received, so it stops a
///   dead/dripping peer without capping legitimate slow-but-healthy transfers.
///
/// No global per-request timeout is set on purpose: mirror syncs stream large
/// toolchain/crate files, and a total-time cap would break slow links that
/// are otherwise making progress.
pub(crate) fn http_client() -> Client {
    Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .read_timeout(Duration::from_secs(60))
        .build()
        .expect("building a reqwest client with plain timeouts should not fail")
}

#[derive(Error, Debug)]
pub enum DownloadError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("HTTP download error: {0}")]
    Download(#[from] reqwest::Error),
    #[error("Got bad crate: {0}")]
    BadCrate(String),
    #[error("Mismatched hash - expected '{expected}', got '{actual}'")]
    MismatchedHash { expected: String, actual: String },
    #[error("HTTP not found. Status: {status}, URL: {url}, data: {data}")]
    NotFound {
        status: u16,
        url: String,
        data: String,
    },
}

/// Download a URL and return it as a string.
pub async fn download_string(
    from: &str,
    user_agent: &HeaderValue,
) -> Result<String, DownloadError> {
    let client = http_client();

    Ok(client
        .get(from)
        .header(USER_AGENT, user_agent)
        .send()
        .await?
        .text()
        .await?)
}

/// Append a string to a path.
pub fn append_to_path(path: &Path, suffix: &str) -> PathBuf {
    let mut new_path = path.as_os_str().to_os_string();
    new_path.push(suffix);
    PathBuf::from(new_path)
}

/// Write a string to a file, creating directories if needed.
pub async fn write_file_create_dir(path: &Path, contents: &str) -> Result<(), DownloadError> {
    let mut res = tokio::fs::write(path, contents).await;

    if let Err(e) = &res
        && e.kind() == io::ErrorKind::NotFound
    {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        res = tokio::fs::write(path, contents).await;
    }

    Ok(res?)
}

/// Create a file, creating directories if needed.
pub async fn create_file_create_dir(path: &Path) -> Result<tokio::fs::File, DownloadError> {
    let mut file_res = tokio::fs::File::create(path).await;
    if let Err(e) = &file_res
        && e.kind() == io::ErrorKind::NotFound
    {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        file_res = tokio::fs::File::create(path).await;
    }

    Ok(file_res?)
}

pub async fn move_if_exists(from: &Path, to: &Path) -> Result<(), DownloadError> {
    if tokio::fs::try_exists(from).await? {
        tokio::fs::rename(from, to).await?;
    }
    Ok(())
}

pub async fn move_if_exists_with_sha256(from: &Path, to: &Path) -> Result<(), DownloadError> {
    let sha256_from_path = append_to_path(from, ".sha256");
    let sha256_to_path = append_to_path(to, ".sha256");
    move_if_exists(&sha256_from_path, &sha256_to_path).await?;
    move_if_exists(from, to).await?;
    Ok(())
}

/// Copy a file and its .sha256, creating `to`'s directory if it doesn't exist.
/// Fails if the source .sha256 does not exist.
pub async fn copy_file_create_dir_with_sha256(from: &Path, to: &Path) -> Result<(), DownloadError> {
    let sha256_from_path = append_to_path(from, ".sha256");
    let sha256_to_path = append_to_path(to, ".sha256");
    copy_file_create_dir(&sha256_from_path, &sha256_to_path).await?;
    copy_file_create_dir(from, to).await?;
    Ok(())
}

/// Copy a file, creating `to`'s directory if it doesn't exist.
pub async fn copy_file_create_dir(from: &Path, to: &Path) -> Result<(), DownloadError> {
    if tokio::fs::try_exists(to).await? {
        return Ok(());
    }
    if let Some(parent) = to.parent()
        && !tokio::fs::try_exists(parent).await?
    {
        tokio::fs::create_dir_all(parent).await?;
    }

    tokio::fs::copy(from, to).await?;
    Ok(())
}

async fn one_download(
    client: &Client,
    url: &str,
    path: &Path,
    hash: Option<&str>,
    user_agent: &HeaderValue,
) -> Result<(), DownloadError> {
    let mut http_res = client
        .get(url)
        .header(USER_AGENT, user_agent)
        .send()
        .await?;
    let part_path = append_to_path(path, ".part");
    let mut sha256 = Sha256::new();
    {
        let mut f = create_file_create_dir(&part_path).await?;
        let status = http_res.status();
        if status == 403 || status == 404 {
            let forbidden_path = append_to_path(path, ".notfound");
            let text = http_res.text().await?;
            tokio::fs::write(
                forbidden_path,
                format!("Server returned {}: {}", status, &text),
            )
            .await?;
            return Err(DownloadError::NotFound {
                status: status.as_u16(),
                url: url.to_string(),
                data: text,
            });
        }

        while let Some(chunk) = http_res.chunk().await? {
            if hash.is_some() {
                sha256.update(&chunk);
            }
            f.write_all(&chunk).await?;
        }
    }

    let f_hash = format!("{:x}", sha256.finalize());

    if let Some(h) = hash {
        if f_hash == h {
            move_if_exists(&part_path, path).await?;
            Ok(())
        } else {
            let badsha_path = append_to_path(path, ".badsha256");
            tokio::fs::write(badsha_path, &f_hash).await?;
            Err(DownloadError::MismatchedHash {
                expected: h.to_string(),
                actual: f_hash,
            })
        }
    } else {
        tokio::fs::rename(part_path, path).await?;
        Ok(())
    }
}

/// Download file, verifying its hash, and retrying if needed
pub async fn download(
    client: &Client,
    url: &str,
    path: &Path,
    hash: Option<&str>,
    retries: usize,
    force_download: bool,
    user_agent: &HeaderValue,
) -> Result<(), DownloadError> {
    if tokio::fs::try_exists(path).await? && !force_download {
        if let Some(h) = hash {
            // Verify SHA-256 hash on the filesystem.
            let mut file = tokio::fs::File::open(path).await?;
            let mut buf = [0u8; 4096];
            let mut sha256 = Sha256::new();

            loop {
                let n = file.read(&mut buf).await?;
                if n == 0 {
                    break;
                }

                sha256.update(&buf[..n]);
            }

            let f_hash = format!("{:x}", sha256.finalize());
            if h == f_hash {
                // Calculated hash matches specified hash.
                return Ok(());
            }
        } else {
            return Ok(());
        }
    }

    let mut res = Ok(());
    for _ in 0..=retries {
        res = match one_download(client, url, path, hash, user_agent).await {
            Ok(_) => break,
            Err(e) => Err(e),
        }
    }

    res
}

/// Download file and associated .sha256 file, verifying the hash, and retrying if needed
pub async fn download_with_sha256_file(
    client: &Client,
    url: &str,
    path: &Path,
    retries: usize,
    force_download: bool,
    user_agent: &HeaderValue,
) -> Result<(), DownloadError> {
    let sha256_url = format!("{url}.sha256");
    let sha256_data = download_string(&sha256_url, user_agent).await?;

    let sha256_hash = &sha256_data[..64];
    download(
        client,
        url,
        path,
        Some(sha256_hash),
        retries,
        force_download,
        user_agent,
    )
    .await?;

    let sha256_path = append_to_path(path, ".sha256");
    write_file_create_dir(&sha256_path, &sha256_data).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::Filter;

    /// Spin up a small warp server on an ephemeral port serving `content` at
    /// `/file.bin` and its hex sha256 at `/file.bin.sha256`. Returns the base URL.
    async fn start_test_server(content: Vec<u8>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let hash = format!("{:x}", Sha256::digest(&content));
        let file_content = content.clone();
        let routes = warp::path::tail().and_then(move |tail: warp::path::Tail| {
            let name = tail.as_str().trim_start_matches('/').to_string();
            let file_content = file_content.clone();
            let hash_bytes = hash.clone().into_bytes();
            async move {
                if name == "file.bin" {
                    Ok::<_, warp::reject::Rejection>(warp::reply::html(file_content))
                } else if name == "file.bin.sha256" {
                    Ok(warp::reply::html(hash_bytes))
                } else {
                    Err(warp::reject::not_found())
                }
            }
        });

        tokio::spawn(async move {
            warp::serve(routes).run(addr).await;
        });

        // Wait for the server to accept connections (avoid a startup race):
        // the listening socket is bound before the accept loop starts, so
        // allow a brief grace period after connect succeeds.
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(50)).await;
                return format!("http://{addr}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("test server did not start on {addr}");
    }

    fn test_user_agent() -> HeaderValue {
        HeaderValue::from_static("panamax-test")
    }

    #[tokio::test]
    async fn download_string_returns_body() {
        let base = start_test_server(b"hello panamax".to_vec()).await;
        let out = download_string(&format!("{base}/file.bin"), &test_user_agent())
            .await
            .unwrap();
        assert_eq!(out, "hello panamax");
    }

    #[tokio::test]
    async fn download_with_matching_hash_writes_file() {
        let content = b"toolchain-bytes".to_vec();
        let base = start_test_server(content.clone()).await;
        let expected_hash = format!("{:x}", Sha256::digest(&content));
        let dir = tempfile::tempdir().unwrap();
        // Use a nested path to exercise directory creation.
        let path = dir.path().join("sub").join("file.bin");
        download(
            &http_client(),
            &format!("{base}/file.bin"),
            &path,
            Some(&expected_hash),
            0,
            false,
            &test_user_agent(),
        )
        .await
        .unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), content);
        // The .part file must have been renamed into place, not left behind.
        assert!(!append_to_path(&path, ".part").exists());
    }

    #[tokio::test]
    async fn download_with_mismatched_hash_errors_and_writes_badsha() {
        let content = b"toolchain-bytes".to_vec();
        let base = start_test_server(content.clone()).await;
        let bad_hash = "0".repeat(64);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        let err = download(
            &http_client(),
            &format!("{base}/file.bin"),
            &path,
            Some(&bad_hash),
            0,
            false,
            &test_user_agent(),
        )
        .await
        .unwrap_err();
        match err {
            DownloadError::MismatchedHash { expected, actual } => {
                assert_eq!(expected, bad_hash);
                assert_ne!(actual, bad_hash);
            }
            other => panic!("expected MismatchedHash, got {other:?}"),
        }
        // The bad download must not have been promoted to the final path.
        assert!(!path.exists());
        let badsha = tokio::fs::read(append_to_path(&path, ".badsha256"))
            .await
            .unwrap();
        assert_eq!(
            badsha,
            format!("{:x}", Sha256::digest(&content)).into_bytes()
        );
    }

    #[tokio::test]
    async fn download_existing_file_with_matching_hash_is_skipped() {
        let content = b"already-here".to_vec();
        let base = start_test_server(content.clone()).await;
        let expected_hash = format!("{:x}", Sha256::digest(&content));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        tokio::fs::write(&path, &content).await.unwrap();
        download(
            &http_client(),
            &format!("{base}/file.bin"),
            &path,
            Some(&expected_hash),
            0,
            false,
            &test_user_agent(),
        )
        .await
        .unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), content);
    }

    #[tokio::test]
    async fn download_404_maps_to_not_found() {
        let base = start_test_server(b"whatever".to_vec()).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.bin");
        let err = download(
            &http_client(),
            &format!("{base}/does-not-exist"),
            &path,
            None,
            0,
            false,
            &test_user_agent(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DownloadError::NotFound { status: 404, .. }));
        assert!(!path.exists());
        assert!(append_to_path(&path, ".notfound").exists());
    }
}
