use crate::{ApiResponseError, AppState};
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use lattice_crypto::{sha256_hex, valid_sha256_hex};
use std::path::{Path as FsPath, PathBuf};
use uuid::Uuid;

pub fn content_dir(data_dir: &FsPath) -> PathBuf {
    data_dir.join("content").join("objects")
}

pub async fn store(dir: &FsPath, bytes: &Bytes) -> Result<(String, u64, PathBuf), String> {
    if bytes.is_empty() {
        return Err("content payload must not be empty".to_string());
    }

    tokio::fs::create_dir_all(dir)
        .await
        .map_err(|error| error.to_string())?;
    secure_directory(dir)?;

    let sha256 = sha256_hex(bytes);
    let size_bytes = bytes.len() as u64;
    let path = dir.join(&sha256);

    match tokio::fs::metadata(&path).await {
        Ok(metadata) => {
            if metadata.len() != size_bytes {
                return Err("content-addressed object exists with an unexpected size".to_string());
            }
            let existing = tokio::fs::read(&path)
                .await
                .map_err(|error| error.to_string())?;
            if sha256_hex(&existing) != sha256 {
                return Err("content-addressed object failed SHA-256 verification".to_string());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let temporary = dir.join(format!(".{sha256}.{}.tmp", Uuid::new_v4().simple()));
            tokio::fs::write(&temporary, bytes)
                .await
                .map_err(|error| error.to_string())?;
            secure_file(&temporary)?;
            match tokio::fs::rename(&temporary, &path).await {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let _ = tokio::fs::remove_file(&temporary).await;
                }
                Err(error) => {
                    let _ = tokio::fs::remove_file(&temporary).await;
                    return Err(error.to_string());
                }
            }
            secure_file(&path)?;
        }
        Err(error) => return Err(error.to_string()),
    }

    Ok((sha256, size_bytes, path))
}

pub async fn get(
    State(state): State<AppState>,
    Path(sha256): Path<String>,
) -> Result<Response, ApiResponseError> {
    if !valid_sha256_hex(&sha256) {
        return Err(ApiResponseError::bad_request(
            "invalid_content_hash",
            "content hash must be lowercase SHA-256",
        ));
    }

    let path = state.content_dir.join(&sha256);
    let bytes = tokio::fs::read(&path).await.map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ApiResponseError::new(StatusCode::NOT_FOUND, "content_not_found", "content does not exist")
        } else {
            ApiResponseError::internal(error)
        }
    })?;

    if sha256_hex(&bytes) != sha256 {
        return Err(ApiResponseError::internal(
            "content-addressed object failed SHA-256 verification",
        ));
    }

    let mut response = Response::new(Body::from(bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{sha256}\""))
            .map_err(ApiResponseError::internal)?,
    );
    Ok(response)
}

#[cfg(unix)]
fn secure_directory(path: &FsPath) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn secure_directory(_path: &FsPath) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn secure_file(path: &FsPath) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn secure_file(_path: &FsPath) -> Result<(), String> {
    Ok(())
}
