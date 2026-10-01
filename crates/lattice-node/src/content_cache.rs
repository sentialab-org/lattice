use reqwest::Client;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

pub struct ContentSpec<'a> {
    pub sha256: &'a str,
    pub size_bytes: u64,
    pub download_url: &'a str,
}

pub async fn ensure_content(
    client: &Client,
    cache_root: &Path,
    spec: &ContentSpec<'_>,
    retries: u32,
    label: &str,
) -> Result<PathBuf, String> {
    let objects_dir = cache_root.join("objects");
    let temp_dir = cache_root.join("tmp");
    tokio::fs::create_dir_all(&objects_dir)
        .await
        .map_err(|error| error.to_string())?;
    tokio::fs::create_dir_all(&temp_dir)
        .await
        .map_err(|error| error.to_string())?;
    secure_directory(&objects_dir)?;
    secure_directory(&temp_dir)?;
    cleanup_temp_files(&temp_dir).await?;

    let final_path = objects_dir.join(spec.sha256);

    if tokio::fs::try_exists(&final_path)
        .await
        .map_err(|error| error.to_string())?
    {
        if verify_file(&final_path, spec).await.is_ok() {
            return Ok(final_path);
        }
        tokio::fs::remove_file(&final_path)
            .await
            .map_err(|error| error.to_string())?;
    }

    let retries = retries.clamp(1, 5);
    let mut last_error = format!("{label} download failed");

    for attempt in 1..=retries {
        let temp_path = temp_dir.join(format!("{}.part", Uuid::new_v4().simple()));
        match download_once(client, spec, &temp_path, label).await {
            Ok(()) => {
                if tokio::fs::try_exists(&final_path)
                    .await
                    .map_err(|error| error.to_string())?
                {
                    if verify_file(&final_path, spec).await.is_ok() {
                        let _ = tokio::fs::remove_file(&temp_path).await;
                        return Ok(final_path);
                    }
                    tokio::fs::remove_file(&final_path)
                        .await
                        .map_err(|error| error.to_string())?;
                }

                tokio::fs::rename(&temp_path, &final_path)
                    .await
                    .map_err(|error| error.to_string())?;
                secure_file(&final_path)?;
                verify_file(&final_path, spec).await?;
                return Ok(final_path);
            }
            Err(error) => {
                last_error = error;
                let _ = tokio::fs::remove_file(&temp_path).await;
                if attempt < retries {
                    tokio::time::sleep(Duration::from_millis(250 * u64::from(attempt))).await;
                }
            }
        }
    }

    Err(last_error)
}

pub async fn verify_file(path: &Path, spec: &ContentSpec<'_>) -> Result<(), String> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|error| error.to_string())?;

    if metadata.len() != spec.size_bytes {
        return Err("cached content size does not match the signed manifest".to_string());
    }

    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];

    loop {
        let read = tokio::io::AsyncReadExt::read(&mut file, &mut buffer)
            .await
            .map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    let digest = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    if digest != spec.sha256 {
        return Err("cached content SHA-256 does not match the signed manifest".to_string());
    }

    Ok(())
}

async fn cleanup_temp_files(temp_dir: &Path) -> Result<(), String> {
    let mut entries = tokio::fs::read_dir(temp_dir)
        .await
        .map_err(|error| error.to_string())?;

    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|error| error.to_string())?
    {
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "part")
        {
            let _ = tokio::fs::remove_file(path).await;
        }
    }

    Ok(())
}

async fn download_once(
    client: &Client,
    spec: &ContentSpec<'_>,
    temp_path: &Path,
    label: &str,
) -> Result<(), String> {
    let mut response = client
        .get(spec.download_url)
        .send()
        .await
        .map_err(|error| format!("{label} request failed: {error}"))?;

    if !response.status().is_success() {
        return Err(format!(
            "{label} server returned HTTP {}",
            response.status()
        ));
    }

    if let Some(length) = response.content_length()
        && length != spec.size_bytes
    {
        return Err(format!(
            "{label} Content-Length does not match the signed manifest"
        ));
    }

    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(temp_path)
        .await
        .map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("{label} download failed: {error}"))?
    {
        total = total
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| format!("{label} size overflow"))?;

        if total > spec.size_bytes {
            return Err(format!("{label} exceeded the signed size"));
        }

        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(|error| error.to_string())?;
    }

    if total != spec.size_bytes {
        return Err(format!("{label} size does not match the signed manifest"));
    }

    let digest = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    if digest != spec.sha256 {
        return Err(format!(
            "{label} SHA-256 does not match the signed manifest"
        ));
    }

    file.flush().await.map_err(|error| error.to_string())?;
    file.sync_all().await.map_err(|error| error.to_string())?;
    Ok(())
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn secure_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn secure_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn secure_file(_path: &Path) -> Result<(), String> {
    Ok(())
}
