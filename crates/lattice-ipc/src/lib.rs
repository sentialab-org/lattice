use lattice_protocol::{IpcRequest, IpcResponse};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};

pub const WINDOWS_PIPE_NAME: &str = r"\\.\pipe\lattice-node";
#[cfg(target_os = "linux")]
pub const UNIX_SOCKET_PATH: &str = "/run/lattice/node.sock";
#[cfg(not(target_os = "linux"))]
pub const UNIX_SOCKET_PATH: &str = "/var/run/lattice/node.sock";

/// Includes base64 overhead for the largest supported local content operation.
pub const MAX_FRAME_BYTES: usize = 96 * 1024 * 1024;

pub async fn read_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> Result<String, String> {
    let mut bytes = Vec::new();
    let count = reader
        .take(limit.saturating_add(1) as u64)
        .read_until(b'\n', &mut bytes)
        .await
        .map_err(|_| "IPC frame read failed")?;
    if count > limit {
        return Err("IPC frame exceeds size limit".into());
    }
    if count > 0 && bytes.last() != Some(&b'\n') {
        return Err("truncated IPC frame".into());
    }
    String::from_utf8(bytes).map_err(|_| "IPC frame is not UTF-8".into())
}

pub async fn request(request: &IpcRequest) -> Result<IpcResponse, String> {
    request_platform(request).await
}

async fn exchange<S>(mut stream: S, request: &IpcRequest) -> Result<IpcResponse, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut payload = serde_json::to_vec(request).map_err(|error| error.to_string())?;
    payload.push(b'\n');
    if payload.len() > MAX_FRAME_BYTES {
        return Err("IPC frame exceeds size limit".into());
    }
    stream
        .write_all(&payload)
        .await
        .map_err(|error| error.to_string())?;
    stream.flush().await.map_err(|error| error.to_string())?;

    let mut reader = BufReader::new(stream);
    let line = tokio::time::timeout(
        std::time::Duration::from_secs(180),
        read_frame(&mut reader, MAX_FRAME_BYTES),
    )
    .await
    .map_err(|_| "IPC response timed out")??;
    if line.is_empty() {
        return Err("lattice-node closed the IPC connection without a response".to_string());
    }

    serde_json::from_str(&line).map_err(|error| error.to_string())
}

#[cfg(windows)]
async fn request_platform(request: &IpcRequest) -> Result<IpcResponse, String> {
    use std::time::Duration;
    use tokio::net::windows::named_pipe::ClientOptions;
    use tokio::time::sleep;

    let pipe_name = std::env::var("LATTICE_PIPE").unwrap_or_else(|_| WINDOWS_PIPE_NAME.to_string());
    let mut last_error = None;

    for _ in 0..20 {
        match ClientOptions::new().open(&pipe_name) {
            Ok(client) => return exchange(client, request).await,
            Err(error) => {
                last_error = Some(error.to_string());
                sleep(Duration::from_millis(50)).await;
            }
        }
    }

    Err(last_error.unwrap_or_else(|| "unable to connect to lattice-node".to_string()))
}

#[cfg(unix)]
async fn request_platform(request: &IpcRequest) -> Result<IpcResponse, String> {
    use tokio::net::UnixStream;

    let socket_path =
        std::env::var("LATTICE_SOCKET").unwrap_or_else(|_| UNIX_SOCKET_PATH.to_string());
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|error| error.to_string())?;
    exchange(stream, request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn frames_reject_oversized_or_truncated_messages() {
        for data in [b"123456789\n".as_slice(), b"partial".as_slice()] {
            let (mut writer, reader) = tokio::io::duplex(64);
            writer.write_all(data).await.unwrap();
            writer.shutdown().await.unwrap();
            assert!(read_frame(&mut BufReader::new(reader), 8).await.is_err());
        }
        let (mut writer, reader) = tokio::io::duplex(64);
        writer.write_all(b"{}\nsecond\n").await.unwrap();
        let mut reader = BufReader::new(reader);
        assert_eq!(read_frame(&mut reader, 8).await.unwrap(), "{}\n");
        assert_eq!(read_frame(&mut reader, 8).await.unwrap(), "second\n");
    }
}
