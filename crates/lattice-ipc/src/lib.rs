use lattice_protocol::{IpcRequest, IpcResponse};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

pub const WINDOWS_PIPE_NAME: &str = r"\\.\pipe\lattice-node";
pub const UNIX_SOCKET_PATH: &str = "/tmp/lattice-node.sock";

pub async fn request(request: &IpcRequest) -> Result<IpcResponse, String> {
    request_platform(request).await
}

async fn exchange<S>(mut stream: S, request: &IpcRequest) -> Result<IpcResponse, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut payload = serde_json::to_vec(request).map_err(|error| error.to_string())?;
    payload.push(b'\n');
    stream
        .write_all(&payload)
        .await
        .map_err(|error| error.to_string())?;
    stream.flush().await.map_err(|error| error.to_string())?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let bytes = reader
        .read_line(&mut line)
        .await
        .map_err(|error| error.to_string())?;
    if bytes == 0 {
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
