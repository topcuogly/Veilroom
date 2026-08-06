//! SOCKS5 client for connecting through the session's Tor SOCKS socket
//! (sections 9 and 13).
//!
//! Tor is launched with a Unix-socket SOCKS port. A participant connects to
//! that socket, performs the SOCKS5 greeting without authentication, and
//! requests a CONNECT to `<onion>:<port>`. The reply is validated byte by
//! byte; a refused or malformed reply is an error.

use std::io;
use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Connects to `onion_address:port` through the SOCKS socket at
/// `socks_path`.
///
/// The returned stream is the established tunnel to the onion service.
pub async fn connect_via_socks(
    socks_path: &Path,
    onion_address: &str,
    port: u16,
) -> io::Result<UnixStream> {
    let operation = async {
        let mut stream = UnixStream::connect(socks_path).await?;
        handshake(&mut stream, onion_address, port).await?;
        Ok(stream)
    };
    tokio::time::timeout(std::time::Duration::from_secs(30), operation)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS connection timed out"))?
}

/// Performs the SOCKS5 handshake on an already-connected stream.
async fn handshake(stream: &mut UnixStream, onion_address: &str, port: u16) -> io::Result<()> {
    if onion_address.len() > u8::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "onion address is too long for SOCKS5",
        ));
    }
    // Version 5, one offered method: no authentication.
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [0x05, 0x00] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("the SOCKS proxy rejected the no-auth method: {greeting:02x?}"),
        ));
    }
    // CONNECT, reserved, address type 0x03 (domain name), host, port.
    let mut request = Vec::with_capacity(7 + onion_address.len());
    request.push(0x05); // version
    request.push(0x01); // CONNECT
    request.push(0x00); // reserved
    request.push(0x03); // domain name
    request.push(onion_address.len() as u8);
    request.extend_from_slice(onion_address.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed SOCKS reply: {header:02x?}"),
        ));
    }
    if header[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS connect refused with code {}", header[1]),
        ));
    }
    // The bind address in the reply is not trusted; only the success code
    // matters. The address type determines the remaining reply length,
    // which must be fully consumed so the tunnel bytes start cleanly.
    let tail = match header[3] {
        0x01 => 4 + 2, // IPv4 + port
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            len[0] as usize + 2
        }
        0x04 => 16 + 2, // IPv6 + port
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown SOCKS address type {other}"),
            ));
        }
    };
    if tail > 0 {
        let mut rest = vec![0u8; tail];
        stream.read_exact(&mut rest).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    /// Reads the greeting and CONNECT request, replies with success, and
    /// echoes everything back until EOF.
    async fn fake_proxy(mut server: UnixStream, expect_host: &str, accept: bool) {
        let mut greeting = [0u8; 3];
        server.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        server.write_all(&[0x05, 0x00]).await.unwrap();
        let mut header = [0u8; 5];
        server.read_exact(&mut header).await.unwrap();
        assert_eq!(header, [0x05, 0x01, 0x00, 0x03, expect_host.len() as u8]);
        let mut host = vec![0u8; expect_host.len()];
        server.read_exact(&mut host).await.unwrap();
        assert_eq!(host, expect_host.as_bytes());
        let mut port = [0u8; 2];
        server.read_exact(&mut port).await.unwrap();
        let status = if accept { 0x00 } else { 0x05 };
        server
            .write_all(&[0x05, status, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        if !accept {
            return;
        }
        let mut buf = [0u8; 64];
        while let Ok(n) = server.read(&mut buf).await {
            if n == 0 {
                break;
            }
            server.write_all(&buf[..n]).await.unwrap();
        }
    }

    #[tokio::test]
    async fn handshake_connects_through_a_fake_proxy() {
        let (client, server) = UnixStream::pair().unwrap();
        let proxy = tokio::spawn(fake_proxy(server, "abc.onion", true));
        let mut stream = handshake_into_stream(client, "abc.onion", 80)
            .await
            .unwrap();
        // The tunnel is established; bytes now flow end to end.
        stream.write_all(b"ping").await.unwrap();
        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ping");
        drop(stream);
        proxy.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_reports_a_refused_connect() {
        let (client, server) = UnixStream::pair().unwrap();
        let proxy = tokio::spawn(fake_proxy(server, "abc.onion", false));
        let error = handshake_into_stream(client, "abc.onion", 80)
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        proxy.await.unwrap();
    }

    /// Runs the handshake and echoes everything back until EOF.
    async fn handshake_into_stream(
        client: UnixStream,
        host: &str,
        port: u16,
    ) -> io::Result<UnixStream> {
        let mut stream = client;
        handshake(&mut stream, host, port).await?;
        Ok(stream)
    }

    #[tokio::test]
    async fn connect_via_socks_uses_the_socket_path() {
        let dir = std::env::temp_dir().join(format!("veilroom-socks-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("socks.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let accept = tokio::spawn(async move {
            let (server, _) = listener.accept().await.unwrap();
            fake_proxy(server, "abc.onion", true).await;
        });
        let mut stream = connect_via_socks(&sock, "abc.onion", 80).await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut reply = [0u8; 5];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"hello");
        drop(stream);
        accept.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
