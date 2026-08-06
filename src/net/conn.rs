//! Per-connection reader/writer tasks (architecture decision 12, section 29).
//!
//! Every connection is one [`PeerConnection`]: a spawned task owns the
//! socket and multiplexes (a) inbound frames decoded into typed
//! [`Message`]s forwarded to the supervisor, (b) outbound typed messages
//! from a bounded queue, and (c) a keepalive ticker. A full outbound queue
//! is reported immediately to the caller, which must close the slow
//! connection; other members are never blocked (section 29).

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinHandle;

use crate::limits::Limits;
#[cfg(test)]
use crate::net::INBOUND_QUEUE_CAPACITY;
use crate::net::OUTBOUND_QUEUE_CAPACITY;
use crate::protocol::frame::{Frame, FrameDecoder};
use crate::protocol::ids::ErrorCode;
use crate::protocol::messages::{ErrorMessage, Message};

/// The default keepalive interval.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// A spawned per-connection read/write task.
#[derive(Debug)]
pub struct PeerConnection {
    outbound: mpsc::Sender<Message>,
    handle: JoinHandle<()>,
}

impl PeerConnection {
    /// Spawns the connection task over `stream`.
    ///
    /// Decoded inbound messages are forwarded to `inbound` as `Some`;
    /// `None` marks connection teardown (EOF, frame error, or an
    /// unrecoverable write failure). The outbound queue is bounded at
    /// [`OUTBOUND_QUEUE_CAPACITY`].
    pub fn spawn(
        stream: UnixStream,
        limits: Limits,
        inbound: mpsc::Sender<Option<Message>>,
    ) -> Self {
        Self::spawn_with_keepalive(stream, limits, inbound, KEEPALIVE_INTERVAL)
    }

    /// Spawns the connection task with an explicit keepalive interval
    /// (test seam).
    pub fn spawn_with_keepalive(
        stream: UnixStream,
        limits: Limits,
        inbound: mpsc::Sender<Option<Message>>,
        keepalive: Duration,
    ) -> Self {
        let (outbound, outbound_rx) = mpsc::channel::<Message>(OUTBOUND_QUEUE_CAPACITY);
        let handle = tokio::spawn(run(stream, limits, inbound, outbound_rx, keepalive));
        Self { outbound, handle }
    }

    /// Queues a message for the peer.
    ///
    /// Returns [`PeerSendError::QueueFull`] immediately when the bounded
    /// outbound queue is full: the peer is a slow client and must be
    /// closed. Returns [`PeerSendError::Closed`] when the task has ended.
    pub fn send(&self, message: Message) -> Result<(), PeerSendError> {
        match self.outbound.try_send(message) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(PeerSendError::QueueFull),
            Err(TrySendError::Closed(_)) => Err(PeerSendError::Closed),
        }
    }

    /// Closes the connection task.
    pub fn close(self) {
        drop(self);
    }
}

impl Drop for PeerConnection {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Sending to a peer failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSendError {
    /// The outbound queue is full; the slow connection must be closed.
    QueueFull,
    /// The connection task has ended.
    Closed,
}

impl std::fmt::Display for PeerSendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueueFull => formatter.write_str("the connection's outbound queue is full"),
            Self::Closed => formatter.write_str("the connection is closed"),
        }
    }
}

impl std::error::Error for PeerSendError {}

/// The connection task loop.
async fn run(
    stream: UnixStream,
    limits: Limits,
    inbound: mpsc::Sender<Option<Message>>,
    mut outbound: mpsc::Receiver<Message>,
    keepalive: Duration,
) {
    let (mut reader, mut writer) = stream.into_split();
    let mut decoder = FrameDecoder::new(limits);
    let mut ticker = tokio::time::interval(keepalive);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;
            _ = ticker.tick() => {
                let message = Message::Keepalive(crate::protocol::messages::Keepalive);
                if encode_write(&mut writer, &message, &limits).await.is_err() {
                    close(&inbound).await;
                    return;
                }
            }
            maybe = outbound.recv() => {
                let Some(message) = maybe else {
                    close(&inbound).await;
                    return;
                };
                if encode_write(&mut writer, &message, &limits).await.is_err() {
                    close(&inbound).await;
                    return;
                }
            }
            frames = read_frames(&mut reader, &mut decoder, &limits) => {
                match frames {
                    Ok(Some(frames)) => {
                        for frame in frames {
                            match Message::decode(&frame, &limits) {
                                Ok(message) => {
                                    if inbound.send(Some(message)).await.is_err() {
                                        return;
                                    }
                                }
                                Err(_) => {
                                    // Protocol violation: report, then close.
                                    let reason = ErrorMessage::new(
                                        ErrorCode::ProtocolViolation,
                                        Some("undecodable frame".to_owned()),
                                    )
                                    .unwrap_or_else(|_| {
                                        ErrorMessage::new(ErrorCode::ProtocolViolation, None)
                                            .expect("a reason-less error is always valid")
                                    });
                                    let error = Message::Error(reason);
                                    if inbound.send(Some(error.clone())).await.is_err() {
                                        return;
                                    }
                                    let _ = encode_write(&mut writer, &error, &limits).await;
                                    close(&inbound).await;
                                    return;
                                }
                            }
                        }
                    }
                    Ok(None) | Err(_) => {
                        close(&inbound).await;
                        return;
                    }
                }
            }
        }
    }
}

/// Signals teardown on the inbound channel.
async fn close(inbound: &mpsc::Sender<Option<Message>>) {
    let _ = inbound.send(None).await;
}

/// Reads and decodes one batch of complete frames.
///
/// Returns `Ok(Some(frames))` on new frames, `Ok(None)` on EOF, and
/// `Err` on a frame error (oversized, malformed header, ...).
async fn read_frames(
    reader: &mut tokio::net::unix::OwnedReadHalf,
    decoder: &mut FrameDecoder,
    limits: &Limits,
) -> Result<Option<Vec<Frame>>, crate::protocol::frame::FrameError> {
    let mut buf = [0u8; 2048];
    let n = match reader.read(&mut buf).await {
        Ok(0) => {
            decoder.finish()?;
            return Ok(None);
        }
        Ok(n) => n,
        Err(_) => return Err(crate::protocol::frame::FrameError::UnexpectedEof),
    };
    let frames = decoder.feed(&buf[..n])?;
    let _ = limits;
    if frames.is_empty() {
        Ok(Some(Vec::new()))
    } else {
        Ok(Some(frames))
    }
}

/// Encodes and writes one message as a frame.
async fn encode_write(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    message: &Message,
    limits: &Limits,
) -> Result<(), std::io::Error> {
    let bytes = message
        .encode(limits)
        .map_err(|_| std::io::Error::other("message could not be encoded"))?;
    tokio::time::timeout(std::time::Duration::from_secs(10), writer.write_all(&bytes))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "peer write timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::messages::Shutdown;

    #[tokio::test]
    async fn messages_round_trip_through_a_peer_pair() {
        let (host_stream, client_stream) = UnixStream::pair().unwrap();
        let (host_inbound, mut host_rx) = mpsc::channel(INBOUND_QUEUE_CAPACITY);
        let (client_inbound, mut client_rx) = mpsc::channel(INBOUND_QUEUE_CAPACITY);
        let host = PeerConnection::spawn(host_stream, Limits::default(), host_inbound);
        let client = PeerConnection::spawn(client_stream, Limits::default(), client_inbound);

        client.send(Message::Shutdown(Shutdown)).expect("queued");
        let received = tokio::time::timeout(Duration::from_secs(5), host_rx.recv())
            .await
            .expect("message arrives")
            .expect("channel open")
            .expect("message, not teardown");
        assert_eq!(received, Message::Shutdown(Shutdown));

        host.send(Message::Keepalive(crate::protocol::messages::Keepalive))
            .expect("queued");
        let received = tokio::time::timeout(Duration::from_secs(5), client_rx.recv())
            .await
            .expect("message arrives")
            .expect("channel open")
            .expect("message, not teardown");
        assert_eq!(
            received,
            Message::Keepalive(crate::protocol::messages::Keepalive)
        );

        host.close();
        client.close();
    }

    #[tokio::test]
    async fn eof_reports_teardown_on_the_inbound_channel() {
        let (host_stream, client_stream) = UnixStream::pair().unwrap();
        let (inbound, mut rx) = mpsc::channel(INBOUND_QUEUE_CAPACITY);
        let peer = PeerConnection::spawn(host_stream, Limits::default(), inbound);
        drop(client_stream);
        // The immediate first keepalive tick may deliver a keepalive before
        // the EOF is observed; drain until the teardown marker.
        let teardown = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match rx.recv().await {
                    Some(Some(_)) => continue,
                    Some(None) => return,
                    None => panic!("channel closed without teardown"),
                }
            }
        })
        .await;
        assert!(teardown.is_ok(), "teardown must arrive");
        peer.close();
    }

    #[tokio::test]
    async fn keepalive_frames_are_sent_periodically() {
        let (host_stream, client_stream) = UnixStream::pair().unwrap();
        let (host_inbound, _host_rx) = mpsc::channel(INBOUND_QUEUE_CAPACITY);
        let (client_inbound, mut client_rx) = mpsc::channel(INBOUND_QUEUE_CAPACITY);
        let peer = PeerConnection::spawn_with_keepalive(
            host_stream,
            Limits::default(),
            host_inbound,
            Duration::from_millis(50),
        );
        // The client decodes frames; the host's keepalive arrives here.
        let _client_peer = PeerConnection::spawn(client_stream, Limits::default(), client_inbound);
        let frame = tokio::time::timeout(Duration::from_secs(5), client_rx.recv())
            .await
            .expect("keepalive arrives")
            .expect("channel open")
            .expect("message, not teardown");
        assert_eq!(
            frame,
            Message::Keepalive(crate::protocol::messages::Keepalive)
        );
        peer.close();
    }

    #[tokio::test]
    async fn full_outbound_queue_reports_queue_full() {
        let (host_stream, client_stream) = UnixStream::pair().unwrap();
        let (inbound, _rx) = mpsc::channel(INBOUND_QUEUE_CAPACITY);
        let peer = PeerConnection::spawn(host_stream, Limits::default(), inbound);
        // The client never reads: writes block, the bounded outbound queue
        // fills, and sends must report QueueFull instead of hanging.
        let _keep_alive = client_stream;
        let mut saw_full = false;
        for _ in 0..OUTBOUND_QUEUE_CAPACITY * 4 {
            match peer.send(Message::Keepalive(crate::protocol::messages::Keepalive)) {
                Ok(()) => {}
                Err(PeerSendError::QueueFull) => {
                    saw_full = true;
                    break;
                }
                Err(PeerSendError::Closed) => break,
            }
        }
        assert!(saw_full, "the bounded queue must reject excess messages");
        peer.close();
    }
}
