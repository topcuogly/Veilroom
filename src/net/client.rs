//! Participant-side network adapter (architecture decision 12, section 29).
//!
//! [`ClientNetwork`] owns the single connection of a joining participant:
//! the SOCKS tunnel to the host's onion service (or a direct stream in
//! tests), wrapped in a [`PeerConnection`]. The supervisor polls inbound
//! messages and pushes outbound typed messages.

use std::path::Path;

use tokio::net::UnixStream;
use tokio::sync::mpsc;

use crate::limits::Limits;
use crate::net::conn::{PeerConnection, PeerSendError};
use crate::net::socks::connect_via_socks;
use crate::protocol::messages::Message;

/// The participant-side network adapter.
#[derive(Debug)]
pub struct ClientNetwork {
    peer: PeerConnection,
    inbound: mpsc::Receiver<Option<Message>>,
}

impl ClientNetwork {
    /// Connects to the host through the session's SOCKS socket.
    pub async fn connect(
        socks_path: &Path,
        onion_address: &str,
        port: u16,
        limits: Limits,
    ) -> std::io::Result<Self> {
        let stream = connect_via_socks(socks_path, onion_address, port).await?;
        Ok(Self::from_stream(stream, limits))
    }

    /// Wraps an already-connected stream (test seam).
    pub fn from_stream(stream: UnixStream, limits: Limits) -> Self {
        let (inbound_tx, inbound) = mpsc::channel(crate::net::INBOUND_QUEUE_CAPACITY);
        let peer = PeerConnection::spawn(stream, limits, inbound_tx);
        Self { peer, inbound }
    }

    /// Queues a message for the host.
    pub fn send(&self, message: Message) -> Result<(), PeerSendError> {
        self.peer.send(message)
    }

    /// Receives the next inbound message.
    ///
    /// `None` marks the teardown of the connection; `Some(None)` is not
    /// produced. The outer `None` means the channel closed.
    pub async fn recv(&mut self) -> Option<Option<Message>> {
        self.inbound.recv().await
    }

    /// Closes the connection.
    pub fn close(self) {
        drop(self);
    }
}
