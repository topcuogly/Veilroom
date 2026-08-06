//! Host-side network adapter (architecture decision 12, section 29).
//!
//! [`HostNetwork`] binds the Unix socket that the ephemeral onion service
//! forwards to, accepts connections up to `max_pre_auth_connections`,
//! spawns a [`PeerConnection`] per client, and routes typed messages. The
//! supervisor owns one instance and polls it from its select loop: accepted
//! connection ids arrive on [`HostNetwork::connects`], inbound messages on
//! [`HostNetwork::inbound`] (`None` marks teardown).

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::event::ConnectionId;
use crate::limits::Limits;
use crate::net::conn::{PeerConnection, PeerSendError};
use crate::protocol::messages::Message;

/// One accepted connection and its admission status.
///
/// The flag is what the pre-auth budget counts; it lives next to the
/// connection so that closing the connection releases the budget with it.
#[derive(Debug)]
struct Peer {
    connection: PeerConnection,
    admitted: bool,
}

/// The map of live connections, shared with the accept loop.
type PeerMap = Arc<Mutex<HashMap<ConnectionId, Peer>>>;

/// Pause after a failed `accept` before the listener is polled again.
const ACCEPT_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);

/// Consecutive `accept` failures tolerated before the listener is retired.
const MAX_CONSECUTIVE_ACCEPT_ERRORS: u32 = 64;

/// The host-side network adapter.
#[derive(Debug)]
pub struct HostNetwork {
    connects: mpsc::Receiver<ConnectionId>,
    inbound: mpsc::Receiver<(ConnectionId, Option<Message>)>,
    peers: PeerMap,
    accept_task: JoinHandle<()>,
}

impl HostNetwork {
    /// Binds `chat_socket` and spawns the accept task.
    pub async fn listen(chat_socket: &Path, limits: Limits) -> std::io::Result<Self> {
        let listener = UnixListener::bind(chat_socket)?;
        Ok(Self::from_listener(listener, limits))
    }

    /// Wraps an existing listener (test seam).
    pub fn from_listener(listener: UnixListener, limits: Limits) -> Self {
        let (connect_tx, connects) = mpsc::channel(crate::net::INBOUND_QUEUE_CAPACITY);
        let (inbound_tx, inbound) = mpsc::channel(crate::net::INBOUND_QUEUE_CAPACITY);
        let peers: PeerMap = Arc::default();
        let accept_task = tokio::spawn(accept_loop(
            listener,
            limits,
            connect_tx,
            inbound_tx,
            peers.clone(),
        ));
        Self {
            connects,
            inbound,
            peers,
            accept_task,
        }
    }

    /// Records that `connection` was admitted as a member.
    ///
    /// Admitted members no longer count against the pre-auth connection
    /// budget, so a full room does not silently refuse new join flows. The
    /// flag is stored on the connection itself, so the budget is released
    /// again as soon as the member's connection is closed; a counter that
    /// only ever grew would let departures inflate the cap without bound.
    pub fn mark_admitted(&self, connection: ConnectionId) {
        if let Some(peer) = self
            .peers
            .lock()
            .expect("peer map poisoned")
            .get_mut(&connection)
        {
            peer.admitted = true;
        }
    }

    /// The number of live connections that have not been admitted yet.
    pub fn pre_auth_connections(&self) -> usize {
        pre_auth_count(&self.peers.lock().expect("peer map poisoned"))
    }

    /// The receiver of accepted connection ids.
    pub fn connects(&mut self) -> &mut mpsc::Receiver<ConnectionId> {
        &mut self.connects
    }

    /// The receiver of inbound `(connection, message)` pairs.
    ///
    /// A `None` message marks the teardown of that connection.
    pub fn inbound(&mut self) -> &mut mpsc::Receiver<(ConnectionId, Option<Message>)> {
        &mut self.inbound
    }

    /// Takes the two receivers out for use in a `tokio::select!` loop.
    ///
    /// The stored receivers are replaced with fresh (empty) ones; the
    /// supervisor uses the returned receivers and keeps the network handle
    /// for `send_to` and `close`.
    pub fn take_receivers(
        &mut self,
    ) -> (
        mpsc::Receiver<ConnectionId>,
        mpsc::Receiver<(ConnectionId, Option<Message>)>,
    ) {
        let (_, connects) = mpsc::channel(1);
        let (_, inbound) = mpsc::channel(1);
        (
            std::mem::replace(&mut self.connects, connects),
            std::mem::replace(&mut self.inbound, inbound),
        )
    }

    /// Queues a message for one connection.
    pub fn send_to(&self, connection: ConnectionId, message: Message) -> Result<(), PeerSendError> {
        self.peers
            .lock()
            .expect("peer map poisoned")
            .get(&connection)
            .ok_or(PeerSendError::Closed)?
            .connection
            .send(message)
    }

    /// Drops one connection.
    pub fn close(&self, connection: ConnectionId) {
        self.peers
            .lock()
            .expect("peer map poisoned")
            .remove(&connection);
    }

    /// Drops every connection.
    pub fn close_all(&self) {
        self.peers.lock().expect("peer map poisoned").clear();
    }

    /// Stops accepting new connections and frees the listener.
    pub fn stop(&self) {
        self.accept_task.abort();
    }
}

impl Drop for HostNetwork {
    fn drop(&mut self) {
        self.accept_task.abort();
        self.peers.lock().expect("peer map poisoned").clear();
    }
}

/// Counts the live connections that have not been admitted as members.
///
/// Admitted members do not consume pre-auth budget: only connections that
/// are still inside the admission gate are counted against the cap
/// (section 28).
fn pre_auth_count(peers: &HashMap<ConnectionId, Peer>) -> usize {
    peers.values().filter(|peer| !peer.admitted).count()
}

/// The accept loop: accepts, registers, and spawns connection tasks.
async fn accept_loop(
    listener: UnixListener,
    limits: Limits,
    connects: mpsc::Sender<ConnectionId>,
    inbound: mpsc::Sender<(ConnectionId, Option<Message>)>,
    peers: PeerMap,
) {
    let mut next_id: u64 = 1;
    let mut consecutive_errors: u32 = 0;
    let max_pre_auth = limits.max_pre_auth_connections();
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => {
                consecutive_errors = 0;
                stream
            }
            Err(_) => {
                // A failed accept (descriptor exhaustion, a peer that
                // vanished between its connect and this accept) must not
                // silently retire the listener: the room would stay alive
                // but never take another connection again. Back off and
                // retry, giving up only once the listener keeps failing.
                consecutive_errors += 1;
                if consecutive_errors >= MAX_CONSECUTIVE_ACCEPT_ERRORS {
                    return;
                }
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        // The lock is only held inside this block, never across an await.
        let over_cap = {
            let peers = peers.lock().expect("peer map poisoned");
            pre_auth_count(&peers) >= max_pre_auth
        };
        if over_cap {
            // Over the pre-auth cap: refuse immediately.
            drop(stream);
            continue;
        }
        let id = ConnectionId::new(next_id);
        next_id += 1;
        let (inbound_tx, mut inbound_rx) = mpsc::channel(crate::net::INBOUND_QUEUE_CAPACITY);
        let connection = PeerConnection::spawn(stream, limits, inbound_tx);
        peers.lock().expect("peer map poisoned").insert(
            id,
            Peer {
                connection,
                admitted: false,
            },
        );
        let shared = inbound.clone();
        tokio::spawn(async move {
            while let Some(item) = inbound_rx.recv().await {
                if shared.send((id, item)).await.is_err() {
                    return;
                }
            }
        });
        let _ = connects.send(id).await;
    }
}
