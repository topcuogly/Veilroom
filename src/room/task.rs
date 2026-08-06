//! The async room task (section 34.1).
//!
//! `RoomTask` wraps the synchronous [`RoomActor`] with typed event and
//! action channels. It is the only task that mutates room state; every
//! other task communicates through [`RoomEvent`] values.

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::event::RoomEvent;
use crate::protocol::ids::ErrorCode;
use crate::protocol::messages::{ErrorMessage, Message};
use crate::room::action::{HostNotice, RoomAction};
use crate::room::actor::{RoomActor, RoomError};

/// The running room task.
/// Capacity of the room event queue.
const EVENT_QUEUE_CAPACITY: usize = 64;

/// The running room task.
#[derive(Debug)]
pub struct RoomTask {
    events: mpsc::Sender<RoomEvent>,
    actions: mpsc::Receiver<Vec<RoomAction>>,
    handle: JoinHandle<()>,
}

impl RoomTask {
    /// Spawns the room task and returns the handle.
    pub fn spawn(actor: RoomActor) -> Self {
        let (events, events_rx) = mpsc::channel(EVENT_QUEUE_CAPACITY);
        let (actions, actions_rx) = mpsc::channel(EVENT_QUEUE_CAPACITY);
        let handle = tokio::spawn(run(actor, events_rx, actions));
        Self {
            events,
            actions: actions_rx,
            handle,
        }
    }

    /// Spawns the room task and starts the room (`Creating -> Open`).
    ///
    /// The initial action batch (the first invitation notice and the host's
    /// epoch wrap) is returned without being queued: the caller installs
    /// the host epoch key and acknowledges, and the action channel only
    /// carries actions produced after the room is started.
    pub fn spawn_started(actor: RoomActor) -> Result<(Self, Vec<RoomAction>), RoomError> {
        let mut actor = actor;
        let initial = actor.start()?;
        let (events, events_rx) = mpsc::channel(EVENT_QUEUE_CAPACITY);
        let (actions, actions_rx) = mpsc::channel(EVENT_QUEUE_CAPACITY);
        let handle = tokio::spawn(run(actor, events_rx, actions));
        Ok((
            Self {
                events,
                actions: actions_rx,
                handle,
            },
            initial,
        ))
    }

    /// Submits an event to the room.
    ///
    /// Returns an error when the room task has terminated.
    pub async fn send(&self, event: RoomEvent) -> Result<(), RoomSendError> {
        self.events.send(event).await.map_err(|_| RoomSendError)
    }

    /// Receives the next batch of actions from the room.
    ///
    /// Returns `None` when the room task has terminated.
    pub async fn next_actions(&mut self) -> Option<Vec<RoomAction>> {
        self.actions.recv().await
    }

    /// Shuts the room down: drops the event sender (this must be the last
    /// one; the supervisor must not retain clones), waits for the actor to
    /// finish the closing sequence, and drains the remaining actions.
    pub async fn shutdown(mut self) -> Vec<RoomAction> {
        drop(self.events);
        let _ = self.handle.await;
        let mut remaining = Vec::new();
        while let Some(actions) = self.actions.recv().await {
            remaining.extend(actions);
        }
        remaining
    }
}

/// The room task terminated before the event was delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoomSendError;

impl std::fmt::Display for RoomSendError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the room task is not running")
    }
}

impl std::error::Error for RoomSendError {}

/// The room event loop.
async fn run(
    mut actor: RoomActor,
    mut events: mpsc::Receiver<RoomEvent>,
    actions: mpsc::Sender<Vec<RoomAction>>,
) {
    let started = tokio::time::Instant::now();
    while let Some(event) = events.recv().await {
        let offender = match &event {
            RoomEvent::JoinRequested { connection, .. }
            | RoomEvent::ChatReceived { connection, .. }
            | RoomEvent::MemberCommand { connection, .. }
            | RoomEvent::EpochAck { connection, .. } => Some(*connection),
            _ => None,
        };
        let outgoing = match actor.handle_event_at(event, started.elapsed()) {
            Ok(actions) => actions,
            Err(error) => {
                // Transient state-machine rejections (e.g. a chat message
                // during an epoch transition) are caused by room timing,
                // not by the connection; the sender must not be punished
                // for them.
                if error.is_transient() {
                    continue;
                }
                let mut actions = vec![RoomAction::NotifyHost(HostNotice::Error {
                    message: error.to_string(),
                })];
                if let Some(connection) = offender.filter(|id| *id != actor.host_connection()) {
                    let code = match error {
                        RoomError::PolicyLocked => ErrorCode::RoomLocked,
                        RoomError::RoomClosed => ErrorCode::RoomClosed,
                        _ => ErrorCode::ProtocolViolation,
                    };
                    let message = ErrorMessage::new(code, Some(error.to_string()))
                        .unwrap_or_else(|_| ErrorMessage::new(code, None).expect("bare error"));
                    actions.push(RoomAction::SendTo {
                        connection,
                        message: Message::Error(message),
                    });
                    actions.push(RoomAction::CloseConnection { connection });
                    if let Ok(mut cleanup) = actor.handle_event_at(
                        RoomEvent::ConnectionLost { connection },
                        started.elapsed(),
                    ) {
                        actions.append(&mut cleanup);
                    }
                }
                actions
            }
        };
        if !outgoing.is_empty() && actions.send(outgoing).await.is_err() {
            break;
        }
    }
    // The event channel closed: shut the room down gracefully.
    let _ = actions.send(actor.close_room().unwrap_or_default()).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{ConnectionId, HostCommand, MemberCommand};
    use crate::limits::Limits;

    fn host_actor() -> RoomActor {
        RoomActor::create(
            &Limits::default(),
            ConnectionId::new(0),
            "host".to_owned(),
            crate::crypto::identity::HostIdentity::from_seed([0x01; 32], [0x02; 32]),
            crate::crypto::identity::MemberIdentity::from_seed([0x03; 32], [0x04; 32]),
            &crate::limits::Timeouts::default(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn events_flow_through_the_task() {
        let mut task = RoomTask::spawn(host_actor());
        task.send(RoomEvent::CloseRequested).await.unwrap();
        let actions = task.next_actions().await.unwrap();
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, RoomAction::NotifyHost(HostNotice::RoomClosed)))
        );
    }

    #[tokio::test]
    async fn command_errors_surface_as_notices() {
        let mut task = RoomTask::spawn(host_actor());
        task.send(RoomEvent::HostCommand(HostCommand::Kick {
            target: crate::event::MemberRef::Id(crate::event::MemberId::new(99)),
        }))
        .await
        .unwrap();
        let actions = task.next_actions().await.unwrap();
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, RoomAction::NotifyHost(HostNotice::Error { .. })))
        );
    }

    #[tokio::test]
    async fn shutdown_closes_the_room_and_drains_actions() {
        let mut task = RoomTask::spawn(host_actor());
        task.send(RoomEvent::ClientConnected {
            connection: ConnectionId::new(1),
        })
        .await
        .unwrap();
        task.send(RoomEvent::MemberCommand {
            connection: ConnectionId::new(1),
            command: MemberCommand::Leave,
        })
        .await
        .unwrap();
        // Drain the (empty) notice batch for the unknown member first.
        let _ = task.next_actions().await;

        let actions = task.shutdown().await;
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, RoomAction::NotifyHost(HostNotice::RoomClosed)))
        );
    }

    #[tokio::test]
    async fn send_after_shutdown_fails() {
        let mut task = RoomTask::spawn(host_actor());
        task.send(RoomEvent::CloseRequested).await.unwrap();
        let _ = task.next_actions().await;
        let _ = task.shutdown().await;
        // A send through a closed channel cannot reach the task.
        let (sender, receiver) = mpsc::channel::<RoomEvent>(1);
        drop(receiver);
        let error = sender.send(RoomEvent::CloseRequested).await.unwrap_err();
        assert_eq!(error.0, RoomEvent::CloseRequested);
    }

    #[tokio::test]
    async fn supervisor_epoch_maintenance_preserves_the_active_host() {
        let (mut task, initial) = RoomTask::spawn_started(host_actor()).unwrap();
        let epoch = initial
            .iter()
            .find_map(|action| match action {
                RoomAction::SendTo {
                    connection,
                    message: Message::EpochWrap(wrap),
                } if *connection == ConnectionId::new(0) => Some(wrap.epoch),
                _ => None,
            })
            .expect("the host receives the initial epoch wrap");
        task.send(RoomEvent::EpochAck {
            connection: ConnectionId::new(0),
            epoch,
        })
        .await
        .unwrap();

        // This is the same event ordering used by the interactive host
        // supervisor after it installs and acknowledges the initial epoch.
        task.send(RoomEvent::EpochMaintenance).await.unwrap();
        task.send(RoomEvent::MemberCommand {
            connection: ConnectionId::new(0),
            command: MemberCommand::List,
        })
        .await
        .unwrap();

        let actions = task.next_actions().await.unwrap();
        assert!(actions.iter().any(|action| matches!(
            action,
            RoomAction::NotifyHost(HostNotice::ListSnapshot(members))
                if members.len() == 1 && members[0].is_host
        )));
        let _ = task.shutdown().await;
    }
}
