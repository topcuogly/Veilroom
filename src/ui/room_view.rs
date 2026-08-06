//! The room-screen view model (sections 31-33).
//!
//! [`RoomView`] holds everything the message view renders: the bounded
//! message buffer, the notice list, the member table, the host's pending
//! request list, and the input line. It is pure presentation state updated
//! by the supervisor from typed room actions; it contains no room logic.

use crate::command::ColorChoice;
use crate::event::{MemberId, RequestId};
use crate::ui::buffer::{GmtTimestamp, LineStyle, MessageLine, NicknameSpan, RenderBuffer};
use crate::ui::input::TextField;
use crate::ui::notice::NoticeBuffer;
use crate::ui::sanitize::sanitize_for_display;

/// The maximum byte length of the room input line.
pub const ROOM_INPUT_MAX_BYTES: usize = 4096;

/// One member shown in the member panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberLine {
    /// The room-lifetime member id.
    pub member_id: MemberId,
    /// The display nickname.
    pub nickname: String,
    /// The display color.
    pub color: ColorChoice,
    /// Whether this is the host participant.
    pub is_host: bool,
}

/// The kind-specific details of a pending host request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestKind {
    /// A participant asking to join the room.
    Join {
        /// The optional introduction message.
        introduction: Option<String>,
    },
    /// A member asking to change the room's message lifetime.
    Timeout {
        /// The requested lifetime in seconds.
        seconds: u64,
    },
}

/// One pending join or timeout request shown to the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestLine {
    /// The request id.
    pub request_id: RequestId,
    /// The requested nickname.
    pub nickname: String,
    /// The request-specific details.
    pub kind: RequestKind,
}

/// The result of submitting the room input line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineSubmit {
    /// The line was accepted and cleared.
    Done,
    /// The line was rejected (empty or over limit) and is retained.
    Rejected,
}

/// The room layout selected by a host for the local terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomViewMode {
    /// Messages with the host-only member and join-request panels.
    Host,
    /// The full-width message layout seen by ordinary members.
    Member,
}

/// The room message view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomView {
    /// Whether the local participant is the host.
    pub is_host: bool,
    /// The local room layout. Only a host can toggle this value.
    pub view_mode: RoomViewMode,
    /// The local participant's nickname.
    pub own_nickname: String,
    /// When this local room view became active.
    ///
    /// For a host this is the room-open instant; for a participant it is the
    /// instant their accepted room session began.
    entered_at: std::time::Instant,
    /// The invitation URI shown to the host.
    pub invitation: Option<String>,
    /// The room session state line (policy, epoch).
    pub status: String,
    /// The bounded message render buffer.
    pub messages: RenderBuffer,
    /// Whether non-chat messages and notices are visible in the message pane.
    pub show_system_messages: bool,
    /// The bounded notice list.
    pub notices: NoticeBuffer,
    /// The active member table.
    pub members: Vec<MemberLine>,
    /// The host's pending join and timeout requests.
    pub requests: Vec<RequestLine>,
    /// The input line at the bottom of the screen.
    pub input: TextField,
    /// The host-configured lifetime of each message line, in seconds.
    ///
    /// `None` means message lines do not expire automatically. The setting is
    /// room-wide, while expiration is evaluated against each local line's
    /// original timestamp.
    message_timeout_interval: Option<u64>,
}

impl RoomView {
    /// Creates a room view for a participant.
    pub fn participant(nickname: String) -> Self {
        Self::new(false, nickname)
    }

    /// Creates a room view for the host.
    pub fn host(nickname: String) -> Self {
        Self::new(true, nickname)
    }

    fn new(is_host: bool, own_nickname: String) -> Self {
        Self {
            is_host,
            view_mode: if is_host {
                RoomViewMode::Host
            } else {
                RoomViewMode::Member
            },
            own_nickname,
            entered_at: std::time::Instant::now(),
            invitation: None,
            status: String::new(),
            messages: RenderBuffer::new(),
            show_system_messages: true,
            notices: NoticeBuffer::new(),
            members: Vec::new(),
            requests: Vec::new(),
            input: TextField::new(ROOM_INPUT_MAX_BYTES),
            message_timeout_interval: None,
        }
    }

    /// Whether host-only side panels should be visible.
    pub const fn uses_host_view(&self) -> bool {
        self.is_host && matches!(self.view_mode, RoomViewMode::Host)
    }

    /// How long the local viewer has been in the room.
    ///
    /// On the host this is the room uptime.
    pub fn room_elapsed(&self) -> std::time::Duration {
        self.entered_at.elapsed()
    }

    /// The current number of room participants, excluding the host.
    pub fn participant_count(&self) -> usize {
        let participants = self.members.iter().filter(|member| !member.is_host).count();
        // Before a participant's first membership snapshot arrives, that
        // participant is already present. The host, however, is never counted.
        if self.is_host {
            participants
        } else {
            participants.max(1)
        }
    }

    /// Switches a host between host and member layouts.
    ///
    /// Returns `true` when the layout changed. Participant views cannot be
    /// changed through this method.
    pub fn toggle_host_member_view(&mut self) -> bool {
        if !self.is_host {
            return false;
        }
        self.view_mode = match self.view_mode {
            RoomViewMode::Host => RoomViewMode::Member,
            RoomViewMode::Member => RoomViewMode::Host,
        };
        true
    }

    /// Toggles system messages and notices in the message pane.
    pub fn toggle_system_messages(&mut self) {
        self.show_system_messages = !self.show_system_messages;
    }

    /// The configured per-message lifetime in seconds, if any.
    pub const fn message_timeout_interval(&self) -> Option<u64> {
        self.message_timeout_interval
    }

    /// Enables or disables per-message expiry.
    ///
    /// Existing lines retain their original creation times, so changing the
    /// setting never grants old lines a fresh lifetime. Zero is treated as
    /// disabled.
    pub fn set_message_timeout(&mut self, interval: Option<u64>) {
        self.message_timeout_interval = interval.filter(|seconds| *seconds > 0);
        self.messages.set_expiry(
            self.message_timeout_interval
                .map(std::time::Duration::from_secs),
        );
    }

    /// Expires every line whose individual age reached the configured limit.
    ///
    /// The supervisor calls this once per maintenance tick. Returns `true`
    /// when at least one line was removed; newer lines remain untouched.
    pub fn tick_message_timeout(&mut self) -> bool {
        if self.message_timeout_interval.is_none() {
            return false;
        }
        self.messages.expire_due(std::time::Instant::now()) > 0
    }

    /// Returns the nearest message-specific expiry deadline.
    pub(crate) fn next_message_expiry(&self) -> Option<std::time::Instant> {
        self.messages.next_expiry()
    }

    /// Appends a line and assigns its own deadline from its creation time.
    fn push_message(&mut self, text: String, style: LineStyle, nickname: Option<NicknameSpan>) {
        let created_at = std::time::Instant::now();
        let expires_at = self
            .message_timeout_interval
            .and_then(|seconds| created_at.checked_add(std::time::Duration::from_secs(seconds)));
        self.messages.push(MessageLine {
            text,
            style,
            nickname,
            timestamp: GmtTimestamp::now(),
            created_at,
            expires_at,
        });
    }

    /// Appends a chat message line from `nickname`, shown in `color`.
    ///
    /// The color is captured now: a later `/color` change does not re-color
    /// lines that are already in the buffer.
    pub fn push_chat(&mut self, nickname: &str, color: ColorChoice, text: &str) {
        let nickname = sanitize_for_display(nickname);
        let mut line = String::new();
        line.push_str(&nickname);
        line.push_str(": ");
        line.push_str(&sanitize_for_display(text));
        self.push_message(
            line,
            LineStyle::Chat,
            Some(NicknameSpan {
                text: nickname,
                color,
            }),
        );
    }

    /// Appends an own message line.
    ///
    /// The own nickname is drawn in the color currently assigned to the
    /// local member, falling back to the palette default when the member
    /// table does not yet know the local member.
    pub fn push_own(&mut self, text: &str) {
        let color = self
            .member_by_nickname(&self.own_nickname)
            .map(|member| member.color)
            .unwrap_or_default();
        let nickname = self.own_nickname.clone();
        self.push_chat(&nickname, color, text);
    }

    /// Appends a system notice line.
    pub fn push_system(&mut self, text: impl Into<String>) {
        self.push_message(sanitize_for_display(&text.into()), LineStyle::Notice, None);
    }

    /// Appends a muted auxiliary line (invitation URI, hints).
    pub fn push_muted(&mut self, text: impl Into<String>) {
        self.push_message(sanitize_for_display(&text.into()), LineStyle::Muted, None);
    }

    /// Appends an error line.
    pub fn push_error(&mut self, text: impl Into<String>) {
        self.push_message(sanitize_for_display(&text.into()), LineStyle::Error, None);
    }

    /// Prints every selectable color using its own display color.
    pub fn push_color_list(&mut self) {
        for color in ColorChoice::ALL {
            self.push_message(color.name().to_owned(), LineStyle::Palette(color), None);
        }
    }

    /// Clears the local message pane immediately.
    pub fn clear_messages(&mut self) {
        self.messages.clear();
    }

    /// Appends a highlighted notice in chronological message order.
    ///
    /// The bounded notice list is retained for callers that need the latest
    /// notifications, while the render-buffer entry ensures the notice is
    /// displayed where it occurred instead of being grouped at the bottom.
    pub fn notice(&mut self, text: impl Into<String>) {
        let text = sanitize_for_display(&text.into());
        self.notices.push(text.clone());
        self.push_message(format!("! {text}"), LineStyle::Alert, None);
    }

    /// Replaces the member table.
    pub fn set_members(&mut self, members: Vec<MemberLine>) {
        self.members = members;
    }

    /// Replaces the pending request list.
    pub fn set_requests(&mut self, requests: Vec<RequestLine>) {
        self.requests = requests;
    }

    /// Replaces and prints a `/requests` snapshot.
    ///
    /// The side panel remains useful on large terminals, while notices make
    /// request ids and the exact accept/reject commands visible even when
    /// that panel is too small to display its contents. Snapshot notices
    /// enter the ordinary chronological message flow.
    pub fn show_requests(&mut self, requests: Vec<RequestLine>) {
        let lines = if requests.is_empty() {
            vec!["no pending requests".to_owned()]
        } else {
            let mut lines = Vec::with_capacity(requests.len() + 1);
            lines.push(format!("pending requests: {}", requests.len()));
            lines.extend(requests.iter().map(|request| {
                let id = request.request_id.as_u64();
                match &request.kind {
                    RequestKind::Join { introduction } => {
                        let introduction = introduction
                            .as_deref()
                            .map(|text| format!(" — {text}"))
                            .unwrap_or_default();
                        format!(
                            "join request {id}: {}{introduction} — /accept {id} or /reject {id}",
                            request.nickname
                        )
                    }
                    RequestKind::Timeout { seconds } => format!(
                        "timeout request {id}: {} — {seconds} seconds — /accept {id} or /reject {id}",
                        request.nickname
                    ),
                }
            }));
            lines
        };
        self.requests = requests;
        for line in lines {
            self.notice(line);
        }
    }

    /// Shows the invitation URI.
    ///
    /// The full URI is retained in memory; the messages panel renders a
    /// shortened preview, and the full value is available through the copy
    /// action. The stored value is never truncated.
    pub fn set_invitation(&mut self, uri: String) {
        self.invitation = Some(uri);
    }

    /// The shortened preview of the stored invitation, if any.
    ///
    /// Rendered as `veilroom://abcd…wxyz.onion · token: present`; the
    /// onion hostname is shortened but the token presence is shown. The
    /// full URI remains available through [`RoomView::set_invitation`] and
    /// the copy action.
    pub fn invitation_preview(&self) -> Option<String> {
        self.invitation.as_deref().map(preview_invitation)
    }

    /// Sets the status line.
    pub fn set_status(&mut self, status: impl Into<String>) {
        self.status = status.into();
    }

    /// Resolves a member by nickname (case-sensitive, exact match).
    pub fn member_by_nickname(&self, nickname: &str) -> Option<&MemberLine> {
        self.members
            .iter()
            .find(|member| member.nickname == nickname)
    }

    /// Submits the input line.
    pub fn submit_line(&mut self) -> LineSubmit {
        match self.input.submit() {
            crate::ui::input::Submit::Value(text) => {
                let _ = text;
                self.input.clear();
                LineSubmit::Done
            }
            crate::ui::input::Submit::None => LineSubmit::Rejected,
            crate::ui::input::Submit::Cancel => LineSubmit::Rejected,
        }
    }
}

/// Renders a shortened, terminal-safe preview of a full invitation URI.
///
/// The onion hostname keeps only its first and last four body characters
/// (`veilroom://abcd…wxyz.onion`), and the token is never revealed —
/// only its presence is shown. The preview exists for display only; the
/// full URI is stored separately and copied verbatim.
pub fn preview_invitation(uri: &str) -> String {
    let host = uri
        .strip_prefix(crate::constants::INVITATION_SCHEME)
        .and_then(|rest| rest.strip_prefix("://"))
        .and_then(|rest| rest.split(':').next())
        .unwrap_or_default();
    let shortened = if let Some(body) = host.strip_suffix(crate::constants::ONION_V3_SUFFIX) {
        if body.len() > 8 {
            // `get` returns `None` when the range falls inside a UTF-8
            // sequence, so this never panics on non-ASCII input.
            let head = body.get(..4).unwrap_or(body);
            let tail = body.get(body.len() - 4..).unwrap_or_default();
            format!("{head}…{tail}{}", crate::constants::ONION_V3_SUFFIX)
        } else {
            host.to_owned()
        }
    } else {
        host.to_owned()
    };
    format!(
        "{}://{shortened} · token: present",
        crate::constants::INVITATION_SCHEME
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::buffer::DEFAULT_RENDER_BUFFER_CAPACITY;

    #[test]
    fn chat_lines_are_sanitized() {
        let mut view = RoomView::participant("deniz".to_owned());
        view.push_chat("alice", ColorChoice::Blue, "hello\u{1b}[31m");
        let line = view.messages.iter().last().unwrap();
        assert_eq!(line.text, "alice: hello[31m");
        assert_eq!(line.style, LineStyle::Chat);
        assert_eq!(
            line.nickname,
            Some(NicknameSpan {
                text: "alice".to_owned(),
                color: ColorChoice::Blue,
            })
        );
    }

    #[test]
    fn own_messages_use_the_own_nickname() {
        let mut view = RoomView::participant("deniz".to_owned());
        view.push_own("selam");
        let line = view.messages.iter().last().unwrap();
        assert_eq!(line.text, "deniz: selam");
    }

    #[test]
    fn own_messages_use_the_own_member_color() {
        let mut view = RoomView::participant("deniz".to_owned());
        view.set_members(vec![MemberLine {
            member_id: MemberId::new(2),
            nickname: "deniz".to_owned(),
            color: ColorChoice::Cyan,
            is_host: false,
        }]);
        view.push_own("selam");
        let line = view.messages.iter().last().unwrap();
        assert_eq!(line.text, "deniz: selam");
        assert_eq!(
            line.nickname,
            Some(NicknameSpan {
                text: "deniz".to_owned(),
                color: ColorChoice::Cyan,
            })
        );
    }

    #[test]
    fn only_hosts_can_toggle_between_host_and_member_views() {
        let mut host = RoomView::host("host".to_owned());
        assert!(host.uses_host_view());
        assert!(host.toggle_host_member_view());
        assert_eq!(host.view_mode, RoomViewMode::Member);
        assert!(!host.uses_host_view());
        assert!(host.toggle_host_member_view());
        assert_eq!(host.view_mode, RoomViewMode::Host);

        let mut participant = RoomView::participant("alice".to_owned());
        assert!(!participant.toggle_host_member_view());
        assert_eq!(participant.view_mode, RoomViewMode::Member);
    }

    #[test]
    fn system_message_visibility_toggles_without_removing_lines() {
        let mut view = RoomView::participant("alice".to_owned());
        view.push_chat("bob", ColorChoice::Green, "hello");
        view.push_system("bob joined");
        view.notice("room notice");
        let message_count = view.messages.len();
        let notice_count = view.notices.len();

        view.toggle_system_messages();
        assert!(!view.show_system_messages);
        assert_eq!(view.messages.len(), message_count);
        assert_eq!(view.notices.len(), notice_count);
        view.toggle_system_messages();
        assert!(view.show_system_messages);
    }

    #[test]
    fn system_and_error_lines_have_distinct_styles() {
        let mut view = RoomView::participant("deniz".to_owned());
        view.push_system("deniz joined");
        view.push_error("kick failed");
        let styles: Vec<LineStyle> = view.messages.iter().map(|l| l.style).collect();
        assert_eq!(styles, [LineStyle::Notice, LineStyle::Error]);
    }

    #[test]
    fn highlighted_notices_keep_their_message_flow_position() {
        let mut view = RoomView::host("host".to_owned());
        view.push_system("before");
        view.notice("join request from alice");
        view.push_system("after");

        let lines: Vec<(&str, LineStyle)> = view
            .messages
            .iter()
            .map(|line| (line.text.as_str(), line.style))
            .collect();
        assert_eq!(
            lines,
            [
                ("before", LineStyle::Notice),
                ("! join request from alice", LineStyle::Alert),
                ("after", LineStyle::Notice),
            ]
        );
    }

    #[test]
    fn member_table_is_replaceable() {
        let mut view = RoomView::participant("deniz".to_owned());
        view.set_members(vec![MemberLine {
            member_id: MemberId::new(0),
            nickname: "host".to_owned(),
            color: ColorChoice::White,
            is_host: true,
        }]);
        assert!(view.member_by_nickname("host").is_some());
        assert!(view.member_by_nickname("host").unwrap().is_host);
        assert!(view.member_by_nickname("missing").is_none());
    }

    #[test]
    fn request_list_is_replaceable() {
        let mut view = RoomView::host("host".to_owned());
        view.set_requests(vec![RequestLine {
            request_id: RequestId::new(3),
            nickname: "alice".to_owned(),
            kind: RequestKind::Join {
                introduction: Some("hi".to_owned()),
            },
        }]);
        assert_eq!(view.requests.len(), 1);
        assert_eq!(view.requests[0].request_id, RequestId::new(3));
    }

    #[test]
    fn request_snapshot_prints_ids_and_accept_reject_commands() {
        let mut view = RoomView::host("host".to_owned());
        view.show_requests(vec![RequestLine {
            request_id: RequestId::new(3),
            nickname: "deniz".to_owned(),
            kind: RequestKind::Join {
                introduction: Some("hello".to_owned()),
            },
        }]);

        assert_eq!(view.requests.len(), 1);
        let output = view
            .notices
            .iter()
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>();
        assert_eq!(output[0], "pending requests: 1");
        assert_eq!(
            output[1],
            "join request 3: deniz — hello — /accept 3 or /reject 3"
        );
    }

    #[test]
    fn empty_request_snapshot_is_not_silent() {
        let mut view = RoomView::host("host".to_owned());
        view.show_requests(Vec::new());
        assert_eq!(
            view.notices.iter().last().unwrap().text,
            "no pending requests"
        );
    }

    #[test]
    fn timeout_requests_are_shown_in_the_shared_request_list() {
        let mut view = RoomView::host("host".to_owned());
        view.show_requests(vec![RequestLine {
            request_id: RequestId::new(4),
            nickname: "alice".to_owned(),
            kind: RequestKind::Timeout { seconds: 30 },
        }]);

        assert_eq!(view.requests.len(), 1);
        assert_eq!(
            view.notices.iter().last().unwrap().text,
            "timeout request 4: alice — 30 seconds — /accept 4 or /reject 4"
        );
    }

    #[test]
    fn submitting_the_line_clears_it() {
        let mut view = RoomView::participant("deniz".to_owned());
        view.input.insert_char('h');
        assert_eq!(view.submit_line(), LineSubmit::Done);
        assert!(view.input.is_empty());
        assert_eq!(view.submit_line(), LineSubmit::Rejected);
    }

    #[test]
    fn message_timeout_matches_the_103000_and_103009_timeline() {
        let mut view = RoomView::host("host".to_owned());
        let at_10_30_00 = std::time::Instant::now();
        let at_10_30_09 = at_10_30_00 + std::time::Duration::from_secs(9);
        let at_10_30_10 = at_10_30_00 + std::time::Duration::from_secs(10);
        let at_10_30_19 = at_10_30_00 + std::time::Duration::from_secs(19);
        view.messages.push(MessageLine {
            text: "alice: 10:30:00".to_owned(),
            style: LineStyle::Chat,
            nickname: None,
            timestamp: GmtTimestamp::from_hms(10, 30, 0).unwrap(),
            created_at: at_10_30_00,
            expires_at: None,
        });
        view.messages.push(MessageLine {
            text: "bob: 10:30:09".to_owned(),
            style: LineStyle::Chat,
            nickname: None,
            timestamp: GmtTimestamp::from_hms(10, 30, 9).unwrap(),
            created_at: at_10_30_09,
            expires_at: None,
        });
        view.set_message_timeout(Some(10));

        assert_eq!(view.messages.expire_due(at_10_30_10), 1);
        assert_eq!(
            view.messages
                .iter()
                .map(|line| line.text.as_str())
                .collect::<Vec<_>>(),
            ["bob: 10:30:09"],
            "10:30:10 removes only the 10:30:00 message"
        );
        assert_eq!(
            view.messages
                .expire_due(at_10_30_19 - std::time::Duration::from_secs(1)),
            0,
            "the 10:30:09 message remains before its own deadline"
        );
        assert_eq!(view.messages.expire_due(at_10_30_19), 1);
        assert!(
            view.messages.is_empty(),
            "the 10:30:09 message expires at 10:30:19"
        );
    }

    #[test]
    fn message_timeout_off_disables_and_zero_is_treated_as_off() {
        let mut view = RoomView::host("host".to_owned());
        view.set_message_timeout(Some(2));
        view.set_message_timeout(None);
        assert_eq!(view.message_timeout_interval(), None);
        assert!(!view.tick_message_timeout(), "disabled never expires lines");

        view.set_message_timeout(Some(0));
        assert_eq!(view.message_timeout_interval(), None, "zero is off");
    }

    #[test]
    fn render_buffer_stays_bounded_in_the_view() {
        let mut view = RoomView::participant("deniz".to_owned());
        for index in 0..DEFAULT_RENDER_BUFFER_CAPACITY + 10 {
            view.push_system(format!("line {index}"));
        }
        assert_eq!(view.messages.len(), DEFAULT_RENDER_BUFFER_CAPACITY);
    }

    #[test]
    fn invitation_and_status_are_settable() {
        let mut view = RoomView::host("host".to_owned());
        view.set_invitation("veilroom://abc.onion:80?v=1&token=x".to_owned());
        view.set_status("room open");
        assert!(
            view.invitation
                .as_deref()
                .unwrap()
                .starts_with("veilroom://")
        );
        assert_eq!(view.status, "room open");
    }

    #[test]
    fn header_metrics_include_elapsed_time_and_at_least_the_viewer() {
        let mut view = RoomView::participant("alice".to_owned());
        view.entered_at = std::time::Instant::now() - std::time::Duration::from_secs(3_661);
        assert!(view.room_elapsed().as_secs() >= 3_661);
        assert_eq!(view.participant_count(), 1);

        view.set_members(vec![
            MemberLine {
                member_id: MemberId::new(0),
                nickname: "host".to_owned(),
                color: ColorChoice::White,
                is_host: true,
            },
            MemberLine {
                member_id: MemberId::new(1),
                nickname: "alice".to_owned(),
                color: ColorChoice::Cyan,
                is_host: false,
            },
        ]);
        assert_eq!(view.participant_count(), 1);

        let host = RoomView::host("host".to_owned());
        assert_eq!(host.participant_count(), 0);
    }

    #[test]
    fn invitation_is_retained_in_full() {
        // The stored value must never be truncated, whatever the preview.
        let body = "a".repeat(56);
        let uri = format!("veilroom://{body}.onion:80?v=1&token=abcdefghijklmnop");
        let mut view = RoomView::host("host".to_owned());
        view.set_invitation(uri.clone());
        assert_eq!(view.invitation.as_deref(), Some(uri.as_str()));
        assert_eq!(
            view.invitation_preview(),
            Some(preview_invitation(&uri)),
            "the preview is derived from, but distinct from, the full URI"
        );
    }

    #[test]
    fn preview_shortens_the_onion_but_shows_token_presence() {
        let body = "a".repeat(56);
        let uri = format!("veilroom://{body}.onion:80?v=1&token=abcdefghijklmnop");
        let preview = preview_invitation(&uri);
        // The onion hostname is shortened, keeping the first and last four
        // body characters, and the suffix is preserved.
        assert_eq!(
            preview,
            format!("veilroom://aaaa…aaaa.onion · token: present")
        );
        // The preview never contains the token value.
        assert!(!preview.contains("abcdefghijklmnop"));
        // The preview is far shorter than the full URI.
        assert!(preview.len() < uri.len());
    }

    #[test]
    fn preview_never_contains_the_token_value() {
        let body = "a".repeat(56);
        let token = "0123456789abcdef0123456789abcdef";
        let uri = format!("veilroom://{body}.onion:80?v=1&token={token}");
        let preview = preview_invitation(&uri);
        assert!(!preview.contains(token));
        assert!(preview.contains("token: present"));
    }

    #[test]
    fn preview_never_panics_on_non_ascii_hosts() {
        // A non-ASCII host used to panic on byte-boundary slicing.
        let uri = format!(
            "veilroom://{}.onion:80?v=1&token=abcdefghijklmnop",
            "Ğ".repeat(56)
        );
        let preview = preview_invitation(&uri);
        assert!(preview.starts_with("veilroom://"));
    }
}
