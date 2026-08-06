//! Ratatui rendering of every screen (sections 25 and 34.2).
//!
//! All user-controlled text passes through `sanitize_for_display` before
//! reaching the widgets; the renderer never emits raw control sequences.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Gauge, List, ListItem, Paragraph, Wrap};

use crate::command::ColorChoice;
use crate::ui::app::App;
use crate::ui::buffer::LineStyle;
use crate::ui::room_view::{RequestKind, RoomView};
use crate::ui::sanitize::sanitize_for_display;
use crate::ui::screen::{ABOUT_TEXT, HostField, JoinField, JoinFormField, Screen};

/// The color used for the host marker.
const HOST_MARKER: &str = "[HOST]";

/// Draws the current screen.
pub fn draw(frame: &mut Frame, app: &App) {
    match app.screen() {
        Screen::Menu(menu) => draw_menu(frame, menu.selection),
        Screen::TorConnecting(connection) => draw_tor_connection(frame, connection.progress()),
        Screen::HostSetup(form) => draw_host_setup(frame, form),
        Screen::JoinSetup(form) => draw_join_setup(frame, form),
        Screen::JoinForm(form) => draw_join_form(frame, form),
        Screen::JoinPending => draw_join_pending(frame),
        Screen::Room(view) => draw_room(frame, view),
        Screen::About => draw_about(frame),
        Screen::Message(text) => draw_message(frame, text),
    }
}

/// Renders the color of a member line as a ratatui color.
fn member_color(color: ColorChoice) -> Color {
    match color {
        ColorChoice::Red => Color::Red,
        ColorChoice::Green => Color::Green,
        ColorChoice::Yellow => Color::Yellow,
        ColorChoice::Blue => Color::Blue,
        ColorChoice::Magenta => Color::Magenta,
        ColorChoice::Cyan => Color::Cyan,
        ColorChoice::White => Color::Gray,
    }
}

/// The style of a render-buffer line.
fn line_style(style: LineStyle) -> Style {
    match style {
        LineStyle::Chat => Style::default(),
        LineStyle::Notice => Style::default().fg(Color::Cyan),
        LineStyle::Alert => Style::default().fg(Color::Yellow),
        LineStyle::Palette(color) => Style::default().fg(member_color(color)),
        LineStyle::Error => Style::default().fg(Color::Red),
        LineStyle::Muted => Style::default().fg(Color::DarkGray),
    }
}

/// The title bar shared by all screens.
fn title_block(title: &str) -> Block<'static> {
    Block::default().borders(Borders::ALL).title(Span::styled(
        title.to_owned(),
        Style::default().add_modifier(Modifier::BOLD),
    ))
}

fn draw_menu(frame: &mut Frame, selection: usize) {
    let area = centered_area(frame.area(), 44, 12);
    let items: Vec<ListItem> = crate::ui::screen::MENU_ITEMS
        .iter()
        .enumerate()
        .map(|(index, label)| {
            let text = if index == selection {
                format!("> {label}")
            } else {
                format!("  {label}")
            };
            ListItem::new(Line::from(Span::styled(
                text,
                if index == selection {
                    Style::default().add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                },
            )))
        })
        .collect();
    frame.render_widget(List::new(items).block(title_block("VEILROOM")), area);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "up/down select, enter confirm, q quit",
            Style::default().fg(Color::DarkGray),
        )))
        .alignment(Alignment::Center),
        footer_row(area),
    );
}

/// Draws only the real Tor bootstrap progress during connection setup.
fn draw_tor_connection(frame: &mut Frame, progress: u8) {
    let area = centered_area(frame.area(), 44, 3);
    frame.render_widget(
        Gauge::default()
            .block(title_block("Connecting to Tor"))
            .gauge_style(Style::default().fg(Color::Cyan))
            .percent(u16::from(progress))
            .label(format!("{progress}%")),
        area,
    );
}

fn draw_host_setup(frame: &mut Frame, form: &crate::ui::screen::HostSetupModel) {
    let area = centered_area(frame.area(), 56, 12);
    frame.render_widget(title_block("Host a room"), area);
    let inner = inner_area(area);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);

    let hint = form
        .error
        .as_deref()
        .map(sanitize_for_display)
        .unwrap_or_else(|| "Enter the room password twice.".to_owned());
    render_label(frame, rows[0], &hint, form.error.is_some());

    render_label(frame, rows[1], "Password:", false);
    render_field(
        frame,
        rows[2],
        &form.password.masked(),
        form.focus == HostField::Password,
    );
    render_label(frame, rows[3], "Confirm password:", false);
    render_field(
        frame,
        rows[4],
        &form.confirm.masked(),
        form.focus == HostField::Confirm,
    );
    render_field(
        frame,
        rows[5],
        &format!("Nickname: {}", sanitize_for_display(form.nickname.text())),
        form.focus == HostField::Nickname,
    );
}

fn render_label(frame: &mut Frame, area: Rect, text: &str, error: bool) {
    let color = if error { Color::Red } else { Color::DarkGray };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(text, Style::default().fg(color)))),
        area,
    );
}

fn render_field(frame: &mut Frame, area: Rect, value: &str, active: bool) {
    let style = if active {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default()
    };
    frame.render_widget(Paragraph::new(Line::from(Span::styled(value, style))), area);
}

fn draw_join_setup(frame: &mut Frame, form: &crate::ui::screen::JoinSetupModel) {
    let area = centered_area(frame.area(), 64, 10);
    frame.render_widget(title_block("Join a room"), area);
    let inner = inner_area(area);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);
    let hint = form
        .error
        .as_deref()
        .map(sanitize_for_display)
        .unwrap_or_else(|| "Paste the invitation URI from the host.".to_owned());
    render_label(frame, rows[0], &hint, form.error.is_some());
    render_label(frame, rows[1], "Invitation URI:", false);
    render_field(
        frame,
        rows[2],
        &sanitize_for_display(form.invitation.text()),
        form.focus == JoinField::Invitation,
    );
    render_field(
        frame,
        rows[3],
        &format!("Password: {}", form.password.masked()),
        form.focus == JoinField::Password,
    );
}

fn draw_join_form(frame: &mut Frame, form: &crate::ui::screen::JoinFormModel) {
    let area = centered_area(frame.area(), 56, 9);
    frame.render_widget(title_block("Join request"), area);
    let inner = inner_area(area);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);
    let hint = form
        .error
        .as_deref()
        .map(sanitize_for_display)
        .unwrap_or_else(|| {
            "Complete the join form; the password was verified during the handshake.".to_owned()
        });
    render_label(frame, rows[0], &hint, form.error.is_some());
    let nickname = format!("Nickname: {}", sanitize_for_display(form.nickname.text()));
    render_field(
        frame,
        rows[1],
        &nickname,
        form.focus == JoinFormField::Nickname,
    );
    let introduction = format!(
        "Introduction: {}",
        sanitize_for_display(form.introduction.text())
    );
    render_field(
        frame,
        rows[2],
        &introduction,
        form.focus == JoinFormField::Introduction,
    );
    render_label(
        frame,
        rows[3],
        "Enter submits, Esc goes back; introduction is optional.",
        false,
    );
}

fn draw_join_pending(frame: &mut Frame) {
    let area = centered_area(frame.area(), 56, 7);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from("Your join request was sent."),
            Line::from(""),
            Line::from(Span::styled(
                "Waiting for the host to accept or reject it...",
                Style::default().fg(Color::Yellow),
            )),
        ])
        .alignment(Alignment::Center)
        .block(title_block("Waiting for host approval")),
        area,
    );
}

fn draw_room(frame: &mut Frame, view: &RoomView) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(3),
            Constraint::Length(3),
        ])
        .split(frame.area());
    let mut header = if view.is_host {
        let mode = if view.uses_host_view() {
            "host view"
        } else {
            "member view"
        };
        format!(
            "VEILROOM — hosting as {} — {mode}",
            sanitize_for_display(&view.own_nickname),
        )
    } else {
        format!(
            "VEILROOM — joined as {}",
            sanitize_for_display(&view.own_nickname)
        )
    };
    if !view.status.is_empty() {
        header.push_str(" — ");
        header.push_str(&sanitize_for_display(&view.status));
    }
    if !view.show_system_messages {
        header.push_str(" — user messages only");
    }
    draw_room_header(frame, view, chunks[0], header);

    // Body: messages and (for the host) member/request panels.
    let body: Vec<Rect> = if view.uses_host_view() {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(20), Constraint::Percentage(35)])
            .split(chunks[1])
            .to_vec()
    } else {
        vec![chunks[1]]
    };

    let messages_area = body[0];
    draw_messages(frame, view, messages_area);
    if view.uses_host_view() {
        draw_host_panels(frame, view, body[1]);
    }

    draw_input_line(frame, view, chunks[2]);
}

/// Draws one complete header rectangle split into room and live-stat halves.
fn draw_room_header(frame: &mut Frame, view: &RoomView, area: Rect, header: String) {
    frame.render_widget(Block::default().borders(Borders::ALL), area);
    if area.width < 5 || area.height < 3 {
        return;
    }

    let divider_x = area.x + area.width / 2;
    let inner_y = area.y + 1;
    let inner_height = area.height.saturating_sub(2);
    let left = Rect {
        x: area.x + 1,
        y: inner_y,
        width: divider_x.saturating_sub(area.x + 1),
        height: inner_height,
    };
    let right_x = divider_x.saturating_add(1);
    let right = Rect {
        x: right_x,
        y: inner_y,
        width: area
            .x
            .saturating_add(area.width)
            .saturating_sub(1)
            .saturating_sub(right_x),
        height: inner_height,
    };

    frame.render_widget(
        Paragraph::new(vec![Line::from(""), Line::from(header)]).alignment(Alignment::Center),
        left,
    );
    let elapsed_label = if view.is_host {
        "Room uptime"
    } else {
        "In room"
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(format!("GMT: {}", crate::ui::buffer::GmtTimestamp::now())),
            Line::from(format!(
                "{elapsed_label}: {}",
                format_elapsed(view.room_elapsed())
            )),
            Line::from(format!("Participants: {}", view.participant_count())),
        ])
        .alignment(Alignment::Center),
        right,
    );

    let divider: Vec<Line> = (0..area.height)
        .map(|row| {
            Line::from(if row == 0 {
                "┬"
            } else if row + 1 == area.height {
                "┴"
            } else {
                "│"
            })
        })
        .collect();
    frame.render_widget(
        Paragraph::new(divider),
        Rect {
            x: divider_x,
            y: area.y,
            width: 1,
            height: area.height,
        },
    );
}

fn draw_messages(frame: &mut Frame, view: &RoomView, area: Rect) {
    // Long lines (such as a full invitation URI) are wrapped to the panel
    // width so they are fully visible and never clipped at the right edge.
    let inner_width = area.width.saturating_sub(2) as usize;
    let mut rows: Vec<ListItem> = Vec::new();
    for line in view
        .messages
        .iter()
        .filter(|line| view.show_system_messages || matches!(line.style, LineStyle::Chat))
    {
        let style = line_style(line.style);
        let timestamped = format!("[{}] ", line.timestamp);
        if let Some(nickname) = &line.nickname {
            // `line.text` is the nickname followed by `: body`; the nickname
            // is drawn in the sender's color. The wrap may fall inside the
            // nickname or its suffix, so the segments are wrapped together
            // and split into styled spans across the resulting chunks.
            let rest = line.text.get(nickname.text.len()..).unwrap_or(&line.text);
            let segments = [
                (timestamped.as_str(), style),
                (
                    nickname.text.as_str(),
                    Style::default().fg(member_color(nickname.color)),
                ),
                (rest, style),
            ];
            for spans in wrap_segments(&segments, inner_width) {
                rows.push(ListItem::new(Line::from(spans)));
            }
        } else {
            let full = format!("{timestamped}{}", sanitize_for_display(&line.text));
            for chunk in wrap_for_display(&full, inner_width) {
                rows.push(ListItem::new(Line::from(Span::styled(chunk, style))));
            }
        }
    }
    let visible = area.height.saturating_sub(2) as usize;
    let total = rows.len();
    let skip = total.saturating_sub(visible);
    frame.render_widget(
        List::new(rows.into_iter().skip(skip).collect::<Vec<_>>())
            .block(Block::default().borders(Borders::ALL).title("Messages")),
        area,
    );
}

/// Splits `text` into display-width chunks of at most `width` cells.
///
/// A zero or one-cell width leaves the text as a single chunk; the caller
/// (the `List` widget) truncates only in that degenerate case. Otherwise
/// every chunk fits the panel and nothing is silently clipped.
fn wrap_for_display(text: &str, width: usize) -> Vec<String> {
    if width <= 1 || text.is_empty() {
        return vec![text.to_owned()];
    }
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut used = 0usize;
    for ch in text.chars() {
        let ch_width = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + ch_width > width {
            chunks.push(std::mem::take(&mut current));
            used = 0;
        }
        current.push(ch);
        used += ch_width;
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

/// Splits styled `segments` into display-width lines, preserving each
/// segment's style across wrap boundaries.
///
/// A wrap can fall inside a styled segment (for example, inside a colored
/// nickname), so every returned line carries its text as separate spans that
/// keep the segment styles. A zero or one-cell width leaves the input as a
/// single line; the caller (the `List` widget) truncates only in that
/// degenerate case.
fn wrap_segments(segments: &[(&str, Style)], width: usize) -> Vec<Vec<Span<'static>>> {
    let mut lines: Vec<Vec<Span<'static>>> = Vec::new();
    let mut current: Vec<Span<'static>> = Vec::new();
    let mut pending = String::new();
    let mut pending_style = Style::default();
    let mut used = 0usize;
    for &(text, style) in segments {
        for ch in text.chars() {
            if style != pending_style {
                // A style boundary: close the pending run so adjacent spans
                // never merge two styles.
                if !pending.is_empty() {
                    current.push(Span::styled(std::mem::take(&mut pending), pending_style));
                }
                pending_style = style;
            }
            let ch_width = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
            if width > 1 && used + ch_width > width {
                if !pending.is_empty() {
                    current.push(Span::styled(std::mem::take(&mut pending), pending_style));
                }
                if !current.is_empty() {
                    lines.push(std::mem::take(&mut current));
                }
                used = 0;
            }
            pending.push(ch);
            used += ch_width;
        }
    }
    if !pending.is_empty() {
        current.push(Span::styled(std::mem::take(&mut pending), pending_style));
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn draw_host_panels(frame: &mut Frame, view: &RoomView, area: Rect) {
    let panels = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    let members: Vec<ListItem> = view
        .members
        .iter()
        .map(|member| {
            let marker = if member.is_host {
                format!("{HOST_MARKER} ")
            } else {
                String::new()
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{}{} ", marker, member.member_id.as_u64()),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    sanitize_for_display(&member.nickname),
                    Style::default().fg(member_color(member.color)),
                ),
            ]))
        })
        .collect();
    frame.render_widget(
        List::new(members).block(Block::default().borders(Borders::ALL).title("Members")),
        panels[0],
    );

    let requests: Vec<ListItem> = view
        .requests
        .iter()
        .map(|request| {
            let id = request.request_id.as_u64();
            let nickname = sanitize_for_display(&request.nickname);
            let text = match &request.kind {
                RequestKind::Join { introduction } => {
                    let introduction = introduction
                        .as_deref()
                        .map(|intro| format!(": {}", sanitize_for_display(intro)))
                        .unwrap_or_default();
                    format!("{id} join — {nickname}{introduction}")
                }
                RequestKind::Timeout { seconds } => {
                    format!("{id} timeout — {nickname}: {seconds}s")
                }
            };
            ListItem::new(Line::from(text))
        })
        .collect();
    frame.render_widget(
        List::new(requests).block(Block::default().borders(Borders::ALL).title("Requests")),
        panels[1],
    );
}

fn draw_input_line(frame: &mut Frame, view: &RoomView, area: Rect) {
    let prompt = if view.is_host { "host> " } else { "> " };
    let inner_width = area.width.saturating_sub(2) as usize;
    let prompt_width = unicode_width::UnicodeWidthStr::width(prompt);
    let input_width = inner_width.saturating_sub(prompt_width);
    let visible_input = input_viewport(view.input.text(), view.input.cursor(), input_width);
    let mut text = String::from(prompt);
    text.push_str(&sanitize_for_display(&visible_input));
    let paragraph = Paragraph::new(Line::from(Span::styled(
        text,
        Style::default().add_modifier(Modifier::REVERSED),
    )));
    frame.render_widget(
        paragraph.block(Block::default().borders(Borders::ALL).title("Input")),
        area,
    );
}

/// Returns the part of a single-line input that fits around its cursor.
///
/// Once the text is wider than the input box, the viewport follows the
/// cursor instead of letting the paragraph wrap into an invisible second
/// row. Display-cell widths are used so wide Unicode characters do not make
/// the selected slice overflow the box.
fn input_viewport(text: &str, cursor: usize, width: usize) -> String {
    if text.is_empty() || width == 0 {
        return String::new();
    }

    let cursor = cursor.min(text.len());
    debug_assert!(text.is_char_boundary(cursor));
    let prefix = &text[..cursor];
    let prefix_width = unicode_width::UnicodeWidthStr::width(prefix);
    let start = if prefix_width <= width {
        0
    } else {
        let mut used = 0usize;
        let mut start = cursor;
        for (index, ch) in prefix.char_indices().rev() {
            let char_width = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
            if used + char_width > width {
                break;
            }
            used += char_width;
            start = index;
        }
        start
    };

    let mut used = 0usize;
    let mut end = start;
    for (offset, ch) in text[start..].char_indices() {
        let char_width = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + char_width > width {
            break;
        }
        used += char_width;
        end = start + offset + ch.len_utf8();
    }
    text[start..end].to_owned()
}

fn draw_message(frame: &mut Frame, text: &str) {
    // The only user-visible surface that used to bypass the sanitizer.
    // Everything reaching it is control-char validated at decode today, but
    // the sanitizer is the invariant, not the decoders.
    let text = sanitize_for_display(text);
    let text = text.as_str();
    let area = centered_area(frame.area(), 60, 5);
    frame.render_widget(Clear, frame.area());
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            sanitize_for_display(text),
            Style::default().fg(Color::Yellow),
        )))
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true })
        .block(title_block("VEILROOM")),
        area,
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "Press any key to return to the menu.",
            Style::default().fg(Color::DarkGray),
        )))
        .alignment(Alignment::Center),
        footer_row(area),
    );
}

/// Draws the project-purpose text selected from the main menu.
fn draw_about(frame: &mut Frame) {
    let area = centered_area(frame.area(), 86, 9);
    frame.render_widget(Clear, frame.area());
    frame.render_widget(
        Paragraph::new(ABOUT_TEXT)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .block(title_block("About Veilroom")),
        area,
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "Press any key to return to the menu.",
            Style::default().fg(Color::DarkGray),
        )))
        .alignment(Alignment::Center),
        footer_row(area),
    );
}

/// Formats an elapsed duration without wrapping at 24 hours.
fn format_elapsed(duration: std::time::Duration) -> String {
    let seconds = duration.as_secs();
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let seconds = seconds % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

/// A centered area of at most `width` by `height`.
fn centered_area(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    }
}

/// A one-row strip at the bottom of `area`, for footer hints.
///
/// Saturating throughout: a terminal that reports zero rows makes
/// `centered_area` return a zero-height rect, and `y + height - 1` would
/// then underflow.
fn footer_row(area: Rect) -> Rect {
    Rect {
        x: area.x,
        y: area.y.saturating_add(area.height.saturating_sub(1)),
        width: area.width,
        height: area.height.min(1),
    }
}

/// The area inside the border of a block.
fn inner_area(area: Rect) -> Rect {
    Rect {
        x: area.x + 1,
        y: area.y + 1,
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::RequestId;
    use crate::ui::room_view::RequestLine;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    #[test]
    fn wrap_for_display_chunks_within_the_width() {
        // A full invitation URI, ~120 chars, must be split into chunks no
        // wider than the panel so nothing is clipped.
        let body = "a".repeat(56);
        let token = "0123456789abcdef0123456789abcdef";
        let uri = format!("veilroom://{body}.onion:80?v=1&token={token}");
        let chunks = wrap_for_display(&uri, 40);
        assert!(chunks.len() > 1, "the URI is wrapped across rows");
        assert!(
            chunks
                .iter()
                .all(|chunk| unicode_width::UnicodeWidthStr::width(chunk.as_str()) <= 40),
            "no chunk may exceed the panel width"
        );
        let joined: String = chunks.concat();
        assert_eq!(joined, uri, "wrapping must not drop any character");
    }

    #[test]
    fn wrap_for_display_preserves_wide_characters() {
        let text = "日本語のメッセージです";
        let chunks = wrap_for_display(text, 6);
        assert!(
            chunks
                .iter()
                .all(|chunk| unicode_width::UnicodeWidthStr::width(chunk.as_str()) <= 6)
        );
        let joined: String = chunks.concat();
        assert_eq!(joined, text);
    }

    #[test]
    fn wrap_for_display_short_lines_stay_unchanged() {
        assert_eq!(wrap_for_display("hello", 40), vec!["hello".to_owned()]);
        assert_eq!(wrap_for_display("", 40), vec![String::new()]);
    }

    #[test]
    fn input_viewport_follows_the_cursor_after_overflow() {
        assert_eq!(input_viewport("abcdefghij", 10, 5), "fghij");
        assert_eq!(input_viewport("abcdefghij", 0, 5), "abcde");
        assert_eq!(input_viewport("日本語abcd", 13, 6), "語abcd");
    }

    #[test]
    fn room_input_keeps_new_characters_visible_after_overflow() {
        let mut app = App::new();
        let mut view = RoomView::participant("deniz".to_owned());
        view.input
            .insert_text(&format!("{}VISIBLE", "x".repeat(40)));
        app.enter_room(view);

        let backend = TestBackend::new(24, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let buffer = terminal.backend().buffer();
        let input_row = buffer.content()[22 * 24..23 * 24]
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();

        assert!(
            input_row.contains("VISIBLE"),
            "the newest input must remain visible: {input_row:?}"
        );
    }

    #[test]
    fn request_ids_and_accept_commands_reach_the_terminal_buffer() {
        let mut app = App::new();
        let mut view = RoomView::host("host".to_owned());
        view.show_requests(vec![
            RequestLine {
                request_id: RequestId::new(3),
                nickname: "deniz".to_owned(),
                kind: RequestKind::Join { introduction: None },
            },
            RequestLine {
                request_id: RequestId::new(4),
                nickname: "ece".to_owned(),
                kind: RequestKind::Timeout { seconds: 30 },
            },
        ]);
        app.enter_room(view);

        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("request 3: deniz"));
        assert!(rendered.contains("/accept 3 or /reject 3"));
        assert!(rendered.contains("Requests"));
        assert!(rendered.contains("4 timeout"));
        assert!(rendered.contains("ece: 30s"));
    }

    #[test]
    fn host_can_switch_to_the_member_room_layout() {
        let mut app = App::new();
        let mut view = RoomView::host("host".to_owned());
        view.set_members(vec![crate::ui::room_view::MemberLine {
            member_id: crate::event::MemberId::new(0),
            nickname: "host".to_owned(),
            color: crate::command::ColorChoice::White,
            is_host: true,
        }]);
        app.enter_room(view);

        let host_render = render_app(&app);
        assert!(host_render.contains("host view"));
        assert!(host_render.contains("Members"));
        assert!(host_render.contains("Requests"));

        app.room_view_mut().unwrap().toggle_host_member_view();
        let member_render = render_app(&app);
        assert!(member_render.contains("member view"));
        assert!(!member_render.contains("Members"));
        assert!(!member_render.contains("Requests"));
        assert!(member_render.contains("host> "));
    }

    #[test]
    fn message_filter_keeps_only_timestamped_user_chat() {
        let mut app = App::new();
        let mut view = RoomView::participant("alice".to_owned());
        view.messages.push(crate::ui::buffer::MessageLine {
            text: "bob: hello".to_owned(),
            style: LineStyle::Chat,
            nickname: None,
            timestamp: crate::ui::buffer::GmtTimestamp::from_hms(1, 2, 3).unwrap(),
            created_at: std::time::Instant::now(),
            expires_at: None,
        });
        view.messages.push(crate::ui::buffer::MessageLine {
            text: "bob joined".to_owned(),
            style: LineStyle::Notice,
            nickname: None,
            timestamp: crate::ui::buffer::GmtTimestamp::from_hms(4, 5, 6).unwrap(),
            created_at: std::time::Instant::now(),
            expires_at: None,
        });
        view.notice("pending request");
        app.enter_room(view);

        let all_messages = render_app(&app);
        assert!(all_messages.contains("[01:02:03] bob: hello"));
        assert!(all_messages.contains("[04:05:06] bob joined"));
        assert!(all_messages.contains("] ! pending request"));
        assert!(
            all_messages.contains("GMT: "),
            "the room header shows live GMT"
        );

        app.room_view_mut().unwrap().toggle_system_messages();
        let user_only = render_app(&app);
        assert!(user_only.contains("[01:02:03] bob: hello"));
        assert!(!user_only.contains("bob joined"));
        assert!(!user_only.contains("pending request"));
        assert!(user_only.contains("user messages only"));
    }

    #[test]
    fn chat_nickname_is_drawn_in_the_sender_color() {
        let mut app = App::new();
        let mut view = RoomView::participant("deniz".to_owned());
        view.push_chat("alice", crate::command::ColorChoice::Red, "hello");
        app.enter_room(view);

        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let buffer = terminal.backend().buffer();
        let symbols: Vec<&str> = buffer.content().iter().map(|cell| cell.symbol()).collect();
        let nickname = "alice";
        let offset = symbols
            .windows(nickname.chars().count())
            .position(|window| {
                window
                    .iter()
                    .zip(nickname.chars())
                    .all(|(symbol, ch)| *symbol == ch.to_string().as_str())
            })
            .expect("the nickname is rendered");
        for (index, _) in nickname.char_indices() {
            let cell = &buffer.content()[offset + index];
            assert_eq!(
                cell.style().fg,
                Some(Color::Red),
                "nickname cell `{}` is drawn in the sender color",
                cell.symbol()
            );
        }
        // The message body must keep the plain chat style.
        let body_start = offset + nickname.chars().count() + 2; // skip `: `
        for (index, _) in "hello".char_indices() {
            let cell = &buffer.content()[body_start + index];
            assert_ne!(cell.style().fg, Some(Color::Red));
        }
    }

    #[test]
    fn wrap_segments_preserves_styles_across_chunk_boundaries() {
        let mut text = String::from("pre");
        text.push_str(&"x".repeat(60));
        let segments = [
            ("[00:00:00] ", Style::default()),
            ("alice", Style::default().fg(Color::Red)),
            (&text, Style::default()),
        ];
        let lines = wrap_segments(&segments, 20);
        assert!(lines.len() > 1, "the long body wraps across lines");
        let joined: String = lines
            .iter()
            .flat_map(|spans| spans.iter())
            .map(|span| span.content.as_ref().to_owned())
            .collect();
        assert_eq!(joined, "[00:00:00] alicepre".to_owned() + &"x".repeat(60));
        // The nickname style survives wrapping: every span that contains the
        // substring "alice" is styled with the red foreground.
        let has_red_nickname = lines.iter().flatten().any(|span| {
            span.content.as_ref().contains("alice") && span.style.fg == Some(Color::Red)
        });
        assert!(
            has_red_nickname,
            "the colored nickname span survives wrapping"
        );
    }

    #[test]
    fn join_pending_screen_explains_the_host_decision() {
        let mut app = App::new();
        app.show_join_pending();
        let rendered = render_app(&app);
        assert!(rendered.contains("Waiting for host approval"));
        assert!(rendered.contains("Your join request was sent."));
        assert!(rendered.contains("Waiting for the host to accept or reject it..."));
    }

    #[test]
    fn room_header_shows_live_metrics_for_host_and_participant() {
        let mut host = App::new();
        let mut host_view = RoomView::host("host".to_owned());
        host_view.set_status("epoch 1");
        host_view.set_members(vec![
            crate::ui::room_view::MemberLine {
                member_id: crate::event::MemberId::new(0),
                nickname: "host".to_owned(),
                color: ColorChoice::White,
                is_host: true,
            },
            crate::ui::room_view::MemberLine {
                member_id: crate::event::MemberId::new(1),
                nickname: "alice".to_owned(),
                color: ColorChoice::Cyan,
                is_host: false,
            },
        ]);
        host.enter_room(host_view);
        let rendered = render_app(&host);
        assert!(rendered.contains("GMT: "));
        assert!(rendered.contains("Room uptime: "));
        assert!(rendered.contains("Participants: 1"));
        assert!(rendered.contains("VEILROOM"));
        assert!(rendered.contains("hosting as host"));
        assert!(rendered.contains("epoch 1"));

        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &host)).unwrap();
        let buffer = terminal.backend().buffer();
        assert_eq!(buffer.content()[50].symbol(), "┬");
        assert_eq!(buffer.content()[100 + 50].symbol(), "│");
        assert_eq!(buffer.content()[4 * 100 + 50].symbol(), "┴");

        let mut participant = App::new();
        participant.enter_room(RoomView::participant("alice".to_owned()));
        let rendered = render_app(&participant);
        assert!(rendered.contains("In room: "));
        assert!(rendered.contains("Participants: 1"));
    }

    #[test]
    fn about_screen_renders_the_requested_statement() {
        assert_eq!(
            ABOUT_TEXT,
            "Veilroom is free software created to help protect individuals’ right to communicate freely. We believe messaging should be as simple, fast, and private as possible. Yet governments have deemed even this too much for their citizens. -topcuogly"
        );
        let mut app = App::new();
        app.set_screen(Screen::About);
        let rendered = render_app(&app);
        assert!(rendered.contains("About Veilroom"));
        assert!(rendered.contains("Veilroom is free software"));
        assert!(rendered.contains("governments have deemed"));
        assert!(rendered.contains("-topcuogly"));
    }

    #[test]
    fn elapsed_duration_format_does_not_wrap_after_one_day() {
        assert_eq!(
            format_elapsed(std::time::Duration::from_secs(27 * 3_600 + 4 * 60 + 5)),
            "27:04:05"
        );
    }

    #[test]
    fn tor_progress_is_the_only_connection_screen_content() {
        let mut app = App::new();
        app.begin_tor_connection();
        app.set_tor_progress(42);

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let buffer = terminal.backend().buffer();
        let rendered = buffer
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("Connecting to Tor"));
        assert!(rendered.contains("42%"));
        assert!(!rendered.contains("VEILROOM"));
        assert!(!rendered.contains("Host a room"));
        assert!(!rendered.contains("Join a room"));
        assert!(!rendered.contains("Exit"));
    }

    fn render_app(app: &App) -> String {
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, app)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }
}
