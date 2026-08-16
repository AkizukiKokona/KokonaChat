//! 三栏布局：好友列表 | 聊天区（+状态栏）| 输入框。

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use crate::store::friends::Friend;
use crate::tui::app::{App, Dir, MsgStatus, UiMsg};
use crate::util;

fn online(f: &Friend) -> bool {
    match f.last_seen {
        Some(ts) => util::unix_millis().saturating_sub(ts) < 300_000,
        None => false,
    }
}

pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1), Constraint::Length(3)])
        .split(area);
    let main = chunks[0];
    let inner = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
        .split(main);
    draw_friends(frame, inner[0], app);
    draw_chat(frame, inner[1], app);
    draw_status(frame, chunks[1], app);
    draw_input(frame, chunks[2], app);
}

fn draw_friends(frame: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
        .friends
        .iter()
        .map(|f| {
            let mark = if online(f) {
                Span::styled("●", Style::default().fg(Color::Green))
            } else {
                Span::styled("○", Style::default().fg(Color::DarkGray))
            };
            let nick = Span::styled(f.nickname.clone(), Style::default().fg(Color::Cyan));
            let short = Span::styled(format!(" {}", crate::crypto::id::short_from_hex(&f.pubkey)), Style::default().fg(Color::DarkGray));
            let unread = app.unread(&f.pubkey);
            let badge = if unread > 0 {
                Span::styled(format!(" [未读 {unread}]"), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            } else {
                Span::raw("")
            };
            let line = Line::from(vec![mark, Span::raw(" "), nick, short, badge]);
            ListItem::new(line)
        })
        .collect();
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" 好友 "))
        .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan))
        .highlight_symbol("▸ ");
    let mut state = ListState::default();
    state.select(Some(app.selected));
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_chat(frame: &mut Frame, area: Rect, app: &App) {
    let pubkey = app.current_pubkey();
    let title = match public_string(app, &pubkey) {
        Some((nick, short)) => format!(" 与 {nick}（{short}）的聊天 "),
        None => " 聊天（尚未选择好友） ".into(),
    };
    let block = Block::default().borders(Borders::ALL).title(title);
    let msgs = app.current_msgs();
    // 自动滚动：仅展示最后 inner_h 行
    let inner_h = area.height.saturating_sub(2).max(1) as usize;
    let mut lines: Vec<Line<'static>> = msgs.iter().rev().take(inner_h).collect::<Vec<_>>().into_iter().rev().map(|m| msg_line(app, m)).collect();
    if lines.is_empty() {
        lines.push(Line::from(Span::styled("（暂无消息，在下方输入框按 Enter 发送）", Style::default().fg(Color::DarkGray))));
    }
    let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    frame.render_widget(p, area);
}

fn public_string(app: &App, pubkey: &Option<String>) -> Option<(String, String)> {
    app.current().map(|f| (f.nickname.clone(), crate::crypto::id::short_from_hex(pubkey.as_deref().unwrap_or(""))))
}

fn msg_line(app: &App, m: &UiMsg) -> Line<'static> {
    let who = match m.dir {
        Dir::In => app.current().map(|f| f.nickname.clone()).unwrap_or_else(|| "对方".into()),
        Dir::Out => app.own_short.clone(),
    };
    let time = util::format_time(m.ts);
    let mut spans = vec![
        Span::styled(format!("[{}] {}: ", time, who), Style::default().fg(Color::DarkGray)),
        Span::styled(m.text.clone(), Style::default()),
    ];
    if m.dir == Dir::Out {
        let status = match m.status {
            MsgStatus::Sending => Span::styled(" …", Style::default().fg(Color::Yellow)),
            MsgStatus::Sent => Span::styled(" ✓", Style::default().fg(Color::Green)),
            MsgStatus::Failed => Span::styled(" ✗ [失败]", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        };
        spans.push(status);
    }
    Line::from(spans)
}

fn draw_status(frame: &mut Frame, area: Rect, app: &App) {
    let last = app.status.last().cloned().unwrap_or_default();
    let auto = if app.auto_addr { "  [自动寻址:开]" } else { "" };
    let hint = if app.show_help {
        "  Enter发送 Ctrl+P/N切换 Ctrl+F寻址 Ctrl+R重发 Ctrl+Q退出" 
    } else {
        ""
    };
    let text = Line::from(vec![
        Span::styled(format!(" {last}{auto}"), Style::default().fg(Color::Yellow)),
        Span::styled(hint, Style::default().fg(Color::DarkGray)),
    ]);
    frame.render_widget(Paragraph::new(text), area);
}

fn draw_input(frame: &mut Frame, area: Rect, app: &App) {
    let block = Block::default().borders(Borders::ALL).title(" 输入 ");
    let p = Paragraph::new(Line::from(Span::styled(format!("> {}", app.input), Style::default())))
        .block(block)
        .wrap(Wrap { trim: false });
    frame.render_widget(p, area);
    let x = (area.x + 2 + app.input.len() as u16).min(area.x + area.width.saturating_sub(2));
    frame.set_cursor_position((x, area.y + 1));
}