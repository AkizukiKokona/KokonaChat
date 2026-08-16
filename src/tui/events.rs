use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::tui::app::App;

/// 键位：
///   Enter 发送；Ctrl+N/Ctrl+P/Tab 切换好友；Ctrl+R 重发失败消息；
///   Ctrl+F 查找新地址；Ctrl+H 帮助；Ctrl+Q 或 Esc 退出。
pub fn handle_key(app: &mut App, ev: KeyEvent) {
    if ev.modifiers.contains(KeyModifiers::CONTROL) {
        match ev.code {
            KeyCode::Char('q') => app.quit = true,
            KeyCode::Char('n') => app.select_next(),
            KeyCode::Char('p') => app.select_prev(),
            KeyCode::Char('f') => app.find_address(),
            KeyCode::Char('r') => app.retry_failed(),
            KeyCode::Char('h') => app.show_help = !app.show_help,
            _ => {}
        }
        return;
    }
    match ev.code {
        KeyCode::Enter => app.send_current(),
        KeyCode::Backspace => {
            app.input.pop();
        }
        KeyCode::Tab => app.select_next(),
        KeyCode::Char(c) if !c.is_control() => app.input.push(c),
        KeyCode::Esc => app.quit = true,
        _ => {}
    }
}