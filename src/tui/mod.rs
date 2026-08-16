pub mod app;
pub mod events;
pub mod ui;

use std::io;

use anyhow::Result;
use crossterm::event::{Event, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::tui::app::App;

pub fn run(mut app: App) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.hide_cursor()?;

    let res = run_loop(&mut terminal, &mut app);

    terminal.show_cursor()?;
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    res
}

fn run_loop(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> Result<()> {
    while !app.quit {
        app.drain_events();
        terminal.draw(|f| ui::draw(f, app))?;
        if crossterm::event::poll(std::time::Duration::from_millis(60))? {
            if let Event::Key(ev) = crossterm::event::read()? {
                if ev.kind == KeyEventKind::Press {
                    events::handle_key(app, ev);
                }
            }
        }
    }
    Ok(())
}