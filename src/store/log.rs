//! 简单的追加式消息记录。

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use anyhow::Result;

pub fn append(path: &Path, line: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(f, "{line}")?;
    Ok(())
}