//! 应用头像/图标：默认加载项目根目录的 `kokonacir.jpg`，
//! 也支持按路径加载用户自定义头像。解码一次并缓存。
//! 窗口/任务栏图标固定用默认头像；界面内头像由 `avatar_texture` 按签名动态切换。

use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Clone)]
pub struct Avatar {
    pub rgba: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

static DEFAULT_CACHE: Mutex<Option<Avatar>> = Mutex::new(None);

/// 软件默认头像（kokonacir.jpg，项目根目录或可执行文件旁）。
pub fn default_avatar() -> Option<Avatar> {
    let mut cache = DEFAULT_CACHE.lock().unwrap();
    if let Some(a) = &*cache {
        return Some(a.clone());
    }
    let path = candidate_paths().into_iter().find(|p| p.exists())?;
    let a = decode_file(&path)?;
    *cache = Some(a.clone());
    Some(a)
}

/// 解码任意图片文件为 RGBA。
pub fn load_path(path: &Path) -> Option<Avatar> {
    decode_file(path)
}

/// 生成 winit 窗口/任务栏图标（用默认头像）。
pub fn icon() -> Option<winit::window::Icon> {
    let a = default_avatar()?;
    winit::window::Icon::from_rgba(a.rgba.clone(), a.width, a.height).ok()
}

fn decode_file(path: &Path) -> Option<Avatar> {
    let bytes = std::fs::read(path).ok()?;
    let img = image::load_from_memory(&bytes).ok()?.to_rgba8();
    let (width, height) = img.dimensions();
    Some(Avatar { rgba: img.into_raw(), width, height })
}

fn candidate_paths() -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from("kokonacir.jpg")];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            v.push(dir.join("kokonacir.jpg"));
        }
    }
    v
}