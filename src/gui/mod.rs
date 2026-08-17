//! 原生图形界面：winit + egui + wgpu（与 TUI 共用同一套聊天状态模型）。
//!
//! 渲染走 `egui-wgpu` 的 `winit` 特性内置 `Painter`（处理 surface/device/render state/present），
//! 事件接入用 `egui-winit` 的 `State`。

mod ui;
mod avatar;

use std::num::NonZeroU32;
use std::sync::Arc;

use anyhow::Result;
use egui::ViewportId;
use egui_wgpu::{RendererOptions, WgpuConfiguration};
use winit::application::ApplicationHandler;
use winit::dpi::PhysicalSize;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::window::{Theme, Window, WindowId};

use crate::tui::app::App as ChatApp;

pub fn run(app: ChatApp, mobile: bool) -> Result<()> {
    let event_loop = EventLoop::new()?;
    let egui_ctx = egui::Context::default();
    // 中文显示：egui 默认字体不含 CJK 字形，需要加载系统字体 + 设置浅色主题。
    ui::configure(&egui_ctx, false);

    let mut handler = GuiHandler {
        chat: app,
        egui_ctx,
        egui_state: None,
        painter: None,
        window: None,
        proxy: event_loop.create_proxy(),
        mica: false,
        mobile,
    };

    event_loop.set_control_flow(ControlFlow::Wait);
    event_loop.run_app(&mut handler)?;
    Ok(())
}

struct GuiHandler {
    chat: ChatApp,
    egui_ctx: egui::Context,
    egui_state: Option<egui_winit::State>,
    painter: Option<egui_wgpu::winit::Painter>,
    window: Option<Arc<Window>>,
    proxy: EventLoopProxy<()>,
    /// Win11 毛玻璃（Acrylic）是否已启用（决定透明清屏与半透明面板）。
    mica: bool,
    /// 移动端 UI 预览（竖屏手机比例窗口）。
    mobile: bool,
}

impl GuiHandler {
    fn repaint_frame(&mut self, event_loop: &ActiveEventLoop) {
        let Self {
            chat,
            egui_ctx,
            egui_state,
            painter,
            window,
            ..
        } = self;

        let Some(window) = window else { return };

        // 拉取网络事件并刷新好友/消息状态。
        chat.drain_events();

        let state = match egui_state {
            Some(s) => s,
            None => return,
        };

        let raw_input = state.take_egui_input(window);
        let mobile = self.mobile;
        let mut full_output = egui_ctx.run_ui(raw_input, |ui| {
            ui::show(ui, chat, mobile);
        });

        // 退出请求：UI 里点了“退出”按钮。
        if chat.quit {
            event_loop.exit();
            return;
        }

        state.handle_platform_output(window, full_output.platform_output);

        let primitives =
            egui_ctx.tessellate(std::mem::take(&mut full_output.shapes), full_output.pixels_per_point);

        let mut textures_delta = full_output.textures_delta;
        let painter = match painter {
            Some(p) => p,
            None => return,
        };
        // 浅色主题留白底色；毛玻璃开启时清屏色完全透明，露出系统 Acrylic 磨砂。
        let clear_color = if self.mica {
            [0.0, 0.0, 0.0, 0.0]
        } else {
            [0.95, 0.95, 0.96, 1.0]
        };
        painter.paint_and_update_textures(
            ViewportId::ROOT,
            full_output.pixels_per_point,
            clear_color,
            &primitives,
            &mut textures_delta,
            Vec::new(),
            window,
        );
    }
}

impl ApplicationHandler for GuiHandler {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return; // 已经建过窗口
        }

        let window_attributes = Window::default_attributes()
            .with_title(format!("KokonaChat · {}", self.chat.own_short))
            .with_inner_size(if self.mobile {
                PhysicalSize::new(400, 820)
            } else {
                PhysicalSize::new(1120, 760)
            })
            .with_min_inner_size(PhysicalSize::new(320, 480))
            .with_resizable(true)
            .with_theme(Some(Theme::Light))
            .with_window_icon(avatar::icon());

        // Win11 毛玻璃：winit 的 with_system_backdrop 设置 DWMWA_SYSTEMBACKDROP_TYPE。
        // 注意：Mica(MAINWINDOW) 是不透明材质、看不出磨砂；用户要的“毛玻璃”是
        // Acrylic(TRANSIENTWINDOW) —— 半透明 + 实时模糊桌面。
        // with_transparent(true) + with_no_redirection_bitmap 让客户区逐像素透明，
        // 透明像素之上即可透出 Acrylic 磨砂。非 Windows 平台保持普通实底窗口。
        #[cfg(target_os = "windows")]
        let window_attributes = {
            use winit::platform::windows::{BackdropType, WindowAttributesExtWindows};
            window_attributes
                .with_system_backdrop(BackdropType::TransientWindow)
                // 透明后缓冲的 alpha 需直达 DWM：移除不透明的重定向表面（白底）
                // 才能让毛玻璃从客户区透出。NVIDIA Vulkan 下该组合可用。
                .with_transparent(true)
                .with_no_redirection_bitmap(true)
        };

        let mica = cfg!(target_os = "windows");

        let window = match event_loop.create_window(window_attributes) {
            Ok(w) => Arc::new(w),
            Err(e) => {
                log::error!("创建窗口失败: {e}");
                event_loop.exit();
                return;
            }
        };

        self.mica = mica;
        if mica {
            ui::configure(&self.egui_ctx, true);
            log::info!("已启用 Win11 Acrylic 毛玻璃");
        }

        // 移动端默认停在好友列表页（聊天页由点击进入，返回键回到列表）。
        if self.mobile {
            self.chat.selected = usize::MAX;
        }

        // wgpu 初始化（adapter/device）是异步的，一次性 block_on 即可。
        let wgpu_config = WgpuConfiguration::default();
        let mut painter = pollster::block_on(egui_wgpu::winit::Painter::new(
            self.egui_ctx.clone(),
            wgpu_config,
            mica, // Mica 需要透明后缓冲
            RendererOptions::default(),
        ));
        if let Err(e) =
            pollster::block_on(painter.set_window(ViewportId::ROOT, Some(window.clone())))
        {
            log::error!("wgpu 绑定窗口失败: {e}");
            event_loop.exit();
            return;
        }

        let egui_state = egui_winit::State::new(
            self.egui_ctx.clone(),
            ViewportId::ROOT,
            &window,
            None, // 使用 DPI 缩放
            None,
            painter.max_texture_side(),
        );

        // egui 任何线程发起 request_repaint 时唤醒事件循环（含延迟重绘）。
        let proxy = self.proxy.clone();
        let ctx = self.egui_ctx.clone();
        ctx.set_request_repaint_callback(move |info| {
            let proxy = proxy.clone();
            if info.delay.is_zero() {
                let _ = proxy.send_event(());
            } else {
                std::thread::spawn(move || {
                    std::thread::sleep(info.delay);
                    let _ = proxy.send_event(());
                });
            }
        });

        self.egui_state = Some(egui_state);
        self.painter = Some(painter);
        self.window = Some(window.clone());

        window.request_redraw();
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        window_id: WindowId,
        event: WindowEvent,
    ) {
        let Some(window) = &self.window else { return };
        if window.id() != window_id {
            return;
        }

        if let WindowEvent::CloseRequested = event {
            event_loop.exit();
            return;
        }

        let mut repaint = false;

        if let Some(state) = self.egui_state.as_mut() {
            repaint |= state.on_window_event(window, &event).repaint;
        }

        match event {
            WindowEvent::Resized(size) => {
                if let Some(painter) = self.painter.as_mut() {
                    if let (Some(w), Some(h)) = (
                        NonZeroU32::new(size.width),
                        NonZeroU32::new(size.height),
                    ) {
                        painter.on_window_resize_state_change(ViewportId::ROOT, true);
                        painter.on_window_resized(ViewportId::ROOT, w, h);
                        painter.on_window_resize_state_change(ViewportId::ROOT, false);
                    }
                }
            }
            WindowEvent::RedrawRequested => {
                self.repaint_frame(event_loop);
                return;
            }
            _ => {}
        }

        if repaint {
            window.request_redraw();
        }
    }

    fn user_event(&mut self, _event_loop: &ActiveEventLoop, _event: ()) {
        if let Some(window) = &self.window {
            window.request_redraw();
        }
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        // 周期唤醒（约 10 帧/秒）以轮询网络事件通道；交互事件时由上文直接触发重绘。
        event_loop.set_control_flow(ControlFlow::WaitUntil(
            std::time::Instant::now() + std::time::Duration::from_millis(100),
        ));
        if let Some(window) = &self.window {
            window.request_redraw();
        }
    }
}