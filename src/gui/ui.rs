//! egui 界面：浅色主题 + 系统 CJK 字体加载（egui 默认字体不含中文字形）。
//! 桌面端与移动端（竖屏手机比例）两套布局，共用同一聊天状态模型。

use std::path::PathBuf;

use egui::{Color32, FontFamily, FontId, RichText, TextEdit};

use crate::crypto::id;
use crate::gui::avatar;
use crate::tui::app::{App as ChatApp, Dir, MsgKind, MsgStatus, UiMsg, WarnChoice};

const ACCENT: Color32 = Color32::from_rgb(0, 108, 191);
const TEXT_MAIN: Color32 = Color32::from_rgb(20, 20, 22);
const TEXT_WEAK: Color32 = Color32::from_rgb(130, 130, 140);
const CHIP_OUT: Color32 = Color32::from_rgb(226, 240, 252);
const CHIP_IN: Color32 = Color32::from_rgb(244, 244, 247);
const FAIL: Color32 = Color32::from_rgb(200, 50, 50);

/// 头像纹理缓存：签名 = 头像来源（默认/自定义路径+mtime），变化时自动重载。
static AVATAR_TEX: std::sync::Mutex<Option<(String, egui::TextureHandle)>> = std::sync::Mutex::new(None);

fn avatar_texture(ctx: &egui::Context, app: &ChatApp) -> Option<egui::TextureHandle> {
    let sig = app.avatar_signature();
    {
        let cache = AVATAR_TEX.lock().unwrap();
        if let Some((s, tex)) = &*cache {
            if s == &sig {
                return Some(tex.clone());
            }
        }
    }
    let loaded = app
        .custom_avatar()
        .and_then(|p| avatar::load_path(&p))
        .or_else(avatar::default_avatar);
    let mut cache = AVATAR_TEX.lock().unwrap();
    *cache = loaded.map(|a| {
        let tex = ctx.load_texture(
            "app_avatar",
            egui::ColorImage::from_rgba_unmultiplied(
                [a.width as usize, a.height as usize],
                &a.rgba,
            ),
            egui::TextureOptions::LINEAR,
        );
        (sig, tex)
    });
    cache.as_ref().map(|(_, t)| t.clone())
}

/// 全局外观与字体：必须在第一帧前调用一次。
/// `mica = true` 时面板填充改为半透明，让 Win11 Acrylic 毛玻璃透出来。
pub fn configure(ctx: &egui::Context, mica: bool) {
    let mut fonts = egui::FontDefinitions::default();
    if let Some(path) = cjk_font_candidates().into_iter().find(|p| p.exists()) {
        if let Ok(bytes) = std::fs::read(&path) {
            let name = "cjk".to_owned();
            fonts.font_data.insert(
                name.clone(),
                std::sync::Arc::new(egui::FontData {
                    font: bytes.into(),
                    index: 0,
                    tweak: Default::default(),
                }),
            );
            // 追加到各字族末尾作为兜底字形：拉丁字符仍用默认字体，中文才落到 CJK 字体。
            for family in [FontFamily::Proportional, FontFamily::Monospace] {
                fonts.families.get_mut(&family).unwrap().push(name.clone());
            }
        }
    }
    ctx.set_fonts(fonts);

    let mut visuals = egui::Visuals::light();
    if mica {
        // 高度透明的面板：让 Win11 Acrylic 毛玻璃清晰透出。
        visuals.panel_fill = Color32::from_rgba_unmultiplied(245, 245, 248, 90);
        visuals.window_fill = Color32::from_rgba_unmultiplied(250, 250, 252, 70);
        visuals.widgets.inactive.bg_fill = Color32::from_rgba_unmultiplied(240, 240, 243, 100);
        visuals.widgets.hovered.bg_fill = Color32::from_rgba_unmultiplied(232, 236, 245, 120);
        visuals.widgets.active.bg_fill = Color32::from_rgba_unmultiplied(214, 224, 238, 130);
    } else {
        visuals.panel_fill = Color32::from_rgb(248, 248, 250);
        visuals.window_fill = Color32::from_rgb(252, 252, 254);
        visuals.widgets.inactive.bg_fill = Color32::from_rgb(240, 240, 243);
        visuals.widgets.hovered.bg_fill = Color32::from_rgb(232, 236, 245);
        visuals.widgets.active.bg_fill = Color32::from_rgb(214, 224, 238);
    }
    visuals.selection.bg_fill = Color32::from_rgb(200, 218, 240);
    ctx.set_visuals(visuals);

    // 整体放大 1.5 倍：间距、控件尺寸与字体按比例放大，改善可读性与点击手感。
    ctx.style_mut_of(egui::Theme::Light, |style| {
        let s = &mut style.spacing;
        s.item_spacing = s.item_spacing * 1.5;
        s.button_padding = s.button_padding * 1.5;
        s.interact_size = s.interact_size * 1.5;
        s.indent *= 1.5;
        s.slider_width *= 1.5;
        s.combo_width *= 1.5;
        s.text_edit_width *= 1.5;
        s.icon_width *= 1.5;
        s.icon_width_inner *= 1.5;
        s.icon_spacing *= 1.5;
        s.extra_text_line_spacing *= 1.5;
        s.tooltip_width *= 1.5;
        s.menu_width *= 1.5;
        s.menu_spacing *= 1.5;
        let scale_margin = |m: egui::Margin| egui::Margin {
            left: (m.left as f32 * 1.5) as i8,
            right: (m.right as f32 * 1.5) as i8,
            top: (m.top as f32 * 1.5) as i8,
            bottom: (m.bottom as f32 * 1.5) as i8,
        };
        s.window_margin = scale_margin(s.window_margin);
        s.menu_margin = scale_margin(s.menu_margin);
        s.scroll.content_margin = scale_margin(s.scroll.content_margin);
        for (_, font_id) in style.text_styles.iter_mut() {
            font_id.size *= 1.4;
        }
    });
}

/// 常见系统 CJK 字体路径（Windows / Linux）。
fn cjk_font_candidates() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(windir) = std::env::var_os("WINDIR") {
        let base = PathBuf::from(windir).join("Fonts");
        v.push(base.join("msyh.ttc")); // 微软雅黑
        v.push(base.join("msyh.ttf"));
        v.push(base.join("simhei.ttf"));
        v.push(base.join("simsun.ttc"));
    }
    v.push(PathBuf::from("/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc"));
    v.push(PathBuf::from("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"));
    v.push(PathBuf::from("/usr/share/fonts/truetype/wqy/wqy-microhei.ttc"));
    v
}

pub fn show(ui: &mut egui::Ui, app: &mut ChatApp, mobile: bool) {
    if app.show_profile {
        profile_page(ui, app);
    } else if mobile {
        mobile_show(ui, app);
    } else {
        top_bar(ui, app);
        status_bar(ui, app);
        friend_list(ui, app);
        central_chat(ui, app);
    }
    modals(ui, app);
}

/// 顶栏头像按钮：点击进入“个人资料”页。
fn avatar_button(ui: &mut egui::Ui, app: &ChatApp, size: f32) -> bool {
    if let Some(tex) = avatar_texture(ui.ctx(), app) {
        ui.add(
            egui::Image::new(&tex)
                .max_size(egui::vec2(size, size))
                .sense(egui::Sense::click())
                .corner_radius(egui::CornerRadius::same((size / 2.0) as u8)),
        )
        .clicked()
    } else {
        ui.add_sized(
            [size, size],
            egui::Button::new(RichText::new("?").size(size * 0.5)).corner_radius(egui::CornerRadius::same((size / 2.0) as u8)),
        )
        .clicked()
    }
}

fn top_bar(ui: &mut egui::Ui, app: &mut ChatApp) {
    egui::Panel::top("top")
        .exact_size(52.0)
        .show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if avatar_button(ui, app, 34.0) {
                    app.show_profile = true;
                }
                ui.add_space(8.0);
                ui.label(RichText::new("KokonaChat").size(20.0).strong().color(ACCENT));
            });
        });
}

fn status_bar(ui: &mut egui::Ui, app: &ChatApp) {
    egui::Panel::bottom("status")
        .resizable(true)
        .default_size(96.0)
        .show(ui, |ui| {
            ui.add_space(4.0);
            ui.label(RichText::new("状态").small().weak());
            for s in app.status.iter().rev().take(5) {
                ui.label(RichText::new(s).size(15.0).weak());
            }
        });
}

fn friend_list(ui: &mut egui::Ui, app: &mut ChatApp) {
    // 好友栏宽度随窗口自适应：约 30% 宽度，收缩到窗口较小时自动变窄。
    let list_w = (ui.available_width() * 0.30).clamp(200.0, 300.0);
    egui::Panel::left("friends")
        .resizable(true)
        .default_size(list_w)
        .size_range(180.0..=420.0)
        .show(ui, |ui| {
            ui.add_space(8.0);
            ui.label(RichText::new("好友").size(18.0).strong());
            ui.separator();
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if app.friends.is_empty() {
                        ui.add_space(10.0);
                        ui.label(RichText::new("还没有好友").weak().size(16.0));
                        ui.label(
                            RichText::new(
                                "用 `kokonachat friend add <昵称> <公钥> <IP>`\n添加，或让对方发送 `kokonachat link` 邀请链接。",
                            )
                            .weak()
                            .size(14.0),
                        );
                    }
                    for (i, f) in app.friends.iter().enumerate() {
                        let unread = app.unread(&f.pubkey);
                        let head = format!("{} · {}", f.nickname, id::short_from_hex(&f.pubkey));
                        let resp = ui
                            .add_sized(
                                [ui.available_width(), 40.0],
                                egui::Button::new(RichText::new(&head).size(16.0)),
                            )
                            .on_hover_text(f.pubkey.clone());
                        if resp.clicked() {
                            app.selected = i;
                        }
                        if unread > 0 {
                            ui.label(RichText::new(format!("未读 {unread}")).size(14.0).color(ACCENT));
                        }
                    }
                });
        });
}

fn central_chat(ui: &mut egui::Ui, app: &mut ChatApp) {
    egui::CentralPanel::default().show(ui, |ui| {
        let Some(f) = app.current().cloned() else {
            ui.centered_and_justified(|ui| {
                ui.label(
                    RichText::new(
                        "还没有好友。\n\n先用 `kokonachat friend add` 添加好友，或让对方发 `kokonachat link` 邀请链接，再点击链接即可开聊。",
                    )
                    .weak()
                    .size(16.0),
                );
            });
            return;
        };

        // 会话头部（窄窗口时自动换行，防止文字出屏）
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(&f.nickname).size(19.0).strong());
            ui.separator();
            ui.label(RichText::new(id::short_from_hex(&f.pubkey)).monospace().weak());
            ui.separator();
            let ips = if f.ips.is_empty() {
                "-".to_string()
            } else {
                f.ips.join(", ")
            };
            ui.label(RichText::new(format!("IP[{ips}]")).weak());
            if ui.small_button("寻址").clicked() {
                app.find_address();
            }
            if ui.small_button("重发失败").clicked() {
                app.retry_failed();
            }
        });
        ui.separator();

        // 消息区
        let msgs = app.current_msgs();
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .id_salt("chat_scroll")
            .show(ui, |ui| {
                ui.add_space(6.0);
                for m in &msgs {
                    message_row(ui, app, m);
                }
            });

        // 输入区
        ui.separator();
        attach_bar(ui, app);
        let mut want_send = false;
        ui.horizontal(|ui| {
            let edit = TextEdit::multiline(&mut app.input)
                .desired_rows(3)
                .desired_width((ui.available_width() - 112.0).max(120.0))
                .hint_text("输入消息…  Enter 发送，Shift+Enter 换行")
                .font(FontId::proportional(17.0));
            let resp = ui.add(edit);
            let clicked = ui
                .add_sized([100.0, 72.0], egui::Button::new(RichText::new("发送").strong().size(17.0)))
                .clicked();
            // Enter（无 Shift）= 发送
            let enter = ui.input(|i| i.key_pressed(egui::Key::Enter) && !i.modifiers.shift);
            want_send = clicked || (enter && resp.has_focus());
        });
        if want_send {
            app.send_current();
        }
    });
}

/// 附件发送栏：图片/视频（多媒体功能）与文件（完整文件功能），按开关显示。
fn attach_bar(ui: &mut egui::Ui, app: &mut ChatApp) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("附件:").weak().size(13.0));
        if app.media_feature {
            if new_button(ui, "图片").clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("图片", &["jpg", "jpeg", "png", "gif", "webp", "bmp"])
                    .pick_file()
                {
                    app.pick_attach(1, p);
                }
            }
            if new_button(ui, "视频").clicked() {
                if let Some(p) = rfd::FileDialog::new()
                    .add_filter("视频", &["mp4", "mov", "avi", "mkv", "webm"])
                    .pick_file()
                {
                    app.pick_attach(2, p);
                }
            }
        }
        if app.file_feature {
            if new_button(ui, "文件").clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_file() {
                    app.pick_attach(3, p);
                }
            }
        }
    });
}

/// 新功能按钮：比默认按钮大 1.5 倍（高度 32 vs 默认约 21，字号 15），
/// 宽度随文字自适应，避免挤压相邻控件。
fn new_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(egui::Button::new(RichText::new(label).size(15.0)).min_size(egui::vec2(0.0, 32.0)))
}

fn message_row(ui: &mut egui::Ui, app: &ChatApp, m: &UiMsg) {
    let who = match m.dir {
        Dir::In => app
            .current()
            .map(|f| f.nickname.clone())
            .unwrap_or_else(|| "对方".into()),
        Dir::Out => "我".into(),
    };
    let time = crate::util::format_time(m.ts);
    let mark = match m.status {
        MsgStatus::Sending => " ↑送中",
        MsgStatus::Sent => "",
        MsgStatus::Failed => " ✗失败",
    };
    let (bg, prefix_color) = match m.dir {
        Dir::Out => (CHIP_OUT, ACCENT),
        Dir::In => (CHIP_IN, TEXT_WEAK),
    };
    let text_color = if m.status == MsgStatus::Failed { FAIL } else { TEXT_MAIN };

    let head = format!("{time} {who}{mark}");
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        ui.add_space(2.0);
        egui::Frame::new()
            .fill(bg)
            .inner_margin(egui::Margin::symmetric(12, 6))
            .corner_radius(egui::CornerRadius::same(8))
            .show(ui, |ui| {
                ui.label(RichText::new(head).size(13.0).weak().color(prefix_color));
                match &m.kind {
                    MsgKind::Text => {
                        ui.label(RichText::new(&m.text).color(text_color).size(17.0));
                    }
                    MsgKind::Image(data) => {
                        attach_image(ui, data);
                    }
                    MsgKind::Video(name, data) => {
                        attach_chip(ui, "视频", name, data.len(), text_color);
                    }
                    MsgKind::File(name, data) => {
                        attach_chip(ui, "文件", name, data.len(), text_color);
                    }
                }
            });
    });
    ui.add_space(3.0);
}

/// 图片附件：解码并预览（每帧临时纹理，便于跟随窗口缩放的简单实现）。
fn attach_image(ui: &mut egui::Ui, data: &[u8]) {
    if let Ok(img) = image::load_from_memory(data) {
        let rgba = img.to_rgba8();
        let (w, h) = rgba.dimensions();
        let color = egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &rgba);
        let tex = ui.ctx().load_texture("attach_img", color, egui::TextureOptions::LINEAR);
        let max_w = 260.0;
        let scale = (max_w / w as f32).min(1.0);
        ui.add(
            egui::Image::new(&tex)
                .max_size(egui::vec2(w as f32 * scale, h as f32 * scale))
                .corner_radius(egui::CornerRadius::same(6)),
        );
    } else {
        ui.label(RichText::new("（无法解码的图片）").weak().size(14.0));
    }
}

/// 视频/文件附件：文件名 + 大小芯片。
fn attach_chip(ui: &mut egui::Ui, tag: &str, name: &str, len: usize, color: Color32) {
    let size = if len >= 1024 * 1024 {
        format!("{:.1} MB", len as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} KB", len as f64 / 1024.0)
    };
    ui.label(RichText::new(format!("[{tag}] {name}（{size}）")).color(color).size(15.0));
}

// ---------------------------------------------------------------------------
// 个人资料页：头像上传、身份密钥、IP、昵称、功能开关、二维码、关于。
// ---------------------------------------------------------------------------

/// 统一按键规范（桌面端与移动端通用）——半仿真拨动开关：
/// 整体椭圆形，带一圈细边框；内部白色滑块（白球）可左右滑动。
/// - 关：底为白色/浅灰，白球在左；
/// - 开：底为绿色，白球在右。
/// 点击任意位置即切换状态。
/// 说明文字在左（自动换行），开关固定在行尾；视觉开关略小，
/// 但可点击区域保持较大，方便手指/鼠标点击。桌面端与移动端通用。
fn toggle_switch(ui: &mut egui::Ui, on: &mut bool, label: &str) -> bool {
    let mut changed = false;
    let hit = egui::vec2(58.0, 34.0); // 点击区域
    let visual = egui::vec2(48.0, 26.0); // 视觉开关
    let spacing = 12.0;

    ui.horizontal(|ui| {
        // 左侧：可换行的说明文字，占满整行除开关外的宽度。
        let avail_w = ui.available_width();
        let label_w = (avail_w - hit.x - spacing).max(60.0);
        let font_id = FontId::proportional(12.0);
        let galley = ui.painter().fonts_mut(|f| f.layout(label.to_owned(), font_id, Color32::WHITE, label_w));
        let label_h = galley.rect.height().max(visual.y);
        ui.allocate_ui_with_layout(
            egui::vec2(label_w, label_h),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                ui.add(egui::Label::new(RichText::new(label).size(12.0)).wrap());
            },
        );
        ui.add_space(spacing);

        // 右侧：开关。点击区域保持 58x34，视觉圆钮居中缩小。
        let (rect, resp) = ui.allocate_exact_size(hit, egui::Sense::click());
        if resp.clicked() {
            *on = !*on;
            changed = true;
        }
        let is_on = *on;
        let painter = ui.painter();
        let v = egui::Rect::from_center_size(rect.center(), visual);
        let radius = v.height() / 2.0;
        // 底
        let bg = if is_on {
            Color32::from_rgb(52, 178, 88)
        } else {
            Color32::from_rgb(238, 238, 241)
        };
        painter.rect_filled(v, radius, bg);
        // 细边框
        painter.rect_stroke(
            v,
            radius,
            egui::Stroke::new(
                1.5,
                if is_on {
                    Color32::from_rgb(42, 160, 76)
                } else {
                    Color32::from_rgb(175, 175, 185)
                },
            ),
            egui::StrokeKind::Inside,
        );
        // 白球（滑块）
        let pad = 3.0;
        let d = v.height() - pad * 2.0;
        let cx = if is_on {
            v.right() - pad - d / 2.0
        } else {
            v.left() + pad + d / 2.0
        };
        painter.circle_filled(egui::pos2(cx, v.center().y), d / 2.0, Color32::WHITE);
    });
    changed
}

fn profile_page(ui: &mut egui::Ui, app: &mut ChatApp) {
    egui::Panel::top("ptop")
        .exact_size(58.0)
        .show(ui, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui
                    .add_sized([48.0, 40.0], egui::Button::new(RichText::new("←").size(22.0).strong()))
                    .clicked()
                {
                    app.show_profile = false;
                }
                ui.label(RichText::new("个人资料").size(15.0).strong());
            });
        });

    egui::CentralPanel::default().show(ui, |ui| {
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add_space(8.0);

                // ---------- 头像 ----------
                if let Some(tex) = avatar_texture(ui.ctx(), app) {
                    ui.add(
                        egui::Image::new(&tex)
                            .max_size(egui::vec2(96.0, 96.0))
                            .corner_radius(egui::CornerRadius::same(48)),
                    );
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if new_button(ui, "更换头像").clicked() {
                        if let Some(p) = rfd::FileDialog::new()
                            .add_filter("图片", &["jpg", "jpeg", "png", "gif", "webp", "bmp"])
                            .pick_file()
                        {
                            app.set_avatar_from(&p);
                        }
                    }
                    if new_button(ui, "恢复默认头像").clicked() {
                        app.set_avatar_path(None);
                    }
                });

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(6.0);

                // ---------- 身份信息 ----------
                ui.label(RichText::new("身份信息").size(13.0).strong());
                ui.add_space(4.0);
                ui.label(RichText::new("用户 ID").size(12.0).weak());
                ui.add(egui::Label::new(RichText::new(&app.own_id).monospace().size(11.0)).wrap());
                ui.add_space(4.0);
                ui.label(RichText::new("身份种子（私钥，勿外泄）").size(12.0).weak());
                ui.add(egui::Label::new(RichText::new(&app.seed_hex).monospace().size(11.0)).wrap());
                ui.add_space(4.0);
                ui.label(RichText::new(format!("当前 IP（不可修改）：{}", app.local_ip)).size(12.0).weak());
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if new_button(ui, "重新生成密钥").clicked() {
                        app.confirm_key = Some("regenerate".into());
                    }
                    if new_button(ui, "手动修改密钥").clicked() {
                        app.confirm_key = Some("manual".into());
                    }
                });

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(6.0);

                // ---------- 昵称 ----------
                ui.label(RichText::new("昵称").size(13.0).strong());
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.add(
                        TextEdit::singleline(&mut app.nick_input)
                            .desired_width((ui.available_width() - 90.0).max(100.0))
                            .font(FontId::proportional(14.0)),
                    );
                    if new_button(ui, "保存昵称").clicked() {
                        app.confirm_nick = true;
                    }
                });

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(6.0);

                // ---------- 消息与寻址 ----------
                ui.label(RichText::new("消息与寻址").size(13.0).strong());
                ui.add_space(4.0);
                let mut auto = app.auto_addr;
                if toggle_switch(
                    ui,
                    &mut auto,
                    "发送失败时自动向共同好友寻址（成功后自动重发失败消息）",
                ) {
                    app.set_auto_addr(auto);
                }

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(6.0);

                // ---------- 功能开关（包含关系：文件 ⇒ 多媒体 ⇒ 头像） ----------
                ui.label(RichText::new("功能开关").size(13.0).strong());
                ui.add_space(4.0);
                let mut av = app.avatar_feature;
                if toggle_switch(ui, &mut av, "头像功能（关闭后使用软件默认头像）") {
                    app.set_feature(1, av);
                }
                let mut me = app.media_feature;
                if toggle_switch(ui, &mut me, "多媒体功能（发送图片、视频）") {
                    app.set_feature(2, me);
                }
                let mut fi = app.file_feature;
                if toggle_switch(ui, &mut fi, "完整文件传送（开启后自动带上头像与多媒体）") {
                    app.set_feature(3, fi);
                }

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(6.0);

                // ---------- 添加好友 ----------
                ui.label(RichText::new("添加好友").size(13.0).strong());
                ui.add_space(4.0);
                if new_button(ui, "生成我的添加二维码").clicked() {
                    app.show_qr = true;
                }

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(6.0);

                // ---------- 关于 ----------
                ui.label(RichText::new("关于").size(13.0).strong());
                ui.add_space(6.0);
                ui.label(RichText::new("KokonaChat").size(12.0).strong());
                ui.label(RichText::new(format!("版本 {}", env!("CARGO_PKG_VERSION"))).size(11.0).weak());
                ui.label(RichText::new("作者：秋月不会解梦").size(11.0).weak());
                ui.add_space(4.0);
                ui.add(egui::Label::new(RichText::new(
                    "去中心化 P2P 即时通讯：\nIPv6/UDP 直连 + 端到端加密 + 被动寻址。",
                )
                .size(11.0)
                .weak())
                .wrap());
            });
    });
}

/// 各确认/警告弹窗：密钥修改、昵称修改、大文件警告、二维码。
fn modals(ui: &mut egui::Ui, app: &mut ChatApp) {
    // 密钥修改二次确认
    if let Some(action) = app.confirm_key.clone() {
        egui::Modal::new(egui::Id::new("key_modal")).show(ui.ctx(), |ui| {
            ui.label(RichText::new("修改身份密钥的后果").size(14.0).strong());
            ui.add_space(6.0);
            ui.add(egui::Label::new(RichText::new(
                "好友记录的是你当前的 ID（公钥）。改密钥后你将成为新 ID：\n· 好友需要重新添加你；\n· 历史消息无法关联到新 ID；\n· 修改立即写入磁盘，网络层重启后生效。",
            ).size(12.0)).wrap());
            ui.add_space(6.0);
            if action == "manual" {
                ui.add(TextEdit::singleline(&mut app.seed_input).hint_text("输入 64 位 hex 种子").font(FontId::proportional(12.0)));
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button("取消").clicked() {
                    app.confirm_key = None;
                    app.seed_input.clear();
                }
                if ui.button("确定").clicked() {
                    if action == "regenerate" {
                        app.regenerate_key();
                    } else {
                        let seed = app.seed_input.clone();
                        if let Err(e) = app.set_seed(&seed) {
                            app.push_status(format!("密钥修改失败: {e}"));
                        }
                    }
                    app.confirm_key = None;
                    app.seed_input.clear();
                }
            });
        });
    }

    // 昵称修改确认
    if app.confirm_nick {
        egui::Modal::new(egui::Id::new("nick_modal")).show(ui.ctx(), |ui| {
            ui.label(RichText::new("修改昵称的后果").size(14.0).strong());
            ui.add_space(6.0);
            ui.add(egui::Label::new(RichText::new(
                "加好友链接（含二维码）会带上新昵称，通过链接添加你的人看到的是新昵称；已添加的好友不受影响。",
            ).size(12.0)).wrap());
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button("取消").clicked() {
                    app.confirm_nick = false;
                }
                if ui.button("确定").clicked() {
                    let nick = app.nick_input.clone();
                    app.set_nickname(&nick);
                    app.confirm_nick = false;
                }
            });
        });
    }

    // 大文件发送警告
    if let Some(draft) = app.warn_attach.clone() {
        egui::Modal::new(egui::Id::new("warn_modal")).show(ui.ctx(), |ui| {
            let size_mb = draft.size as f64 / (1024.0 * 1024.0);
            ui.label(RichText::new("大文件发送警告").size(14.0).strong());
            ui.add_space(6.0);
            ui.add(egui::Label::new(RichText::new(format!(
                "要发送“{}”（约 {:.1} MB）。\n大文件可能因网络不稳导致传输失败，并消耗较多时间与流量。是否继续？",
                draft.name, size_mb
            )).size(12.0)).wrap());
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button("取消").clicked() {
                    app.resolve_warn(WarnChoice::Cancel);
                }
                if ui.button("确定").clicked() {
                    app.resolve_warn(WarnChoice::Confirm);
                }
                if ui.button("确定并不再显示").clicked() {
                    app.resolve_warn(WarnChoice::ConfirmNoMore);
                }
            });
        });
    }

    // 二维码
    if app.show_qr {
        egui::Modal::new(egui::Id::new("qr_modal")).show(ui.ctx(), |ui| {
            ui.label(RichText::new("我的添加二维码").size(14.0).strong());
            ui.add_space(6.0);
            let link = app.invite_link();
            if let Some((w, cells)) = qr_cells(&link) {
                let scale = 6.0;
                let size = w as f32 * scale;
                // 整个弹窗与二维码等宽，链接文字在其内自动换行（可多行）
                ui.set_width(size);
                let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
                let painter = ui.painter();
                painter.rect_filled(rect, 0.0, Color32::WHITE);
                for (i, dark) in cells.iter().enumerate() {
                    if *dark {
                        let x = rect.left() + (i % w) as f32 * scale;
                        let y = rect.top() + (i / w) as f32 * scale;
                        painter.rect_filled(
                            egui::Rect::from_min_size(egui::pos2(x, y), egui::vec2(scale, scale)),
                            0.0,
                            Color32::BLACK,
                        );
                    }
                }
                ui.add_space(8.0);
                ui.add(egui::Label::new(RichText::new(&link).monospace().size(10.0)).wrap());
                ui.add_space(8.0);
                if ui.button("关闭").clicked() {
                    app.show_qr = false;
                }
            } else {
                ui.add(egui::Label::new(RichText::new("链接过长，无法生成二维码").weak().size(12.0)).wrap());
            }
        });
    }
}

/// 生成二维码点阵（(宽度, 逐行 dark 标记)）。
fn qr_cells(text: &str) -> Option<(usize, Vec<bool>)> {
    if text.is_empty() {
        return None;
    }
    let qr = qr_code::QrCode::new(text.as_bytes()).ok()?;
    let w = qr.width();
    Some((w, qr.to_vec()))
}

// ---------------------------------------------------------------------------
// 移动端（竖屏手机比例）：好友列表页 与 聊天页 两屏切换，顶部栏带返回键。
// ---------------------------------------------------------------------------

fn mobile_show(ui: &mut egui::Ui, app: &mut ChatApp) {
    mobile_top_bar(ui, app);
    if app.selected < app.friends.len() {
        mobile_chat(ui, app);
    } else {
        mobile_friend_list(ui, app);
    }
}

fn mobile_top_bar(ui: &mut egui::Ui, app: &mut ChatApp) {
    egui::Panel::top("mtop")
        .exact_size(58.0)
        .show(ui, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let in_chat = app.selected < app.friends.len();
                if in_chat {
                    // 返回好友列表
                    if ui
                        .add_sized([48.0, 40.0], egui::Button::new(RichText::new("←").size(22.0).strong()))
                        .clicked()
                    {
                        app.selected = usize::MAX;
                    }
                    if let Some(f) = app.current() {
                        ui.label(RichText::new(&f.nickname).size(18.0).strong());
                    }
                } else {
                    // 主页：头像（点击进资料页）+ 标题（IP 等数据都在个人资料页展示）
                    if avatar_button(ui, app, 36.0) {
                        app.show_profile = true;
                    }
                    ui.add_space(6.0);
                    ui.label(RichText::new("KokonaChat").size(20.0).strong().color(ACCENT));
                }
            });
        });
}

fn mobile_friend_list(ui: &mut egui::Ui, app: &mut ChatApp) {
    egui::CentralPanel::default().show(ui, |ui| {
        if app.friends.is_empty() {
            ui.add_space(16.0);
            ui.label(RichText::new("还没有好友").weak().size(16.0));
            ui.label(
                RichText::new(
                    "用 `kokonachat friend add <昵称> <公钥> <IP>`\n添加，或让对方发送 `kokonachat link` 邀请链接。",
                )
                .weak()
                .size(14.0),
            );
            return;
        }
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .id_salt("mlist")
            .show(ui, |ui| {
                for (i, f) in app.friends.iter().enumerate() {
                    let unread = app.unread(&f.pubkey);
                    let head = if unread > 0 {
                        format!("{} · 未读 {unread}", f.nickname)
                    } else {
                        f.nickname.clone()
                    };
                    let text = RichText::new(format!("{head}\n{}", id::short_from_hex(&f.pubkey))).size(16.0);
                    let resp = ui.add_sized([ui.available_width(), 60.0], egui::Button::new(text));
                    if resp.clicked() {
                        app.selected = i;
                    }
                    ui.add_space(4.0);
                }
            });
    });
}

fn mobile_chat(ui: &mut egui::Ui, app: &mut ChatApp) {
    egui::CentralPanel::default().show(ui, |ui| {
        let msgs = app.current_msgs();
        // 消息区
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .id_salt("mchat_scroll")
            .show(ui, |ui| {
                ui.add_space(6.0);
                for m in &msgs {
                    message_row(ui, app, m);
                }
            });

        // 输入区
        ui.separator();
        attach_bar(ui, app);
        let mut want_send = false;
        ui.horizontal(|ui| {
            let edit = TextEdit::multiline(&mut app.input)
                .desired_rows(2)
                .desired_width((ui.available_width() - 96.0).max(80.0))
                .hint_text("输入消息…")
                .font(FontId::proportional(17.0));
            let resp = ui.add(edit);
            let clicked = ui
                .add_sized([88.0, 60.0], egui::Button::new(RichText::new("发送").strong().size(16.0)))
                .clicked();
            let enter = ui.input(|i| i.key_pressed(egui::Key::Enter) && !i.modifiers.shift);
            want_send = clicked || (enter && resp.has_focus());
        });
        if want_send {
            app.send_current();
        }
    });
}