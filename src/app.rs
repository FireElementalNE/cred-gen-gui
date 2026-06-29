use eframe::egui;
use rand::{Rng, SeedableRng, TryRng, rand_core::UnwrapErr, rngs::StdRng, rngs::SysRng};
use sha2::{Digest, Sha256};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use crate::generator::{self, Charset};

const RANDOM_ORG_URL: &str = "https://api.random.org/json-rpc/4/invoke";
const RANDOM_ORG_SEED_BITS: usize = 256;

pub struct App {
    charset: Charset,
    length: usize,
    with_username: bool,
    username_digits: usize,
    style_initialized: bool,
    use_random_org: bool,
    random_org_api_key: String,
    entropy_status: String,
    password: String,
    username: String,
    generation_task: Option<GenerationTask>,
}

impl Default for App {
    fn default() -> Self {
        let mut app = Self {
            charset: Charset::default(),
            length: 20,
            with_username: true,
            username_digits: 0,
            style_initialized: false,
            use_random_org: false,
            random_org_api_key: String::new(),
            entropy_status: String::from("Using OS randomness"),
            password: String::new(),
            username: String::new(),
            generation_task: None,
        };
        app.start_regeneration();
        app
    }
}

impl App {
    fn start_regeneration(&mut self) {
        if self.generation_task.is_some() {
            return;
        }

        let settings = GenerationSettings {
            charset: self.charset,
            length: self.length,
            with_username: self.with_username,
            username_digits: self.username_digits,
            use_random_org: self.use_random_org,
            random_org_api_key: self.random_org_api_key.clone(),
        };
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let _ = sender.send(generate_credentials(settings));
        });
        self.generation_task = Some(GenerationTask { receiver });
    }

    fn poll_generation(&mut self, ctx: &egui::Context) {
        let Some(task) = &self.generation_task else {
            return;
        };

        match task.receiver.try_recv() {
            Ok(credentials) => {
                self.password = credentials.password;
                self.username = credentials.username;
                self.entropy_status = credentials.entropy_status;
                self.generation_task = None;
            }
            Err(TryRecvError::Empty) => {
                ctx.request_repaint_after(Duration::from_millis(16));
            }
            Err(TryRecvError::Disconnected) => {
                self.entropy_status = String::from("Generation failed; please try again");
                self.generation_task = None;
            }
        }
    }

    fn is_generating(&self) -> bool {
        self.generation_task.is_some()
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if !self.style_initialized {
            ui.ctx().set_theme(egui::Theme::Dark);
            self.style_initialized = true;
        }
        apply_text_style(ui.ctx());
        self.poll_generation(ui.ctx());

        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Credential Generator");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    egui::global_theme_preference_switch(ui);
                });
            });
            ui.add_space(8.0);

            credential_row(ui, "Password", &self.password);
            if self.with_username {
                credential_row(ui, "Username", &self.username);
            }

            ui.add_space(8.0);
            strength_meter(ui, self.charset, self.length);
            ui.add_space(12.0);
            ui.separator();

            egui::Grid::new("options")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Length");
                    ui.add(egui::Slider::new(&mut self.length, 4..=128));
                    ui.end_row();

                    ui.label("Include");
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.charset.lowercase, "a-z");
                        ui.checkbox(&mut self.charset.uppercase, "A-Z");
                        ui.checkbox(&mut self.charset.digits, "0-9");
                        ui.checkbox(&mut self.charset.symbols, "!@#");
                    });
                    ui.end_row();

                    ui.label("");
                    ui.checkbox(
                        &mut self.charset.exclude_ambiguous,
                        "Exclude look-alikes (Il1O0o)",
                    );
                    ui.end_row();

                    ui.label("Username");
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.with_username, "Generate");
                        ui.add_enabled(
                            self.with_username,
                            egui::Slider::new(&mut self.username_digits, 0..=4).text("digits"),
                        );
                    });
                    ui.end_row();

                    ui.label("Entropy");
                    ui.checkbox(&mut self.use_random_org, "Mix Random.org");
                    ui.end_row();

                    if self.use_random_org {
                        ui.label("API key");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.random_org_api_key)
                                .password(true)
                                .hint_text("Random.org JSON-RPC key"),
                        );
                        ui.end_row();
                    }
                });

            ui.add_space(8.0);
            ui.label(&self.entropy_status);
            ui.add_space(12.0);
            let generate = ui
                .add_enabled(
                    !self.is_generating(),
                    egui::Button::new("Generate").min_size(egui::vec2(ui.available_width(), 32.0)),
                )
                .clicked();
            if generate {
                self.start_regeneration();
            }
        });

        if self.is_generating() {
            show_generation_modal(ui.ctx());
        }
    }
}

struct GenerationTask {
    receiver: Receiver<GeneratedCredentials>,
}

#[derive(Clone)]
struct GenerationSettings {
    charset: Charset,
    length: usize,
    with_username: bool,
    username_digits: usize,
    use_random_org: bool,
    random_org_api_key: String,
}

struct GeneratedCredentials {
    password: String,
    username: String,
    entropy_status: String,
}

fn generate_credentials(settings: GenerationSettings) -> GeneratedCredentials {
    if settings.use_random_org {
        match random_org_rng(&settings.random_org_api_key) {
            Ok(mut rng) => {
                return generate_with(
                    &settings,
                    &mut rng,
                    String::from("Mixed Random.org with OS randomness"),
                );
            }
            Err(err) => {
                let mut rng = UnwrapErr(SysRng);
                return generate_with(
                    &settings,
                    &mut rng,
                    format!("Random.org failed; using OS randomness ({err})"),
                );
            }
        }
    }

    let mut rng = UnwrapErr(SysRng);
    generate_with(&settings, &mut rng, String::from("Using OS randomness"))
}

fn generate_with(
    settings: &GenerationSettings,
    rng: &mut impl Rng,
    entropy_status: String,
) -> GeneratedCredentials {
    GeneratedCredentials {
        password: generator::password(settings.charset, settings.length, rng).unwrap_or_default(),
        username: if settings.with_username {
            generator::username(settings.username_digits, rng)
        } else {
            String::new()
        },
        entropy_status,
    }
}

fn show_generation_modal(ctx: &egui::Context) {
    egui::Modal::new(egui::Id::new("generation_progress_modal")).show(ctx, |ui| {
        ui.set_min_width(220.0);
        ui.vertical_centered(|ui| {
            ui.add(egui::Spinner::new().size(28.0));
            ui.add_space(8.0);
            ui.label("Generating credentials...");
        });
    });
}

/// A monospace credential field with a copy button.
fn credential_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        if ui.button("📋").on_hover_text("Copy").clicked() {
            ui.ctx().copy_text(value.to_owned());
        }
        ui.label(format!("{label}:"));
        ui.add(egui::Label::new(egui::RichText::new(value).monospace().size(16.0)).truncate());
    });
}

fn strength_meter(ui: &mut egui::Ui, charset: Charset, length: usize) {
    let bits = generator::entropy_bits(charset.alphabet_size(), length);
    let (label, color) = match bits as u32 {
        0..=39 => ("Weak", egui::Color32::from_rgb(0xE0, 0x3C, 0x3C)),
        40..=71 => ("Fair", egui::Color32::from_rgb(0xE0, 0xA0, 0x30)),
        72..=99 => ("Strong", egui::Color32::from_rgb(0x4C, 0xAF, 0x50)),
        _ => ("Very strong", egui::Color32::from_rgb(0x2E, 0x8B, 0x3E)),
    };
    let fraction = (bits / 128.0).clamp(0.0, 1.0) as f32;
    ui.add(
        egui::ProgressBar::new(fraction)
            .fill(color)
            .text(format!("{label} · {bits:.0} bits")),
    );
}

fn apply_text_style(ctx: &egui::Context) {
    let mut style = (*ctx.global_style()).clone();
    style
        .text_styles
        .insert(egui::TextStyle::Small, egui::FontId::proportional(14.0));
    style
        .text_styles
        .insert(egui::TextStyle::Body, egui::FontId::proportional(16.0));
    style
        .text_styles
        .insert(egui::TextStyle::Button, egui::FontId::proportional(16.0));
    style
        .text_styles
        .insert(egui::TextStyle::Heading, egui::FontId::proportional(24.0));
    style
        .text_styles
        .insert(egui::TextStyle::Monospace, egui::FontId::monospace(16.0));
    ctx.set_global_style(style);
}

fn random_org_rng(api_key: &str) -> Result<StdRng, String> {
    if api_key.trim().is_empty() {
        return Err(String::from("missing API key"));
    }

    let remote_seed = random_org_seed(api_key.trim())?;
    let mut local_seed = [0_u8; 32];
    SysRng
        .try_fill_bytes(&mut local_seed)
        .map_err(|err| format!("OS RNG failed: {err}"))?;

    let seed = Sha256::new()
        .chain_update(local_seed)
        .chain_update(remote_seed)
        .chain_update(b"credential-generator-gui random.org seed v1")
        .finalize()
        .into();

    Ok(StdRng::from_seed(seed))
}

fn random_org_seed(api_key: &str) -> Result<[u8; 32], String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|err| format!("HTTP client setup failed: {err}"))?;

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "generateBlobs",
        "params": {
            "apiKey": api_key,
            "n": 1,
            "size": RANDOM_ORG_SEED_BITS,
            "format": "hex"
        },
        "id": 1
    });

    let response: serde_json::Value = client
        .post(RANDOM_ORG_URL)
        .json(&request)
        .send()
        .map_err(|err| format!("request failed: {err}"))?
        .error_for_status()
        .map_err(|err| format!("HTTP error: {err}"))?
        .json()
        .map_err(|err| format!("invalid JSON: {err}"))?;

    if let Some(message) = response
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(serde_json::Value::as_str)
    {
        return Err(message.to_owned());
    }

    let hex_seed = response
        .get("result")
        .and_then(|result| result.get("random"))
        .and_then(|random| random.get("data"))
        .and_then(serde_json::Value::as_array)
        .and_then(|data| data.first())
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| String::from("missing random data"))?;

    let bytes = hex::decode(hex_seed).map_err(|err| format!("invalid hex data: {err}"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("expected 32 seed bytes, got {}", bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_credentials_uses_os_randomness() {
        let credentials = generate_credentials(GenerationSettings {
            charset: Charset::default(),
            length: 20,
            with_username: true,
            username_digits: 2,
            use_random_org: false,
            random_org_api_key: String::new(),
        });

        assert_eq!(credentials.password.chars().count(), 20);
        assert!(
            credentials
                .username
                .chars()
                .rev()
                .take(2)
                .all(|c| c.is_ascii_digit())
        );
        assert_eq!(credentials.entropy_status, "Using OS randomness");
    }

    #[test]
    fn generate_credentials_falls_back_when_random_org_key_is_missing() {
        let credentials = generate_credentials(GenerationSettings {
            charset: Charset::default(),
            length: 16,
            with_username: false,
            username_digits: 0,
            use_random_org: true,
            random_org_api_key: String::from("  "),
        });

        assert_eq!(credentials.password.chars().count(), 16);
        assert!(credentials.username.is_empty());
        assert_eq!(
            credentials.entropy_status,
            "Random.org failed; using OS randomness (missing API key)"
        );
    }
}
