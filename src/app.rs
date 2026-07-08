use eframe::egui;
use rand::{Rng, SeedableRng, TryRng, rand_core::UnwrapErr, rngs::StdRng, rngs::SysRng};
use sha2::{Digest, Sha256};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use crate::generator::{self, Charset};

const RANDOM_ORG_URL: &str = "https://api.random.org/json-rpc/4/invoke";
const RANDOM_ORG_SEED_BITS: usize = 256;

/// Separator choices offered for passphrases.
const PASSPHRASE_SEPARATORS: [(char, &str); 4] = [
    ('-', "- hyphen"),
    ('_', "_ underscore"),
    ('.', ". period"),
    (' ', "space"),
];

/// How long the copy confirmation stays visible.
const COPY_FEEDBACK_DURATION: Duration = Duration::from_millis(1500);

/// Quiet period after the last settings change before auto-regenerating,
/// so dragging a slider doesn't fire a generation per frame.
const AUTO_REGEN_DEBOUNCE: Duration = Duration::from_millis(350);

/// The settings that shape the generated credentials, for change detection.
/// Deliberately excludes the entropy-source settings (Random.org toggle and
/// API key): those don't invalidate the current credentials, and reacting to
/// them would fire a network request per keystroke while typing the key.
type CredentialShape = (Charset, usize, SecretMode, usize, char, bool, bool, usize);

const CONFIRM_GREEN: egui::Color32 = egui::Color32::from_rgb(0x4C, 0xAF, 0x50);

/// Which kind of secret to generate.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SecretMode {
    Password,
    Passphrase,
}

pub struct App {
    mode: SecretMode,
    charset: Charset,
    length: usize,
    passphrase_words: usize,
    passphrase_separator: char,
    passphrase_capitalize: bool,
    with_username: bool,
    username_digits: usize,
    style_initialized: bool,
    use_random_org: bool,
    random_org_api_key: String,
    entropy_status: String,
    password: String,
    username: String,
    password_revealed: bool,
    /// Which credential row was just copied, and when, for the confirmation.
    copy_feedback: Option<(String, Instant)>,
    /// Settings as of the last frame; `None` until the first frame runs.
    last_shape: Option<CredentialShape>,
    /// When the most recent settings change happened, if a regen is pending.
    regen_pending_since: Option<Instant>,
    generation_task: Option<GenerationTask>,
}

impl Default for App {
    fn default() -> Self {
        let mut app = Self {
            mode: SecretMode::Password,
            charset: Charset::default(),
            length: 20,
            passphrase_words: 5,
            passphrase_separator: '-',
            passphrase_capitalize: true,
            with_username: true,
            username_digits: 0,
            style_initialized: false,
            use_random_org: false,
            random_org_api_key: String::new(),
            entropy_status: String::from("Using OS randomness"),
            password: String::new(),
            username: String::new(),
            password_revealed: true,
            copy_feedback: None,
            last_shape: None,
            regen_pending_since: None,
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
            mode: self.mode,
            charset: self.charset,
            length: self.length,
            passphrase_words: self.passphrase_words,
            passphrase_separator: self.passphrase_separator,
            passphrase_capitalize: self.passphrase_capitalize,
            with_username: self.with_username,
            username_digits: self.username_digits,
            use_random_org: self.use_random_org,
            random_org_api_key: self.random_org_api_key.clone(),
        };
        let uses_random_org = settings.use_random_org;
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let _ = sender.send(generate_credentials(settings));
        });
        self.generation_task = Some(GenerationTask {
            receiver,
            uses_random_org,
        });
    }

    fn credential_shape(&self) -> CredentialShape {
        (
            self.charset,
            self.length,
            self.mode,
            self.passphrase_words,
            self.passphrase_separator,
            self.passphrase_capitalize,
            self.with_username,
            self.username_digits,
        )
    }

    /// Regenerate automatically once the settings have been stable for the
    /// debounce window. Each further change restarts the timer; if a task is
    /// already running when the timer fires, the regen stays pending and
    /// retries once that task completes.
    fn maybe_auto_regenerate(&mut self, ctx: &egui::Context) {
        let shape = self.credential_shape();
        match self.last_shape {
            None => self.last_shape = Some(shape),
            Some(last) if last != shape => {
                self.last_shape = Some(shape);
                self.regen_pending_since = Some(Instant::now());
            }
            Some(_) => {}
        }

        let Some(since) = self.regen_pending_since else {
            return;
        };
        let elapsed = since.elapsed();
        if elapsed < AUTO_REGEN_DEBOUNCE {
            ctx.request_repaint_after(AUTO_REGEN_DEBOUNCE - elapsed);
        } else if self.is_generating() {
            ctx.request_repaint_after(Duration::from_millis(16));
        } else {
            self.regen_pending_since = None;
            self.start_regeneration();
        }
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

    /// Space/Enter regenerates, Ctrl+C (Cmd+C on macOS) copies the password.
    /// Suppressed while a text field (e.g. the API key) has keyboard focus so
    /// typing spaces or copying selected text keeps working.
    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        if ctx.egui_wants_keyboard_input() {
            return;
        }
        let (regenerate, copy) = ctx.input(|i| {
            (
                i.key_pressed(egui::Key::Space) || i.key_pressed(egui::Key::Enter),
                i.modifiers.command && i.key_pressed(egui::Key::C),
            )
        });
        if regenerate {
            self.start_regeneration();
        }
        if copy && !self.password.is_empty() {
            ctx.copy_text(self.password.clone());
            self.copy_feedback = Some((String::from("Password"), Instant::now()));
        }
    }

    /// Drop the copy confirmation once it has been shown long enough.
    fn expire_copy_feedback(&mut self, ctx: &egui::Context) {
        if let Some((_, since)) = &self.copy_feedback {
            let elapsed = since.elapsed();
            if elapsed >= COPY_FEEDBACK_DURATION {
                self.copy_feedback = None;
            } else {
                ctx.request_repaint_after(COPY_FEEDBACK_DURATION - elapsed);
            }
        }
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
        self.expire_copy_feedback(ui.ctx());
        self.handle_shortcuts(ui.ctx());

        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Credential Generator");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    egui::global_theme_preference_switch(ui);
                });
            });
            ui.add_space(8.0);

            credential_row(
                ui,
                "Password",
                &self.password,
                Some(&mut self.password_revealed),
                &mut self.copy_feedback,
            );
            if self.with_username {
                credential_row(ui, "Username", &self.username, None, &mut self.copy_feedback);
            }

            ui.add_space(8.0);
            let bits = match self.mode {
                SecretMode::Password => {
                    generator::entropy_bits(self.charset.alphabet_size(), self.length)
                }
                SecretMode::Passphrase => {
                    generator::passphrase_entropy_bits(self.passphrase_words)
                }
            };
            strength_meter(ui, bits);
            ui.add_space(12.0);
            ui.separator();

            egui::Grid::new("options")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Mode");
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.mode, SecretMode::Password, "Password");
                        ui.selectable_value(&mut self.mode, SecretMode::Passphrase, "Passphrase");
                    });
                    ui.end_row();

                    match self.mode {
                        SecretMode::Password => {
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
                        }
                        SecretMode::Passphrase => {
                            ui.label("Words");
                            ui.add(egui::Slider::new(&mut self.passphrase_words, 3..=10));
                            ui.end_row();

                            ui.label("Separator");
                            egui::ComboBox::from_id_salt("passphrase_separator")
                                .selected_text(separator_label(self.passphrase_separator))
                                .show_ui(ui, |ui| {
                                    for (separator, label) in PASSPHRASE_SEPARATORS {
                                        ui.selectable_value(
                                            &mut self.passphrase_separator,
                                            separator,
                                            label,
                                        );
                                    }
                                });
                            ui.end_row();

                            ui.label("");
                            ui.checkbox(&mut self.passphrase_capitalize, "Capitalize words");
                            ui.end_row();
                        }
                    }

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
            ui.add_space(4.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    egui::RichText::new("Space/Enter — regenerate · Ctrl+C — copy password")
                        .small()
                        .weak(),
                );
            });
        });

        self.maybe_auto_regenerate(ui.ctx());

        // Only network-bound generation is slow enough to warrant a blocking
        // modal; local generation is instant and would just flash it.
        if self
            .generation_task
            .as_ref()
            .is_some_and(|task| task.uses_random_org)
        {
            show_generation_modal(ui.ctx());
        }
        if let Some((label, _)) = &self.copy_feedback {
            show_copy_toast(ui.ctx(), label);
        }
    }
}

struct GenerationTask {
    receiver: Receiver<GeneratedCredentials>,
    /// Whether this task may block on the network (Random.org seed fetch).
    uses_random_org: bool,
}

#[derive(Clone)]
struct GenerationSettings {
    mode: SecretMode,
    charset: Charset,
    length: usize,
    passphrase_words: usize,
    passphrase_separator: char,
    passphrase_capitalize: bool,
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
        password: match settings.mode {
            SecretMode::Password => {
                generator::password(settings.charset, settings.length, rng).unwrap_or_default()
            }
            SecretMode::Passphrase => generator::passphrase(
                settings.passphrase_words,
                settings.passphrase_separator,
                settings.passphrase_capitalize,
                rng,
            )
            .unwrap_or_default(),
        },
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

/// A monospace credential field with a copy button, and for secrets a
/// reveal/hide toggle. `revealed: None` means the value is always shown.
fn credential_row(
    ui: &mut egui::Ui,
    label: &str,
    value: &str,
    revealed: Option<&mut bool>,
    copy_feedback: &mut Option<(String, Instant)>,
) {
    ui.horizontal(|ui| {
        let copied = copy_feedback.as_ref().is_some_and(|(l, _)| l == label);
        let copy_button = if copied {
            egui::Button::new(egui::RichText::new("✔").color(CONFIRM_GREEN))
        } else {
            egui::Button::new("📋")
        };
        let hover = if copied { "Copied!" } else { "Copy" };
        if ui.add(copy_button).on_hover_text(hover).clicked() {
            ui.ctx().copy_text(value.to_owned());
            *copy_feedback = Some((label.to_owned(), Instant::now()));
        }

        let mut show_value = true;
        if let Some(revealed) = revealed {
            let toggle = if *revealed { "Hide" } else { "Show" };
            if ui.small_button(toggle).clicked() {
                *revealed = !*revealed;
            }
            show_value = *revealed;
        }

        ui.label(format!("{label}:"));
        let display = if show_value {
            value.to_owned()
        } else {
            "•".repeat(value.chars().count())
        };
        ui.add(egui::Label::new(egui::RichText::new(display).monospace().size(16.0)).truncate());
    });
}

/// A transient bottom-anchored toast confirming what was copied.
fn show_copy_toast(ctx: &egui::Context, label: &str) {
    egui::Area::new(egui::Id::new("copy_toast"))
        .anchor(egui::Align2::CENTER_BOTTOM, [0.0, -12.0])
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            egui::Frame::popup(ui.style()).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(CONFIRM_GREEN, "✔");
                    ui.label(format!("{label} copied to clipboard"));
                });
            });
        });
}

fn separator_label(separator: char) -> &'static str {
    PASSPHRASE_SEPARATORS
        .iter()
        .find(|(c, _)| *c == separator)
        .map_or("?", |(_, label)| label)
}

fn strength_meter(ui: &mut egui::Ui, bits: f64) {
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
    ui.label(
        egui::RichText::new(format!(
            "Est. crack time: {} (at 10¹⁰ guesses/sec)",
            generator::crack_time(bits)
        ))
        .small()
        .weak(),
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
            mode: SecretMode::Password,
            charset: Charset::default(),
            length: 20,
            passphrase_words: 5,
            passphrase_separator: '-',
            passphrase_capitalize: true,
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
    fn generate_credentials_in_passphrase_mode() {
        let credentials = generate_credentials(GenerationSettings {
            mode: SecretMode::Passphrase,
            charset: Charset::default(),
            length: 20,
            passphrase_words: 4,
            passphrase_separator: '.',
            passphrase_capitalize: false,
            with_username: false,
            username_digits: 0,
            use_random_org: false,
            random_org_api_key: String::new(),
        });

        let words: Vec<&str> = credentials.password.split('.').collect();
        assert_eq!(words.len(), 4);
        assert!(words.iter().all(|w| !w.is_empty()));
    }

    #[test]
    fn generate_credentials_falls_back_when_random_org_key_is_missing() {
        let credentials = generate_credentials(GenerationSettings {
            mode: SecretMode::Password,
            charset: Charset::default(),
            length: 16,
            passphrase_words: 5,
            passphrase_separator: '-',
            passphrase_capitalize: true,
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
