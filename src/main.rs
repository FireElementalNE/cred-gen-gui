#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod generator;

use eframe::egui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([460.0, 430.0])
            .with_min_inner_size([420.0, 390.0])
            .with_title("Credential Generator"),
        ..Default::default()
    };
    eframe::run_native(
        "Credential Generator",
        options,
        Box::new(|_cc| Ok(Box::<app::App>::default())),
    )
}
