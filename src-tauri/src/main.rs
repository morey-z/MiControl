#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Some(code) = micontrol_windows::hid_tap::run_helper_if_requested() {
        std::process::exit(code);
    }
    micontrol_windows_app::run();
}
