//! Optional RC003 input transport adapted from Bob-Bo1/Vibe-Remote (GPL-3.0-only).
//! Only the three missing buttons are accepted; voice/navigation stay on their
//! existing transports. Starting a worker is not proof that hardware IO works.
use crate::raw_input::decode_report_usages;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const GADGET_SHA256: &str = "6fca4007b2284c765a6c15c967a741f536b5865bf83867326a54029a3b752748";
pub const MISSING_USAGES: [u16; 3] = [0xF1, 0x80, 0x81];

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HidTapSnapshot {
    #[serde(default)]
    pub service_installed: bool,
    pub enabled: bool,
    pub phase: HidTapPhase,
    pub host_pid: Option<u32>,
    pub report_count: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HidTapPhase {
    #[default]
    Disabled,
    Preparing,
    Waiting,
    Ready,
    Failed,
    Unsupported,
}

pub fn decode_tap_report(raw: &str) -> Result<BTreeSet<u16>, String> {
    if raw.len() != 18 || !raw.is_ascii() {
        return Err("RC003 HID report must contain 9 bytes".into());
    }
    let mut bytes = [0u8; 9];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16).map_err(|_| "Invalid HID report hex")?;
    }
    if bytes[..3] != [1, 0, 0] {
        return Err("Unsupported RC003 report prefix".into());
    }
    Ok(decode_report_usages(&bytes)
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|usage| MISSING_USAGES.contains(usage))
        .collect())
}

#[cfg(windows)]
#[path = "hid_tap_windows.rs"]
mod windows;
#[cfg(windows)]
pub use windows::{handle_mode, manage_service, service_installed};
#[cfg(windows)]
pub use windows::{run_helper_if_requested, HidTapRuntime};

#[cfg(not(windows))]
pub fn run_helper_if_requested() -> Option<i32> {
    None
}

#[cfg(not(windows))]
pub fn service_installed() -> bool {
    false
}

#[cfg(not(windows))]
pub fn manage_service(_source: std::path::PathBuf, _install: bool) -> Result<bool, String> {
    Err("RC003 旁路服务仅支持 Windows".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn three_buttons_and_release_decode_without_navigation_or_voice() {
        assert_eq!(
            decode_tap_report("010000f10080008100").unwrap(),
            BTreeSet::from(MISSING_USAGES)
        );
        assert!(decode_tap_report("01000028003e005200").unwrap().is_empty());
        assert!(decode_tap_report("010000000000000000").unwrap().is_empty());
        assert!(decode_tap_report("020000f10080008100").is_err());
        assert!(decode_tap_report("010000zz0080008100").is_err());
        assert!(decode_tap_report("短报文").is_err());
    }
}
