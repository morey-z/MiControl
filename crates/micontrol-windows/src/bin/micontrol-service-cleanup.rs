//! Independent uninstall/rollback helper.
//!
//! This binary is intentionally free of Tauri/WebView dependencies.  The
//! public request mode re-enters the shared elevated service path; the
//! elevated child is dispatched through the same fixed-root native cleanup
//! implementation as the desktop executable.

use std::path::{Path, PathBuf};

const CLEANUP: &str = "--micontrol-service-cleanup";
const REMOVE: &str = "--micontrol-rc003-remove-service";
const COMPAT_CLEANUP: &str = "--micontrol-appcompat-cleanup";
const LAUNCH_SETUP: &str = "--micontrol-launch-setup";
const OPERATION_ID_ARG: &str = "--micontrol-operation-id";
const MAIN_BINARY: &str = "micontrol-windows-app.exe";

#[derive(Debug, PartialEq, Eq)]
enum CleanupInvocation {
    Public,
    InternalRemove,
    CompatCleanup(std::path::PathBuf),
    LaunchSetup(std::path::PathBuf),
}

fn valid_sid(value: &str) -> bool {
    let mut parts = value.split('-');
    matches!(parts.next(), Some("S"))
        && matches!(parts.next(), Some("1"))
        && parts.next().is_some()
        && parts.all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn parse_args(args: &[String], current_exe: &Path) -> Result<CleanupInvocation, String> {
    if args.len() == 2 && args[1] == CLEANUP {
        return Ok(CleanupInvocation::Public);
    }
    if args.len() == 2 && (args[1] == COMPAT_CLEANUP || args[1] == LAUNCH_SETUP) {
        let target = current_exe
            .parent()
            .ok_or_else(|| "invalid cleanup helper directory".to_owned())?
            .join(MAIN_BINARY);
        if target.file_name().and_then(|name| name.to_str()) != Some(MAIN_BINARY) {
            return Err("invalid fixed setup target".into());
        }
        return if args[1] == COMPAT_CLEANUP {
            Ok(CleanupInvocation::CompatCleanup(target))
        } else {
            Ok(CleanupInvocation::LaunchSetup(target))
        };
    }
    if (args.len() != 4 && args.len() != 6) || args[1] != REMOVE {
        return Err("invalid cleanup helper arguments".into());
    }
    if args.len() == 6
        && (args[4] != OPERATION_ID_ARG
            || !micontrol_windows::installer_compat::valid_operation_id(&args[5]))
    {
        return Err("invalid cleanup helper operation id".into());
    }
    let supplied = PathBuf::from(&args[2]);
    let supplied = std::fs::canonicalize(&supplied)
        .map_err(|_| "invalid cleanup helper source path".to_owned())?;
    let expected = std::fs::canonicalize(current_exe)
        .map_err(|_| "invalid cleanup helper executable path".to_owned())?;
    if supplied != expected || !valid_sid(&args[3]) {
        return Err("invalid cleanup helper internal remove arguments".into());
    }
    Ok(CleanupInvocation::InternalRemove)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("cleanup helper executable path failed: {error}");
            std::process::exit(1);
        }
    };
    let invocation = match parse_args(&args, &executable) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };
    match invocation {
        CleanupInvocation::Public => {
            match micontrol_windows::hid_tap::manage_service(executable, false) {
                Ok(_) => std::process::exit(0),
                Err(error) => {
                    eprintln!("cleanup helper failed: {error}");
                    std::process::exit(1);
                }
            }
        }
        CleanupInvocation::InternalRemove => {
            // The fixed four-argument REMOVE form is accepted only after the
            // parser has bound its source path to this helper and validated
            // the SID.  No INSTALL, service runtime, or arbitrary mode can
            // reach the shared dispatcher from this payload.
            if let Some(code) = micontrol_windows::hid_tap::handle_mode(&args) {
                std::process::exit(code);
            }
            eprintln!("cleanup helper internal remove dispatch failed");
            std::process::exit(2);
        }
        CleanupInvocation::CompatCleanup(target) => {
            match micontrol_windows::installer_compat::cleanup_run_as_admin(&target) {
                Ok(()) => std::process::exit(0),
                Err(error) => {
                    eprintln!("AppCompat cleanup failed: {error}");
                    std::process::exit(1);
                }
            }
        }
        CleanupInvocation::LaunchSetup(target) => {
            let result = micontrol_windows::installer_compat::launch_setup_request(&target);
            std::process::exit(micontrol_windows::installer_compat::result_exit_code(
                &result,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn accepts_public_cleanup_entry() {
        assert_eq!(
            parse_args(&args(&["helper.exe", CLEANUP]), Path::new("helper.exe")),
            Ok(CleanupInvocation::Public)
        );
    }

    #[test]
    fn accepts_only_bound_internal_remove_entry() {
        let current = std::env::current_exe().expect("test executable");
        let current_text = current.to_string_lossy().into_owned();
        let values = [
            current_text.as_str(),
            REMOVE,
            current_text.as_str(),
            "S-1-5-21-123",
        ];
        assert_eq!(
            parse_args(&args(&values), &current),
            Ok(CleanupInvocation::InternalRemove)
        );
        let explicit_values = [
            current_text.as_str(),
            REMOVE,
            current_text.as_str(),
            "S-1-5-21-123",
            OPERATION_ID_ARG,
            "setup-20261013-0001",
        ];
        assert_eq!(
            parse_args(&args(&explicit_values), &current),
            Ok(CleanupInvocation::InternalRemove)
        );
    }

    #[test]
    fn rejects_install_and_unbound_remove_modes() {
        let current = std::env::current_exe().expect("test executable");
        let current_text = current.to_string_lossy().into_owned();
        assert!(parse_args(
            &args(&["helper.exe", "--micontrol-rc003-install-service"]),
            &current
        )
        .is_err());
        assert!(parse_args(
            &args(&["helper.exe", REMOVE, "other.exe", "S-1-5-21-123"]),
            &current
        )
        .is_err());
        assert!(parse_args(
            &args(&["helper.exe", REMOVE, current_text.as_str(), "bad"]),
            &current
        )
        .is_err());
        assert!(parse_args(
            &args(&[
                "helper.exe",
                REMOVE,
                current_text.as_str(),
                "S-1-5-21-123",
                OPERATION_ID_ARG,
                "setup;whoami",
            ]),
            &current
        )
        .is_err());
        assert!(parse_args(&args(&["helper.exe", COMPAT_CLEANUP]), &current).is_ok());
        assert!(parse_args(&args(&["helper.exe", LAUNCH_SETUP]), &current).is_ok());
        assert!(parse_args(
            &args(&["helper.exe", LAUNCH_SETUP, "C:\\MiControl\\other.exe"]),
            &current
        )
        .is_err());
    }
}
