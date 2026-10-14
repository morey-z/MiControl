//! Narrow installer compatibility helpers.
//!
//! This module is intentionally separate from the service/ACL implementation.
//! It only touches the exact per-user AppCompat value for the installed main
//! executable and provides a native CreateProcess boundary for the NSIS hook.

use std::path::Path;

/// Operation ids are passed between the fixed installer/helper/service
/// boundary. Keep this validation shared so each parser accepts the same
/// bounded alphabet and cannot smuggle command-line syntax.
pub fn valid_operation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupLaunchResult {
    Completed(u32),
    LaunchError { code: u32, message: String },
    WaitError { code: u32, message: String },
    TimedOut { timeout_ms: u32 },
}

#[cfg(windows)]
mod windows_impl {
    use super::{Path, SetupLaunchResult};
    use sha2::{Digest, Sha256};
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, WAIT_FAILED,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
        HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_32KEY,
        KEY_WOW64_64KEY, REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE,
    };
    use windows::Win32::System::Threading::{
        CreateProcessW, GetExitCodeProcess, CREATE_NO_WINDOW, PROCESS_INFORMATION,
        STARTF_USESHOWWINDOW, STARTUPINFOW,
    };
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    const LAYERS_KEY: &str = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers";
    const RUNASADMIN: &str = "RUNASADMIN";
    const SETUP_REQUEST: &str = "--micontrol-rc003-setup-service-request";
    const OPERATION_ID_ARG: &str = "--micontrol-operation-id";
    const LAUNCH_TIMEOUT: Duration = Duration::from_secs(90);
    const LAUNCH_ERROR_EXIT: i32 = 0xE001;
    const WAIT_ERROR_EXIT: i32 = 0xE002;
    const TIMEOUT_EXIT: i32 = 0xE003;
    static OP_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum WaitClassification {
        Completed,
        TimedOut,
        Failed(u32),
        Unexpected(u32),
    }

    fn classify_wait_status(status: u32) -> WaitClassification {
        if status == WAIT_OBJECT_0.0 {
            WaitClassification::Completed
        } else if status == WAIT_TIMEOUT.0 {
            WaitClassification::TimedOut
        } else if status == WAIT_FAILED.0 {
            WaitClassification::Failed(status)
        } else {
            WaitClassification::Unexpected(status)
        }
    }

    pub(crate) fn classify_runas_error(code: u32) -> &'static str {
        if code == 1223 {
            "uac_cancel"
        } else {
            "launcherror"
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    enum RegistryRoot {
        CurrentUser,
        LocalMachine,
    }

    impl RegistryRoot {
        fn name(self) -> &'static str {
            match self {
                Self::CurrentUser => "HKEY_CURRENT_USER",
                Self::LocalMachine => "HKEY_LOCAL_MACHINE",
            }
        }

        fn writable(self) -> bool {
            matches!(self, Self::CurrentUser)
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    enum RegistryView {
        View64,
        View32,
    }

    impl RegistryView {
        fn name(self) -> &'static str {
            match self {
                Self::View64 => "64",
                Self::View32 => "32",
            }
        }

        fn flag(self) -> REG_SAM_FLAGS {
            match self {
                Self::View64 => KEY_WOW64_64KEY,
                Self::View32 => KEY_WOW64_32KEY,
            }
        }
    }

    trait RegistryBackend {
        fn read(
            &mut self,
            root: RegistryRoot,
            view: RegistryView,
            value_name: &Path,
        ) -> Result<Option<String>, String>;
        fn write(
            &mut self,
            root: RegistryRoot,
            view: RegistryView,
            value_name: &Path,
            value: Option<&str>,
        ) -> Result<(), String>;
    }

    trait BackupSink {
        fn save(
            &mut self,
            operation: &str,
            root: RegistryRoot,
            view: RegistryView,
            target: &Path,
            value: &str,
        ) -> Result<(), String>;
    }

    trait LogSink {
        fn write(&mut self, line: &str) -> Result<(), String>;
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn operation_id(prefix: &str) -> String {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let serial = OP_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}-{millis}-{serial:04}")
    }

    fn target_id(target: &Path) -> String {
        let mut hasher = Sha256::new();
        hasher.update(target.to_string_lossy().to_ascii_lowercase().as_bytes());
        let digest = hasher.finalize();
        digest[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn log_line(line: &str) -> Result<(), String> {
        let local = std::env::var_os("LOCALAPPDATA")
            .ok_or_else(|| "LOCALAPPDATA 不可用，无法写入安装诊断日志".to_owned())?;
        let path = Path::new(&local)
            .join("MiControl")
            .join("Logs")
            .join("install-stage.log");
        let parent = path
            .parent()
            .ok_or_else(|| "安装诊断日志路径无父目录".to_owned())?;
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("创建安装诊断日志目录失败：{error}"))?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| format!("打开安装诊断日志失败：{error}"))?;
        writeln!(file, "{line}").map_err(|error| format!("写入安装诊断日志失败：{error}"))
    }

    fn system_message(code: u32) -> String {
        std::io::Error::from_raw_os_error(code as i32).to_string()
    }

    fn win32_detail(code: u32) -> String {
        format!(
            "win32_code={code} (0x{code:08X}) system_message={}",
            system_message(code)
        )
    }

    fn registry_error(operation: &str, status: u32) -> String {
        format!("{operation} {}", win32_detail(status))
    }

    fn open_layers(
        root: HKEY,
        view: REG_SAM_FLAGS,
        access: REG_SAM_FLAGS,
    ) -> Result<Option<HKEY>, String> {
        let key_name = wide(LAYERS_KEY);
        let mut key = HKEY::default();
        let status = unsafe {
            RegOpenKeyExW(
                root,
                PCWSTR(key_name.as_ptr()),
                None,
                access | view,
                &mut key,
            )
        };
        if status.is_ok() {
            Ok(Some(key))
        } else if status.0 == ERROR_FILE_NOT_FOUND.0 || status.0 == ERROR_PATH_NOT_FOUND.0 {
            Ok(None)
        } else {
            Err(registry_error("打开 AppCompat Layers 失败", status.0))
        }
    }

    fn read_layer_value(key: HKEY, target: &Path) -> Result<Option<String>, String> {
        let name = wide(&target.to_string_lossy());
        let mut value_type = REG_VALUE_TYPE(0);
        let mut bytes = 0u32;
        let status = unsafe {
            RegQueryValueExW(
                key,
                PCWSTR(name.as_ptr()),
                None,
                Some(&mut value_type),
                None,
                Some(&mut bytes),
            )
        };
        if status.0 == ERROR_FILE_NOT_FOUND.0 {
            return Ok(None);
        }
        if status.is_err() {
            return Err(registry_error("读取 AppCompat Layers value 失败", status.0));
        }
        if value_type != REG_SZ {
            return Err(format!(
                "AppCompat Layers value 类型不受支持 type={}",
                value_type.0
            ));
        }
        let mut buffer = vec![0u8; bytes as usize];
        let status = unsafe {
            RegQueryValueExW(
                key,
                PCWSTR(name.as_ptr()),
                None,
                Some(&mut value_type),
                Some(buffer.as_mut_ptr()),
                Some(&mut bytes),
            )
        };
        if status.is_err() {
            return Err(registry_error(
                "读取 AppCompat Layers value 内容失败",
                status.0,
            ));
        }
        let units = buffer[..bytes as usize]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take_while(|unit| *unit != 0)
            .collect::<Vec<_>>();
        Ok(Some(String::from_utf16_lossy(&units)))
    }

    struct WindowsRegistryBackend;

    impl RegistryBackend for WindowsRegistryBackend {
        fn read(
            &mut self,
            root: RegistryRoot,
            view: RegistryView,
            value_name: &Path,
        ) -> Result<Option<String>, String> {
            let root = match root {
                RegistryRoot::CurrentUser => HKEY_CURRENT_USER,
                RegistryRoot::LocalMachine => HKEY_LOCAL_MACHINE,
            };
            let Some(key) = open_layers(root, view.flag(), KEY_QUERY_VALUE)? else {
                return Ok(None);
            };
            let value = read_layer_value(key, value_name);
            unsafe {
                let _ = RegCloseKey(key);
            }
            value
        }

        fn write(
            &mut self,
            root: RegistryRoot,
            view: RegistryView,
            value_name: &Path,
            value: Option<&str>,
        ) -> Result<(), String> {
            let root = match root {
                RegistryRoot::CurrentUser => HKEY_CURRENT_USER,
                RegistryRoot::LocalMachine => HKEY_LOCAL_MACHINE,
            };
            let Some(key) = open_layers(root, view.flag(), KEY_SET_VALUE)? else {
                return Err("AppCompat Layers key 在写入前消失".to_owned());
            };
            let name = wide(&value_name.to_string_lossy());
            let status = if let Some(value) = value {
                let data = wide(value);
                unsafe {
                    RegSetValueExW(
                        key,
                        PCWSTR(name.as_ptr()),
                        None,
                        REG_SZ,
                        Some(std::slice::from_raw_parts(
                            data.as_ptr().cast::<u8>(),
                            data.len() * std::mem::size_of::<u16>(),
                        )),
                    )
                }
            } else {
                unsafe { RegDeleteValueW(key, PCWSTR(name.as_ptr())) }
            };
            unsafe {
                let _ = RegCloseKey(key);
            }
            if status.is_err() {
                return Err(registry_error("写入 AppCompat Layers value 失败", status.0));
            }
            Ok(())
        }
    }

    fn has_run_as_admin(value: &str) -> bool {
        value
            .split_whitespace()
            .any(|token| token.eq_ignore_ascii_case(RUNASADMIN))
    }

    /// Remove only the RUNASADMIN token. Other compatibility tokens remain in
    /// their original semantic order; whitespace is normalized as registry
    /// layer values are token lists rather than free-form text.
    pub fn remove_run_as_admin_token(value: &str) -> Option<String> {
        let tokens = value
            .split_whitespace()
            .filter(|token| !token.eq_ignore_ascii_case(RUNASADMIN))
            .collect::<Vec<_>>();
        if tokens.len() == value.split_whitespace().count() {
            return None;
        }
        Some(tokens.join(" "))
    }

    pub(super) fn escape_reg_string(value: &str) -> String {
        value.replace('\\', "\\\\").replace('"', "\\\"")
    }

    fn render_backup(
        operation: &str,
        root_name: &str,
        view_name: &str,
        target: &Path,
        value: &str,
    ) -> Vec<u8> {
        let escaped_name = escape_reg_string(&target.to_string_lossy());
        let escaped_value = escape_reg_string(value);
        let text = format!(
            "Windows Registry Editor Version 5.00\r\n\r\n; MiControl operation_id={operation} registry_view={view_name}\r\n[{root_name}\\{LAYERS_KEY}]\r\n\"{}\"=\"{}\"\r\n",
            escaped_name, escaped_value
        );
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    fn write_backup(
        operation: &str,
        root_name: &str,
        view_name: &str,
        target: &Path,
        value: &str,
    ) -> Result<(), String> {
        let local = std::env::var_os("LOCALAPPDATA")
            .ok_or_else(|| "LOCALAPPDATA 不可用，无法创建 AppCompat 备份".to_owned())?;
        let dir = Path::new(&local).join("MiControl").join("Logs");
        std::fs::create_dir_all(&dir)
            .map_err(|error| format!("创建 AppCompat 备份目录失败：{error}"))?;
        let path = dir.join(format!("appcompat-{operation}-{view_name}.reg"));
        let bytes = render_backup(operation, root_name, view_name, target, value);
        std::fs::write(&path, bytes).map_err(|error| format!("写入 AppCompat 备份失败：{error}"))
    }

    struct FileBackupSink;

    impl BackupSink for FileBackupSink {
        fn save(
            &mut self,
            operation: &str,
            root: RegistryRoot,
            view: RegistryView,
            target: &Path,
            value: &str,
        ) -> Result<(), String> {
            write_backup(operation, root.name(), view.name(), target, value)
        }
    }

    struct FileLogSink;

    impl LogSink for FileLogSink {
        fn write(&mut self, line: &str) -> Result<(), String> {
            log_line(line)
        }
    }

    fn fail_with_log<L: LogSink>(logger: &mut L, message: String) -> String {
        match logger.write(&message) {
            Ok(()) => message,
            Err(log_error) => format!("{message}; log_write_failed={log_error}"),
        }
    }

    fn cleanup_with_backend<R, B, L>(
        target: &Path,
        operation: &str,
        backend: &mut R,
        backup: &mut B,
        logger: &mut L,
    ) -> Result<(), String>
    where
        R: RegistryBackend,
        B: BackupSink,
        L: LogSink,
    {
        if !target.is_absolute() {
            return Err("AppCompat cleanup 目标必须是绝对路径".to_owned());
        }
        let target_label = target_id(target);
        logger.write(&format!(
            "operation_id={operation} phase=compat_cleanup result=begin target_id={target_label} target=micontrol-windows-app.exe"
        ))?;
        let mut observations = Vec::new();
        for view in [RegistryView::View64, RegistryView::View32] {
            for root in [RegistryRoot::CurrentUser, RegistryRoot::LocalMachine] {
                let value = match backend.read(root, view, target) {
                    Ok(value) => value,
                    Err(error) => {
                        return Err(fail_with_log(
                            logger,
                            format!(
                                "operation_id={operation} phase=compat_cleanup result=failed root={} view={} target_id={target_label} error={error}",
                                root.name(),
                                view.name()
                            ),
                        ));
                    }
                };
                let Some(value) = value else { continue };
                if has_run_as_admin(&value) {
                    observations.push((root, view, value));
                }
            }
        }
        if let Some((root, view, _)) = observations.iter().find(|(root, _, _)| !root.writable()) {
            return Err(fail_with_log(
                logger,
                format!(
                    "operation_id={operation} phase=compat_cleanup result=failed root={} view={} reason=global_RUNASADMIN_present target_id={target_label}",
                    root.name(),
                    view.name()
                ),
            ));
        }
        for (root, view, value) in &observations {
            if let Err(error) = backup.save(operation, *root, *view, target, value) {
                return Err(fail_with_log(
                    logger,
                    format!(
                        "operation_id={operation} phase=compat_cleanup result=failed root={} view={} target_id={target_label} error={error}",
                        root.name(),
                        view.name()
                    ),
                ));
            }
        }
        for (root, view, value) in observations {
            if !root.writable() {
                return Err("internal AppCompat backend root boundary violation".to_owned());
            }
            let replacement = remove_run_as_admin_token(&value)
                .expect("RUNASADMIN was present in the value being repaired");
            let replacement = (!replacement.trim().is_empty()).then_some(replacement.as_str());
            if let Err(error) = backend.write(root, view, target, replacement) {
                return Err(fail_with_log(
                    logger,
                    format!(
                        "operation_id={operation} phase=compat_cleanup result=failed root={} view={} target_id={target_label} error={error}",
                        root.name(),
                        view.name()
                    ),
                ));
            }
            logger.write(&format!(
                "operation_id={operation} phase=compat_cleanup result=updated root={} view={} target_id={target_label} backup=created",
                root.name(),
                view.name()
            ))?;
        }
        logger.write(&format!(
            "operation_id={operation} phase=compat_cleanup result=ok target_id={target_label}"
        ))
    }

    pub fn cleanup_run_as_admin(target: &Path) -> Result<(), String> {
        let operation = operation_id("compat");
        let mut backend = WindowsRegistryBackend;
        let mut backup = FileBackupSink;
        let mut logger = FileLogSink;
        cleanup_with_backend(target, &operation, &mut backend, &mut backup, &mut logger)
    }

    fn quote_arg(value: &str) -> String {
        let mut result = String::from("\"");
        let mut backslashes = 0usize;
        for ch in value.chars() {
            if ch == '\\' {
                backslashes += 1;
            } else if ch == '"' {
                result.push_str(&"\\".repeat(backslashes * 2 + 1));
                result.push(ch);
                backslashes = 0;
            } else {
                result.push_str(&"\\".repeat(backslashes));
                result.push(ch);
                backslashes = 0;
            }
        }
        result.push_str(&"\\".repeat(backslashes * 2));
        result.push('"');
        result
    }

    pub fn launch_setup_request(target: &Path) -> SetupLaunchResult {
        let operation = operation_id("setup");
        let label = target_id(target);
        let timeout_ms = LAUNCH_TIMEOUT.as_millis() as u32;
        let _ = log_line(&format!(
            "operation_id={operation} phase=setup_launch result=begin target_id={label} target=micontrol-windows-app.exe timeout_ms={timeout_ms}"
        ));
        let Some(target_text) = target.to_str() else {
            let _ = log_line(&format!(
                "operation_id={operation} phase=setup_launch result=failed kind=launcherror reason=non_utf8 target_id={label}"
            ));
            return SetupLaunchResult::LaunchError {
                code: 87,
                message: "目标路径不是有效 Unicode".to_owned(),
            };
        };
        let executable = wide(target_text);
        let mut command = wide(&format!(
            "{} {} {} {}",
            quote_arg(target_text),
            SETUP_REQUEST,
            OPERATION_ID_ARG,
            operation
        ));
        let startup = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESHOWWINDOW,
            wShowWindow: SW_HIDE.0 as u16,
            ..Default::default()
        };
        let mut info = PROCESS_INFORMATION::default();
        let created = unsafe {
            CreateProcessW(
                PCWSTR(executable.as_ptr()),
                Some(PWSTR(command.as_mut_ptr())),
                None,
                None,
                false,
                CREATE_NO_WINDOW,
                None,
                PCWSTR::null(),
                &startup,
                &mut info,
            )
        };
        if created.is_err() {
            let code = unsafe { GetLastError().0 };
            let message = win32_detail(code);
            let _ = log_line(&format!(
                "operation_id={operation} phase=setup_launch result=failed kind=launcherror target_id={label} {message}"
            ));
            return SetupLaunchResult::LaunchError { code, message };
        }
        let process = info.hProcess;
        unsafe {
            let _ = CloseHandle(info.hThread);
        }
        let wait =
            unsafe { windows::Win32::System::Threading::WaitForSingleObject(process, timeout_ms) };
        let wait_classification = classify_wait_status(wait.0);
        if wait_classification == WaitClassification::TimedOut {
            unsafe {
                let _ = CloseHandle(process);
            }
            let _ = log_line(&format!(
                "operation_id={operation} phase=setup_launch result=failed kind=timeout target_id={label} timeout_ms={timeout_ms} child_running=unknown termination=not_attempted rollback=not_claimed"
            ));
            return SetupLaunchResult::TimedOut { timeout_ms };
        }
        if let WaitClassification::Failed(_) = wait_classification {
            let code = unsafe { GetLastError().0 };
            let message = win32_detail(code);
            unsafe {
                let _ = CloseHandle(process);
            }
            let _ = log_line(&format!(
                "operation_id={operation} phase=setup_launch result=failed kind=waiterror target_id={label} {message}"
            ));
            return SetupLaunchResult::WaitError { code, message };
        }
        if let WaitClassification::Unexpected(code) = wait_classification {
            let message = format!("unexpected_wait_status={code}");
            unsafe {
                let _ = CloseHandle(process);
            }
            let _ = log_line(&format!(
                "operation_id={operation} phase=setup_launch result=failed kind=waiterror target_id={label} {message}"
            ));
            return SetupLaunchResult::WaitError { code, message };
        }
        let mut exit = 1u32;
        let exit_result = unsafe { GetExitCodeProcess(process, &mut exit) };
        let exit_error = if exit_result.is_err() {
            Some(unsafe { GetLastError().0 })
        } else {
            None
        };
        unsafe {
            let _ = CloseHandle(process);
        }
        if let Err(error) = exit_result {
            let code = exit_error.unwrap_or(1);
            let message = format!("{} api_error={error}", win32_detail(code));
            let _ = log_line(&format!(
                "operation_id={operation} phase=setup_launch result=failed kind=waiterror target_id={label} {message}"
            ));
            return SetupLaunchResult::WaitError { code, message };
        }
        let _ = log_line(&format!(
            "operation_id={operation} phase=setup_launch result=child_exit target_id={label} child_exit_code={exit}"
        ));
        SetupLaunchResult::Completed(exit)
    }

    pub fn result_exit_code(result: &SetupLaunchResult) -> i32 {
        match result {
            SetupLaunchResult::Completed(code) => *code as i32,
            SetupLaunchResult::LaunchError { .. } => LAUNCH_ERROR_EXIT,
            SetupLaunchResult::WaitError { .. } => WAIT_ERROR_EXIT,
            SetupLaunchResult::TimedOut { .. } => TIMEOUT_EXIT,
        }
    }

    #[cfg(test)]
    mod backend_tests {
        use super::*;
        use std::collections::HashMap;
        use std::time::{SystemTime, UNIX_EPOCH};

        struct MemoryRegistry {
            values: HashMap<(RegistryRoot, RegistryView, String), String>,
            read_failure: Option<String>,
            write_failure: Option<String>,
        }

        impl MemoryRegistry {
            fn new() -> Self {
                Self {
                    values: HashMap::new(),
                    read_failure: None,
                    write_failure: None,
                }
            }

            fn key(
                root: RegistryRoot,
                view: RegistryView,
                target: &Path,
            ) -> (RegistryRoot, RegistryView, String) {
                (root, view, target.to_string_lossy().into_owned())
            }

            fn seed(&mut self, root: RegistryRoot, view: RegistryView, target: &Path, value: &str) {
                self.values
                    .insert(Self::key(root, view, target), value.to_owned());
            }

            fn value(&self, root: RegistryRoot, view: RegistryView, target: &Path) -> Option<&str> {
                self.values
                    .get(&Self::key(root, view, target))
                    .map(String::as_str)
            }
        }

        impl RegistryBackend for MemoryRegistry {
            fn read(
                &mut self,
                _root: RegistryRoot,
                _view: RegistryView,
                _value_name: &Path,
            ) -> Result<Option<String>, String> {
                if let Some(error) = &self.read_failure {
                    return Err(error.clone());
                }
                Ok(self
                    .values
                    .get(&Self::key(_root, _view, _value_name))
                    .cloned())
            }

            fn write(
                &mut self,
                root: RegistryRoot,
                view: RegistryView,
                value_name: &Path,
                value: Option<&str>,
            ) -> Result<(), String> {
                if let Some(error) = &self.write_failure {
                    return Err(error.clone());
                }
                let key = Self::key(root, view, value_name);
                if let Some(value) = value {
                    self.values.insert(key, value.to_owned());
                } else {
                    self.values.remove(&key);
                }
                Ok(())
            }
        }

        struct VecBackup {
            saved: Vec<(RegistryRoot, RegistryView, String, String)>,
            failure: Option<String>,
        }

        impl VecBackup {
            fn new() -> Self {
                Self {
                    saved: Vec::new(),
                    failure: None,
                }
            }
        }

        impl BackupSink for VecBackup {
            fn save(
                &mut self,
                _operation: &str,
                root: RegistryRoot,
                view: RegistryView,
                target: &Path,
                value: &str,
            ) -> Result<(), String> {
                if let Some(error) = &self.failure {
                    return Err(error.clone());
                }
                self.saved.push((
                    root,
                    view,
                    target.to_string_lossy().into_owned(),
                    value.to_owned(),
                ));
                Ok(())
            }
        }

        struct VecLogger {
            lines: Vec<String>,
            failure: Option<String>,
        }

        impl VecLogger {
            fn new() -> Self {
                Self {
                    lines: Vec::new(),
                    failure: None,
                }
            }
        }

        impl LogSink for VecLogger {
            fn write(&mut self, line: &str) -> Result<(), String> {
                if let Some(error) = &self.failure {
                    return Err(error.clone());
                }
                self.lines.push(line.to_owned());
                Ok(())
            }
        }

        fn owned_target() -> std::path::PathBuf {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock before epoch")
                .as_nanos();
            std::env::temp_dir().join(format!(
                "micontrol-installer-compat-{}-{stamp}-micontrol-windows-app.exe",
                std::process::id()
            ))
        }

        fn run_cleanup(
            registry: &mut MemoryRegistry,
            backup: &mut VecBackup,
            logger: &mut VecLogger,
            target: &Path,
        ) -> Result<(), String> {
            cleanup_with_backend(target, "compat-test-0001", registry, backup, logger)
        }

        #[test]
        fn backup_failure_does_not_mutate_registry() {
            let target = owned_target();
            let original = r#"~ RUNASADMIN DISABLEDXMAXIMIZEDWINDOWEDMODE"#;
            let mut registry = MemoryRegistry::new();
            registry.seed(
                RegistryRoot::CurrentUser,
                RegistryView::View64,
                &target,
                original,
            );
            let mut backup = VecBackup::new();
            backup.failure = Some("fixture backup access denied".to_owned());
            let mut logger = VecLogger::new();

            let result = run_cleanup(&mut registry, &mut backup, &mut logger, &target);

            assert!(result.is_err());
            assert_eq!(
                registry.value(RegistryRoot::CurrentUser, RegistryView::View64, &target),
                Some(original)
            );
            assert!(logger
                .lines
                .iter()
                .any(|line| line.contains("result=failed")));
        }

        #[test]
        fn read_failure_is_logged_without_false_success() {
            let target = owned_target();
            let mut registry = MemoryRegistry::new();
            registry.seed(
                RegistryRoot::CurrentUser,
                RegistryView::View64,
                &target,
                "~ RUNASADMIN",
            );
            registry.read_failure = Some("fixture read access denied".to_owned());
            let mut backup = VecBackup::new();
            let mut logger = VecLogger::new();

            let result = run_cleanup(&mut registry, &mut backup, &mut logger, &target);

            assert!(result.unwrap_err().contains("fixture read access denied"));
            assert!(backup.saved.is_empty());
            assert_eq!(
                registry.value(RegistryRoot::CurrentUser, RegistryView::View64, &target),
                Some("~ RUNASADMIN")
            );
            assert!(!logger.lines.iter().any(|line| line.contains("result=ok")));
        }

        #[test]
        fn write_failure_is_logged_without_false_success() {
            let target = owned_target();
            let original = "~ RUNASADMIN";
            let mut registry = MemoryRegistry::new();
            registry.seed(
                RegistryRoot::CurrentUser,
                RegistryView::View64,
                &target,
                original,
            );
            registry.write_failure = Some("fixture write access denied".to_owned());
            let mut backup = VecBackup::new();
            let mut logger = VecLogger::new();

            let result = run_cleanup(&mut registry, &mut backup, &mut logger, &target);

            assert!(result.unwrap_err().contains("fixture write access denied"));
            assert_eq!(backup.saved.len(), 1);
            assert_eq!(
                registry.value(RegistryRoot::CurrentUser, RegistryView::View64, &target),
                Some(original)
            );
            assert!(!logger.lines.iter().any(|line| line.contains("result=ok")));
        }

        #[test]
        fn hklm_runasadmin_fails_closed_without_hkcu_mutation() {
            let target = owned_target();
            let user_value = "~ RUNASADMIN DISABLETHEMES";
            let machine_value = "RUNASADMIN";
            let mut registry = MemoryRegistry::new();
            registry.seed(
                RegistryRoot::CurrentUser,
                RegistryView::View64,
                &target,
                user_value,
            );
            registry.seed(
                RegistryRoot::LocalMachine,
                RegistryView::View32,
                &target,
                machine_value,
            );
            let mut backup = VecBackup::new();
            let mut logger = VecLogger::new();

            let result = run_cleanup(&mut registry, &mut backup, &mut logger, &target);

            assert!(result.unwrap_err().contains("global_RUNASADMIN_present"));
            assert!(backup.saved.is_empty());
            assert_eq!(
                registry.value(RegistryRoot::CurrentUser, RegistryView::View64, &target),
                Some(user_value)
            );
            assert_eq!(
                registry.value(RegistryRoot::LocalMachine, RegistryView::View32, &target),
                Some(machine_value)
            );
        }

        #[test]
        fn backup_roundtrip_preserves_flags_and_utf16le_contract() {
            let target = owned_target();
            let original = r#"~  RUNASADMIN  DISABLEDXMAXIMIZEDWINDOWEDMODE"#;
            let mut registry = MemoryRegistry::new();
            registry.seed(
                RegistryRoot::CurrentUser,
                RegistryView::View64,
                &target,
                original,
            );
            let mut backup = VecBackup::new();
            let mut logger = VecLogger::new();

            run_cleanup(&mut registry, &mut backup, &mut logger, &target)
                .expect("cleanup fixture succeeds");

            assert_eq!(
                registry.value(RegistryRoot::CurrentUser, RegistryView::View64, &target),
                Some("~ DISABLEDXMAXIMIZEDWINDOWEDMODE")
            );
            assert_eq!(backup.saved.len(), 1);
            assert_eq!(backup.saved[0].0, RegistryRoot::CurrentUser);
            assert_eq!(backup.saved[0].1, RegistryView::View64);
            assert_eq!(backup.saved[0].3, original);
            assert!(logger.lines.iter().any(|line| line.contains("result=ok")));

            let bytes = render_backup(
                "compat-test-0001",
                "HKEY_CURRENT_USER",
                "64",
                &target,
                original,
            );
            assert_eq!(&bytes[..2], &[0xFF, 0xFE]);
            let units = bytes[2..]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            let text = String::from_utf16(&units).expect("backup is valid UTF-16LE");
            assert!(text.contains("\\\\"));
            assert!(text.contains("RUNASADMIN"));
        }

        #[test]
        fn absent_target_is_noop_and_registry_views_are_independent() {
            let target = owned_target();
            let mut registry = MemoryRegistry::new();
            let mut backup = VecBackup::new();
            let mut logger = VecLogger::new();
            run_cleanup(&mut registry, &mut backup, &mut logger, &target)
                .expect("absent target is safe");
            assert!(backup.saved.is_empty());

            registry.seed(
                RegistryRoot::CurrentUser,
                RegistryView::View32,
                &target,
                "RUNASADMIN DISABLEMOUSEINPUT",
            );
            run_cleanup(&mut registry, &mut backup, &mut logger, &target)
                .expect("32 bit view cleanup succeeds");
            assert_eq!(
                registry.value(RegistryRoot::CurrentUser, RegistryView::View64, &target),
                None
            );
            assert_eq!(
                registry.value(RegistryRoot::CurrentUser, RegistryView::View32, &target),
                Some("DISABLEMOUSEINPUT")
            );
        }

        #[test]
        fn launch_and_wait_error_classifications_are_distinct() {
            assert_eq!(
                classify_wait_status(WAIT_OBJECT_0.0),
                WaitClassification::Completed
            );
            assert_eq!(
                classify_wait_status(WAIT_TIMEOUT.0),
                WaitClassification::TimedOut
            );
            assert_eq!(
                classify_wait_status(WAIT_FAILED.0),
                WaitClassification::Failed(WAIT_FAILED.0)
            );
            assert_eq!(
                classify_wait_status(0xDEAD),
                WaitClassification::Unexpected(0xDEAD)
            );
            assert_eq!(classify_runas_error(1223), "uac_cancel");
            assert_eq!(classify_runas_error(3), "launcherror");
            assert!(win32_detail(3).contains("win32_code=3"));
            assert_ne!(
                result_exit_code(&SetupLaunchResult::Completed(1)),
                result_exit_code(&SetupLaunchResult::LaunchError {
                    code: 740,
                    message: "fixture".to_owned()
                })
            );
        }
    }
}

#[cfg(windows)]
pub(crate) use windows_impl::classify_runas_error;
#[cfg(windows)]
pub use windows_impl::{
    cleanup_run_as_admin, launch_setup_request, remove_run_as_admin_token, result_exit_code,
};

#[cfg(not(windows))]
pub fn cleanup_run_as_admin(_target: &Path) -> Result<(), String> {
    Err("installer compatibility helper requires Windows".to_owned())
}

#[cfg(not(windows))]
pub fn launch_setup_request(_target: &Path) -> SetupLaunchResult {
    SetupLaunchResult::LaunchError {
        code: 50,
        message: "installer compatibility helper requires Windows".to_owned(),
    }
}

#[cfg(not(windows))]
pub fn result_exit_code(result: &SetupLaunchResult) -> i32 {
    match result {
        SetupLaunchResult::Completed(code) => *code as i32,
        _ => 1,
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::windows_impl::{escape_reg_string, remove_run_as_admin_token};

    #[test]
    fn removes_single_runasadmin_token_case_and_whitespace_insensitively() {
        assert_eq!(
            remove_run_as_admin_token("~   RUNASADMIN"),
            Some("~".to_owned())
        );
        assert_eq!(
            remove_run_as_admin_token("~ disableredirection runasadmin"),
            Some("~ disableredirection".to_owned())
        );
        assert_eq!(remove_run_as_admin_token("RUNASADMIN"), Some(String::new()));
        assert_eq!(
            remove_run_as_admin_token("~ DISABLEDXMAXIMIZEDWINDOWEDMODE"),
            None
        );
    }

    #[test]
    fn reg_backup_escapes_name_and_value_and_uses_utf16le_contract() {
        assert_eq!(
            escape_reg_string(r#"D:\MiControl\main\"quoted"#),
            r#"D:\\MiControl\\main\\\"quoted"#
        );
    }
}
