//! RC003 旁路服务的生命周期监督。
//!
//! 服务本身和桌面程序使用同一个安装包中的可执行文件，但服务由 SCM 以
//! LocalSystem 身份运行。桌面程序不能在普通权限下强行启动它；因此这里把
//! “服务停止”“服务运行但 broker 未就绪”和“服务已就绪”区分开，并只在用户
//! 明确点击修复时请求一次 UAC。

use serde::Serialize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const SERVICE_NAME: &str = "MiControlRC003HidTap";
const START_TIMEOUT: Duration = Duration::from_secs(20);
const BROKER_CONNECT_TIMEOUT: Duration = Duration::from_millis(350);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HidTapStatus {
    pub installed: bool,
    pub state: String,
    pub service_name: String,
    pub binary_path: Option<String>,
    pub broker_path: Option<String>,
    pub broker_port: Option<u16>,
    pub broker_ready: bool,
    pub last_error: Option<String>,
    pub observed_at_unix_ms: u128,
}

impl Default for HidTapStatus {
    fn default() -> Self {
        Self {
            installed: false,
            state: "unknown".to_owned(),
            service_name: SERVICE_NAME.to_owned(),
            binary_path: None,
            broker_path: None,
            broker_port: None,
            broker_ready: false,
            last_error: Some("尚未读取旁路服务状态".to_owned()),
            observed_at_unix_ms: 0,
        }
    }
}

#[derive(Clone)]
pub struct HidTapSupervisor {
    status: Arc<Mutex<HidTapStatus>>,
    operation: Arc<Mutex<()>>,
}

impl std::fmt::Debug for HidTapSupervisor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HidTapSupervisor")
            .field(
                "status",
                &self.status.lock().map(|status| status.clone()).ok(),
            )
            .finish()
    }
}

impl HidTapSupervisor {
    pub fn new() -> Self {
        let supervisor = Self {
            status: Arc::new(Mutex::new(HidTapStatus::default())),
            operation: Arc::new(Mutex::new(())),
        };
        supervisor.refresh();

        let background = supervisor.clone();
        std::thread::Builder::new()
            .name("micontrol-hid-tap-supervisor".to_owned())
            .spawn(move || {
                let mut previous: Option<(String, bool, Option<String>)> = None;
                loop {
                    let current = background.refresh();
                    let key = (
                        current.state.clone(),
                        current.broker_ready,
                        current.last_error.clone(),
                    );
                    if previous.as_ref() != Some(&key) {
                        crate::log_hid_tap_status(&current, "poll");
                        previous = Some(key);
                    }
                    std::thread::sleep(Duration::from_secs(5));
                }
            })
            .ok();
        supervisor
    }

    pub fn status(&self) -> HidTapStatus {
        self.status
            .lock()
            .map(|status| status.clone())
            .unwrap_or_else(|_| HidTapStatus {
                last_error: Some("读取旁路服务状态锁失败".to_owned()),
                ..HidTapStatus::default()
            })
    }

    pub fn refresh(&self) -> HidTapStatus {
        let status = query_status();
        if let Ok(mut current) = self.status.lock() {
            *current = status.clone();
        }
        status
    }

    /// 普通 owner 日常恢复：使用安装时授予的 SERVICE_START 权限启动 SCM
    /// 服务，并等待 SCM 与 broker 两层都就绪。此路径不请求 UAC。
    pub fn ensure_ready(&self) -> Result<HidTapStatus, String> {
        let _operation = self
            .operation
            .lock()
            .map_err(|_| "启动旁路服务操作锁失败".to_owned())?;
        self.ensure_ready_locked()
    }

    fn ensure_ready_locked(&self) -> Result<HidTapStatus, String> {
        let before = self.refresh();
        if !before.installed {
            return Err("未安装 RC003 旁路服务，请重新运行安装程序完成服务安装".to_owned());
        }
        if before.state == "running" && before.broker_ready {
            return Ok(before);
        }

        let start_requested_at = if before.state == "stopped" {
            crate::log_hid_tap_status(&before, "auto_start_requested");
            if let Err(error) = start_service_as_owner() {
                // A concurrent actor may have started it between query and
                // start. Only suppress the error when SCM confirms RUNNING.
                let current = self.refresh();
                if current.state != "running" {
                    crate::log_hid_tap_status(&current, "auto_start_denied");
                    return Err(error);
                }
            }
            Some(Instant::now())
        } else {
            None
        };
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            let current = self.refresh();
            if current.state == "running" && current.broker_ready {
                crate::log_hid_tap_status(&current, "auto_start_ready");
                return Ok(current);
            }
            // A service that returns to STOPPED shortly after the start request
            // has a concrete SCM/runtime failure; report it without consuming
            // the full health timeout and let the caller apply backoff.
            if start_requested_at.is_some_and(|started| {
                started.elapsed() >= Duration::from_secs(1) && current.state == "stopped"
            }) {
                let reason = current
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "服务启动后立即停止".to_owned());
                return Err(format!("旁路服务未保持运行：{reason}"));
            }
            if Instant::now() >= deadline {
                let reason = current
                    .last_error
                    .clone()
                    .unwrap_or_else(|| format!("SCM 状态为 {}，broker 尚未就绪", current.state));
                crate::log_hid_tap_status(&current, "auto_start_timeout");
                return Err(format!("旁路服务启动后未就绪：{reason}"));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// 请求管理员启动服务，并等待 SCM 与 broker 两层都就绪。
    /// 普通权限下的自动路径使用 `ensure_ready`；该入口保留给明确的
    /// “修复旁路服务”操作，在权限拒绝时提供一次 UAC 授权机会。
    pub fn repair(&self) -> Result<HidTapStatus, String> {
        let _operation = self
            .operation
            .lock()
            .map_err(|_| "修复旁路服务操作锁失败".to_owned())?;
        self.repair_locked()
    }

    fn repair_locked(&self) -> Result<HidTapStatus, String> {
        let before = self.refresh();
        if !before.installed {
            return Err("未安装 RC003 旁路服务，请重新运行安装程序完成服务安装".to_owned());
        }
        if before.state == "running" && before.broker_ready {
            return Ok(before);
        }

        if before.state == "running" {
            crate::log_hid_tap_status(&before, "repair_restart_requested");
            launch_elevated_service_command("stop")?;
            wait_for_service_state("stopped", Duration::from_secs(15))?;
        }
        launch_elevated_service_command("start")?;
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            let current = self.refresh();
            if current.state == "running" && current.broker_ready {
                crate::log_hid_tap_status(&current, "repair");
                return Ok(current);
            }
            if Instant::now() >= deadline {
                let reason = current
                    .last_error
                    .clone()
                    .unwrap_or_else(|| format!("SCM 状态为 {}，broker 尚未就绪", current.state));
                crate::log_hid_tap_status(&current, "repair_timeout");
                return Err(format!("旁路服务启动后未就绪：{reason}"));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

#[cfg(windows)]
fn start_service_as_owner() -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    let sc_path = system_sc_path()?;
    let output = Command::new(&sc_path)
        .args(["start", SERVICE_NAME])
        .creation_flags(0x08000000)
        .output()
        .map_err(|error| format!("无法执行 {} 启动旁路服务：{error}", sc_path.display()))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = first_non_empty_line(&stderr)
        .or_else(|| first_non_empty_line(&stdout))
        .unwrap_or("sc.exe start 失败");
    let lower = detail.to_ascii_lowercase();
    if lower.contains("access is denied")
        || lower.contains("拒绝访问")
        || lower.contains("error 5")
        || lower.contains(" 5:")
    {
        return Err(
            "当前用户没有 SERVICE_START 权限，旁路服务未启动；请点击“修复旁路服务”并完成管理员授权"
                .to_owned(),
        );
    }
    Err(format!("普通权限启动旁路服务失败：{detail}"))
}

#[cfg(not(windows))]
fn start_service_as_owner() -> Result<(), String> {
    Err("旁路服务仅支持 Windows".to_owned())
}

#[cfg(windows)]
fn query_status() -> HidTapStatus {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    let sc_path = match system_sc_path() {
        Ok(path) => path,
        Err(error) => return query_failed_status(error),
    };
    let query = Command::new(&sc_path)
        .args(["query", SERVICE_NAME])
        .creation_flags(0x08000000)
        .output();
    let output = match query {
        Ok(output) => output,
        Err(error) => {
            return query_failed_status(format!(
                "无法执行 {} 查询旁路服务：{error}",
                sc_path.display()
            ));
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        let detail = first_non_empty_line(&stderr)
            .or_else(|| first_non_empty_line(&stdout))
            .unwrap_or("sc.exe 未返回错误详情");
        let exit_code = output.status.code();
        if is_service_missing_exit_code(exit_code) {
            return error_status(format!("旁路服务未注册（sc.exe exit_code=1060）：{detail}"));
        }
        return query_failed_status(format!(
            "旁路服务状态查询失败（安装状态未知；sc.exe exit_code={:?}）：{detail}",
            exit_code
        ));
    }

    let state = parse_sc_state(&stdout).unwrap_or_else(|| "unknown".to_owned());
    let scm_error = parse_sc_error(&stdout);
    // The service DACL intentionally withholds SERVICE_QUERY_CONFIG from the
    // desktop owner. The installation path is fixed, so derive it locally
    // instead of falling back to `sc qc` (which would make broker health look
    // unavailable under the intended least-privilege ACL).
    let binary_path = installed_binary_path();
    let broker_path = binary_path
        .as_deref()
        .and_then(|path| PathBuf::from(path).parent().map(PathBuf::from))
        .map(|directory| directory.join("broker.json"));
    let (broker, broker_error) = broker_path
        .as_deref()
        .map(read_broker)
        .unwrap_or((None, Some("未找到服务目录或 broker.json".to_owned())));
    let broker_port = broker.as_ref().map(|broker| broker.port);
    let broker_ready = state == "running" && broker.as_ref().is_some_and(probe_broker);
    let last_error = if broker_ready {
        None
    } else if state != "running" {
        Some(match scm_error {
            Some(error) => format!("SCM 当前状态：{state}；{error}"),
            None => format!("SCM 当前状态：{state}"),
        })
    } else {
        broker_error.or_else(|| Some("服务已运行，但 broker 鉴权握手未就绪".to_owned()))
    };
    HidTapStatus {
        installed: true,
        state,
        service_name: SERVICE_NAME.to_owned(),
        binary_path,
        broker_path: broker_path.map(|path| path.display().to_string()),
        broker_port,
        broker_ready,
        last_error,
        observed_at_unix_ms: unix_ms(),
    }
}

#[cfg(not(windows))]
fn query_status() -> HidTapStatus {
    error_status("旁路服务仅支持 Windows")
}

#[cfg(windows)]
fn installed_binary_path() -> Option<String> {
    let root = PathBuf::from(std::env::var_os("ProgramFiles")?).join("MiControlRC003HidService");
    Some(root.join("MiControlHidService.exe").display().to_string())
}

/// Resolve the Windows service-control client from the operating system's
/// protected System32 directory. Service lifecycle operations must not use
/// PATH lookup or an environment variable: a per-user `sc.exe` would make
/// both ordinary status polling and the elevated repair path target an
/// attacker-controlled executable.
#[cfg(windows)]
fn system_sc_path() -> Result<PathBuf, String> {
    let system_directory = windows_system_directory()?;
    system32_program_path(system_directory.as_os_str(), "sc.exe")
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
}

/// Read the actual Windows system directory from the OS rather than trusting
/// `WINDIR`/`SystemRoot` inherited from the process environment. The API's
/// length result is handled as a resize hint, and its last-error value is
/// retained when the call fails.
#[cfg(windows)]
fn windows_system_directory() -> Result<PathBuf, String> {
    let mut capacity = 260usize;
    for _ in 0..4 {
        let mut buffer = vec![0u16; capacity];
        let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), capacity as u32) };
        if length == 0 {
            return Err(format!(
                "GetSystemDirectoryW failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let length = length as usize;
        if length < capacity {
            buffer.truncate(length);
            let directory = String::from_utf16(&buffer)
                .map_err(|_| "GetSystemDirectoryW returned invalid UTF-16".to_owned())?;
            return Ok(PathBuf::from(directory));
        }
        capacity = length
            .checked_add(1)
            .ok_or_else(|| "GetSystemDirectoryW returned an invalid length".to_owned())?;
    }
    Err("GetSystemDirectoryW path length did not converge".to_owned())
}

/// Pure path construction kept separate from the process launch so its safety
/// rules can be tested without touching SCM or invoking an executable.
fn system32_program_path(
    system_directory: &std::ffi::OsStr,
    program: &str,
) -> Result<PathBuf, String> {
    let system_directory = PathBuf::from(system_directory);
    if !system_directory.is_absolute()
        || system_directory
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err("system directory is not a safe absolute path".to_owned());
    }
    if !system_directory
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("System32"))
    {
        return Err("system directory is not Windows System32".to_owned());
    }
    let program_path = PathBuf::from(program);
    if program.is_empty()
        || program_path.components().count() != 1
        || !program_path
            .file_name()
            .is_some_and(|name| name == std::ffi::OsStr::new(program))
    {
        return Err("system program name is not a simple file name".to_owned());
    }
    Ok(system_directory.join(program_path))
}

fn is_service_missing_exit_code(exit_code: Option<i32>) -> bool {
    exit_code == Some(1060)
}

#[cfg(windows)]
fn launch_elevated_service_command(action: &str) -> Result<(), String> {
    use std::mem::size_of;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let sc_path = system_sc_path()?;
    let file = wide_string(&sc_path.display().to_string());
    let parameters = wide_string(&format!("{action} {SERVICE_NAME}"));
    let verb = wide_string("runas");
    let mut execute = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    unsafe { ShellExecuteExW(&mut execute) }
        .map_err(|error| format!("管理员授权未完成，服务 {action} 未执行：{error}"))?;
    if execute.hProcess.is_invalid() {
        return Err(format!("未取得服务 {action} 进程句柄"));
    }
    let wait = unsafe { WaitForSingleObject(execute.hProcess, 20_000) };
    if wait != WAIT_OBJECT_0 {
        let _ = unsafe { CloseHandle(execute.hProcess) };
        return Err(format!("服务 {action} 超时"));
    }
    let mut exit_code = u32::MAX;
    let result = unsafe { GetExitCodeProcess(execute.hProcess, &mut exit_code) };
    let _ = unsafe { CloseHandle(execute.hProcess) };
    result.map_err(|error| format!("无法读取服务 {action} 结果：{error}"))?;
    if exit_code != 0 {
        return Err(format!("服务 {action} 失败，sc.exe exit code={exit_code}"));
    }
    Ok(())
}

#[cfg(not(windows))]
fn launch_elevated_service_command(_action: &str) -> Result<(), String> {
    Err("旁路服务仅支持 Windows".to_owned())
}

#[cfg(windows)]
fn wait_for_service_state(expected: &str, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let current = query_status();
        if current.state == expected {
            return Ok(());
        }
        if current.state == "not_installed" {
            return Err(current
                .last_error
                .unwrap_or_else(|| "旁路服务注册已消失".to_owned()));
        }
        if Instant::now() >= deadline {
            return Err(format!("等待服务进入 {expected} 超时：{}", current.state));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

#[cfg(not(windows))]
fn wait_for_service_state(_expected: &str, _timeout: Duration) -> Result<(), String> {
    Err("旁路服务仅支持 Windows".to_owned())
}

fn wide_string(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn parse_sc_state(text: &str) -> Option<String> {
    let line = text.lines().find(|line| line.contains("STATE"))?;
    let value = line.split_once(':')?.1.trim();
    let token = value.split_whitespace().next()?;
    Some(
        match token {
            "1" => "stopped",
            "2" => "start_pending",
            "3" => "stop_pending",
            "4" => "running",
            "5" => "continue_pending",
            "6" => "pause_pending",
            "7" => "paused",
            _ => "unknown",
        }
        .to_owned(),
    )
}

fn parse_sc_error(text: &str) -> Option<String> {
    for key in ["WIN32_EXIT_CODE", "SERVICE_EXIT_CODE"] {
        let Some(line) = text.lines().find(|line| line.contains(key)) else {
            continue;
        };
        let Some(value) = line.split_once(':').map(|(_, value)| value.trim()) else {
            continue;
        };
        let Some(code) = value.split_whitespace().next() else {
            continue;
        };
        if code != "0" {
            return Some(format!("{key}={code}"));
        }
    }
    None
}

#[cfg(windows)]
struct BrokerMetadata {
    port: u16,
    secret: String,
    protocol: u32,
}

fn read_broker(path: &std::path::Path) -> (Option<BrokerMetadata>, Option<String>) {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) => return (None, Some(format!("读取 broker.json 失败：{error}"))),
    };
    let json: serde_json::Value = match serde_json::from_str(&contents) {
        Ok(json) => json,
        Err(error) => return (None, Some(format!("broker.json 格式错误：{error}"))),
    };
    let port = json
        .get("port")
        .and_then(serde_json::Value::as_u64)
        .and_then(|port| u16::try_from(port).ok());
    let secret = json
        .get("secret")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let protocol = json
        .get("protocol")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());
    match (port, secret, protocol) {
        (Some(port), Some(secret), Some(protocol)) if port != 0 && secret.len() == 64 => (
            Some(BrokerMetadata {
                port,
                secret,
                protocol,
            }),
            None,
        ),
        _ => (
            None,
            Some("broker.json 缺少有效端口、密钥或协议版本".to_owned()),
        ),
    }
}

#[cfg(windows)]
fn probe_broker(broker: &BrokerMetadata) -> bool {
    use std::io::{BufRead, BufReader, Write};
    if broker.protocol != 4 {
        return false;
    }
    let Ok(mut stream) = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], broker.port)),
        BROKER_CONNECT_TIMEOUT,
    ) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(BROKER_CONNECT_TIMEOUT));
    let _ = stream.set_write_timeout(Some(BROKER_CONNECT_TIMEOUT));
    let request = serde_json::json!({"kind":"health","secret":broker.secret});
    if writeln!(stream, "{request}").is_err() {
        return false;
    }
    let mut response = String::new();
    if BufReader::new(stream).read_line(&mut response).is_err() {
        return false;
    }
    serde_json::from_str::<serde_json::Value>(&response)
        .ok()
        .is_some_and(|value| value["ok"] == true && value["protocol"].as_u64() == Some(4))
}

#[cfg(not(windows))]
fn probe_broker(_broker: &BrokerMetadata) -> bool {
    false
}

fn first_non_empty_line(text: &str) -> Option<&str> {
    text.lines().map(str::trim).find(|line| !line.is_empty())
}

fn error_status(error: impl Into<String>) -> HidTapStatus {
    HidTapStatus {
        state: "not_installed".to_owned(),
        last_error: Some(error.into()),
        observed_at_unix_ms: unix_ms(),
        ..HidTapStatus::default()
    }
}

/// A failed SCM query does not prove that the service is absent.  Keep the
/// status in the existing `unknown` UI branch and mark installation as
/// present-for-recovery so the UI cannot offer a destructive reinstall based
/// on an access/launch/query failure.  The diagnostic is retained verbatim in
/// `last_error` for the user and install-stage logs.
fn query_failed_status(error: impl Into<String>) -> HidTapStatus {
    HidTapStatus {
        installed: true,
        state: "unknown".to_owned(),
        last_error: Some(error.into()),
        observed_at_unix_ms: unix_ms(),
        ..HidTapStatus::default()
    }
}

fn unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        is_service_missing_exit_code, parse_sc_error, parse_sc_state, query_failed_status,
        system32_program_path,
    };
    use std::ffi::OsStr;
    use std::path::PathBuf;

    #[test]
    fn parses_scm_states_without_localization_dependency() {
        assert_eq!(
            parse_sc_state("        STATE              : 4  RUNNING"),
            Some("running".to_owned())
        );
        assert_eq!(
            parse_sc_state("        STATE              : 1  STOPPED"),
            Some("stopped".to_owned())
        );
    }

    #[test]
    fn unknown_state_is_explicit() {
        assert_eq!(
            parse_sc_state("        STATE              : 99  UNKNOWN"),
            Some("unknown".to_owned())
        );
    }

    #[test]
    fn reports_nonzero_scm_exit_code() {
        assert_eq!(
            parse_sc_error(
                "        STATE              : 1  STOPPED\n        WIN32_EXIT_CODE    : 1067  (0x42b)\n        SERVICE_EXIT_CODE  : 0  (0x0)"
            ),
            Some("WIN32_EXIT_CODE=1067".to_owned())
        );
        assert_eq!(
            parse_sc_error(
                "        STATE              : 1  STOPPED\n        WIN32_EXIT_CODE    : 0  (0x0)\n        SERVICE_EXIT_CODE  : 5  (0x5)"
            ),
            Some("SERVICE_EXIT_CODE=5".to_owned())
        );
    }

    #[test]
    fn only_service_missing_exit_code_maps_to_not_installed() {
        assert!(is_service_missing_exit_code(Some(1060)));
        assert!(!is_service_missing_exit_code(Some(5)));
        assert!(!is_service_missing_exit_code(Some(1073)));
        assert!(!is_service_missing_exit_code(None));
    }

    #[test]
    fn failed_query_is_unknown_and_does_not_claim_missing_service() {
        let status = query_failed_status("sc.exe exit_code=5: access denied");
        assert!(status.installed);
        assert_eq!(status.state, "unknown");
        assert_eq!(
            status.last_error.as_deref(),
            Some("sc.exe exit_code=5: access denied")
        );
    }

    #[test]
    fn system32_path_is_absolute_and_does_not_accept_path_injection() {
        let path = system32_program_path(OsStr::new(r"C:\Windows\System32"), "sc.exe")
            .expect("the OS-reported System32 directory should produce a path");
        assert_eq!(path, PathBuf::from(r"C:\Windows\System32\sc.exe"));
        assert!(system32_program_path(OsStr::new(r"D:\userdir"), "sc.exe").is_err());
        assert!(system32_program_path(OsStr::new(r"C:\Windows\System32"), r"..\evil.exe").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn system_sc_path_comes_from_the_os_system_directory() {
        let path = super::system_sc_path().expect("Windows should provide System32");
        assert!(path.is_absolute());
        assert_eq!(path.file_name(), Some(OsStr::new("sc.exe")));
        assert!(path
            .parent()
            .and_then(std::path::Path::file_name)
            .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("System32")));
    }

    #[test]
    fn fixed_install_path_with_spaces_uses_full_parent_directory() {
        let binary = r"C:\Program Files\MiControlRC003HidService\MiControlHidService.exe";
        let broker = PathBuf::from(binary)
            .parent()
            .map(PathBuf::from)
            .map(|directory| directory.join("broker.json"));
        assert_eq!(
            broker,
            Some(PathBuf::from(
                r"C:\Program Files\MiControlRC003HidService\broker.json"
            ))
        );
    }
}
