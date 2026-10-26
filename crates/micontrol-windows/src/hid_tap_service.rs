//! One-time installed fixed-purpose RC003 broker. No client-selected executable,
//! DLL path or arbitrary PID: all assets are administrator-protected.
use super::*;
use serde::{Deserialize, Serialize};
use std::os::windows::ffi::OsStringExt;
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{
            GetLastError, ERROR_FILE_NOT_FOUND, ERROR_NOT_ALL_ASSIGNED, ERROR_NO_MORE_FILES,
            ERROR_PATH_NOT_FOUND, HANDLE, LUID, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Security::{
            AddAccessAllowedAceEx, AdjustTokenPrivileges, GetKernelObjectSecurity,
            GetSecurityDescriptorControl, InitializeAcl, LookupPrivilegeValueW, ACE_FLAGS, ACL,
            ACL_REVISION, DACL_SECURITY_INFORMATION, LUID_AND_ATTRIBUTES,
            OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            PSID, SE_BACKUP_NAME, SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME, TOKEN_ADJUST_PRIVILEGES,
            TOKEN_PRIVILEGES, TOKEN_QUERY, UNPROTECTED_DACL_SECURITY_INFORMATION,
        },
        Storage::FileSystem::{
            CreateFileW, FileAttributeTagInfo, FileIdBothDirectoryInfo,
            FileIdBothDirectoryRestartInfo, GetFileInformationByHandleEx, FILE_ALL_ACCESS,
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
            FILE_ID_BOTH_DIR_INFO, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
            FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, OPEN_EXISTING, READ_CONTROL,
            WRITE_DAC, WRITE_OWNER,
        },
        System::{
            Services::*,
            SystemServices::MAXIMUM_ALLOWED,
            Threading::{GetCurrentProcess, OpenProcessToken, TerminateProcess},
        },
    },
};

const NAME: &str = "MiControlRC003HidTap";
const SERVICE_DIRECTORY_NAME: &str = "MiControlRC003HidService";
const MODE: &str = "--micontrol-rc003-service";
const INSTALL: &str = "--micontrol-rc003-install-service";
const REMOVE: &str = "--micontrol-rc003-remove-service";
pub(super) const ACL_HELPER: &str = "--micontrol-rc003-service-acl";
const SETUP_REQUEST: &str = "--micontrol-rc003-setup-service-request";
const OPERATION_ID_ARG: &str = "--micontrol-operation-id";
const REMOVE_REQUEST: &str = "--micontrol-rc003-remove-service-request";
const ACL_STAGE_DEADLINE: Duration = Duration::from_secs(10);
const UNKNOWN_OPERATION_ID: &str = "unknown";
static STOP: AtomicBool = AtomicBool::new(false);
static MANUAL_SHUTDOWN: AtomicBool = AtomicBool::new(false);
static SERVICE_STATUS_RAW: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
static SERVICE_MAIN_EXITED: AtomicBool = AtomicBool::new(true);
static REQUEST_OPERATION_ID: Mutex<Option<String>> = Mutex::new(None);

const SERVICE_STARTUP_GRACE: Duration = Duration::from_secs(30);
const HEALTH_PROBE_INTERVAL: Duration = Duration::from_secs(2);
const HEALTH_FAILURE_THRESHOLD: u32 = 3;
const MAX_OPERATION_DEADLINE: Duration = Duration::from_secs(45);
const WATCHDOG_FINALIZE_GRACE: Duration = Duration::from_secs(5);

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerConfig {
    port: u16,
    secret: String,
    owner_sid: String,
    protocol: u32,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    secret: String,
    pid: u32,
    port: u16,
    token: String,
    #[serde(default = "default_request_deadline_ms")]
    deadline_ms: u32,
}

fn default_request_deadline_ms() -> u32 {
    MAX_OPERATION_DEADLINE.as_millis() as u32
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthRequest {
    kind: String,
    secret: String,
}
fn validate_health_request(req: &HealthRequest, cfg: &BrokerConfig) -> Result<(), String> {
    if req.kind != "health" || req.secret != cfg.secret {
        return Err("Invalid broker health request".into());
    }
    Ok(())
}

#[derive(Debug)]
struct WatchdogState {
    startup_deadline: Instant,
    next_probe: Instant,
    busy_deadline: Option<Instant>,
    probe_failures: u32,
    fault_latched: bool,
}

#[derive(Clone, Debug)]
struct Watchdog {
    state: Arc<Mutex<WatchdogState>>,
}

impl Watchdog {
    fn new(now: Instant) -> Self {
        Self {
            state: Arc::new(Mutex::new(WatchdogState {
                startup_deadline: now + SERVICE_STARTUP_GRACE,
                next_probe: now,
                busy_deadline: None,
                probe_failures: 0,
                fault_latched: false,
            })),
        }
    }

    fn begin_operation(&self, now: Instant, requested: Duration) -> Result<Instant, String> {
        let mut state = self.state.lock().expect("watchdog mutex poisoned");
        if state.fault_latched {
            return Err("旁路 watchdog fault 已锁存，等待服务恢复".into());
        }
        if state.busy_deadline.is_some() {
            return Err("旁路已有 inject operation 正在处理".into());
        }
        let deadline = now
            + requested
                .min(MAX_OPERATION_DEADLINE)
                .max(Duration::from_millis(1));
        state.busy_deadline = Some(deadline);
        Ok(deadline)
    }

    fn complete_operation(&self) {
        let mut state = self.state.lock().expect("watchdog mutex poisoned");
        state.busy_deadline = None;
        if !state.fault_latched {
            state.probe_failures = 0;
        }
    }

    fn fail_operation(&self, now: Instant, deadline: Instant, unrecoverable: bool) {
        let mut state = self.state.lock().expect("watchdog mutex poisoned");
        if now >= deadline || unrecoverable {
            state.fault_latched = true;
        }
        state.busy_deadline = None;
    }

    fn health_success(&self) {
        let mut state = self.state.lock().expect("watchdog mutex poisoned");
        // A health response cannot clear an active operation or a committed
        // fault.  It only resets idle probe jitter.
        if state.busy_deadline.is_none() && !state.fault_latched {
            state.probe_failures = 0;
        }
    }

    fn tick(&self, now: Instant, probe_ok: Option<bool>) -> bool {
        let mut state = self.state.lock().expect("watchdog mutex poisoned");
        if state.fault_latched {
            return true;
        }
        if let Some(deadline) = state.busy_deadline {
            if now >= deadline {
                state.fault_latched = true;
            }
            return state.fault_latched;
        }
        if state.fault_latched || now < state.startup_deadline || now < state.next_probe {
            return state.fault_latched;
        }
        state.next_probe = now + HEALTH_PROBE_INTERVAL;
        match probe_ok {
            Some(true) => state.probe_failures = 0,
            Some(false) => {
                state.probe_failures = state.probe_failures.saturating_add(1);
                if state.probe_failures >= HEALTH_FAILURE_THRESHOLD {
                    state.fault_latched = true;
                }
            }
            None => {}
        }
        state.fault_latched
    }

    fn fault_latched(&self) -> bool {
        self.state
            .lock()
            .expect("watchdog mutex poisoned")
            .fault_latched
    }

    fn manual_finalize_grace(&self, now: Instant) -> Duration {
        let state = self.state.lock().expect("watchdog mutex poisoned");
        state
            .busy_deadline
            .map(|deadline| deadline.saturating_duration_since(now))
            .unwrap_or_default()
            + WATCHDOG_FINALIZE_GRACE
    }

    fn final_exit_code(&self, operation_failed: bool) -> u32 {
        if MANUAL_SHUTDOWN.load(Ordering::Acquire) {
            0
        } else if operation_failed || self.fault_latched() {
            1
        } else {
            0
        }
    }
}
fn root() -> Result<PathBuf, String> {
    let program_files =
        PathBuf::from(std::env::var_os("ProgramFiles").ok_or("ProgramFiles unavailable")?);
    if !program_files.is_absolute()
        || program_files
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err("ProgramFiles is not a safe absolute path".into());
    }
    let parent_metadata = std::fs::symlink_metadata(&program_files)
        .map_err(|error| format!("读取 ProgramFiles 属性失败：{error}"))?;
    if is_reparse_point(&parent_metadata) {
        return Err("ProgramFiles is a reparse point".into());
    }
    let canonical_parent = std::fs::canonicalize(&program_files)
        .map_err(|error| format!("解析 ProgramFiles 路径失败：{error}"))?;
    let service_root = canonical_parent.join(SERVICE_DIRECTORY_NAME);
    match std::fs::symlink_metadata(&service_root) {
        Ok(metadata) => {
            if is_reparse_point(&metadata) {
                return Err("服务目录是 reparse point，拒绝继续".into());
            }
            if !metadata.is_dir() {
                return Err("服务路径不是目录".into());
            }
            let canonical_root = std::fs::canonicalize(&service_root)
                .map_err(|error| format!("解析服务目录失败：{error}"))?;
            if canonical_root != service_root {
                return Err("服务目录解析到了受管路径之外，拒绝继续".into());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("无法读取服务目录属性：{error}")),
    }
    Ok(service_root)
}

pub(super) fn service_runtime_dir() -> Result<PathBuf, String> {
    Ok(super::service_runtime_path(&root()?))
}

fn is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0
}

fn validate_managed_tree(root: &Path) -> Result<(), String> {
    if !root.exists() {
        return Ok(());
    }
    let metadata = std::fs::symlink_metadata(root)
        .map_err(|error| format!("读取服务目录属性失败：{error}"))?;
    if is_reparse_point(&metadata) {
        return Err("服务目录是 reparse point，拒绝递归修改".into());
    }
    if !metadata.is_dir() {
        return Err("服务路径不是目录".into());
    }
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in
            std::fs::read_dir(&directory).map_err(|error| format!("读取服务目录失败：{error}"))?
        {
            let path = entry
                .map_err(|error| format!("读取服务目录项失败：{error}"))?
                .path();
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|error| format!("读取服务目录项属性失败：{error}"))?;
            if is_reparse_point(&metadata) {
                return Err(format!(
                    "服务目录包含 reparse point，拒绝递归修改：{}",
                    path.display()
                ));
            }
            if metadata.is_dir() {
                pending.push(path);
            }
        }
    }
    Ok(())
}

fn enable_backup_privilege() -> Result<OwnedHandle, String> {
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .map_err(|error| format!("打开当前进程令牌失败：{error}"))?;
    }
    let token = OwnedHandle(token);
    let mut luid = LUID::default();
    unsafe {
        LookupPrivilegeValueW(None, SE_BACKUP_NAME, &mut luid)
            .map_err(|error| format!("查询 SeBackupPrivilege 失败：{error}"))?;
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        AdjustTokenPrivileges(token.0, false, Some(&privileges), 0, None, None)
            .map_err(|error| format!("启用 SeBackupPrivilege 失败：{error}"))?;
        if GetLastError() == ERROR_NOT_ALL_ASSIGNED {
            return Err("当前管理员令牌未分配 SeBackupPrivilege，拒绝恢复受限服务目录".into());
        }
    }
    Ok(token)
}

fn enable_restore_privilege() -> Result<OwnedHandle, String> {
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .map_err(|error| format!("打开当前进程令牌失败：{error}"))?;
    }
    let token = OwnedHandle(token);
    let mut luid = LUID::default();
    unsafe {
        LookupPrivilegeValueW(None, SE_RESTORE_NAME, &mut luid)
            .map_err(|error| format!("查询 SeRestorePrivilege 失败：{error}"))?;
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        AdjustTokenPrivileges(token.0, false, Some(&privileges), 0, None, None)
            .map_err(|error| format!("启用 SeRestorePrivilege 失败：{error}"))?;
        if GetLastError() == ERROR_NOT_ALL_ASSIGNED {
            return Err("当前管理员令牌未分配 SeRestorePrivilege，拒绝恢复 SYSTEM owner".into());
        }
    }
    Ok(token)
}

struct RecoveryEntry {
    name: std::ffi::OsString,
    is_directory: bool,
    is_reparse: bool,
}

fn open_recovery_handle(path: &Path, directory: bool) -> Result<OwnedHandle, String> {
    let display = path.display().to_string();
    let path = wide(path);
    let access = if directory {
        FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0
    } else {
        FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0
    };
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    let flags = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS;
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            access,
            share,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }
    .map_err(|error| format!("安全打开受管路径失败：{display}（{error}）"))?;
    Ok(OwnedHandle(handle))
}

fn recovery_attributes(handle: HANDLE) -> Result<(bool, bool), String> {
    let mut info = windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_TAG_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            &mut info as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of_val(&info) as u32,
        )
        .map_err(|error| format!("读取受管路径属性失败：{error}"))?;
    }
    Ok((
        info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0,
        info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 || info.ReparseTag != 0,
    ))
}

fn parse_recovery_directory_buffer(buffer: &[u8]) -> Result<Vec<RecoveryEntry>, String> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    let header_size = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
    loop {
        if offset + header_size > buffer.len() {
            return Err("受管目录枚举记录越过缓冲区".into());
        }
        let info = unsafe { &*(buffer.as_ptr().add(offset) as *const FILE_ID_BOTH_DIR_INFO) };
        if info.FileNameLength == 0 {
            break;
        }
        let name_len = info.FileNameLength as usize;
        if name_len % std::mem::size_of::<u16>() != 0 {
            return Err("受管目录枚举返回了无效文件名".into());
        }
        let record_end = match info.NextEntryOffset {
            0 => buffer.len(),
            next => offset
                .checked_add(next as usize)
                .ok_or("受管目录枚举偏移溢出")?,
        };
        let name_start = offset + header_size;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or("受管目录文件名长度溢出")?;
        if name_end > record_end || record_end > buffer.len() {
            return Err("受管目录枚举文件名越过记录边界".into());
        }
        let name = unsafe {
            std::slice::from_raw_parts(
                buffer.as_ptr().add(name_start) as *const u16,
                name_len / std::mem::size_of::<u16>(),
            )
        };
        let name = std::ffi::OsString::from_wide(name);
        if name != "." && name != ".." {
            entries.push(RecoveryEntry {
                name,
                is_directory: info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0,
                is_reparse: info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0,
            });
        }
        if info.NextEntryOffset == 0 {
            break;
        }
        offset = record_end;
    }
    Ok(entries)
}

fn enumerate_recovery_directory(path: &Path) -> Result<Vec<RecoveryEntry>, String> {
    let handle = open_recovery_handle(path, true)?;
    let mut entries = Vec::new();
    let mut first = true;
    for _ in 0..1024 {
        let mut buffer = vec![0u64; 8192];
        let result = unsafe {
            GetFileInformationByHandleEx(
                handle.0,
                if first {
                    FileIdBothDirectoryRestartInfo
                } else {
                    FileIdBothDirectoryInfo
                },
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                (buffer.len() * std::mem::size_of::<u64>()) as u32,
            )
        };
        match result {
            Ok(()) => {
                let page = parse_recovery_directory_buffer(unsafe {
                    std::slice::from_raw_parts(
                        buffer.as_ptr() as *const u8,
                        buffer.len() * std::mem::size_of::<u64>(),
                    )
                })?;
                if page.is_empty() {
                    return Ok(entries);
                }
                entries.extend(page);
                first = false;
            }
            Err(error) if (error.code().0 as u32 & 0xFFFF) == ERROR_NO_MORE_FILES.0 => {
                return Ok(entries);
            }
            Err(error) => return Err(format!("枚举受管目录失败：{error}")),
        }
    }
    Err("受管目录条目过多，拒绝继续恢复".into())
}

fn validate_managed_tree_for_recovery(root: &Path) -> Result<(), String> {
    // Acquire and verify the backup privilege before probing a potentially
    // SYSTEM-only root.  The native no-follow probe below is the first access
    // on a stale installation; ordinary metadata must not be used here.
    let _backup_privilege = enable_backup_privilege()?;
    if !recovery_root_exists(root)? {
        return Ok(());
    }
    let root_handle = open_recovery_handle(root, true)?;
    let (is_directory, is_reparse) = recovery_attributes(root_handle.0)?;
    if !is_directory || is_reparse {
        return Err("受管服务根目录不是安全的普通目录".into());
    }
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in enumerate_recovery_directory(&directory)? {
            let name_path = Path::new(&entry.name);
            let mut components = name_path.components();
            if !matches!(components.next(), Some(std::path::Component::Normal(_)))
                || components.next().is_some()
            {
                return Err("受管目录包含越界文件名".into());
            }
            let path = directory.join(&entry.name);
            let handle = open_recovery_handle(&path, entry.is_directory)?;
            let (is_directory, is_reparse) = recovery_attributes(handle.0)?;
            if entry.is_reparse || is_reparse || entry.is_directory != is_directory {
                return Err(format!(
                    "受管目录包含 reparse 或类型不一致项，拒绝递归修改：{}",
                    path.display()
                ));
            }
            if is_directory {
                pending.push(path);
            }
        }
    }
    Ok(())
}

fn validate_install_source(source: &Path) -> Result<(), String> {
    if !source.is_absolute()
        || source
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err("安装资源路径不是安全绝对路径".into());
    }
    let current = std::env::current_exe().map_err(|error| error.to_string())?;
    let expected = current
        .parent()
        .ok_or("Invalid executable directory")?
        .join("hid-tap")
        .join("frida-gadget.dll");
    let source_metadata = std::fs::symlink_metadata(source)
        .map_err(|error| format!("读取安装资源属性失败：{error}"))?;
    if is_reparse_point(&source_metadata) || !source_metadata.is_file() {
        return Err("安装资源不是受信任的普通文件".into());
    }
    let canonical_source =
        std::fs::canonicalize(source).map_err(|error| format!("解析安装资源失败：{error}"))?;
    let canonical_expected = std::fs::canonicalize(&expected)
        .map_err(|error| format!("解析安装资源基准路径失败：{error}"))?;
    if canonical_source != canonical_expected {
        return Err("安装资源路径不是当前程序固定的 hid-tap 资源".into());
    }
    Ok(())
}
fn config() -> Result<BrokerConfig, String> {
    let value: BrokerConfig = serde_json::from_slice(
        &std::fs::read(root()?.join("broker.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if value.protocol != 4
        || value.port == 0
        || !valid_nonce(&value.secret)
        || !valid_sid(&value.owner_sid)
    {
        return Err("旁路服务配置无效".into());
    }
    Ok(value)
}
pub fn service_installed() -> bool {
    config().is_ok()
        && open_key(
            HKEY_LOCAL_MACHINE,
            &format!(r"SYSTEM\CurrentControlSet\Services\{NAME}"),
        )
        .is_ok()
}
fn valid_nonce(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn valid_sid(value: &str) -> bool {
    value.starts_with("S-1-")
        && value.len() < 184
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
}

fn sid_bytes(value: &str) -> Result<Vec<u8>, String> {
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() < 3 || parts[0] != "S" {
        return Err("SID 格式无效".into());
    }
    let revision = parts[1].parse::<u8>().map_err(|_| "SID revision 无效")?;
    let authority = parts[2].parse::<u64>().map_err(|_| "SID authority 无效")?;
    if authority > 0x0000_FFFF_FFFF_FFFF || parts.len() - 3 > 15 {
        return Err("SID 数值超出范围".into());
    }
    let mut bytes = vec![0u8; 8 + (parts.len() - 3) * 4];
    bytes[0] = revision;
    bytes[1] = (parts.len() - 3) as u8;
    bytes[2..8].copy_from_slice(&authority.to_be_bytes()[2..]);
    for (index, value) in parts.iter().skip(3).enumerate() {
        let subauthority = value.parse::<u32>().map_err(|_| "SID subauthority 无效")?;
        let offset = 8 + index * 4;
        bytes[offset..offset + 4].copy_from_slice(&subauthority.to_le_bytes());
    }
    Ok(bytes)
}

fn hidden(program: &str, args: &[&str]) -> Result<std::process::Output, String> {
    std::process::Command::new(
        PathBuf::from(std::env::var_os("WINDIR").ok_or("Windows directory unavailable")?)
            .join("System32")
            .join(program),
    )
    .args(args)
    .creation_flags(0x08000000)
    .output()
    .map_err(|e| e.to_string())
}
fn sc(args: &[&str]) -> Result<(), String> {
    let output = hidden("sc.exe", args)?;
    if !output.status.success() {
        let exit_code = output.status.code().unwrap_or(-1);
        let action = if args.first() == Some(&"sdset") {
            format!("sdset {NAME}")
        } else {
            args.join(" ")
        };
        return Err(format!(
            "sc.exe {} 失败，exit_code={exit_code}：{} {}",
            action,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

const DESIRED_FAILURE_ACTIONS: &[(i32, u32)] = &[
    (SC_ACTION_RESTART.0, 5_000),
    (SC_ACTION_RESTART.0, 10_000),
    (SC_ACTION_RESTART.0, 30_000),
];
const DESIRED_FAILURE_RESET_PERIOD: u32 = 86_400;

fn recovery_preserves_unowned_strings(
    before: Option<&FailureActionsSnapshot>,
    after: &FailureActionsSnapshot,
) -> bool {
    after.reboot_message == before.and_then(|value| value.reboot_message.clone())
        && after.command == before.and_then(|value| value.command.clone())
}

fn configure_service_recovery() -> Result<(), String> {
    let before = snapshot_service_configuration()?.ok_or("配置 SCM recovery 前服务注册不存在")?;
    sc(&[
        "failure",
        NAME,
        "reset=",
        "86400",
        "actions=",
        "restart/5000/restart/10000/restart/30000",
    ])?;
    sc(&["failureflag", NAME, "1"])?;
    let snapshot = snapshot_service_configuration()?.ok_or("配置 SCM recovery 后服务注册消失")?;
    let actions = snapshot
        .failure_actions
        .ok_or("配置 SCM recovery 后读取不到 failure actions")?;
    let before_actions = before.failure_actions.as_ref();
    if actions.reset_period != DESIRED_FAILURE_RESET_PERIOD
        || actions.actions != DESIRED_FAILURE_ACTIONS
        || !recovery_preserves_unowned_strings(before_actions, &actions)
        || snapshot.failure_actions_flag != Some(true)
    {
        return Err("SCM recovery 配置读回与期望不一致".into());
    }
    Ok(())
}

fn parse_service_state(output: &str) -> Option<u32> {
    let tokens: Vec<&str> = output.split_whitespace().collect();
    let state_index = tokens.iter().position(|token| *token == "STATE")?;
    tokens
        .iter()
        .skip(state_index + 1)
        .find_map(|token| token.parse::<u32>().ok())
}

fn query_service_state() -> Result<Option<u32>, String> {
    let output = hidden("sc.exe", &["query", NAME])?;
    if !output.status.success() {
        let exit_code = output.status.code().unwrap_or(-1);
        let detail = format!(
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        // ERROR_SERVICE_DOES_NOT_EXIST. Keep this branch independent of the
        // localized message so a Chinese/English host has the same behavior.
        if exit_code == 1060 || detail.contains("1060") {
            return Ok(None);
        }
        return Err(format!("查询受管服务失败，exit_code={exit_code}：{detail}"));
    }
    let detail = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    parse_service_state(&detail)
        .map(Some)
        .ok_or_else(|| "查询受管服务未返回状态码".into())
}

fn ensure_service_stopped() -> Result<(), String> {
    let state = query_service_state()?;
    if state.is_none() || state == Some(1) {
        return Ok(());
    }
    if let Err(error) = sc(&["stop", NAME]) {
        if query_service_state()? != Some(1) {
            return Err(error);
        }
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match query_service_state()? {
            None | Some(1) => return Ok(()),
            Some(_) if Instant::now() >= deadline => return Err("等待受管服务停止超时".into()),
            Some(_) => thread::sleep(Duration::from_millis(250)),
        }
    }
}

fn append_log(path: &Path, message: &str) {
    use std::fs::OpenOptions;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{message}");
    }
}

fn valid_operation_id(value: &str) -> bool {
    crate::installer_compat::valid_operation_id(value)
}

fn parse_operation_suffix(args: &[String]) -> Result<Option<&str>, String> {
    match args {
        [_program, _mode, _path, _sid] => Ok(None),
        [_program, _mode, _path, _sid, marker, operation]
            if marker == OPERATION_ID_ARG && valid_operation_id(operation) =>
        {
            Ok(Some(operation))
        }
        [_program, _mode, _path, _sid, marker, _operation] if marker == OPERATION_ID_ARG => {
            Err("Invalid operation id".into())
        }
        _ => Err("Invalid operation arguments".into()),
    }
}

fn set_request_operation_id(value: Option<&str>) {
    if let Ok(mut current) = REQUEST_OPERATION_ID.lock() {
        *current = value.map(str::to_owned);
    }
}

fn request_operation_id() -> String {
    request_operation_id_opt().unwrap_or_else(|| UNKNOWN_OPERATION_ID.to_owned())
}

fn request_operation_id_opt() -> Option<String> {
    REQUEST_OPERATION_ID
        .lock()
        .ok()
        .and_then(|current| current.clone())
        .filter(|value| valid_operation_id(value))
}

fn operation_log_line(message: &str) -> String {
    format!("operation_id={} {message}", request_operation_id())
}

/// The service directory does not exist during the first preflight. Keep a
/// user-readable diagnostic beside the app so NSIS failures never disappear.
fn install_stage_log(message: &str) {
    let message = operation_log_line(message);
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        append_log(
            &PathBuf::from(local_app_data)
                .join("MiControl")
                .join("Logs")
                .join("install-stage.log"),
            &message,
        );
    }
    if let Ok(root) = root() {
        // Do not create the managed service directory while logging a first
        // install. The installer records pre-existing state before cleanup;
        // creating it here would turn a clean install into an upgrade path.
        if root.is_dir() {
            append_log(&root.join("service.log"), &message);
        }
    }
}

fn sid_suffix(sid: &str) -> &str {
    sid.rsplit('-').next().unwrap_or("unknown")
}

fn install_phase<T>(phase: &str, result: Result<T, String>) -> Result<T, String> {
    match result {
        Ok(value) => {
            install_stage_log(&format!("phase={phase} result=ok"));
            Ok(value)
        }
        Err(error) => {
            install_stage_log(&format!("phase={phase} result=failed error={error}"));
            Err(format!("{phase}失败：{error}"))
        }
    }
}

fn build_runas_arguments(
    path: &str,
    owner: &str,
    install: bool,
    operation: Option<&str>,
) -> String {
    let mut arguments = format!(
        "{} \"{path}\" {owner}",
        if install { INSTALL } else { REMOVE }
    );
    if let Some(operation) = operation.filter(|value| valid_operation_id(value)) {
        arguments.push_str(&format!(" {OPERATION_ID_ARG} {operation}"));
    }
    arguments
}

fn is_exact_runtime_dll_path(service_root: &Path, path: &Path, directory: bool) -> bool {
    if directory {
        return false;
    }
    let expected = service_root
        .join("runtime")
        .join("MiControlRC003HidTap.dll");
    path.to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy())
}

#[cfg(test)]
fn open_acl_handle(path: &Path, directory: bool) -> Result<OwnedHandle, String> {
    open_acl_handle_with_access(path, directory, MAXIMUM_ALLOWED)
}

fn open_acl_handle_for_tree(
    service_root: &Path,
    path: &Path,
    directory: bool,
) -> Result<OwnedHandle, String> {
    // A mapped runtime DLL may be held with FILE_SHARE_READ only.  Keep the
    // old MAXIMUM_ALLOWED contract for every other object so directory ACL
    // propagation and unknown locked-file failures remain unchanged.
    let access = if is_exact_runtime_dll_path(service_root, path, directory) {
        FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0 | WRITE_DAC.0 | WRITE_OWNER.0
    } else {
        MAXIMUM_ALLOWED
    };
    open_acl_handle_with_access(path, directory, access)
}

fn open_acl_handle_with_access(
    path: &Path,
    directory: bool,
    access: u32,
) -> Result<OwnedHandle, String> {
    let display = path.display().to_string();
    let path = wide(path);
    // BACKUP_SEMANTICS is harmless for regular files and is required for
    // directories.  Keep OPEN_REPARSE_POINT for every object so a recovery
    // pass never follows a link between validation and ACL mutation.
    let flags = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS;
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }
    .map_err(|error| format!("打开受管 ACL 句柄失败：{display}（{error}）"))?;
    let handle = OwnedHandle(handle);
    let (actual_directory, is_reparse) = recovery_attributes(handle.0)
        .map_err(|error| format!("校验受管 ACL 句柄失败：{display}（{error}）"))?;
    if is_reparse || actual_directory != directory {
        return Err(format!("受管 ACL 句柄类型或 reparse 属性不匹配：{display}"));
    }
    // Reading the descriptor verifies READ_CONTROL was granted; SetSecurityInfo
    // below remains the authoritative WRITE_DAC/WRITE_OWNER check and reports
    // the path-specific Win32 error.
    security_descriptor_snapshot(handle.0)
        .map_err(|error| format!("校验受管 ACL 句柄权限失败：{display}（{error}）"))?;
    Ok(handle)
}

fn native_security_error(action: &str, error: windows::core::Error) -> String {
    let code = error.code().0 as u32 & 0xffff;
    format!("{action}失败，Win32错误码={code}：{}", error.message())
}

fn set_security_info_checked(
    handle: HANDLE,
    security_information: u32,
    owner: Option<PSID>,
    dacl: Option<*const ACL>,
    action: &str,
) -> Result<(), String> {
    use windows::Win32::Security::Authorization::{SetSecurityInfo, SE_FILE_OBJECT};
    use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;

    let result = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OBJECT_SECURITY_INFORMATION(security_information),
            owner,
            None,
            dacl,
            None,
        )
    };
    if result.0 != 0 {
        return Err(format!("{action}失败，Win32错误码={}", result.0));
    }
    Ok(())
}

fn descriptor_dacl_protected(descriptor: &[u8]) -> Result<bool, String> {
    let mut control = 0u16;
    let mut revision = 0u32;
    unsafe {
        GetSecurityDescriptorControl(
            PSECURITY_DESCRIPTOR(descriptor.as_ptr() as *mut _),
            &mut control,
            &mut revision,
        )
        .map_err(|error| format!("读取安全描述符 DACL control 失败：{error}"))?;
    }
    Ok(control & 0x1000 != 0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DescriptorAclIdentity {
    owner: Vec<u8>,
    dacl: Vec<u8>,
    dacl_protected: bool,
}

fn descriptor_acl_identity(
    descriptor: &[u8],
    action: &str,
) -> Result<DescriptorAclIdentity, String> {
    use windows::core::BOOL;
    use windows::Win32::Security::{
        GetLengthSid, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, ACL, PSID,
    };

    let descriptor_ptr = PSECURITY_DESCRIPTOR(descriptor.as_ptr() as *mut _);
    let mut owner = PSID::default();
    let mut owner_defaulted = BOOL(0);
    let mut dacl_present = BOOL(0);
    let mut dacl = std::ptr::null_mut::<ACL>();
    let mut dacl_defaulted = BOOL(0);
    unsafe {
        GetSecurityDescriptorOwner(descriptor_ptr, &mut owner, &mut owner_defaulted)
            .map_err(|error| format!("{action}读取 owner 失败：{error}"))?;
        if owner.0.is_null() {
            return Err(format!("{action}拒绝 owner 为空的安全描述符"));
        }
        GetSecurityDescriptorDacl(
            descriptor_ptr,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
        .map_err(|error| format!("{action}读取 DACL 失败：{error}"))?;
        if !dacl_present.as_bool() || dacl.is_null() {
            return Err(format!("{action}拒绝 absent/null DACL 安全描述符"));
        }
        let owner_len = GetLengthSid(owner);
        let acl_len = (*dacl).AclSize as usize;
        if owner_len == 0 || acl_len == 0 {
            return Err(format!("{action}拒绝长度无效的 owner/DACL"));
        }
        let owner_bytes = std::slice::from_raw_parts(owner.0 as *const u8, owner_len as usize);
        let dacl_bytes = std::slice::from_raw_parts(dacl as *const u8, acl_len);
        Ok(DescriptorAclIdentity {
            owner: owner_bytes.to_vec(),
            dacl: dacl_bytes.to_vec(),
            dacl_protected: descriptor_dacl_protected(descriptor)?,
        })
    }
}

fn ensure_supported_descriptor(descriptor: &[u8], action: &str) -> Result<(), String> {
    descriptor_acl_identity(descriptor, action).map(|_| ())
}

fn apply_descriptor_security_info(
    handle: HANDLE,
    descriptor: &[u8],
    dacl_protected: bool,
    action: &str,
) -> Result<(), String> {
    use windows::core::BOOL;
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, ACL, PSID,
    };

    let source_identity = descriptor_acl_identity(descriptor, action)?;
    if source_identity.dacl_protected != dacl_protected {
        return Err(format!("{action}的 protected 标记与安全描述符不一致"));
    }
    let descriptor_ptr = PSECURITY_DESCRIPTOR(descriptor.as_ptr() as *mut _);
    let mut owner = PSID::default();
    let mut owner_defaulted = BOOL(0);
    let mut dacl_present = BOOL(0);
    let mut dacl = std::ptr::null_mut::<ACL>();
    let mut dacl_defaulted = BOOL(0);
    unsafe {
        GetSecurityDescriptorOwner(descriptor_ptr, &mut owner, &mut owner_defaulted)
            .map_err(|error| format!("{action}读取 owner 失败：{error}"))?;
        GetSecurityDescriptorDacl(
            descriptor_ptr,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
        .map_err(|error| format!("{action}读取 DACL 失败：{error}"))?;
    }
    let dacl = if dacl_present.as_bool() && !dacl.is_null() {
        Some(dacl as *const ACL)
    } else {
        return Err(format!("{action}拒绝 absent/null DACL 安全描述符"));
    };
    let information = OWNER_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | if dacl_protected {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
    set_security_info_checked(
        handle,
        information.0,
        (!owner.0.is_null()).then_some(owner),
        dacl,
        action,
    )?;
    let (actual_descriptor, actual_protected) = security_descriptor_snapshot(handle)?;
    let actual_identity = descriptor_acl_identity(&actual_descriptor, action)?;
    if actual_identity != source_identity || actual_protected != dacl_protected {
        return Err(format!(
            "{action}后 owner/DACL/protection 精确校验失败：期望 protected={} 实际 protected={}",
            dacl_protected, actual_protected
        ));
    }
    Ok(())
}

fn managed_paths(root: &Path) -> Result<Vec<(PathBuf, bool)>, String> {
    let _backup_privilege = enable_backup_privilege()?;
    validate_managed_tree_for_recovery(root)?;
    let mut paths = vec![(root.to_owned(), true)];
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        for entry in enumerate_recovery_directory(&directory)? {
            if entry.is_reparse {
                return Err(format!(
                    "受管目录包含 reparse point，拒绝修改 ACL：{}",
                    directory.join(&entry.name).display()
                ));
            }
            let path = directory.join(&entry.name);
            paths.push((path.clone(), entry.is_directory));
            if entry.is_directory {
                pending.push(path);
            }
        }
    }
    Ok(paths)
}

fn set_acl_entries(handle: HANDLE, entries: &[(&[u8], u32, ACE_FLAGS)]) -> Result<(), String> {
    let mut acl = vec![0u8; 2048];
    let acl_ptr = acl.as_mut_ptr() as *mut ACL;
    unsafe {
        InitializeAcl(acl_ptr, acl.len() as u32, ACL_REVISION)
            .map_err(|error| native_security_error("初始化受管 ACL", error))?;
        for (sid, mask, ace_flags) in entries {
            AddAccessAllowedAceEx(
                acl_ptr,
                ACL_REVISION,
                *ace_flags,
                *mask,
                PSID(sid.as_ptr() as *mut _),
            )
            .map_err(|error| native_security_error("写入受管 ACL ACE", error))?;
        }
        set_security_info_checked(
            handle,
            (DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION).0,
            None,
            Some(acl_ptr as *const ACL),
            "应用受管 DACL",
        )?;
    }
    let (descriptor, protected) = security_descriptor_snapshot(handle)?;
    if !protected {
        return Err("应用受管 DACL 后未读回 DACL protection".into());
    }
    let actual = descriptor_acl_identity(&descriptor, "应用受管 DACL")?.dacl;
    if actual.len() < std::mem::size_of::<ACL>() || actual.len() > acl.len() {
        return Err(format!(
            "应用受管 DACL 后读回 ACL 长度无效：actual_len={}",
            actual.len()
        ));
    }
    // InitializeAcl stores the allocation capacity in AclSize. Windows writes
    // the compact ACL size into the descriptor, so normalize only that header
    // field before comparing every header/ACE byte exactly.
    let mut expected = acl[..actual.len()].to_vec();
    expected[2..4].copy_from_slice(&(actual.len() as u16).to_le_bytes());
    if actual != expected {
        return Err(format!(
            "应用受管 DACL 后精确读回校验失败 expected_len={} actual_len={}",
            expected.len(),
            actual.len()
        ));
    }
    Ok(())
}

fn inherited_ace_flags(directory: bool) -> ACE_FLAGS {
    if directory {
        ACE_FLAGS(
            windows::Win32::Security::OBJECT_INHERIT_ACE.0
                | windows::Win32::Security::CONTAINER_INHERIT_ACE.0,
        )
    } else {
        ACE_FLAGS(0)
    }
}

fn set_exact_acl(
    handle: HANDLE,
    directory: bool,
    owner: &str,
    local_service_traverse: bool,
) -> Result<(), String> {
    let system = sid_bytes("S-1-5-18")?;
    let administrators = sid_bytes("S-1-5-32-544")?;
    let owner = sid_bytes(owner)?;
    let inherited = inherited_ace_flags(directory);
    let mut entries = vec![
        (&system[..], FILE_ALL_ACCESS.0, inherited),
        (&administrators[..], FILE_ALL_ACCESS.0, inherited),
        (
            &owner[..],
            FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0,
            inherited,
        ),
    ];
    if local_service_traverse {
        let local_service = sid_bytes("S-1-5-19")?;
        entries.push((&local_service[..], FILE_TRAVERSE.0, ACE_FLAGS(0)));
        let result = set_acl_entries(handle, &entries);
        // Keep the SID bytes alive until SetSecurityInfo and its exact readback
        // have completed; entries contains borrowed slices into local_service.
        return result;
    }
    set_acl_entries(handle, &entries)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuntimeAclTarget {
    ServiceRoot,
    RuntimeDirectory,
    RuntimeDll,
    RuntimeReadFile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuntimeAclHelperTarget {
    ServiceRoot,
    RuntimeDirectory,
    RuntimeDll,
    ConfigTemp,
    ScriptTemp,
    EndpointTemp,
}

impl RuntimeAclHelperTarget {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "root" => Ok(Self::ServiceRoot),
            "runtime" => Ok(Self::RuntimeDirectory),
            "dll" => Ok(Self::RuntimeDll),
            "config-temp" => Ok(Self::ConfigTemp),
            "script-temp" => Ok(Self::ScriptTemp),
            "endpoint-temp" => Ok(Self::EndpointTemp),
            _ => Err("service ACL helper target 无效".into()),
        }
    }

    fn runtime_target(self) -> RuntimeAclTarget {
        match self {
            Self::ServiceRoot => RuntimeAclTarget::ServiceRoot,
            Self::RuntimeDirectory => RuntimeAclTarget::RuntimeDirectory,
            Self::RuntimeDll => RuntimeAclTarget::RuntimeDll,
            Self::ConfigTemp | Self::ScriptTemp | Self::EndpointTemp => {
                RuntimeAclTarget::RuntimeReadFile
            }
        }
    }
}

fn runtime_path_for_target(service_root: &Path, target: RuntimeAclTarget) -> PathBuf {
    let runtime = service_root.join("runtime");
    match target {
        RuntimeAclTarget::ServiceRoot => service_root.to_owned(),
        RuntimeAclTarget::RuntimeDirectory => runtime,
        RuntimeAclTarget::RuntimeDll => runtime.join("MiControlRC003HidTap.dll"),
        RuntimeAclTarget::RuntimeReadFile => runtime,
    }
}

fn runtime_read_file_name_allowed(name: &std::ffi::OsStr) -> bool {
    matches!(
        name.to_string_lossy().as_ref(),
        "MiControlRC003HidTap.tmp" | "rc003_hid_tap.tmp" | "endpoint.tmp"
    )
}

pub(super) fn runtime_acl_helper_target(
    path: &Path,
    target: RuntimeAclTarget,
) -> Result<&'static str, String> {
    let service_root = root()?;
    let runtime = service_root.join("runtime");
    let expected = runtime_path_for_target(&service_root, target);
    match target {
        RuntimeAclTarget::ServiceRoot if path == service_root => Ok("root"),
        RuntimeAclTarget::RuntimeDirectory if path == runtime => Ok("runtime"),
        RuntimeAclTarget::RuntimeDll if path == expected => Ok("dll"),
        RuntimeAclTarget::RuntimeReadFile if path.parent() == Some(runtime.as_path()) => {
            match path.file_name().and_then(|name| name.to_str()) {
                Some("MiControlRC003HidTap.tmp") => Ok("config-temp"),
                Some("rc003_hid_tap.tmp") => Ok("script-temp"),
                Some("endpoint.tmp") => Ok("endpoint-temp"),
                _ => Err("service ACL helper 拒绝未知 runtime 文件".into()),
            }
        }
        _ => Err("service ACL helper target/path 不匹配".into()),
    }
}

fn runtime_acl_helper_path(service_root: &Path, target: RuntimeAclHelperTarget) -> PathBuf {
    let runtime = service_root.join("runtime");
    match target {
        RuntimeAclHelperTarget::ServiceRoot => service_root.to_owned(),
        RuntimeAclHelperTarget::RuntimeDirectory => runtime,
        RuntimeAclHelperTarget::RuntimeDll => runtime.join("MiControlRC003HidTap.dll"),
        RuntimeAclHelperTarget::ConfigTemp => runtime.join("MiControlRC003HidTap.tmp"),
        RuntimeAclHelperTarget::ScriptTemp => runtime.join("rc003_hid_tap.tmp"),
        RuntimeAclHelperTarget::EndpointTemp => runtime.join("endpoint.tmp"),
    }
}

fn run_acl_helper(args: &[String]) -> Result<(), String> {
    let has_operation = args.len() == 6 && args[4] == OPERATION_ID_ARG;
    if args.len() != 4 && !has_operation {
        return Err("service ACL helper 参数数量无效".into());
    }
    if has_operation {
        if !valid_operation_id(&args[5]) {
            return Err("service ACL helper operation id 无效".into());
        }
        set_request_operation_id(Some(&args[5]));
    }
    let helper_target = RuntimeAclHelperTarget::parse(&args[2])?;
    let owner = &args[3];
    if !valid_sid(owner) {
        return Err("service ACL helper owner SID 无效".into());
    }
    sid_bytes(owner)?;
    let service_root = root()?;
    let path = runtime_acl_helper_path(&service_root, helper_target);
    apply_runtime_acl(
        &path,
        helper_target.runtime_target(),
        owner,
        "RX",
        Instant::now() + ACL_STAGE_DEADLINE,
    )
}

/// Apply the exact service-mode ACL needed by a LocalService WUDFHost.
///
/// The service root and runtime directory receive a non-inherited traverse ACE
/// only.  The target DLL receives non-inherited read/execute, while the three
/// Frida inputs receive non-inherited read.  No broker or service-management
/// file is included in this contract.
pub(super) fn apply_runtime_acl(
    path: &Path,
    target: RuntimeAclTarget,
    owner: &str,
    owner_access: &str,
    deadline: Instant,
) -> Result<(), String> {
    if Instant::now() >= deadline {
        return Err(format!(
            "ACL 阶段预算已耗尽，未启动 native ACL path={} budget_ms=0",
            path.display()
        ));
    }
    if owner_access != "RX" {
        return Err(format!(
            "服务运行时 owner 权限契约无效：expected=RX actual={owner_access}"
        ));
    }
    let _restore_privilege = enable_restore_privilege()?;
    let service_root = root()?;
    let runtime_root = service_root.join("runtime");
    let expected = runtime_path_for_target(&service_root, target);
    match target {
        RuntimeAclTarget::ServiceRoot => {
            if path != service_root {
                return Err(format!(
                    "服务 root ACL 路径不匹配：expected={} actual={}",
                    service_root.display(),
                    path.display()
                ));
            }
        }
        RuntimeAclTarget::RuntimeDirectory => {
            if path != runtime_root {
                return Err(format!(
                    "runtime 目录 ACL 路径不匹配：expected={} actual={}",
                    runtime_root.display(),
                    path.display()
                ));
            }
        }
        RuntimeAclTarget::RuntimeDll => {
            if path != expected {
                return Err(format!(
                    "runtime DLL ACL 路径不匹配：expected={} actual={}",
                    expected.display(),
                    path.display()
                ));
            }
        }
        RuntimeAclTarget::RuntimeReadFile => {
            if path.parent() != Some(runtime_root.as_path())
                || path
                    .file_name()
                    .is_none_or(|name| !runtime_read_file_name_allowed(name))
            {
                return Err(format!(
                    "runtime 只读文件 ACL 路径不在固定临时文件集合：{}",
                    path.display()
                ));
            }
        }
    }

    // The parent service root may have been installed by an older build.  Make
    // the single non-inherited traverse ACE explicit before touching runtime;
    // this does not grant LocalService read access to any child.
    if target != RuntimeAclTarget::ServiceRoot {
        if Instant::now() >= deadline {
            return Err(format!(
                "ACL 阶段预算已耗尽，未打开服务 root path={} budget_ms=0",
                service_root.display()
            ));
        }
        let root_handle = open_acl_handle_for_tree(&service_root, &service_root, true)?;
        set_exact_acl(root_handle.0, true, owner, true)
            .map_err(|error| format!("{}：{error}", service_root.display()))?;
    }

    if Instant::now() >= deadline {
        return Err(format!(
            "ACL 阶段预算已耗尽，未打开目标 path={} budget_ms=0",
            path.display()
        ));
    }
    match target {
        RuntimeAclTarget::ServiceRoot => {
            let handle = open_acl_handle_for_tree(&service_root, path, true)?;
            set_exact_acl(handle.0, true, owner, true)
                .map_err(|error| format!("{}：{error}", path.display()))?;
        }
        RuntimeAclTarget::RuntimeDirectory => {
            let handle = open_acl_handle_for_tree(&service_root, path, true)?;
            set_exact_acl(handle.0, true, owner, true)
                .map_err(|error| format!("{}：{error}", path.display()))?;
        }
        RuntimeAclTarget::RuntimeDll | RuntimeAclTarget::RuntimeReadFile => {
            let handle = open_acl_handle_for_tree(&service_root, path, false)?;
            let system = sid_bytes("S-1-5-18")?;
            let administrators = sid_bytes("S-1-5-32-544")?;
            let owner = sid_bytes(owner)?;
            let local_service = sid_bytes("S-1-5-19")?;
            let local_service_access = match target {
                RuntimeAclTarget::RuntimeDll => FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0,
                RuntimeAclTarget::RuntimeReadFile => FILE_GENERIC_READ.0,
                _ => unreachable!(),
            };
            set_acl_entries(
                handle.0,
                &[
                    (&system, FILE_ALL_ACCESS.0, ACE_FLAGS(0)),
                    (&administrators, FILE_ALL_ACCESS.0, ACE_FLAGS(0)),
                    (
                        &owner,
                        FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0,
                        ACE_FLAGS(0),
                    ),
                    (&local_service, local_service_access, ACE_FLAGS(0)),
                ],
            )
            .map_err(|error| format!("{}：{error}", path.display()))?;
        }
    }
    Ok(())
}

fn set_administrator_maintenance_acl(handle: HANDLE, directory: bool) -> Result<(), String> {
    let system = sid_bytes("S-1-5-18")?;
    let administrators = sid_bytes("S-1-5-32-544")?;
    let inherited = inherited_ace_flags(directory);
    set_acl_entries(
        handle,
        &[
            (&system, FILE_ALL_ACCESS.0, inherited),
            (&administrators, FILE_ALL_ACCESS.0, inherited),
        ],
    )
}

fn set_owner_handle(handle: HANDLE, owner: &str) -> Result<(), String> {
    let owner = sid_bytes(owner)?;
    set_security_info_checked(
        handle,
        OWNER_SECURITY_INFORMATION.0,
        Some(PSID(owner.as_ptr() as *mut _)),
        None,
        "设置对象 owner",
    )?;
    let (descriptor, _) = security_descriptor_snapshot(handle)?;
    let actual_owner = descriptor_acl_identity(&descriptor, "设置对象 owner")?.owner;
    if actual_owner != owner {
        return Err("设置对象 owner 后 SID 精确读回不匹配".into());
    }
    Ok(())
}

fn set_system_owner_handle(handle: HANDLE) -> Result<(), String> {
    set_owner_handle(handle, "S-1-5-18")?;
    if !owner_is_system(handle)? {
        return Err("恢复 SYSTEM owner 后校验失败".into());
    }
    Ok(())
}

fn owner_is_system(handle: HANDLE) -> Result<bool, String> {
    use windows::core::BOOL;
    use windows::Win32::Security::{
        EqualSid, GetKernelObjectSecurity, GetSecurityDescriptorOwner, PSECURITY_DESCRIPTOR,
    };
    let mut required = 0u32;
    unsafe {
        let _ =
            GetKernelObjectSecurity(handle, OWNER_SECURITY_INFORMATION.0, None, 0, &mut required);
    }
    if required == 0 {
        return Err("读取 SYSTEM owner 描述符大小失败".into());
    }
    let mut descriptor = vec![0u8; required as usize];
    unsafe {
        GetKernelObjectSecurity(
            handle,
            OWNER_SECURITY_INFORMATION.0,
            Some(PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr() as *mut _)),
            descriptor.len() as u32,
            &mut required,
        )
        .map_err(|error| format!("读取 SYSTEM owner 描述符失败：{error}"))?;
        let mut owner = PSID::default();
        let mut owner_defaulted = BOOL(0);
        GetSecurityDescriptorOwner(
            PSECURITY_DESCRIPTOR(descriptor.as_ptr() as *mut _),
            &mut owner,
            &mut owner_defaulted,
        )
        .map_err(|error| format!("读取 SYSTEM owner SID 失败：{error}"))?;
        let system = sid_bytes("S-1-5-18")?;
        Ok(EqualSid(owner, PSID(system.as_ptr() as *mut _)).is_ok())
    }
}

fn protect(path: &Path, owner: &str) -> Result<(), String> {
    if !valid_sid(owner) {
        return Err("服务用户 SID 无效".into());
    }
    // Enable SeRestore before the first ACL handle is opened.  On a stale
    // SYSTEM-only tree, WRITE_DAC/WRITE_OWNER access is granted by this
    // privilege at CreateFile time; enabling it after enumeration is too late.
    let _restore_privilege = enable_restore_privilege()?;
    let entries = managed_paths(path)?;
    let mut handles = Vec::with_capacity(entries.len());
    for (entry, directory) in entries {
        let handle = open_acl_handle_for_tree(path, &entry, directory)?;
        let (actual_directory, is_reparse) = recovery_attributes(handle.0)?;
        if is_reparse || actual_directory != directory {
            return Err(format!(
                "打开后的受管 ACL 句柄属性不匹配，拒绝修改：{}",
                entry.display()
            ));
        }
        handles.push((entry, directory, handle));
    }
    // Every handle is opened while Administrators still has maintenance access.
    // Each object receives one exact protected DACL; no recursive reopen occurs.
    for (entry, directory, handle) in &handles {
        // The UMDF host normally runs as LocalService.  Give that account only
        // traverse permission on the managed service root; it must never inherit
        // access to broker.json or any other child.  Runtime files receive their
        // own explicit LocalService ACE when the injection directory is prepared.
        set_exact_acl(handle.0, *directory, owner, entry == path)
            .map_err(|error| format!("{}：{error}", entry.display()))?;
    }
    for (entry, _, handle) in &handles {
        set_system_owner_handle(handle.0)
            .map_err(|error| format!("{}：{error}", entry.display()))?;
    }
    Ok(())
}

fn recovery_root_exists(path: &Path) -> Result<bool, String> {
    // Existence and type are determined by a no-follow native handle.  Do not
    // use metadata here: a SYSTEM-only root can deny that ordinary probe even
    // though SeBackupPrivilege permits the recovery handle to be opened.
    let _backup_privilege = enable_backup_privilege()?;
    let display = path.display().to_string();
    let path = wide(path);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    };
    let handle = match handle {
        Ok(handle) => OwnedHandle(handle),
        Err(error) => {
            let code = error.code().0 as u32 & 0xffff;
            if code == ERROR_FILE_NOT_FOUND.0 || code == ERROR_PATH_NOT_FOUND.0 {
                return Ok(false);
            }
            return Err(native_security_error(
                &format!("探测受管服务根目录 {display}"),
                error,
            ));
        }
    };
    let (is_directory, is_reparse) = recovery_attributes(handle.0)?;
    if !is_directory || is_reparse {
        return Err("受管服务根目录不是安全的普通目录".into());
    }
    Ok(true)
}

fn set_system_owner(path: &Path) -> Result<(), String> {
    let _restore_privilege = enable_restore_privilege()?;
    let entries = managed_paths(path)?;
    let mut handles = Vec::with_capacity(entries.len());
    for (entry, directory) in entries {
        let handle = open_acl_handle_for_tree(path, &entry, directory)?;
        let (actual_directory, is_reparse) = recovery_attributes(handle.0)?;
        if is_reparse || actual_directory != directory {
            return Err(format!(
                "恢复 SYSTEM owner 时句柄属性不匹配，拒绝修改：{}",
                entry.display()
            ));
        }
        handles.push((entry, handle));
    }
    for (entry, handle) in &handles {
        set_system_owner_handle(handle.0)
            .map_err(|error| format!("{}：{error}", entry.display()))?;
    }
    Ok(())
}

fn restore_administrator_maintenance(path: &Path) -> Result<(), String> {
    // Enable restore before probing or opening a potentially SYSTEM-only root.
    let _restore_privilege = enable_restore_privilege()?;
    if !recovery_root_exists(path)? {
        return Ok(());
    }
    validate_managed_tree_for_recovery(path)?;
    // Do not use takeown/icacls here.  Both tools recursively reopen each
    // child after changing its parent, which fails on the exact SYSTEM-only
    // residue left by an interrupted install.  Native handles are opened
    // while the restore privilege is enabled and held for the whole pass.
    let entries = managed_paths(path)?;
    let mut handles = Vec::with_capacity(entries.len());
    for (entry, directory) in entries {
        let handle = open_acl_handle_for_tree(path, &entry, directory)?;
        let (actual_directory, is_reparse) = recovery_attributes(handle.0)?;
        if is_reparse || actual_directory != directory {
            return Err(format!(
                "恢复管理员维护权限时句柄属性不匹配，拒绝修改：{}",
                entry.display()
            ));
        }
        handles.push((entry, directory, handle));
    }
    for (entry, directory, handle) in &handles {
        set_administrator_maintenance_acl(handle.0, *directory)
            .map_err(|error| format!("{}：{error}", entry.display()))?;
    }
    for (entry, _, handle) in &handles {
        set_owner_handle(handle.0, "S-1-5-32-544")
            .map_err(|error| format!("{}：{error}", entry.display()))?;
    }
    Ok(())
}

#[derive(Clone)]
struct ObjectSecuritySnapshot {
    relative_path: PathBuf,
    directory: bool,
    descriptor: Vec<u8>,
    dacl_protected: bool,
}

fn security_descriptor_snapshot(handle: HANDLE) -> Result<(Vec<u8>, bool), String> {
    let requested = (OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION).0;
    let mut required = 0u32;
    unsafe {
        let _ = GetKernelObjectSecurity(handle, requested, None, 0, &mut required);
    }
    if required == 0 {
        return Err("读取旧服务对象安全描述符大小失败".into());
    }
    let mut descriptor = vec![0u8; required as usize];
    unsafe {
        GetKernelObjectSecurity(
            handle,
            requested,
            Some(PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr() as *mut _)),
            descriptor.len() as u32,
            &mut required,
        )
        .map_err(|error| format!("读取旧服务对象安全描述符失败：{error}"))?;
        descriptor.truncate(required as usize);
        let mut control = 0u16;
        let mut revision = 0u32;
        GetSecurityDescriptorControl(
            PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr() as *mut _),
            &mut control,
            &mut revision,
        )
        .map_err(|error| format!("读取旧服务对象安全描述符控制位失败：{error}"))?;
        Ok((
            descriptor,
            control & 0x1000 != 0, // SE_DACL_PROTECTED
        ))
    }
}

fn snapshot_managed_tree_security(root: &Path) -> Result<Vec<ObjectSecuritySnapshot>, String> {
    let _backup_privilege = enable_backup_privilege()?;
    if !recovery_root_exists(root)? {
        return Ok(Vec::new());
    }
    validate_managed_tree_for_recovery(root)?;
    let mut snapshots = Vec::new();
    let mut pending = vec![(root.to_owned(), PathBuf::new(), true)];
    while let Some((path, relative_path, directory)) = pending.pop() {
        let handle = open_recovery_handle(&path, directory)?;
        let (actual_directory, is_reparse) = recovery_attributes(handle.0)?;
        if is_reparse || actual_directory != directory {
            return Err(format!(
                "快照句柄属性不匹配，拒绝读取旧服务对象：{}",
                path.display()
            ));
        }
        let (descriptor, dacl_protected) = security_descriptor_snapshot(handle.0)?;
        ensure_supported_descriptor(&descriptor, &format!("快照旧服务对象 {}", path.display()))?;
        snapshots.push(ObjectSecuritySnapshot {
            relative_path: relative_path.clone(),
            directory,
            descriptor,
            dacl_protected,
        });
        if directory {
            for entry in enumerate_recovery_directory(&path)? {
                let child_relative = relative_path.join(&entry.name);
                pending.push((path.join(&entry.name), child_relative, entry.is_directory));
            }
        }
    }
    Ok(snapshots)
}

fn restore_managed_tree_security(
    root: &Path,
    snapshots: &[ObjectSecuritySnapshot],
) -> Result<(), String> {
    if snapshots.is_empty() {
        return Ok(());
    }
    let _restore_privilege = enable_restore_privilege()?;
    let mut handles = Vec::with_capacity(snapshots.len());
    for snapshot in snapshots {
        let path = root.join(&snapshot.relative_path);
        let handle = open_acl_handle_for_tree(root, &path, snapshot.directory)?;
        let (actual_directory, is_reparse) = recovery_attributes(handle.0)?;
        if is_reparse || actual_directory != snapshot.directory {
            return Err(format!(
                "恢复句柄属性不匹配，拒绝写入旧服务对象：{}",
                path.display()
            ));
        }
        handles.push((path.clone(), snapshot, handle));
    }
    for (path, snapshot, handle) in handles {
        apply_descriptor_security_info(
            handle.0,
            &snapshot.descriptor,
            snapshot.dacl_protected,
            &format!("恢复旧服务对象安全描述符 {}", path.display()),
        )?;
    }
    Ok(())
}

fn prepare_service_root(path: &Path, owner: &str, recover_existing: bool) -> Result<(), String> {
    if recover_existing {
        // A previous partial install can leave broker.json owned by SYSTEM
        // before the first ACL reset. Temporarily recover Administrators'
        // maintenance right while the tree is known to be inside Program
        // Files and free of reparse points, then apply the final restricted
        // ACL and return ownership to SYSTEM.
        restore_administrator_maintenance(path)?;
    } else {
        validate_managed_tree(path)?;
    }
    protect(path, owner)
}

fn transaction_sibling(root: &Path, kind: &str) -> Result<PathBuf, String> {
    let parent = root.parent().ok_or("服务目录缺少事务父目录")?;
    let name = root
        .file_name()
        .ok_or("服务目录缺少事务名称")?
        .to_string_lossy();
    Ok(parent.join(format!(
        "{name}.{kind}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos()
    )))
}

fn cleanup_transaction_tree(path: &Path) -> Result<(), String> {
    if !recovery_root_exists(path)? {
        return Ok(());
    }
    validate_managed_tree_for_recovery(path)?;
    restore_administrator_maintenance(path)?;
    validate_managed_tree(path)?;
    std::fs::remove_dir_all(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn wait_for_existing_service_ready(timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(current) = config() {
            if broker_health(&current) {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err("恢复旧旁路服务后 broker 鉴权握手未就绪".into());
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn format_install_failure(primary: &str, rollback: Result<(), String>) -> String {
    match rollback {
        Ok(()) => format!("{primary}；rollback=passed"),
        Err(error) => format!("{primary}；rollback=failed：{error}"),
    }
}

fn maintenance_pending_gate(root: &Path, action: &str) -> Result<(), String> {
    let path = super::pending_injection_path(&super::service_runtime_path(root));
    if !pending_present(&path)? {
        return Ok(());
    }
    let pending = read_pending_injection(&path).map_err(|error| {
        format!("{action}拒绝：旁路 pending intent 损坏（{error}），请重启后重试")
    })?;
    match previous_target_state(pending.pid) {
        PreviousTarget::Alive(creation_time) if creation_time == pending.process_creation_time => {
            Err(format!(
                "{action}拒绝：旧 WUDFHost 仍持有未确认远程加载，请重启后重试"
            ))
        }
        PreviousTarget::Denied => Err(format!(
            "{action}拒绝：无法确认旧 WUDFHost 是否退出，请重启后重试"
        )),
        PreviousTarget::Alive(_) | PreviousTarget::Gone => {
            remove_pending_injection(&path).map_err(|error| {
                format!("{action}拒绝：清理已结束目标的 pending intent 失败：{error}")
            })
        }
    }
}

fn rollback_install(
    service_root: &Path,
    staging_root: &Path,
    backup_root: Option<&Path>,
    old_tree_security: &[ObjectSecuritySnapshot],
    old_service: Option<&ServiceSnapshot>,
    service_was_present: bool,
    service_was_running: bool,
    mutation: &InstallMutation,
) -> Result<(), String> {
    let mut ops = ProductionRollbackOps {
        service_root,
        staging_root,
        backup_root,
        old_tree_security,
        old_service,
    };
    run_rollback(&mut ops, mutation, service_was_present, service_was_running)
}

struct ProductionRollbackOps<'a> {
    service_root: &'a Path,
    staging_root: &'a Path,
    backup_root: Option<&'a Path>,
    old_tree_security: &'a [ObjectSecuritySnapshot],
    old_service: Option<&'a ServiceSnapshot>,
}

impl RollbackOps for ProductionRollbackOps<'_> {
    fn stop_candidate(&mut self) -> Result<(), String> {
        ensure_service_stopped()
    }

    fn delete_created_service(&mut self) -> Result<(), String> {
        match query_service_state()? {
            Some(_) => sc(&["delete", NAME]),
            None => Ok(()),
        }
    }

    fn cleanup_active_candidate(&mut self) -> Result<(), String> {
        cleanup_transaction_tree(self.service_root)
    }

    fn restore_old_tree(&mut self) -> Result<(), String> {
        let backup = self.backup_root.ok_or("旧服务目录备份状态无对应路径")?;
        match recovery_root_exists(backup)? {
            true => std::fs::rename(backup, self.service_root).map_err(|error| error.to_string()),
            false => Err("旧服务目录备份已不存在".into()),
        }
    }

    fn restore_old_tree_security(&mut self) -> Result<(), String> {
        restore_managed_tree_security(self.service_root, self.old_tree_security)
    }

    fn restore_old_service_configuration(&mut self) -> Result<(), String> {
        self.old_service
            .ok_or_else(|| "旧旁路服务缺少 SCM 配置快照".to_owned())
            .and_then(restore_service_configuration)
    }

    fn cleanup_staging(&mut self) -> Result<(), String> {
        cleanup_transaction_tree(self.staging_root)
    }

    fn restart_old_service(&mut self) -> Result<(), String> {
        sc(&["start", NAME])?;
        wait_for_existing_service_ready(Duration::from_secs(20))
    }
}

/// Service-object rights are separate from the file ACL. The installer owner
/// only needs to query and start the service during normal desktop recovery;
/// stop/delete/configuration/write rights remain with SYSTEM/Administrators.
fn service_security_descriptor(owner: &str) -> String {
    format!(
        "D:(A;;LCRP;;;{owner})(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)"
    )
}

#[derive(Clone)]
struct ServiceSnapshot {
    service_type: u32,
    error_control: u32,
    binary_path: String,
    start_type: u32,
    load_order_group: String,
    _tag_id: u32,
    dependencies: Vec<u16>,
    display_name: String,
    service_start_name: String,
    delayed_auto_start: Option<bool>,
    description: Option<String>,
    failure_actions: Option<FailureActionsSnapshot>,
    failure_actions_flag: Option<bool>,
    descriptor: Vec<u8>,
}

#[derive(Clone)]
struct FailureActionsSnapshot {
    reset_period: u32,
    reboot_message: Option<String>,
    command: Option<String>,
    actions: Vec<(i32, u32)>,
}

struct ServiceHandle(SC_HANDLE);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq)]
struct InstallMutation {
    service_stopped: bool,
    service_created: bool,
    service_config_changed: bool,
    service_dacl_changed: bool,
    old_tree_touched: bool,
    old_root_backed_up: bool,
    swapped: bool,
}

#[derive(Debug)]
struct InstallTransactionFailure {
    error: String,
    mutation: InstallMutation,
}

/// The transaction state machine is shared by production and fault-injection
/// tests.  Implementations only provide the side effects; mutation flags are
/// set here, immediately before each operation, so partial SCM/rename effects
/// are rolled back conservatively.
trait InstallOps {
    fn stop_existing(&mut self) -> Result<(), String>;
    fn check_pending_guard(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn recover_old_tree(&mut self) -> Result<(), String>;
    fn backup_old_tree(&mut self) -> Result<(), String>;
    fn activate_candidate(&mut self) -> Result<(), String>;
    fn configure_existing(&mut self) -> Result<(), String>;
    fn create_service(&mut self) -> Result<(), String>;
    fn start_and_wait_health(&mut self) -> Result<(), String>;
    fn protect_service(&mut self) -> Result<(), String>;
    fn cleanup_backup(&mut self) -> Result<(), String>;
}

trait RollbackOps {
    fn stop_candidate(&mut self) -> Result<(), String>;
    fn delete_created_service(&mut self) -> Result<(), String>;
    fn cleanup_active_candidate(&mut self) -> Result<(), String>;
    fn restore_old_tree(&mut self) -> Result<(), String>;
    fn restore_old_tree_security(&mut self) -> Result<(), String>;
    fn restore_old_service_configuration(&mut self) -> Result<(), String>;
    fn cleanup_staging(&mut self) -> Result<(), String>;
    fn restart_old_service(&mut self) -> Result<(), String>;
}

fn run_rollback<O: RollbackOps>(
    ops: &mut O,
    mutation: &InstallMutation,
    service_was_present: bool,
    service_was_running: bool,
) -> Result<(), String> {
    let mut failures = Vec::new();
    if mutation.service_created || mutation.service_stopped {
        // A stop failure is a hard boundary: any following delete/rename can
        // destroy a running candidate or leave SCM pointing at a missing tree.
        if let Err(error) = ops.stop_candidate() {
            return Err(format!(
                "停止候选服务失败：{error}；未执行后续回滚，保留 candidate/backup"
            ));
        }
    }
    if mutation.service_created {
        if let Err(error) = ops.delete_created_service() {
            failures.push(format!("删除候选 SCM 注册失败：{error}"));
        }
    }
    if mutation.swapped {
        if let Err(error) = ops.cleanup_active_candidate() {
            failures.push(format!("删除候选服务目录失败：{error}"));
        }
    }
    let mut old_root_restored = !mutation.old_root_backed_up;
    if mutation.old_root_backed_up {
        match ops.restore_old_tree() {
            Ok(()) => old_root_restored = true,
            Err(error) => failures.push(format!("恢复旧服务目录失败：{error}")),
        }
    }
    if mutation.old_tree_touched && old_root_restored {
        if let Err(error) = ops.restore_old_tree_security() {
            failures.push(format!("恢复旧服务目录 owner/DACL 失败：{error}"));
        }
    }
    if (mutation.service_config_changed || mutation.service_dacl_changed) && service_was_present {
        if let Err(error) = ops.restore_old_service_configuration() {
            failures.push(format!("恢复旧旁路服务 SCM 配置/DACL 失败：{error}"));
        }
    }
    if let Err(error) = ops.cleanup_staging() {
        failures.push(format!("删除 staging 服务目录失败：{error}"));
    }
    if service_was_present && service_was_running && mutation.service_stopped {
        if let Err(error) = ops.restart_old_service() {
            failures.push(format!("恢复旧服务启动失败：{error}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("；"))
    }
}

fn run_install_transaction<O: InstallOps>(
    ops: &mut O,
    service_was_present: bool,
    has_backup: bool,
) -> Result<InstallMutation, InstallTransactionFailure> {
    let mut mutation = InstallMutation::default();
    if service_was_present {
        mutation.service_stopped = true;
        transaction_stage("existing_service_stop", ops.stop_existing(), &mutation)?;
    }
    if has_backup {
        transaction_stage(
            "pending_guard_after_stop",
            ops.check_pending_guard(),
            &mutation,
        )?;
        mutation.old_tree_touched = true;
        transaction_stage(
            "old_service_root_recover",
            ops.recover_old_tree(),
            &mutation,
        )?;
        transaction_stage(
            "pending_guard_before_backup",
            ops.check_pending_guard(),
            &mutation,
        )?;
        transaction_stage("old_service_root_backup", ops.backup_old_tree(), &mutation)?;
        mutation.old_root_backed_up = true;
    }
    if has_backup {
        transaction_stage(
            "pending_guard_before_activate",
            ops.check_pending_guard(),
            &mutation,
        )?;
    }
    transaction_stage("service_root_activate", ops.activate_candidate(), &mutation)?;
    mutation.swapped = true;
    if service_was_present {
        mutation.service_config_changed = true;
        transaction_stage("sc_config", ops.configure_existing(), &mutation)?;
    } else {
        mutation.service_created = true;
        transaction_stage("sc_create", ops.create_service(), &mutation)?;
    }
    transaction_stage("broker_health_wait", ops.start_and_wait_health(), &mutation)?;
    mutation.service_dacl_changed = true;
    transaction_stage("sc_acl", ops.protect_service(), &mutation)?;
    Ok(mutation)
}

fn transaction_stage(
    name: &str,
    result: Result<(), String>,
    mutation: &InstallMutation,
) -> Result<(), InstallTransactionFailure> {
    result.map_err(|error| InstallTransactionFailure {
        error: format!("{name}失败：{error}"),
        mutation: mutation.clone(),
    })
}

struct ProductionInstallOps<'a> {
    service_root: &'a Path,
    staging_root: &'a Path,
    backup_root: Option<&'a Path>,
    owner: &'a str,
    cfg: &'a BrokerConfig,
}

impl InstallOps for ProductionInstallOps<'_> {
    fn stop_existing(&mut self) -> Result<(), String> {
        ensure_service_stopped()
    }

    fn check_pending_guard(&mut self) -> Result<(), String> {
        maintenance_pending_gate(self.service_root, "服务升级")
    }

    fn recover_old_tree(&mut self) -> Result<(), String> {
        restore_administrator_maintenance(self.service_root)
    }

    fn backup_old_tree(&mut self) -> Result<(), String> {
        let backup = self.backup_root.ok_or("旧服务目录缺少备份路径")?;
        std::fs::rename(self.service_root, backup).map_err(|error| error.to_string())
    }

    fn activate_candidate(&mut self) -> Result<(), String> {
        std::fs::rename(self.staging_root, self.service_root).map_err(|error| error.to_string())
    }

    fn configure_existing(&mut self) -> Result<(), String> {
        let exe = self.service_root.join("MiControlHidService.exe");
        let command = format!("\"{}\" {MODE}", exe.display());
        sc(&["config", NAME, "binPath=", &command, "start=", "auto"])?;
        configure_service_recovery()
    }

    fn create_service(&mut self) -> Result<(), String> {
        let exe = self.service_root.join("MiControlHidService.exe");
        let command = format!("\"{}\" {MODE}", exe.display());
        sc(&[
            "create",
            NAME,
            "binPath=",
            &command,
            "start=",
            "auto",
            "DisplayName=",
            "MiControl RC003 完整按键服务",
        ])?;
        sc(&[
            "description",
            NAME,
            "MiControl RC003 固定按键旁路；仅处理已配对遥控器，无 UI/音频采集。",
        ])?;
        configure_service_recovery()
    }

    fn start_and_wait_health(&mut self) -> Result<(), String> {
        sc(&["start", NAME])?;
        wait_for_ready(self.cfg, Duration::from_secs(20))
    }

    fn protect_service(&mut self) -> Result<(), String> {
        protect_service(self.owner)
    }

    fn cleanup_backup(&mut self) -> Result<(), String> {
        if let Some(backup) = self.backup_root {
            cleanup_transaction_tree(backup)
        } else {
            Ok(())
        }
    }
}

fn service_handle(access: u32) -> Result<ServiceHandle, String> {
    let manager = unsafe { OpenSCManagerW(None, None, SC_MANAGER_CONNECT) }
        .map_err(|error| format!("打开服务控制管理器失败：{error}"))?;
    let manager = ServiceHandle(manager);
    let name = wide(NAME);
    let service = unsafe { OpenServiceW(manager.0, PCWSTR(name.as_ptr()), access) }
        .map_err(|error| format!("打开旧旁路服务失败：{error}"))?;
    Ok(ServiceHandle(service))
}

unsafe fn pwstr_to_string(pointer: PWSTR) -> Result<String, String> {
    if pointer.0.is_null() {
        return Ok(String::new());
    }
    let mut length = 0usize;
    while *pointer.0.add(length) != 0 {
        length = length.checked_add(1).ok_or("旧旁路服务字符串长度溢出")?;
    }
    String::from_utf16(std::slice::from_raw_parts(pointer.0, length))
        .map_err(|_| "旧旁路服务配置包含无效 UTF-16".into())
}

unsafe fn pwstr_to_optional_string(pointer: PWSTR) -> Result<Option<String>, String> {
    if pointer.0.is_null() {
        Ok(None)
    } else {
        pwstr_to_string(pointer).map(Some)
    }
}

struct OwnedServiceConfig {
    service_type: u32,
    error_control: u32,
    binary_path: String,
    start_type: u32,
    load_order_group: String,
    tag_id: u32,
    dependencies: Vec<u16>,
    display_name: String,
    service_start_name: String,
}

unsafe fn copy_config_string(pointer: PWSTR, buffer: &[u64]) -> Result<String, String> {
    copy_utf16_string(
        pointer,
        buffer.as_ptr() as *const u8,
        std::mem::size_of_val(buffer),
    )
}

unsafe fn copy_utf16_string(
    pointer: PWSTR,
    start_pointer: *const u8,
    byte_length: usize,
) -> Result<String, String> {
    if pointer.0.is_null() {
        return Ok(String::new());
    }
    let start = start_pointer as usize;
    let end = start + byte_length;
    let address = pointer.0 as usize;
    if address < start || address >= end || (address - start) % 2 != 0 {
        return Err("旧旁路服务配置字符串指针越过查询缓冲区".into());
    }
    let count = (end - address) / std::mem::size_of::<u16>();
    let values = std::slice::from_raw_parts(pointer.0, count);
    let length = values
        .iter()
        .position(|value| *value == 0)
        .ok_or("旧旁路服务配置字符串未终止")?;
    String::from_utf16(&values[..length]).map_err(|_| "旧旁路服务配置包含无效 UTF-16".into())
}

unsafe fn copy_config_multisz(pointer: PWSTR, buffer: &[u64]) -> Result<Vec<u16>, String> {
    if pointer.0.is_null() {
        return Ok(vec![0]);
    }
    let start = buffer.as_ptr() as usize;
    let end = start + std::mem::size_of_val(buffer);
    let address = pointer.0 as usize;
    if address < start || address >= end || (address - start) % 2 != 0 {
        return Err("旧旁路服务依赖项指针越过查询缓冲区".into());
    }
    let count = (end - address) / std::mem::size_of::<u16>();
    let values = std::slice::from_raw_parts(pointer.0, count);
    let terminator = values
        .windows(2)
        .position(|pair| pair == [0, 0])
        .ok_or("旧旁路服务依赖项 MULTI_SZ 未终止")?;
    Ok(values[..terminator + 2].to_vec())
}

fn query_service_config_native(service: SC_HANDLE) -> Result<OwnedServiceConfig, String> {
    let mut required = 0u32;
    unsafe {
        let _ = QueryServiceConfigW(service, None, 0, &mut required);
    }
    if required == 0 {
        return Err("读取旧旁路服务配置大小失败".into());
    }
    let units = (required as usize).div_ceil(std::mem::size_of::<u64>());
    let mut buffer = vec![0u64; units];
    unsafe {
        QueryServiceConfigW(
            service,
            Some(buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW),
            (buffer.len() * std::mem::size_of::<u64>()) as u32,
            &mut required,
        )
        .map_err(|error| format!("读取旧旁路服务配置失败：{error}"))?;
        let config = &*(buffer.as_ptr() as *const QUERY_SERVICE_CONFIGW);
        Ok(OwnedServiceConfig {
            service_type: config.dwServiceType.0,
            error_control: config.dwErrorControl.0,
            binary_path: copy_config_string(config.lpBinaryPathName, &buffer)?,
            start_type: config.dwStartType.0,
            load_order_group: copy_config_string(config.lpLoadOrderGroup, &buffer)?,
            tag_id: config.dwTagId,
            dependencies: copy_config_multisz(config.lpDependencies, &buffer)?,
            display_name: copy_config_string(config.lpDisplayName, &buffer)?,
            service_start_name: copy_config_string(config.lpServiceStartName, &buffer)?,
        })
    }
}

fn query_service_config2_native(
    service: SC_HANDLE,
    level: SERVICE_CONFIG,
) -> Result<Option<Vec<u8>>, String> {
    let mut required = 0u32;
    let first = unsafe { QueryServiceConfig2W(service, level, None, &mut required) };
    if required == 0 && first.is_ok() {
        return Ok(None);
    }
    if required == 0 {
        return Err(format!("读取旧旁路服务扩展配置大小失败：{first:?}"));
    }
    let mut buffer = vec![0u8; required as usize];
    unsafe {
        QueryServiceConfig2W(service, level, Some(&mut buffer), &mut required)
            .map_err(|error| format!("读取旧旁路服务扩展配置失败：{error}"))?;
    }
    buffer.truncate(required as usize);
    Ok(Some(buffer))
}

fn query_service_descriptor_native(service: SC_HANDLE) -> Result<Vec<u8>, String> {
    let requested = (OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION).0;
    let mut required = 0u32;
    unsafe {
        let _ = QueryServiceObjectSecurity(service, requested, None, 0, &mut required);
    }
    if required == 0 {
        return Err("读取旧旁路服务安全描述符大小失败".into());
    }
    let mut descriptor = vec![0u8; required as usize];
    unsafe {
        QueryServiceObjectSecurity(
            service,
            requested,
            Some(PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr() as *mut _)),
            descriptor.len() as u32,
            &mut required,
        )
        .map_err(|error| format!("读取旧旁路服务安全描述符失败：{error}"))?;
    }
    descriptor.truncate(required as usize);
    Ok(descriptor)
}

fn snapshot_service_configuration() -> Result<Option<ServiceSnapshot>, String> {
    if query_service_state()?.is_none() {
        return Ok(None);
    }
    let service = service_handle(SERVICE_QUERY_CONFIG | READ_CONTROL.0)?;
    let config = query_service_config_native(service.0)?;
    let delayed_auto_start =
        query_service_config2_native(service.0, SERVICE_CONFIG_DELAYED_AUTO_START_INFO)?
            .map(|buffer| unsafe { *(buffer.as_ptr() as *const SERVICE_DELAYED_AUTO_START_INFO) })
            .map(|info| info.fDelayedAutostart.as_bool());
    let description = query_service_config2_native(service.0, SERVICE_CONFIG_DESCRIPTION)?
        .map(|buffer| unsafe {
            let info = *(buffer.as_ptr() as *const SERVICE_DESCRIPTIONW);
            if info.lpDescription.0.is_null() {
                Ok(None)
            } else {
                copy_utf16_string(info.lpDescription, buffer.as_ptr(), buffer.len()).map(Some)
            }
        })
        .transpose()?
        .flatten();
    let failure_actions = query_service_config2_native(service.0, SERVICE_CONFIG_FAILURE_ACTIONS)?
        .map(|buffer| unsafe {
            let info = *(buffer.as_ptr() as *const SERVICE_FAILURE_ACTIONSW);
            let actions = if info.lpsaActions.is_null() {
                Vec::new()
            } else {
                std::slice::from_raw_parts(info.lpsaActions, info.cActions as usize)
                    .iter()
                    .map(|action| (action.Type.0, action.Delay))
                    .collect()
            };
            Ok::<_, String>(FailureActionsSnapshot {
                reset_period: info.dwResetPeriod,
                reboot_message: pwstr_to_optional_string(info.lpRebootMsg)?,
                command: pwstr_to_optional_string(info.lpCommand)?,
                actions,
            })
        })
        .transpose()?;
    let failure_actions_flag =
        query_service_config2_native(service.0, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG)?.map(
            |buffer| unsafe {
                (*(buffer.as_ptr() as *const SERVICE_FAILURE_ACTIONS_FLAG))
                    .fFailureActionsOnNonCrashFailures
                    .as_bool()
            },
        );
    let descriptor = query_service_descriptor_native(service.0)?;
    Ok(Some(ServiceSnapshot {
        service_type: config.service_type,
        error_control: config.error_control,
        binary_path: config.binary_path,
        start_type: config.start_type,
        load_order_group: config.load_order_group,
        _tag_id: config.tag_id,
        dependencies: config.dependencies,
        display_name: config.display_name,
        service_start_name: config.service_start_name,
        delayed_auto_start,
        description,
        failure_actions,
        failure_actions_flag,
        descriptor,
    }))
}

fn restore_service_configuration(snapshot: &ServiceSnapshot) -> Result<(), String> {
    let service =
        service_handle(SERVICE_CHANGE_CONFIG | SERVICE_START | READ_CONTROL.0 | WRITE_DAC.0)?;
    let binary_path = wide(&snapshot.binary_path);
    let load_order_group = wide(&snapshot.load_order_group);
    let display_name = wide(&snapshot.display_name);
    let service_start_name = wide(&snapshot.service_start_name);
    let dependencies = snapshot.dependencies.clone();
    let dependencies_ptr = if dependencies.len() <= 1 {
        None
    } else {
        Some(PCWSTR(dependencies.as_ptr()))
    };
    unsafe {
        ChangeServiceConfigW(
            service.0,
            ENUM_SERVICE_TYPE(snapshot.service_type),
            SERVICE_START_TYPE(snapshot.start_type),
            SERVICE_ERROR(snapshot.error_control),
            PCWSTR(binary_path.as_ptr()),
            PCWSTR(load_order_group.as_ptr()),
            // dwTagId is an output assigned by SCM when lpTagId is supplied;
            // it is not an input pointer.  Passing the saved value here would
            // treat an integer as an address and corrupt memory.  A null
            // pointer preserves the service's existing SCM tag semantics.
            None,
            dependencies_ptr.unwrap_or(PCWSTR::null()),
            PCWSTR(service_start_name.as_ptr()),
            PCWSTR::null(),
            PCWSTR(display_name.as_ptr()),
        )
        .map_err(|error| format!("恢复旧旁路服务 SCM 配置失败：{error}"))?;
        if let Some(delayed) = snapshot.delayed_auto_start {
            let info = SERVICE_DELAYED_AUTO_START_INFO {
                fDelayedAutostart: delayed.into(),
            };
            ChangeServiceConfig2W(
                service.0,
                SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                Some((&info as *const SERVICE_DELAYED_AUTO_START_INFO).cast::<std::ffi::c_void>()),
            )
            .map_err(|error| format!("恢复旧旁路服务延迟启动配置失败：{error}"))?;
        }
        if let Some(description) = &snapshot.description {
            let description = wide(description);
            let info = SERVICE_DESCRIPTIONW {
                lpDescription: PWSTR(description.as_ptr() as *mut _),
            };
            ChangeServiceConfig2W(
                service.0,
                SERVICE_CONFIG_DESCRIPTION,
                Some((&info as *const SERVICE_DESCRIPTIONW).cast::<std::ffi::c_void>()),
            )
            .map_err(|error| format!("恢复旧旁路服务描述失败：{error}"))?;
        }
        if let Some(actions) = &snapshot.failure_actions {
            let reboot = actions.reboot_message.as_ref().map(|value| wide(value));
            let command = actions.command.as_ref().map(|value| wide(value));
            let mut native_actions: Vec<SC_ACTION> = actions
                .actions
                .iter()
                .map(|(kind, delay)| SC_ACTION {
                    Type: SC_ACTION_TYPE(*kind),
                    Delay: *delay,
                })
                .collect();
            let info = SERVICE_FAILURE_ACTIONSW {
                dwResetPeriod: actions.reset_period,
                lpRebootMsg: reboot
                    .as_ref()
                    .map_or(PWSTR::null(), |value| PWSTR(value.as_ptr() as *mut _)),
                lpCommand: command
                    .as_ref()
                    .map_or(PWSTR::null(), |value| PWSTR(value.as_ptr() as *mut _)),
                cActions: native_actions.len() as u32,
                lpsaActions: native_actions.as_mut_ptr(),
            };
            ChangeServiceConfig2W(
                service.0,
                SERVICE_CONFIG_FAILURE_ACTIONS,
                Some((&info as *const SERVICE_FAILURE_ACTIONSW).cast::<std::ffi::c_void>()),
            )
            .map_err(|error| format!("恢复旧旁路服务故障动作失败：{error}"))?;
        } else {
            // Keep a non-null action pointer with cActions=0.  SCM treats a
            // null action array as "leave the existing array alone" on some
            // Windows builds, while an empty array is an explicit clear.
            let mut empty_action = SC_ACTION {
                Type: SC_ACTION_TYPE(0),
                Delay: 0,
            };
            let info = SERVICE_FAILURE_ACTIONSW {
                dwResetPeriod: 0,
                lpRebootMsg: PWSTR::null(),
                lpCommand: PWSTR::null(),
                cActions: 0,
                lpsaActions: &mut empty_action,
            };
            ChangeServiceConfig2W(
                service.0,
                SERVICE_CONFIG_FAILURE_ACTIONS,
                Some((&info as *const SERVICE_FAILURE_ACTIONSW).cast::<std::ffi::c_void>()),
            )
            .map_err(|error| format!("清除旧旁路服务故障动作失败：{error}"))?;
        }
        if let Some(flag) = snapshot.failure_actions_flag {
            let info = SERVICE_FAILURE_ACTIONS_FLAG {
                fFailureActionsOnNonCrashFailures: flag.into(),
            };
            ChangeServiceConfig2W(
                service.0,
                SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                Some((&info as *const SERVICE_FAILURE_ACTIONS_FLAG).cast::<std::ffi::c_void>()),
            )
            .map_err(|error| format!("恢复旧旁路服务故障标志失败：{error}"))?;
        } else {
            let info = SERVICE_FAILURE_ACTIONS_FLAG {
                fFailureActionsOnNonCrashFailures: false.into(),
            };
            ChangeServiceConfig2W(
                service.0,
                SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                Some((&info as *const SERVICE_FAILURE_ACTIONS_FLAG).cast::<std::ffi::c_void>()),
            )
            .map_err(|error| format!("清除旧旁路服务故障标志失败：{error}"))?;
        }
        SetServiceObjectSecurity(
            service.0,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR(snapshot.descriptor.as_ptr() as *mut _),
        )
        .map_err(|error| format!("恢复旧旁路服务安全描述符失败：{error}"))?;
    }
    Ok(())
}

fn protect_service(owner: &str) -> Result<(), String> {
    let descriptor = service_security_descriptor(owner);
    sc(&["sdset", NAME, &descriptor])
        .map_err(|error| format!("设置旁路服务最小管理权限失败：{error}"))
}
pub fn manage_service(source: PathBuf, install: bool) -> Result<bool, String> {
    let action = if install { "install" } else { "remove" };
    install_stage_log(&format!(
        "phase=setup action={action} result=begin source={}",
        source.display()
    ));
    if install {
        let actual = install_phase("preflight_hash_read", hash_file(&source))?;
        if actual != GADGET_SHA256 {
            install_stage_log(&format!(
                "phase=preflight_hash_compare result=failed expected={GADGET_SHA256} actual={actual}"
            ));
            return Err("Gadget 校验失败".into());
        }
        install_stage_log("phase=preflight_hash_compare result=ok");
    }
    let who = install_phase(
        "preflight_whoami_launch",
        hidden("whoami.exe", &["/user", "/fo", "csv", "/nh"]),
    )?;
    if !who.status.success() {
        let exit_code = who.status.code().unwrap_or(-1);
        let detail = String::from_utf8_lossy(&who.stderr);
        install_stage_log(&format!(
            "phase=preflight_whoami_status result=failed exit_code={exit_code} stderr={detail}"
        ));
        return Err(format!(
            "无法识别当前用户 SID（whoami exit_code={exit_code}）"
        ));
    }
    install_stage_log("phase=preflight_whoami_status result=ok");
    let owner = String::from_utf8_lossy(&who.stdout)
        .split('"')
        .find(|part| valid_sid(part))
        .ok_or_else(|| {
            install_stage_log("phase=preflight_sid_parse result=failed sid_present=false");
            "无法识别当前用户 SID"
        })?
        .to_owned();
    install_stage_log(&format!(
        "phase=preflight_sid_parse result=ok sid_suffix={}",
        sid_suffix(&owner)
    ));
    let path = source.to_str().ok_or_else(|| {
        install_stage_log("phase=preflight_source_path result=failed reason=non_utf8");
        "Invalid asset path"
    })?;
    if path.contains('"') {
        install_stage_log("phase=preflight_source_path result=failed reason=quote");
        return Err("Invalid asset path".into());
    }
    let argument_text =
        build_runas_arguments(path, &owner, install, request_operation_id_opt().as_deref());
    let arguments = wide(argument_text);
    let current_exe = install_phase(
        "preflight_current_exe",
        std::env::current_exe().map_err(|e| e.to_string()),
    )?;
    let exe = wide(current_exe);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(exe.as_ptr()),
        lpParameters: PCWSTR(arguments.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    install_stage_log("phase=runas_dispatch result=begin");
    let dispatch_result = unsafe { ShellExecuteExW(&mut info) };
    if let Err(e) = dispatch_result {
        let code_dec = unsafe { GetLastError().0 };
        install_stage_log(&format!(
            "phase=runas_dispatch result=failed kind={} win32_code={} (0x{code_dec:08X}) system_message={} hresult={}",
            crate::installer_compat::classify_runas_error(code_dec),
            code_dec,
            std::io::Error::from_raw_os_error(code_dec as i32),
            e.code().0
        ));
        return Err(format!(
            "管理员授权未完成（Win32 {code_dec} / 0x{code_dec:08X}）：{e}"
        ));
    }
    install_stage_log("phase=runas_dispatch result=ok");
    let handle = OwnedHandle(info.hProcess);
    let wait_result = unsafe { WaitForSingleObject(handle.0, 60_000) };
    match wait_result.0 {
        value if value == WAIT_OBJECT_0.0 => {}
        value if value == WAIT_TIMEOUT.0 => {
            install_stage_log(
                "phase=runas_wait result=failed kind=timeout child_running=unknown termination=not_attempted rollback=not_claimed",
            );
            return Err(
                "服务安装/卸载等待超时（60 秒），子进程状态未知，未声明终止或回滚完成".into(),
            );
        }
        value if value == WAIT_FAILED.0 => {
            let code = unsafe { GetLastError().0 };
            let detail = format!(
                "win32_code={code} (0x{code:08X}) system_message={}",
                std::io::Error::from_raw_os_error(code as i32)
            );
            install_stage_log(&format!(
                "phase=runas_wait result=failed kind=waiterror {detail}"
            ));
            return Err(format!("等待服务安装/卸载子进程失败（{detail}）"));
        }
        code => {
            install_stage_log(&format!(
                "phase=runas_wait result=failed kind=waiterror wait_code={code} (0x{code:08X})"
            ));
            return Err(format!(
                "等待服务安装/卸载子进程失败（WaitForSingleObject {code} / 0x{code:08X}）"
            ));
        }
    }
    install_stage_log("phase=runas_wait result=ok");
    let mut exit = 1;
    let exit_result = unsafe { GetExitCodeProcess(handle.0, &mut exit) };
    let exit_error = if exit_result.is_err() {
        Some(unsafe { GetLastError().0 })
    } else {
        None
    };
    if let Err(e) = exit_result {
        let code = exit_error.unwrap_or(1);
        install_stage_log(&format!(
            "phase=runas_exit_code result=failed win32_code={code} (0x{code:08X}) system_message={}",
            std::io::Error::from_raw_os_error(code as i32)
        ));
        return Err(format!(
            "读取管理员安装进程退出码失败（Win32 {code} / 0x{code:08X}）：{e}"
        ));
    }
    if exit != 0 {
        install_stage_log(&format!(
            "phase=runas_exit_code result=failed child_exit_code={exit}"
        ));
        return Err(format!(
            "服务安装/卸载失败（子进程退出码 {exit}），请查看 %LOCALAPPDATA%\\MiControl\\Logs\\install-stage.log"
        ));
    }
    install_stage_log("phase=runas_exit_code result=ok child_exit_code=0");
    let installed = service_installed();
    if install && !installed {
        install_stage_log("phase=postcondition result=failed service_installed=false");
        return Err("服务安装进程已成功退出，但服务配置未通过验收，请查看安装日志".into());
    }
    install_stage_log(&format!(
        "phase=postcondition result=ok service_installed={installed}"
    ));
    Ok(installed)
}
fn install(source: &Path, owner: &str) -> Result<(), String> {
    install_stage_log(&format!(
        "phase=elevated_install result=begin sid_suffix={} source={}",
        sid_suffix(owner),
        source.display()
    ));
    if !valid_sid(owner) {
        install_stage_log("phase=install_arguments result=failed reason=invalid_sid");
        return Err("Invalid install arguments".into());
    }
    install_phase("install_source_path", validate_install_source(source))?;
    let actual_hash = install_phase("install_hash_read", hash_file(source))?;
    if actual_hash != GADGET_SHA256 {
        install_stage_log(&format!(
            "phase=install_hash_compare result=failed expected={GADGET_SHA256} actual={actual_hash}"
        ));
        return Err("Invalid install arguments".into());
    }
    install_stage_log("phase=install_hash_compare result=ok");
    let service_root = install_phase("service_root_resolve", root())?;
    let service_root_preexisting =
        install_phase("service_root_probe", recovery_root_exists(&service_root))?;
    if service_root_preexisting {
        install_phase(
            "pending_guard_preflight",
            maintenance_pending_gate(&service_root, "服务升级"),
        )?;
    }
    let existing_service = install_phase("existing_service_query", query_service_state())?;
    let service_was_present = existing_service.is_some();
    let service_was_running = existing_service == Some(4);
    let old_service = install_phase(
        "existing_service_snapshot",
        snapshot_service_configuration(),
    )?;
    let old_tree_security = if service_root_preexisting {
        install_phase(
            "old_service_tree_snapshot",
            snapshot_managed_tree_security(&service_root),
        )?
    } else {
        Vec::new()
    };
    let staging_root = transaction_sibling(&service_root, "staging")?;
    let backup_root = if service_root_preexisting {
        Some(transaction_sibling(&service_root, "backup")?)
    } else {
        None
    };

    // Build and fully validate the candidate away from the live fixed root.
    // A failure here must not touch an existing service or directory.
    let candidate: Result<BrokerConfig, String> = (|| {
        install_phase(
            "service_root_create",
            std::fs::create_dir_all(&staging_root).map_err(|e| e.to_string()),
        )?;
        install_phase(
            "service_root_acl",
            prepare_service_root(&staging_root, owner, false),
        )?;
        install_phase(
            "service_root_path_validate",
            validate_managed_tree(&staging_root),
        )?;
        let exe = staging_root.join("MiControlHidService.exe");
        install_phase(
            "service_binary_copy",
            std::env::current_exe()
                .map_err(|e| e.to_string())
                .and_then(|current| std::fs::copy(current, &exe).map_err(|e| e.to_string())),
        )?;
        install_phase(
            "gadget_copy",
            std::fs::copy(source, staging_root.join("frida-gadget.dll")).map_err(|e| e.to_string()),
        )?;
        let license = source.with_file_name("frida-COPYING.txt");
        if license.is_file() {
            install_phase(
                "license_copy",
                std::fs::copy(license, staging_root.join("frida-COPYING.txt"))
                    .map_err(|e| e.to_string()),
            )?;
        }
        let listener = install_phase(
            "broker_port_bind",
            TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string()),
        )?;
        let port = install_phase(
            "broker_port_read",
            listener.local_addr().map_err(|e| e.to_string()),
        )?
        .port();
        drop(listener);
        let mut bytes = [0u8; 32];
        install_phase(
            "broker_secret_generate",
            unsafe { BCryptGenRandom(None, &mut bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG) }
                .ok()
                .map_err(|e| e.to_string()),
        )?;
        let cfg = BrokerConfig {
            port,
            secret: bytes.iter().map(|b| format!("{b:02x}")).collect(),
            owner_sid: owner.into(),
            protocol: 4,
        };
        install_phase(
            "broker_write",
            std::fs::write(
                staging_root.join("broker.json"),
                serde_json::to_vec(&cfg).unwrap(),
            )
            .map_err(|e| e.to_string()),
        )?;
        install_phase("service_tree_owner", set_system_owner(&staging_root))?;
        install_phase("service_tree_acl_final", protect(&staging_root, owner))?;
        Ok(cfg)
    })();
    let cfg = match candidate {
        Ok(candidate) => candidate,
        Err(error) => {
            let cleanup = cleanup_transaction_tree(&staging_root);
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup_error) => format!("{error}；staging清理失败：{cleanup_error}"),
            });
        }
    };

    let mut ops = ProductionInstallOps {
        service_root: &service_root,
        staging_root: &staging_root,
        backup_root: backup_root.as_deref(),
        owner,
        cfg: &cfg,
    };
    let transaction = run_install_transaction(&mut ops, service_was_present, backup_root.is_some());
    match transaction {
        Ok(_) => {}
        Err(failure) => {
            install_stage_log(&format!(
                "phase=elevated_install result=failed error={}",
                failure.error
            ));
            let rollback = rollback_install(
                &service_root,
                &staging_root,
                backup_root.as_deref(),
                &old_tree_security,
                old_service.as_ref(),
                service_was_present,
                service_was_running,
                &failure.mutation,
            );
            return Err(format_install_failure(&failure.error, rollback));
        }
    }
    if backup_root.is_some() {
        let cleanup = backup_root
            .as_ref()
            .map(|backup| maintenance_pending_gate(backup, "旧服务备份清理"))
            .unwrap_or(Ok(()))
            .and_then(|_| ops.cleanup_backup());
        if let Err(error) = cleanup {
            // Candidate health is the transaction commit point.  Never roll
            // back a healthy candidate merely because old residue cleanup
            // failed; leave the backup in place for a later cleanup pass.
            install_stage_log(&format!(
                "phase=old_service_backup_cleanup result=failed error={error}"
            ));
            log(&format!("安装已提交；旧服务备份清理失败：{error}"));
        } else {
            install_stage_log("phase=old_service_backup_cleanup result=ok");
        }
    }
    install_stage_log("phase=elevated_install result=ok");
    log("service_start phase=ready broker_authenticated=true");
    Ok(())
}

fn wait_for_ready(expected: &BrokerConfig, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        // service_main selects a fresh port and atomically rewrites broker.json;
        // reread it on every attempt instead of probing the pre-start port.
        if let Ok(current) = config() {
            if current.secret == expected.secret && broker_health(&current) {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err("服务已启动但 broker 鉴权握手未就绪".into());
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn broker_health(config: &BrokerConfig) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], config.port)),
        Duration::from_millis(300),
    ) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
    let request = serde_json::json!({"kind":"health","secret":config.secret});
    if writeln!(stream, "{request}").is_err() {
        return false;
    }
    let Ok(response) = read_line(&mut stream, Duration::from_millis(700)) else {
        return false;
    };
    serde_json::from_str::<serde_json::Value>(&response)
        .ok()
        .is_some_and(|value| value["ok"] == true && value["protocol"].as_u64() == Some(4))
}
fn remove() -> Result<(), String> {
    let root = root()?;
    maintenance_pending_gate(&root, "服务卸载")?;
    ensure_service_stopped()?;
    maintenance_pending_gate(&root, "服务卸载")?;
    // Only delete SCM registration after its process has gracefully stopped.
    if query_service_state()?.is_some() {
        sc(&["delete", NAME])?;
    }
    // A failed or interrupted upgrade can leave broker.json owned by SYSTEM.
    // The recovery-specific handle walk runs before any recursive ACL or file
    // operation; it also handles the no-directory case itself.
    restore_administrator_maintenance(&root)?;
    // Explicit fixed directory; preserve runtime DLLs still loaded by WUDFHost.
    for name in [
        "broker.json",
        "frida-gadget.dll",
        "frida-COPYING.txt",
        "MiControlHidService.exe",
        "runtime/.rc003-injection-pending.json",
    ] {
        let path = root.join(name);
        if name == "runtime/.rc003-injection-pending.json" {
            if pending_present(&path)? {
                remove_pending_injection(&path)?;
            }
            continue;
        }
        if path.exists() {
            let began = Instant::now();
            loop {
                match std::fs::remove_file(&path) {
                    Ok(()) => break,
                    Err(error) if began.elapsed() < Duration::from_secs(5) => {
                        let _ = error;
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(error) => return Err(error.to_string()),
                }
            }
        }
    }
    Ok(())
}
fn log(message: &str) {
    if let Ok(root) = root() {
        use std::fs::OpenOptions;
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("service.log"))
        {
            let _ = writeln!(file, "{message}");
        }
    }
}
pub fn handle_mode(args: &[String]) -> Option<i32> {
    let mode = args.get(1)?.as_str();
    set_request_operation_id(None);
    let diagnostic_mode = matches!(
        mode,
        SETUP_REQUEST | REMOVE_REQUEST | INSTALL | REMOVE | ACL_HELPER
    );
    let setup_with_operation = mode == SETUP_REQUEST
        && ((args.len() == 2)
            || (args.len() == 4 && args[2] == OPERATION_ID_ARG && valid_operation_id(&args[3])));
    let result = match mode {
        ACL_HELPER => run_acl_helper(args),
        SETUP_REQUEST if setup_with_operation => {
            if args.len() == 4 {
                set_request_operation_id(Some(&args[3]));
            }
            let source = std::env::current_exe()
                .map_err(|e| e.to_string())
                .and_then(|exe| {
                    Ok(exe
                        .parent()
                        .ok_or("Invalid executable directory")?
                        .join("hid-tap/frida-gadget.dll"))
                });
            source.and_then(|source| manage_service(source, true).map(|_| ()))
        }
        SETUP_REQUEST => Err("Invalid setup request arguments".into()),
        REMOVE_REQUEST if args.len() == 2 => {
            if open_key(
                HKEY_LOCAL_MACHINE,
                &format!(r"SYSTEM\CurrentControlSet\Services\{NAME}"),
            )
            .is_ok()
            {
                std::env::current_exe()
                    .map_err(|e| e.to_string())
                    .and_then(|exe| manage_service(exe, false).map(|_| ()))
            } else {
                Ok(())
            }
        }
        MODE => {
            let name = wide(NAME);
            let table = [
                SERVICE_TABLE_ENTRYW {
                    lpServiceName: PWSTR(name.as_ptr() as *mut _),
                    lpServiceProc: Some(service_main),
                },
                SERVICE_TABLE_ENTRYW::default(),
            ];
            unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) }.map_err(|e| e.to_string())
        }
        INSTALL if args.len() == 4 => install(Path::new(&args[2]), &args[3]),
        INSTALL if args.len() == 6 || args.len() == 4 => match parse_operation_suffix(&args) {
            Ok(operation) => {
                set_request_operation_id(operation);
                install(Path::new(&args[2]), &args[3])
            }
            Err(error) => Err(format!("Invalid install arguments: {error}")),
        },
        REMOVE if args.len() == 4 => remove(),
        REMOVE if args.len() == 6 => match parse_operation_suffix(&args) {
            Ok(operation) => {
                set_request_operation_id(operation);
                remove()
            }
            Err(error) => Err(format!("Invalid remove arguments: {error}")),
        },
        INSTALL | REMOVE => Err("Invalid service arguments".into()),
        _ => return None,
    };
    if let Err(error) = result {
        if diagnostic_mode {
            install_stage_log(&format!("phase=helper result=failed error={error}"));
        }
        log(&error);
        Some(1)
    } else {
        if diagnostic_mode {
            install_stage_log("phase=helper result=ok");
        }
        Some(0)
    }
}
unsafe extern "system" fn handler(
    control: u32,
    _: u32,
    _: *mut std::ffi::c_void,
    _: *mut std::ffi::c_void,
) -> u32 {
    if control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN {
        MANUAL_SHUTDOWN.store(true, Ordering::Release);
        STOP.store(true, Ordering::Relaxed);
    }
    0
}

fn run_watchdog(watchdog: Watchdog, cfg: BrokerConfig) {
    // This thread must remain independent from the request thread: an inject
    // call can occupy the listener for the whole operation deadline.
    loop {
        if SERVICE_MAIN_EXITED.load(Ordering::Acquire) {
            return;
        }
        let manual = MANUAL_SHUTDOWN.load(Ordering::Acquire);
        let mut fault = false;
        if !manual && !STOP.load(Ordering::Acquire) {
            fault = watchdog.tick(Instant::now(), Some(broker_health(&cfg)));
            if fault {
                STOP.store(true, Ordering::Release);
            }
        }
        let stopping = manual || STOP.load(Ordering::Acquire) || fault;
        if stopping {
            let now = Instant::now();
            let grace = if manual {
                watchdog.manual_finalize_grace(now)
            } else {
                WATCHDOG_FINALIZE_GRACE
            };
            let finalize_deadline = now + grace;
            while !SERVICE_MAIN_EXITED.load(Ordering::Acquire) && Instant::now() < finalize_deadline
            {
                thread::sleep(Duration::from_millis(100));
            }
            if SERVICE_MAIN_EXITED.load(Ordering::Acquire) {
                return;
            }
            let code = if MANUAL_SHUTDOWN.load(Ordering::Acquire) {
                0
            } else {
                1
            };
            let raw = SERVICE_STATUS_RAW.load(Ordering::Acquire);
            if !raw.is_null() {
                let status = SERVICE_STATUS {
                    dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                    dwCurrentState: SERVICE_STOPPED,
                    dwControlsAccepted: 0,
                    dwWin32ExitCode: code,
                    ..Default::default()
                };
                unsafe {
                    let _ = SetServiceStatus(SERVICE_STATUS_HANDLE(raw), &status);
                    // This is a service-only last resort after a bounded
                    // shutdown window. Terminate only this service process;
                    // never use it for unit-test decisions or external hosts.
                    let _ = TerminateProcess(GetCurrentProcess(), code);
                }
            }
            return;
        }
        thread::sleep(Duration::from_millis(250));
    }
}

unsafe extern "system" fn service_main(_: u32, _: *mut PWSTR) {
    let Ok(handle) = (unsafe {
        RegisterServiceCtrlHandlerExW(PCWSTR(wide(NAME).as_ptr()), Some(handler), None)
    }) else {
        return;
    };
    SERVICE_STATUS_RAW.store(handle.0, Ordering::Release);
    SERVICE_MAIN_EXITED.store(false, Ordering::Release);
    let status = |state, code| {
        let value = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: if state == SERVICE_RUNNING {
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            } else {
                0
            },
            dwWin32ExitCode: code,
            ..Default::default()
        };
        unsafe {
            let _ = SetServiceStatus(handle, &value);
        }
    };
    STOP.store(false, Ordering::Relaxed);
    MANUAL_SHUTDOWN.store(false, Ordering::Release);
    status(SERVICE_START_PENDING, 0);
    let watchdog = Watchdog::new(Instant::now());
    let result = (|| {
        let mut cfg = config()?;
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
        cfg.port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let root = root()?;
        let temporary = root.join("broker.tmp");
        std::fs::write(&temporary, serde_json::to_vec(&cfg).unwrap()).map_err(|e| e.to_string())?;
        unsafe {
            windows::Win32::Storage::FileSystem::MoveFileExW(
                PCWSTR(wide(&temporary).as_ptr()),
                PCWSTR(wide(root.join("broker.json")).as_ptr()),
                windows::Win32::Storage::FileSystem::MOVEFILE_REPLACE_EXISTING,
            )
        }
        .map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        status(SERVICE_RUNNING, 0);
        log("service_runtime state=running broker_bound=true");
        let watchdog_thread = thread::Builder::new()
            .name("micontrol-rc003-watchdog".into())
            .spawn({
                let watchdog = watchdog.clone();
                let cfg = cfg.clone();
                move || run_watchdog(watchdog, cfg)
            })
            .map_err(|e| format!("启动旁路 watchdog 失败：{e}"))?;
        while !STOP.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let mut stream = match configure_broker_client_stream(stream) {
                        Ok(stream) => stream,
                        Err(error) => {
                            log(&error);
                            continue;
                        }
                    };
                    let result = serve_request(&mut stream, &cfg, &watchdog);
                    let answer = match result {
                        Ok(answer) => answer,
                        Err(error) => {
                            log(&error);
                            serde_json::json!({"ok":false,"error":error})
                        }
                    };
                    let _ = writeln!(stream, "{answer}");
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(100))
                }
                Err(e) => return Err(e.to_string()),
            }
        }
        STOP.store(true, Ordering::Release);
        drop(watchdog_thread);
        Ok::<(), String>(())
    })();
    if let Err(error) = &result {
        STOP.store(true, Ordering::Release);
        log(error);
    }
    log(format!(
        "service_runtime state=stopped result={}",
        if result.is_ok() { "normal" } else { "failed" }
    )
    .as_str());
    status(SERVICE_STOPPED, watchdog.final_exit_code(result.is_err()));
    SERVICE_MAIN_EXITED.store(true, Ordering::Release);
}

fn configure_broker_client_stream(stream: TcpStream) -> Result<TcpStream, String> {
    // Windows accept returns a socket with the listener's properties. The
    // listener is intentionally nonblocking so service_main can observe STOP;
    // each accepted request must be returned to blocking mode before read_line.
    stream
        .set_nonblocking(false)
        .map_err(|error| format!("配置 broker 客户端 socket 阻塞模式失败：{error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("配置 broker 客户端读超时失败：{error}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("配置 broker 客户端写超时失败：{error}"))?;
    Ok(stream)
}

fn read_line(stream: &mut TcpStream, timeout: Duration) -> Result<String, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    // Limit memory and wall time even if a local peer trickles data.
    let began = Instant::now();
    while bytes.len() < 4096 && began.elapsed() < timeout {
        let mut one = [0u8; 1];
        stream.read_exact(&mut one).map_err(|e| e.to_string())?;
        if one[0] == b'\n' {
            return String::from_utf8(bytes).map_err(|e| e.to_string());
        }
        bytes.push(one[0]);
    }
    Err("服务请求过长或超时".into())
}
fn validate_request(req: &Request, cfg: &BrokerConfig) -> Result<(), String> {
    if req.secret != cfg.secret
        || req.pid == 0
        || req.port == 0
        || !valid_nonce(&req.token)
        || req.deadline_ms == 0
        || req.deadline_ms > 45_000
    {
        return Err("Invalid broker request".into());
    }
    Ok(())
}
fn serve_request(
    stream: &mut TcpStream,
    cfg: &BrokerConfig,
    watchdog: &Watchdog,
) -> Result<serde_json::Value, String> {
    let value: serde_json::Value =
        serde_json::from_str(&read_line(stream, Duration::from_secs(2))?)
            .map_err(|e| e.to_string())?;
    if value["kind"].as_str() == Some("health") {
        let req: HealthRequest = serde_json::from_value(value).map_err(|e| e.to_string())?;
        validate_health_request(&req, cfg)?;
        watchdog.health_success();
        return Ok(serde_json::json!({"ok":true,"protocol":4,"kind":"health"}));
    }
    let req: Request = serde_json::from_value(value).map_err(|e| e.to_string())?;
    validate_request(&req, cfg)?;
    if STOP.load(Ordering::Relaxed) || host_pid()? != req.pid {
        return Err("RC003 驱动宿主变化，等待自动重连".into());
    }
    let deadline = watchdog.begin_operation(
        Instant::now(),
        Duration::from_millis(u64::from(req.deadline_ms)),
    )?;
    let result = inject(
        req.pid,
        req.port,
        &req.token,
        &root()?.join("frida-gadget.dll"),
        Some(&cfg.owner_sid),
        deadline,
    );
    match result {
        Ok(()) => {
            watchdog.complete_operation();
            Ok(serde_json::json!({"ok":true}))
        }
        Err(error) => {
            let unrecoverable = error.contains("远程加载超时");
            watchdog.fail_operation(Instant::now(), deadline, unrecoverable);
            Err(error)
        }
    }
}
pub fn request(pid: u32, port: u16, token: &str) -> Result<(), String> {
    let cfg = config()?;
    let mut stream = TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], cfg.port)),
        Duration::from_secs(2),
    )
    .map_err(|e| format!("旁路服务未运行：{e}"))?;
    // The service may spend the full 45-second operation budget in the
    // native path. Leave transport headroom for response serialization and
    // the final socket read so the desktop does not report a false timeout.
    stream
        .set_read_timeout(Some(Duration::from_secs(55)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| e.to_string())?;
    writeln!(
        stream,
        "{}",
        serde_json::to_string(&Request {
            secret: cfg.secret,
            pid,
            port,
            token: token.into(),
            deadline_ms: 45_000,
        })
        .unwrap()
    )
    .map_err(|e| e.to_string())?;
    let response: serde_json::Value =
        serde_json::from_str(&read_line(&mut stream, Duration::from_secs(55))?)
            .map_err(|e| e.to_string())?;
    if response["ok"] == true {
        Ok(())
    } else {
        Err(response["error"].as_str().unwrap_or("旁路服务失败").into())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_acl_contract_accepts_only_fixed_runtime_inputs() {
        let root = PathBuf::from(r"C:\Program Files\MiControlRC003HidService");
        let runtime = root.join("runtime");
        assert_eq!(
            runtime_path_for_target(&root, RuntimeAclTarget::ServiceRoot),
            root
        );
        assert_eq!(
            runtime_path_for_target(&root, RuntimeAclTarget::RuntimeDirectory),
            runtime
        );
        assert_eq!(
            runtime_path_for_target(&root, RuntimeAclTarget::RuntimeDll),
            runtime.join("MiControlRC003HidTap.dll")
        );
        assert!(runtime_read_file_name_allowed(OsStr::new(
            "MiControlRC003HidTap.tmp"
        )));
        assert!(runtime_read_file_name_allowed(OsStr::new(
            "rc003_hid_tap.tmp"
        )));
        assert!(runtime_read_file_name_allowed(OsStr::new("endpoint.tmp")));
        assert!(!runtime_read_file_name_allowed(OsStr::new("broker.tmp")));
        assert!(!runtime_read_file_name_allowed(OsStr::new("service.log")));
        assert!(!runtime_read_file_name_allowed(OsStr::new(
            "MiControlRC003HidTap.config"
        )));
        for value in [
            "root",
            "runtime",
            "dll",
            "config-temp",
            "script-temp",
            "endpoint-temp",
        ] {
            assert!(RuntimeAclHelperTarget::parse(value).is_ok());
        }
        for value in [
            r"C:\Program Files\MiControlRC003HidService\runtime\broker.json",
            "../runtime",
            "dll MiControlRC003HidTap.dll",
            "",
        ] {
            assert!(RuntimeAclHelperTarget::parse(value).is_err());
        }
    }

    #[test]
    fn runtime_dll_acl_access_requires_exact_trusted_root_relative_path() {
        let root = PathBuf::from(r"C:\Program Files\MiControlRC003HidService");
        let dll = root.join("runtime").join("MiControlRC003HidTap.dll");
        assert!(is_exact_runtime_dll_path(&root, &dll, false));
        assert!(is_exact_runtime_dll_path(
            &root,
            Path::new(
                r"c:\program files\micontrolrc003hidservice\RUNTIME\micontrolrc003hidtap.dll"
            ),
            false
        ));
        assert!(!is_exact_runtime_dll_path(
            &PathBuf::from(r"D:\Program Files\MiControlRC003HidService"),
            &dll,
            false
        ));
        assert!(!is_exact_runtime_dll_path(
            &root,
            &root.join("runtime").join("MiControlRC003HidTap.dll.bak"),
            false
        ));
        assert!(!is_exact_runtime_dll_path(
            &root,
            &root
                .join("runtime")
                .join("MiControlRC003HidTap.dll")
                .join("extra"),
            false
        ));
        assert!(!is_exact_runtime_dll_path(&root, &dll, true));
    }

    fn apply_fixture_file_acl(
        handle: HANDLE,
        owner: &str,
        local_service_access: Option<u32>,
    ) -> Result<(), String> {
        let system = sid_bytes("S-1-5-18")?;
        let administrators = sid_bytes("S-1-5-32-544")?;
        let owner = sid_bytes(owner)?;
        let local_service = sid_bytes("S-1-5-19")?;
        let mut entries = vec![
            (&system[..], FILE_ALL_ACCESS.0, ACE_FLAGS(0)),
            (&administrators[..], FILE_ALL_ACCESS.0, ACE_FLAGS(0)),
            (
                &owner[..],
                FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0,
                ACE_FLAGS(0),
            ),
        ];
        if let Some(access) = local_service_access {
            entries.push((&local_service[..], access, ACE_FLAGS(0)));
        }
        set_acl_entries(handle, &entries)
    }

    fn local_service_acl_records(handle: HANDLE) -> Result<Vec<FixtureAceRecord>, String> {
        let descriptor = fixture_security_descriptor(handle)?;
        let local_service = sid_bytes("S-1-5-19")?;
        let (_, _, records) = descriptor_acl_records(&descriptor)?;
        Ok(records
            .into_iter()
            .filter(|record| record.ace_type == 0 && record.sid == local_service)
            .collect())
    }

    fn restore_fixture_cleanup_acl(
        path: &Path,
        directory: bool,
        owner: &str,
    ) -> Result<(), String> {
        let handle = open_acl_handle(path, directory)?;
        let system = sid_bytes("S-1-5-18")?;
        let administrators = sid_bytes("S-1-5-32-544")?;
        let owner = sid_bytes(owner)?;
        let inherited = inherited_ace_flags(directory);
        set_acl_entries(
            handle.0,
            &[
                (&system, FILE_ALL_ACCESS.0, inherited),
                (&administrators, FILE_ALL_ACCESS.0, inherited),
                (&owner, FILE_ALL_ACCESS.0, inherited),
            ],
        )
    }

    #[test]
    fn exact_runtime_acl_fixture_reads_back_local_service_contract() {
        let owner = current_user_sid().expect("读取 ACL fixture owner SID");
        let root = std::env::temp_dir().join(format!(
            "MiControl-runtime-acl-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("读取 fixture nonce")
                .as_nanos()
        ));
        let runtime = root.join("runtime");
        let dll = runtime.join("MiControlRC003HidTap.dll");
        let temp_names = [
            "MiControlRC003HidTap.tmp",
            "rc003_hid_tap.tmp",
            "endpoint.tmp",
        ];
        let unknown_names = ["broker.json", ".rc003-injection-pending.json"];
        let helper = root.join("helper-runtime");
        std::fs::create_dir_all(&runtime).expect("创建 runtime ACL fixture");
        std::fs::create_dir_all(&helper).expect("创建 helper ACL fixture");
        std::fs::write(&dll, b"dll").expect("创建 DLL ACL fixture");
        for name in temp_names.iter().chain(unknown_names.iter()) {
            std::fs::write(runtime.join(name), b"fixture").expect("创建文件 ACL fixture");
        }

        let result = (|| -> Result<(), String> {
            {
                let handle = open_acl_handle(&root, true)?;
                set_exact_acl(handle.0, true, &owner, true)?;
                let records = local_service_acl_records(handle.0)?;
                if records.len() != 1
                    || records[0].mask != Some(FILE_TRAVERSE.0)
                    || records[0].flags != 0
                {
                    return Err(format!(
                        "服务 root LocalService ACE 不符合精确契约：{records:?}"
                    ));
                }
            }
            {
                let handle = open_acl_handle(&runtime, true)?;
                set_exact_acl(handle.0, true, &owner, true)?;
                let records = local_service_acl_records(handle.0)?;
                if records.len() != 1
                    || records[0].mask != Some(FILE_TRAVERSE.0)
                    || records[0].flags != 0
                {
                    return Err(format!(
                        "runtime 目录 LocalService ACE 不符合精确契约：{records:?}"
                    ));
                }
            }
            {
                let handle = open_acl_handle(&dll, false)?;
                apply_fixture_file_acl(
                    handle.0,
                    &owner,
                    Some(FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0),
                )?;
                let records = local_service_acl_records(handle.0)?;
                if records.len() != 1
                    || records[0].mask != Some(FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0)
                    || records[0].flags != 0
                {
                    return Err(format!(
                        "runtime DLL LocalService ACE 不符合精确契约：{records:?}"
                    ));
                }
            }
            for name in temp_names {
                let path = runtime.join(name);
                let handle = open_acl_handle(&path, false)?;
                apply_fixture_file_acl(handle.0, &owner, Some(FILE_GENERIC_READ.0))?;
                let records = local_service_acl_records(handle.0)?;
                if records.len() != 1
                    || records[0].mask != Some(FILE_GENERIC_READ.0)
                    || records[0].flags != 0
                {
                    return Err(format!(
                        "runtime temp LocalService ACE 不符合精确契约 path={} records={records:?}",
                        path.display()
                    ));
                }
            }
            for name in unknown_names {
                let path = runtime.join(name);
                let handle = open_acl_handle(&path, false)?;
                apply_fixture_file_acl(handle.0, &owner, None)?;
                if !local_service_acl_records(handle.0)?.is_empty() {
                    return Err(format!(
                        "未知 runtime 文件意外获得 LocalService ACE：{}",
                        path.display()
                    ));
                }
            }
            {
                let handle = open_acl_handle(&helper, true)?;
                set_exact_acl(handle.0, true, &owner, false)?;
                if !local_service_acl_records(handle.0)?.is_empty() {
                    return Err("helper 运行目录意外获得 LocalService ACE".into());
                }
            }
            Ok(())
        })();

        let mut cleanup_errors = Vec::new();
        for name in temp_names.iter().chain(unknown_names.iter()) {
            let path = runtime.join(name);
            if let Err(error) = restore_fixture_cleanup_acl(&path, false, &owner) {
                cleanup_errors.push(format!("{}: {error}", path.display()));
            }
        }
        if let Err(error) = restore_fixture_cleanup_acl(&dll, false, &owner) {
            cleanup_errors.push(format!("{}: {error}", dll.display()));
        }
        for path in [&helper, &runtime, &root] {
            if let Err(error) = restore_fixture_cleanup_acl(path, true, &owner) {
                cleanup_errors.push(format!("{}: {error}", path.display()));
            }
        }
        for name in temp_names.iter().chain(unknown_names.iter()) {
            if let Err(error) = std::fs::remove_file(runtime.join(name)) {
                cleanup_errors.push(error.to_string());
            }
        }
        if let Err(error) = std::fs::remove_file(&dll) {
            cleanup_errors.push(error.to_string());
        }
        for path in [&helper, &runtime, &root] {
            if let Err(error) = std::fs::remove_dir(path) {
                cleanup_errors.push(format!("{}: {error}", path.display()));
            }
        }
        assert!(
            cleanup_errors.is_empty(),
            "ACL fixture 清理失败：{cleanup_errors:?}"
        );
        result.expect("exact runtime ACL fixture failed");
    }

    fn accept_loopback(listener: &TcpListener) -> TcpStream {
        loop {
            match listener.accept() {
                Ok((stream, _)) => return stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("loopback accept failed: {error}"),
            }
        }
    }

    #[test]
    fn locked_runtime_dll_uses_minimum_acl_rights_and_unknown_files_keep_strict_open() {
        let owner = current_user_sid().expect("读取 ACL fixture owner SID");
        let root = std::env::temp_dir().join(format!(
            "MiControl-runtime-dll-share-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("读取 fixture nonce")
                .as_nanos()
        ));
        let runtime = root.join("runtime");
        let dll = runtime.join("MiControlRC003HidTap.dll");
        let unknown = runtime.join("broker.json");
        std::fs::create_dir_all(&runtime).expect("创建共享锁 fixture");
        std::fs::write(&dll, b"dll").expect("创建 DLL 共享锁 fixture");
        std::fs::write(&unknown, b"unknown").expect("创建未知文件共享锁 fixture");

        let result = (|| -> Result<(), String> {
            let dll_lock = open_shared_read_fixture(&dll)?;
            let old_error = open_acl_handle(&dll, false)
                .err()
                .ok_or_else(|| "旧 MAXIMUM_ALLOWED 路径意外绕过共享锁".to_string())?;
            if !old_error.contains("0x80070020") && !old_error.contains("32") {
                return Err(format!(
                    "旧 MAXIMUM_ALLOWED 路径共享冲突错误缺少 ERROR_SHARING_VIOLATION：{old_error}"
                ));
            }

            let handle = open_acl_handle_for_tree(&root, &dll, false)?;
            let before = fixture_security_descriptor(handle.0)?;
            let before_identity = descriptor_acl_identity(&before, "共享锁 fixture owner 前")?;
            apply_fixture_file_acl(
                handle.0,
                &owner,
                Some(FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0),
            )?;
            set_owner_handle(handle.0, &owner)?;
            let after = fixture_security_descriptor(handle.0)?;
            let after_identity = descriptor_acl_identity(&after, "共享锁 fixture owner 后")?;
            if after_identity.owner != sid_bytes(&owner)? {
                return Err("最小权限句柄 owner 读回不匹配".into());
            }
            if after_identity.dacl == before_identity.dacl {
                return Err("最小权限句柄未实际修改 DACL".into());
            }
            let records = local_service_acl_records(handle.0)?;
            if records.len() != 1
                || records[0].mask != Some(FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0)
            {
                return Err(format!("最小权限句柄 DACL 读回不匹配：{records:?}"));
            }
            drop(handle);
            drop(dll_lock);

            let unknown_lock = open_shared_read_fixture(&unknown)?;
            let unknown_error = open_acl_handle_for_tree(&root, &unknown, false)
                .err()
                .ok_or_else(|| "未知文件错误地获得 runtime DLL 最小权限例外".to_string())?;
            if !unknown_error.contains("0x80070020") && !unknown_error.contains("32") {
                return Err(format!(
                    "未知文件严格 MAXIMUM_ALLOWED 共享冲突错误缺少 ERROR_SHARING_VIOLATION：{unknown_error}"
                ));
            }
            drop(unknown_lock);
            Ok(())
        })();
        let _ = std::fs::remove_dir_all(&root);
        result.expect("共享锁 ACL fixture 应验证精确 DLL 例外与未知文件严格失败");
    }

    fn open_shared_read_fixture(path: &Path) -> Result<OwnedHandle, String> {
        let wide_path = wide(path);
        unsafe {
            CreateFileW(
                PCWSTR(wide_path.as_ptr()),
                FILE_GENERIC_READ.0,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
        }
        .map(OwnedHandle)
        .map_err(|error| format!("打开共享读锁 fixture 失败：{}（{error}）", path.display()))
    }

    #[test]
    fn nonblocking_listener_accepted_stream_reads_delayed_request() {
        use std::io::Write;

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
        listener
            .set_nonblocking(true)
            .expect("set listener nonblocking");
        let address = listener.local_addr().expect("listener address");
        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).expect("connect loopback listener");
            thread::sleep(Duration::from_millis(50));
            stream
                .write_all(b"delayed-request\n")
                .expect("send delayed request");
        });

        let mut stream = configure_broker_client_stream(accept_loopback(&listener))
            .expect("configure accepted stream");
        assert_eq!(
            read_line(&mut stream, Duration::from_secs(1)).expect("read delayed request"),
            "delayed-request"
        );
        client.join().expect("client thread");
    }

    #[test]
    fn accepted_stream_read_timeout_remains_bounded() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
        listener
            .set_nonblocking(true)
            .expect("set listener nonblocking");
        let address = listener.local_addr().expect("listener address");
        let client = thread::spawn(move || {
            let _stream = TcpStream::connect(address).expect("connect loopback listener");
            thread::sleep(Duration::from_millis(250));
        });

        let mut stream = configure_broker_client_stream(accept_loopback(&listener))
            .expect("configure accepted stream");
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("set bounded read timeout");
        let began = Instant::now();
        assert!(read_line(&mut stream, Duration::from_millis(100)).is_err());
        assert!(began.elapsed() < Duration::from_secs(1));
        client.join().expect("client thread");
    }

    #[test]
    fn broker_accepts_only_fixed_schema_and_authenticated_endpoint() {
        let cfg = BrokerConfig {
            port: 100,
            secret: "a".repeat(64),
            owner_sid: "S-1-5-21-1".into(),
            protocol: 4,
        };
        let mut req = Request {
            secret: cfg.secret.clone(),
            pid: 42,
            port: 100,
            token: "b".repeat(64),
            deadline_ms: 45_000,
        };
        assert!(validate_request(&req, &cfg).is_ok());
        req.secret = "bad".into();
        assert!(validate_request(&req, &cfg).is_err());
        req.secret = cfg.secret.clone();
        req.pid = 0;
        assert!(validate_request(&req, &cfg).is_err());
        req.pid = 42;
        req.token = "bad".into();
        assert!(validate_request(&req, &cfg).is_err());
        assert!(serde_json::from_str::<Request>(
            r#"{"secret":"a","pid":42,"port":3,"token":"b","source":"evil.dll"}"#
        )
        .is_err());
    }

    #[test]
    fn legacy_protocol4_request_defaults_to_full_operation_budget() {
        let request: Request = serde_json::from_str(
            r#"{"secret":"a","pid":42,"port":3,"token":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#,
        )
        .expect("legacy protocol4 request remains decodable");
        assert_eq!(request.deadline_ms, 45_000);
    }

    #[test]
    fn request_budget_rejects_zero_and_values_above_service_cap() {
        let cfg = BrokerConfig {
            port: 100,
            secret: "a".repeat(64),
            owner_sid: "S-1-5-21-1".into(),
            protocol: 4,
        };
        let mut request: Request = serde_json::from_value(serde_json::json!({
            "secret": cfg.secret.clone(),
            "pid": 42,
            "port": 100,
            "token": "b".repeat(64),
            "deadline_ms": 1,
        }))
        .unwrap();
        assert!(validate_request(&request, &cfg).is_ok());
        request.deadline_ms = 0;
        assert!(validate_request(&request, &cfg).is_err());
        request.deadline_ms = 45_001;
        assert!(validate_request(&request, &cfg).is_err());
    }

    #[test]
    fn watchdog_busy_deadline_is_nonrenewable_and_fault_latches() {
        let now = Instant::now();
        let watchdog = Watchdog::new(now);
        let deadline = watchdog
            .begin_operation(now, MAX_OPERATION_DEADLINE)
            .expect("first operation starts");
        assert!(watchdog
            .begin_operation(now, Duration::from_secs(1))
            .is_err());
        assert!(!watchdog.tick(deadline - Duration::from_millis(1), None));
        assert!(watchdog.tick(deadline + Duration::from_millis(1), None));
        watchdog.complete_operation();
        assert!(watchdog.fault_latched());
        assert!(watchdog
            .begin_operation(now, Duration::from_secs(1))
            .is_err());
    }

    #[test]
    fn watchdog_idle_probe_requires_consecutive_failures_and_success_clears_count() {
        let now = Instant::now();
        let watchdog = Watchdog::new(now);
        let first = now + SERVICE_STARTUP_GRACE + Duration::from_millis(1);
        assert!(!watchdog.tick(first, Some(false)));
        assert!(!watchdog.tick(first + HEALTH_PROBE_INTERVAL, Some(false)));
        // A successful probe clears ordinary jitter before the threshold.
        assert!(!watchdog.tick(first + HEALTH_PROBE_INTERVAL * 2, Some(true)));
        assert!(!watchdog.tick(first + HEALTH_PROBE_INTERVAL * 3, Some(false)));
        assert!(!watchdog.tick(first + HEALTH_PROBE_INTERVAL * 4, Some(false)));
        assert!(watchdog.tick(first + HEALTH_PROBE_INTERVAL * 5, Some(false)));
    }

    #[test]
    fn recovery_preserves_null_and_empty_unowned_strings_exactly() {
        let before = FailureActionsSnapshot {
            reset_period: 1,
            reboot_message: None,
            command: Some(String::new()),
            actions: Vec::new(),
        };
        let after = before.clone();
        assert!(recovery_preserves_unowned_strings(Some(&before), &after));
        let changed = FailureActionsSnapshot {
            command: None,
            ..after
        };
        assert!(!recovery_preserves_unowned_strings(Some(&before), &changed));
    }
    #[test]
    fn broker_health_requires_protocol4_secret_and_fixed_schema() {
        let cfg = BrokerConfig {
            port: 100,
            secret: "a".repeat(64),
            owner_sid: "S-1-5-21-1".into(),
            protocol: 4,
        };
        let request = HealthRequest {
            kind: "health".into(),
            secret: cfg.secret.clone(),
        };
        assert!(validate_health_request(&request, &cfg).is_ok());
        assert!(validate_health_request(
            &HealthRequest {
                kind: "health".into(),
                secret: "wrong".into(),
            },
            &cfg,
        )
        .is_err());
        assert!(serde_json::from_str::<HealthRequest>(&format!(
            r#"{{"kind":"health","secret":"{}","pid":1}}"#,
            cfg.secret
        ))
        .is_err());
    }
    #[test]
    fn installer_sid_rejects_command_arguments() {
        assert!(valid_sid("S-1-5-21-123"));
        assert!(!valid_sid("S-1-5-21 /grant Everyone:F"));
    }

    #[test]
    fn sid_bytes_matches_system_well_known_sid() {
        use windows::Win32::Security::{
            CreateWellKnownSid, EqualSid, IsWellKnownSid, WinLocalSystemSid, PSID,
        };
        let sid = sid_bytes("S-1-5-18").expect("system SID parses");
        let mut expected = [0u8; 68];
        let mut expected_len = expected.len() as u32;
        unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                None,
                Some(PSID(expected.as_mut_ptr() as *mut _)),
                &mut expected_len,
            )
            .expect("system SID constructs");
            let actual = PSID(sid.as_ptr() as *mut _);
            assert!(IsWellKnownSid(actual, WinLocalSystemSid).as_bool());
            assert!(EqualSid(actual, PSID(expected.as_mut_ptr() as *mut _)).is_ok());
        }
    }

    #[test]
    fn parses_numeric_scm_state_without_localized_text() {
        assert_eq!(
            parse_service_state(
                "SERVICE_NAME: MiControlRC003HidTap\n    STATE              : 4  RUNNING\n"
            ),
            Some(4)
        );
        assert_eq!(
            parse_service_state(
                "SERVICE_NAME: MiControlRC003HidTap\n    STATE              : 1  STOPPED\n"
            ),
            Some(1)
        );
        assert_eq!(
            parse_service_state("service query output without state"),
            None
        );
    }

    #[test]
    fn copies_unicode_service_description_before_query_buffer_is_dropped() {
        let text = wide("旁路服务中文描述");
        let header_units =
            std::mem::size_of::<SERVICE_DESCRIPTIONW>().div_ceil(std::mem::size_of::<u64>());
        let total_units = header_units
            + (text.len() * std::mem::size_of::<u16>()).div_ceil(std::mem::size_of::<u64>());
        let mut buffer = vec![0u64; total_units];
        unsafe {
            let text_pointer = buffer.as_mut_ptr() as *mut u16;
            let text_offset = header_units * std::mem::size_of::<u64>() / 2;
            std::ptr::copy_nonoverlapping(text.as_ptr(), text_pointer.add(text_offset), text.len());
            let description = buffer.as_mut_ptr() as *mut SERVICE_DESCRIPTIONW;
            (*description).lpDescription = PWSTR(text_pointer.add(text_offset));
            let owned = copy_utf16_string(
                (*description).lpDescription,
                buffer.as_ptr() as *const u8,
                std::mem::size_of_val(buffer.as_slice()),
            )
            .expect("unicode description copies");
            assert_eq!(owned, "旁路服务中文描述");
        }
    }

    #[test]
    fn install_failure_preserves_primary_error_when_rollback_succeeds() {
        let message = format_install_failure("broker_health_wait 失败", Ok(()));
        assert_eq!(message, "broker_health_wait 失败；rollback=passed");
    }

    #[test]
    fn install_failure_preserves_primary_and_rollback_errors() {
        let message = format_install_failure("主程序缺失", Err("cleanup helper 缺失".into()));
        assert_eq!(message, "主程序缺失；rollback=failed：cleanup helper 缺失");
    }

    #[test]
    fn transaction_sibling_is_private_and_never_the_fixed_root() {
        let root = Path::new(r"C:\Program Files\MiControlRC003HidService");
        let staging = transaction_sibling(root, "staging").expect("sibling path");
        let backup = transaction_sibling(root, "backup").expect("sibling path");
        assert_ne!(staging, root);
        assert_ne!(backup, root);
        assert!(staging.starts_with(root.parent().unwrap()));
        assert!(backup.starts_with(root.parent().unwrap()));
        assert!(staging
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains(".staging-"));
        assert!(backup
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains(".backup-"));
    }

    #[derive(Default)]
    struct MockInstallOps {
        fail_stage: Option<&'static str>,
        events: Vec<&'static str>,
    }

    impl MockInstallOps {
        fn stage(&mut self, name: &'static str) -> Result<(), String> {
            self.events.push(name);
            if self.fail_stage == Some(name) {
                Err(format!("injected {name} failure"))
            } else {
                Ok(())
            }
        }

        fn run(
            fail_stage: Option<&'static str>,
        ) -> (Self, Result<InstallMutation, InstallTransactionFailure>) {
            let mut ops = Self {
                fail_stage,
                ..Default::default()
            };
            let result = run_install_transaction(&mut ops, true, true);
            (ops, result)
        }
    }

    impl InstallOps for MockInstallOps {
        fn stop_existing(&mut self) -> Result<(), String> {
            self.stage("existing_service_stop")
        }
        fn recover_old_tree(&mut self) -> Result<(), String> {
            self.stage("old_service_root_recover")
        }
        fn backup_old_tree(&mut self) -> Result<(), String> {
            self.stage("old_service_root_backup")
        }
        fn activate_candidate(&mut self) -> Result<(), String> {
            self.stage("service_root_activate")
        }
        fn configure_existing(&mut self) -> Result<(), String> {
            self.stage("sc_config")
        }
        fn create_service(&mut self) -> Result<(), String> {
            self.stage("sc_create")
        }
        fn start_and_wait_health(&mut self) -> Result<(), String> {
            self.stage("broker_health_wait")
        }
        fn protect_service(&mut self) -> Result<(), String> {
            self.stage("sc_acl")
        }
        fn cleanup_backup(&mut self) -> Result<(), String> {
            self.stage("backup_cleanup")
        }
    }

    #[test]
    fn production_transaction_state_machine_tracks_each_partial_side_effect() {
        for stage in [
            "existing_service_stop",
            "old_service_root_recover",
            "old_service_root_backup",
            "service_root_activate",
            "sc_config",
            "broker_health_wait",
            "sc_acl",
        ] {
            let (ops, result) = MockInstallOps::run(Some(stage));
            let failure = result.expect_err("injected stage must fail");
            assert!(failure.error.contains(stage));
            assert!(ops.events.contains(&stage));
            if stage == "existing_service_stop" {
                assert_eq!(ops.events, vec!["existing_service_stop"]);
                assert!(!failure.mutation.old_root_backed_up);
            }
            if stage == "old_service_root_backup" {
                assert!(failure.mutation.old_tree_touched);
                assert!(!failure.mutation.old_root_backed_up);
                assert!(!failure.mutation.swapped);
            }
            if stage == "sc_config" {
                assert!(failure.mutation.old_root_backed_up);
                assert!(failure.mutation.swapped);
                assert!(failure.mutation.service_config_changed);
            }
        }
    }

    #[test]
    fn production_transaction_commits_before_backup_cleanup_failure() {
        let (mut ops, result) = MockInstallOps::run(None);
        let mutation = result.expect("transaction must commit");
        assert!(mutation.swapped);
        assert!(mutation.old_root_backed_up);
        ops.fail_stage = Some("backup_cleanup");
        assert!(ops.cleanup_backup().is_err());
        assert_eq!(ops.events.last(), Some(&"backup_cleanup"));
    }

    #[derive(Default)]
    struct MockRollbackOps {
        fail_stage: Option<&'static str>,
        events: Vec<&'static str>,
    }

    impl MockRollbackOps {
        fn stage(&mut self, name: &'static str) -> Result<(), String> {
            self.events.push(name);
            if self.fail_stage == Some(name) {
                Err(format!("injected {name} failure"))
            } else {
                Ok(())
            }
        }
    }

    impl RollbackOps for MockRollbackOps {
        fn stop_candidate(&mut self) -> Result<(), String> {
            self.stage("stop_candidate")
        }
        fn delete_created_service(&mut self) -> Result<(), String> {
            self.stage("delete_created_service")
        }
        fn cleanup_active_candidate(&mut self) -> Result<(), String> {
            self.stage("cleanup_active_candidate")
        }
        fn restore_old_tree(&mut self) -> Result<(), String> {
            self.stage("restore_old_tree")
        }
        fn restore_old_tree_security(&mut self) -> Result<(), String> {
            self.stage("restore_old_tree_security")
        }
        fn restore_old_service_configuration(&mut self) -> Result<(), String> {
            self.stage("restore_old_service_configuration")
        }
        fn cleanup_staging(&mut self) -> Result<(), String> {
            self.stage("cleanup_staging")
        }
        fn restart_old_service(&mut self) -> Result<(), String> {
            self.stage("restart_old_service")
        }
    }

    fn full_rollback_mutation() -> InstallMutation {
        InstallMutation {
            service_stopped: true,
            service_created: true,
            service_config_changed: true,
            service_dacl_changed: true,
            old_tree_touched: true,
            old_root_backed_up: true,
            swapped: true,
        }
    }

    #[test]
    fn production_rollback_stop_failure_preserves_all_transaction_trees() {
        let mut ops = MockRollbackOps {
            fail_stage: Some("stop_candidate"),
            ..Default::default()
        };
        let result = run_rollback(&mut ops, &full_rollback_mutation(), true, true);
        assert!(result
            .expect_err("stop failure must fail rollback")
            .contains("保留 candidate/backup"));
        assert_eq!(ops.events, vec!["stop_candidate"]);
    }

    #[test]
    fn production_rollback_restores_tree_and_scm_before_restart() {
        let mut ops = MockRollbackOps::default();
        run_rollback(&mut ops, &full_rollback_mutation(), true, true)
            .expect("rollback ops succeed");
        assert_eq!(
            ops.events,
            vec![
                "stop_candidate",
                "delete_created_service",
                "cleanup_active_candidate",
                "restore_old_tree",
                "restore_old_tree_security",
                "restore_old_service_configuration",
                "cleanup_staging",
                "restart_old_service",
            ]
        );
    }

    #[test]
    fn production_rollback_preserves_primary_and_restore_errors() {
        let mut ops = MockRollbackOps {
            fail_stage: Some("restore_old_tree"),
            ..Default::default()
        };
        let rollback = run_rollback(&mut ops, &full_rollback_mutation(), true, true);
        let combined = format_install_failure("health failed", rollback);
        assert!(combined.contains("health failed"));
        assert!(combined.contains("恢复旧服务目录失败"));
        assert!(!ops.events.contains(&"restore_old_tree_security"));
        assert!(ops.events.contains(&"restore_old_service_configuration"));
    }

    #[test]
    fn service_owner_descriptor_is_start_and_query_only() {
        let sid = "S-1-5-21-123";
        let descriptor = service_security_descriptor(sid);
        assert!(descriptor.contains("(A;;LCRP;;;S-1-5-21-123)"));
        assert!(!descriptor.contains("(A;;LCRPWP"));
        assert!(!descriptor.contains("(A;;LCRPSD"));
        assert!(!descriptor.contains("(A;;LCRPDC"));
    }

    fn open_fixture_security_handle(path: &Path, directory: bool) -> Result<OwnedHandle, String> {
        use windows::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        };
        let display = path.display().to_string();
        let path = wide(path);
        let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
        if directory {
            flags |= FILE_FLAG_BACKUP_SEMANTICS;
        }
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path.as_ptr()),
                MAXIMUM_ALLOWED,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                flags,
                None,
            )
        }
        .map_err(|error| format!("预留 fixture 安全句柄失败（{display}）：{error}"))?;
        let handle = OwnedHandle(handle);
        let (actual_directory, is_reparse) = recovery_attributes(handle.0)
            .map_err(|error| format!("校验 fixture 安全句柄失败：{display}（{error}）"))?;
        if is_reparse || actual_directory != directory {
            return Err(format!(
                "fixture 安全句柄类型或 reparse 属性不匹配：{display}"
            ));
        }
        Ok(handle)
    }

    fn fixture_security_descriptor(handle: HANDLE) -> Result<Vec<u8>, String> {
        use windows::Win32::Security::{
            GetKernelObjectSecurity, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR,
        };
        let requested = (OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION).0;
        let mut required = 0u32;
        unsafe {
            let _ = GetKernelObjectSecurity(handle, requested, None, 0, &mut required);
        }
        if required == 0 {
            return Err("查询 fixture 安全描述符大小失败".into());
        }
        let mut descriptor = vec![0u8; required as usize];
        unsafe {
            GetKernelObjectSecurity(
                handle,
                requested,
                Some(PSECURITY_DESCRIPTOR(descriptor.as_mut_ptr() as *mut _)),
                descriptor.len() as u32,
                &mut required,
            )
            .map_err(|error| format!("读取 fixture 安全描述符失败：{error}"))?;
        }
        descriptor.truncate(required as usize);
        Ok(descriptor)
    }

    fn fixture_security_identity(
        path: &Path,
        directory: bool,
    ) -> Result<DescriptorAclIdentity, String> {
        let handle = open_fixture_security_handle(path, directory)?;
        let descriptor = fixture_security_descriptor(handle.0)?;
        descriptor_acl_identity(
            &descriptor,
            &format!("读取 fixture 安全摘要 {}", path.display()),
        )
    }

    fn descriptor_diagnostic(descriptor: &[u8]) -> String {
        use windows::core::BOOL;
        use windows::Win32::Security::{
            GetAce, GetLengthSid, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
            GetSecurityDescriptorOwner, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, PSECURITY_DESCRIPTOR,
        };
        let descriptor_ptr = PSECURITY_DESCRIPTOR(descriptor.as_ptr() as *mut _);
        let mut control = 0u16;
        let mut sd_revision = 0u32;
        let mut owner = PSID::default();
        let mut owner_defaulted = BOOL(0);
        let mut dacl_present = BOOL(0);
        let mut dacl = std::ptr::null_mut::<ACL>();
        let mut dacl_defaulted = BOOL(0);
        unsafe {
            if GetSecurityDescriptorControl(descriptor_ptr, &mut control, &mut sd_revision).is_err()
                || GetSecurityDescriptorOwner(descriptor_ptr, &mut owner, &mut owner_defaulted)
                    .is_err()
                || GetSecurityDescriptorDacl(
                    descriptor_ptr,
                    &mut dacl_present,
                    &mut dacl,
                    &mut dacl_defaulted,
                )
                .is_err()
            {
                return "descriptor diagnostic unavailable".into();
            }
            let owner_text = sid_to_string(owner).unwrap_or_else(|error| error);
            let mut result = format!(
                "sd_revision={} control=0x{control:04x} owner_sid={} dacl_present={} ",
                sd_revision,
                owner_text,
                dacl_present.as_bool()
            );
            if !dacl_present.as_bool() || dacl.is_null() {
                result.push_str("dacl=null");
                return result;
            }
            result.push_str(&format!(
                "acl_revision={} acl_size={} ace_count={}",
                (*dacl).AclRevision,
                (*dacl).AclSize,
                (*dacl).AceCount
            ));
            for index in 0..(*dacl).AceCount {
                let mut ace = std::ptr::null_mut();
                if GetAce(dacl, u32::from(index), &mut ace).is_err() || ace.is_null() {
                    result.push_str(&format!(" ace[{index}]=unreadable"));
                    continue;
                }
                let header = &*(ace as *const ACE_HEADER);
                let ace_size = usize::from(header.AceSize);
                let raw = std::slice::from_raw_parts(ace as *const u8, ace_size);
                let raw_hex = raw
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join("");
                let (mask, sid_text) = if ace_size >= std::mem::size_of::<ACCESS_ALLOWED_ACE>() {
                    let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
                    let sid = PSID(&allowed.SidStart as *const _ as *mut _);
                    let sid_text = if GetLengthSid(sid) == 0 {
                        "invalid-sid".into()
                    } else {
                        sid_to_string(sid).unwrap_or_else(|error| error)
                    };
                    (format!("0x{:08x}", allowed.Mask), sid_text)
                } else {
                    ("n/a".into(), "n/a".into())
                };
                result.push_str(&format!(
                    " ace[{index}]={{type={},flags=0x{:02x},size={},mask={},sid={},raw={}}}",
                    header.AceType, header.AceFlags, ace_size, mask, sid_text, raw_hex
                ));
            }
            result
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct FixtureAceRecord {
        ace_type: u8,
        flags: u8,
        mask: Option<u32>,
        sid: Vec<u8>,
        raw: Vec<u8>,
    }

    fn descriptor_acl_records(
        descriptor: &[u8],
    ) -> Result<(u8, u16, Vec<FixtureAceRecord>), String> {
        use windows::core::BOOL;
        use windows::Win32::Security::{
            GetAce, GetLengthSid, GetSecurityDescriptorDacl, ACCESS_ALLOWED_ACE, ACL,
            PSECURITY_DESCRIPTOR,
        };
        let descriptor_ptr = PSECURITY_DESCRIPTOR(descriptor.as_ptr() as *mut _);
        let mut present = BOOL(0);
        let mut dacl = std::ptr::null_mut::<ACL>();
        let mut defaulted = BOOL(0);
        unsafe {
            GetSecurityDescriptorDacl(descriptor_ptr, &mut present, &mut dacl, &mut defaulted)
                .map_err(|error| format!("读取 DACL 失败：{error}"))?;
            if !present.as_bool() || dacl.is_null() {
                return Err("descriptor 缺少显式 DACL".into());
            }
            let mut records = Vec::with_capacity(usize::from((*dacl).AceCount));
            for index in 0..(*dacl).AceCount {
                let mut ace = std::ptr::null_mut();
                GetAce(dacl, u32::from(index), &mut ace)
                    .map_err(|error| format!("读取 ACE {index} 失败：{error}"))?;
                if ace.is_null() {
                    return Err(format!("ACE {index} 为空"));
                }
                let header = &*(ace as *const windows::Win32::Security::ACE_HEADER);
                let size = usize::from(header.AceSize);
                if size < std::mem::size_of::<windows::Win32::Security::ACE_HEADER>() {
                    return Err(format!("ACE {index} 长度无效：{size}"));
                }
                let raw = std::slice::from_raw_parts(ace as *const u8, size).to_vec();
                let (mask, sid) = if size >= std::mem::size_of::<ACCESS_ALLOWED_ACE>() {
                    let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
                    let sid = PSID(&allowed.SidStart as *const _ as *mut _);
                    let sid_len = GetLengthSid(sid);
                    if sid_len == 0
                        || std::mem::size_of::<ACCESS_ALLOWED_ACE>() + sid_len as usize
                            - std::mem::size_of::<u32>()
                            > size
                    {
                        return Err(format!("ACE {index} SID 长度无效：{sid_len}"));
                    }
                    (
                        Some(allowed.Mask),
                        std::slice::from_raw_parts(sid.0 as *const u8, sid_len as usize).to_vec(),
                    )
                } else {
                    (None, Vec::new())
                };
                records.push(FixtureAceRecord {
                    ace_type: header.AceType,
                    flags: header.AceFlags,
                    mask,
                    sid,
                    raw,
                });
            }
            Ok(((*dacl).AclRevision, (*dacl).AclSize, records))
        }
    }

    fn expected_fixture_acl_after_protection(
        before: &[FixtureAceRecord],
        protected: bool,
    ) -> Vec<FixtureAceRecord> {
        const INHERITED_ACE: u8 = 0x10;
        let mut expected = before
            .iter()
            .map(|ace| {
                let mut normalized = ace.clone();
                if protected {
                    normalized.flags &= !INHERITED_ACE;
                    if normalized.raw.len() > 1 {
                        normalized.raw[1] = normalized.flags;
                    }
                }
                normalized
            })
            .collect::<Vec<_>>();
        if !protected {
            expected.extend(before.iter().map(|ace| {
                let mut inherited = ace.clone();
                inherited.flags |= INHERITED_ACE;
                if inherited.raw.len() > 1 {
                    inherited.raw[1] = inherited.flags;
                }
                inherited
            }));
        }
        expected
    }

    fn validate_fixture_acl_transition(
        before_revision: u8,
        before_size: u16,
        before: &[FixtureAceRecord],
        after_revision: u8,
        after_size: u16,
        after: &[FixtureAceRecord],
        protected: bool,
    ) -> Result<(), String> {
        let expected = expected_fixture_acl_after_protection(before, protected);
        let expected_size = if protected {
            before_size
        } else {
            (std::mem::size_of::<windows::Win32::Security::ACL>()
                + expected.iter().map(|ace| ace.raw.len()).sum::<usize>()) as u16
        };
        if before_revision != after_revision || after_size != expected_size || after != expected {
            return Err(format!(
                "expected_revision={} actual_revision={} expected_size={} actual_size={} expected_aces={:?} actual_aces={:?}",
                before_revision, after_revision, expected_size, after_size, expected, after
            ));
        }
        Ok(())
    }

    fn first_descriptor_diff(left: &[u8], right: &[u8]) -> String {
        match left
            .iter()
            .zip(right)
            .position(|(before, after)| before != after)
        {
            Some(index) => format!(
                "diff_index={} left_len={} right_len={}",
                index,
                left.len(),
                right.len()
            ),
            None if left.len() != right.len() => format!(
                "diff_index={} left_len={} right_len={}",
                left.len().min(right.len()),
                left.len(),
                right.len()
            ),
            None => "diff_index=none".into(),
        }
    }

    fn set_fixture_dacl_protection(
        handle: HANDLE,
        protected: bool,
        action: &str,
    ) -> Result<(), String> {
        use windows::core::BOOL;
        use windows::Win32::Security::{
            GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, UNPROTECTED_DACL_SECURITY_INFORMATION,
        };
        let descriptor = fixture_security_descriptor(handle)?;
        let before = descriptor_acl_identity(&descriptor, action)?;
        let descriptor_ptr = PSECURITY_DESCRIPTOR(descriptor.as_ptr() as *mut _);
        let mut dacl_present = BOOL(0);
        let mut dacl = std::ptr::null_mut::<ACL>();
        let mut dacl_defaulted = BOOL(0);
        unsafe {
            GetSecurityDescriptorDacl(
                descriptor_ptr,
                &mut dacl_present,
                &mut dacl,
                &mut dacl_defaulted,
            )
            .map_err(|error| format!("{action}读取 DACL 失败：{error}"))?;
        }
        if !dacl_present.as_bool() || dacl.is_null() {
            return Err(format!("{action}拒绝 absent/null DACL"));
        }
        let information = DACL_SECURITY_INFORMATION
            | if protected {
                PROTECTED_DACL_SECURITY_INFORMATION
            } else {
                UNPROTECTED_DACL_SECURITY_INFORMATION
            };
        set_security_info_checked(
            handle,
            information.0,
            None,
            Some(dacl as *const ACL),
            action,
        )?;
        let (after_descriptor, after_protected) = security_descriptor_snapshot(handle)?;
        let after = descriptor_acl_identity(&after_descriptor, action)?;
        let (before_revision, before_size, before_aces) = descriptor_acl_records(&descriptor)?;
        let (after_revision, after_size, after_aces) = descriptor_acl_records(&after_descriptor)?;
        if before.owner != after.owner || after_protected != protected {
            return Err(format!(
                "{action}未精确保持 owner/protection：期望 protected={} 实际 protected={} {}; before=[{}]; after=[{}]",
                protected,
                after_protected,
                first_descriptor_diff(&descriptor, &after_descriptor),
                descriptor_diagnostic(&descriptor),
                descriptor_diagnostic(&after_descriptor)
            ));
        }
        if let Err(transition_error) = validate_fixture_acl_transition(
            before_revision,
            before_size,
            &before_aces,
            after_revision,
            after_size,
            &after_aces,
            protected,
        ) {
            return Err(format!(
                "{action}出现非预期 DACL 变化：{transition_error}; before={:?}; after={:?}",
                descriptor_diagnostic(&descriptor),
                descriptor_diagnostic(&after_descriptor)
            ));
        }
        if before.dacl != after.dacl {
            eprintln!(
                "{action} Windows 规范化了继承 ACE；后续 fixture 基线使用设置后的完整描述符：{}; before=[{}]; after=[{}]",
                first_descriptor_diff(&descriptor, &after_descriptor),
                descriptor_diagnostic(&descriptor),
                descriptor_diagnostic(&after_descriptor)
            );
        }
        Ok(())
    }

    #[test]
    fn fixture_acl_transition_rejects_mask_and_sid_tampering() {
        let before = FixtureAceRecord {
            ace_type: 0,
            flags: 0x10,
            mask: Some(0x001f01ff),
            sid: vec![1, 2, 3, 4],
            raw: vec![0, 0x10, 0x14, 0, 0xff, 0x01, 0x1f, 0],
        };
        let expected = expected_fixture_acl_after_protection(std::slice::from_ref(&before), true);
        let mut mask_tampered = expected.clone();
        mask_tampered[0].mask = Some(0x001301bf);
        assert!(validate_fixture_acl_transition(
            2,
            16,
            std::slice::from_ref(&before),
            2,
            16,
            &mask_tampered,
            true
        )
        .is_err());
        let mut sid_tampered = expected;
        sid_tampered[0].sid[0] = 9;
        assert!(validate_fixture_acl_transition(
            2,
            16,
            std::slice::from_ref(&before),
            2,
            16,
            &sid_tampered,
            true
        )
        .is_err());
    }

    #[test]
    fn fixture_dacl_protection_roundtrip_reports_exact_descriptor() {
        let path = std::env::temp_dir().join(format!(
            "micontrol-dacl-diagnostic-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock before unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("create dacl fixture directory");
        let result = (|| -> Result<(), String> {
            let handle = open_fixture_security_handle(&path, true)?;
            eprintln!(
                "ordinary TEMP DACL diagnostic SDDL before={}",
                fixture_sddl(&path).unwrap_or_else(|error| format!("unavailable: {error}"))
            );
            set_fixture_dacl_protection(handle.0, true, "ordinary TEMP protected=true")?;
            eprintln!(
                "ordinary TEMP DACL diagnostic SDDL protected=true={}",
                fixture_sddl(&path).unwrap_or_else(|error| format!("unavailable: {error}"))
            );
            set_fixture_dacl_protection(handle.0, false, "ordinary TEMP protected=false")?;
            eprintln!(
                "ordinary TEMP DACL diagnostic SDDL protected=false={}",
                fixture_sddl(&path).unwrap_or_else(|error| format!("unavailable: {error}"))
            );
            Ok(())
        })();
        let sddl_after = fixture_sddl(&path).unwrap_or_else(|error| error);
        let _ = std::fs::remove_dir_all(&path);
        result.unwrap_or_else(|error| {
            panic!(
                "ordinary TEMP DACL protection roundtrip failed path={} error={error} SDDL={}",
                path.display(),
                sddl_after
            )
        });
    }

    fn sid_to_string(sid: PSID) -> Result<String, String> {
        use windows::Win32::Security::{
            GetSidIdentifierAuthority, GetSidSubAuthority, GetSidSubAuthorityCount, IsValidSid,
        };
        unsafe {
            if !IsValidSid(sid).as_bool() {
                return Err("owner SID 无效".into());
            }
            let revision = *(sid.0 as *const u8);
            let authority = &*GetSidIdentifierAuthority(sid);
            let authority = authority
                .Value
                .iter()
                .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
            let count = *GetSidSubAuthorityCount(sid);
            let mut text = format!("S-{revision}-{authority}");
            for index in 0..count {
                text.push('-');
                text.push_str(&(*GetSidSubAuthority(sid, u32::from(index))).to_string());
            }
            Ok(text)
        }
    }

    fn fixture_sddl(path: &Path) -> Result<String, String> {
        let path = path
            .to_str()
            .ok_or_else(|| format!("fixture SDDL 路径不是 UTF-8：{}", path.display()))?;
        let path = path.replace('\'', "''");
        let command = format!("(Get-Acl -LiteralPath '{path}').Sddl");
        let output = hidden(
            r"WindowsPowerShell\v1.0\powershell.exe",
            &["-NoProfile", "-NonInteractive", "-Command", &command],
        )
        .map_err(|error| format!("Get-Acl 启动失败：{error}"))?;
        if !output.status.success() {
            return Err(format!(
                "Get-Acl exit_code={:?} stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    fn record_fixture_owner_and_sddl(
        handle: HANDLE,
        path: &Path,
        stage: &str,
    ) -> Result<(), String> {
        use windows::core::BOOL;
        use windows::Win32::Security::{GetSecurityDescriptorOwner, PSECURITY_DESCRIPTOR};
        let descriptor = fixture_security_descriptor(handle)?;
        let mut owner = PSID::default();
        let mut owner_defaulted = BOOL(0);
        unsafe {
            GetSecurityDescriptorOwner(
                PSECURITY_DESCRIPTOR(descriptor.as_ptr() as *mut _),
                &mut owner,
                &mut owner_defaulted,
            )
            .map_err(|error| format!("读取 fixture owner 失败：{error}"))?;
        }
        let actual_owner = sid_to_string(owner)?;
        let sddl = fixture_sddl(path)?;
        eprintln!(
            "ACL QA owner evidence: stage={stage} path={} actual_owner_sid={actual_owner} sddl={sddl}",
            path.display()
        );
        Ok(())
    }

    fn decode_icacls_snapshot(bytes: &[u8]) -> String {
        let (payload, has_bom) = if bytes.starts_with(&[0xFF, 0xFE]) {
            (&bytes[2..], true)
        } else {
            (bytes, false)
        };
        let utf16le_without_bom = !has_bom
            && payload.len() % 2 == 0
            && !payload.is_empty()
            && payload.chunks_exact(2).filter(|pair| pair[1] == 0).count() * 4
                >= (payload.len() / 2) * 3;
        if has_bom || utf16le_without_bom {
            let units: Vec<u16> = payload
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            String::from_utf8_lossy(bytes).into_owned()
        }
    }

    #[test]
    fn decodes_icacls_utf16le_snapshots_with_or_without_bom() {
        let expected = "D:P(A;OICI;FA;;;SY)(A;ID;FA;;;BA)";
        let utf16: Vec<u8> = expected
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        assert_eq!(decode_icacls_snapshot(&utf16), expected);
        let mut with_bom = vec![0xFF, 0xFE];
        with_bom.extend_from_slice(&utf16);
        assert_eq!(decode_icacls_snapshot(&with_bom), expected);
    }

    fn assert_fixture_owner_and_acl(
        handle: HANDLE,
        path: &Path,
        stage: &str,
        require_system_only: bool,
        expected_owner: Option<&str>,
    ) -> Result<(), String> {
        use windows::core::BOOL;
        use windows::Win32::Security::{
            EqualSid, GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
            GetSecurityDescriptorOwner, IsWellKnownSid, WinBuiltinAdministratorsSid,
            WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACL, PSECURITY_DESCRIPTOR, PSID,
            SE_DACL_PROTECTED,
        };
        use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
        let descriptor = fixture_security_descriptor(handle)?;
        let descriptor_ptr = PSECURITY_DESCRIPTOR(descriptor.as_ptr() as *mut _);
        let expected_owner_bytes = expected_owner
            .map(sid_bytes)
            .transpose()
            .map_err(|error| format!("解析 fixture 预期 owner SID 失败：{error}"))?;
        let expected_owner_ptr = expected_owner_bytes
            .as_ref()
            .map(|bytes| PSID(bytes.as_ptr() as *mut _));
        let mut control = 0u16;
        let mut revision = 0u32;
        unsafe {
            GetSecurityDescriptorControl(descriptor_ptr, &mut control, &mut revision)
                .map_err(|error| format!("读取 fixture DACL control 失败：{error}"))?;
        }
        if control & SE_DACL_PROTECTED.0 == 0 {
            return Err(format!(
                "fixture DACL 未受保护：stage={stage} path={} control=0x{control:04x}",
                path.display()
            ));
        }
        let mut owner = PSID::default();
        let mut owner_defaulted = BOOL(0);
        unsafe {
            GetSecurityDescriptorOwner(descriptor_ptr, &mut owner, &mut owner_defaulted)
                .map_err(|error| format!("读取 fixture owner 失败：{error}"))?;
        }
        if !unsafe { IsWellKnownSid(owner, WinLocalSystemSid) }.as_bool() {
            let actual_owner = sid_to_string(owner).unwrap_or_else(|error| error);
            let sddl = fixture_sddl(path).unwrap_or_else(|error| error);
            return Err(format!(
                "fixture owner 不是 SYSTEM：stage={stage} path={} actual_owner_sid={actual_owner} sddl={sddl}",
                path.display()
            ));
        }
        let mut dacl_present = BOOL(0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut dacl_defaulted = BOOL(0);
        unsafe {
            GetSecurityDescriptorDacl(
                descriptor_ptr,
                &mut dacl_present,
                &mut dacl,
                &mut dacl_defaulted,
            )
            .map_err(|error| format!("读取 fixture DACL 失败：{error}"))?;
        }
        if !dacl_present.as_bool() || dacl.is_null() {
            return Err("fixture 没有显式 DACL".into());
        }
        let ace_count = unsafe { (*dacl).AceCount };
        let mut system_full = false;
        let mut admin_full = false;
        let mut owner_ace_count = 0u32;
        let mut owner_rx_count = 0u32;
        let owner_rx = FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0;
        for index in 0..ace_count {
            let mut ace = std::ptr::null_mut();
            unsafe {
                GetAce(dacl, index as u32, &mut ace)
                    .map_err(|error| format!("读取 fixture ACE 失败：{error}"))?;
                let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
                if allowed.Header.AceType != 0 {
                    continue;
                }
                let sid = PSID(&allowed.SidStart as *const _ as *mut _);
                if let Some(expected_owner) = expected_owner_ptr {
                    if EqualSid(sid, expected_owner).is_ok() {
                        owner_ace_count += 1;
                        if allowed.Mask == owner_rx {
                            owner_rx_count += 1;
                        }
                    }
                }
                if allowed.Mask != FILE_ALL_ACCESS.0 {
                    continue;
                }
                system_full |= IsWellKnownSid(sid, WinLocalSystemSid).as_bool();
                admin_full |= IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool();
            }
        }
        if require_system_only {
            if ace_count != 1 || !system_full || admin_full {
                return Err(format!(
                    "fixture 未达到 SYSTEM-only DACL：ace_count={ace_count} system_full={system_full} admin_full={admin_full}"
                ));
            }
        } else if !system_full || !admin_full {
            return Err(format!(
                "最终 fixture ACL 未确认 SYSTEM F 与 Administrators F：ace_count={ace_count} system_full={system_full} admin_full={admin_full}"
            ));
        }
        if expected_owner.is_some() && (owner_ace_count != 1 || owner_rx_count != 1) {
            return Err(format!(
                "最终 fixture ACL 未确认传入 owner SID 仅有 RX ACE：stage={stage} path={} owner_ace_count={owner_ace_count} owner_rx_count={owner_rx_count}",
                path.display()
            ));
        }
        eprintln!(
            "ACL QA stage passed: stage={stage} path={} owner=SYSTEM system_full={system_full} admin_full={admin_full} owner_rx_count={owner_rx_count} dacl_protected=true require_system_only={require_system_only}",
            path.display()
        );
        Ok(())
    }

    fn assert_no_broad_acl_aces(handle: HANDLE) -> Result<(), String> {
        use windows::core::BOOL;
        use windows::Win32::Security::{
            GetAce, GetSecurityDescriptorDacl, IsWellKnownSid, WinBuiltinUsersSid, WinWorldSid,
            ACCESS_ALLOWED_ACE, ACL, PSECURITY_DESCRIPTOR, PSID,
        };
        let descriptor = fixture_security_descriptor(handle)?;
        let descriptor_ptr = PSECURITY_DESCRIPTOR(descriptor.as_ptr() as *mut _);
        let mut dacl_present = BOOL(0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut dacl_defaulted = BOOL(0);
        unsafe {
            GetSecurityDescriptorDacl(
                descriptor_ptr,
                &mut dacl_present,
                &mut dacl,
                &mut dacl_defaulted,
            )
            .map_err(|error| format!("读取宽权限检查 DACL 失败：{error}"))?;
        }
        if !dacl_present.as_bool() || dacl.is_null() {
            return Err("宽权限检查发现没有显式 DACL".into());
        }
        for index in 0..unsafe { (*dacl).AceCount } {
            let mut ace = std::ptr::null_mut();
            unsafe {
                GetAce(dacl, index as u32, &mut ace)
                    .map_err(|error| format!("读取宽权限检查 ACE 失败：{error}"))?;
                let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
                if allowed.Header.AceType != 0 {
                    continue;
                }
                let sid = PSID(&allowed.SidStart as *const _ as *mut _);
                if IsWellKnownSid(sid, WinBuiltinUsersSid).as_bool()
                    || IsWellKnownSid(sid, WinWorldSid).as_bool()
                {
                    return Err("最终 DACL 仍包含 Users/Everyone ACE".into());
                }
            }
        }
        Ok(())
    }

    fn restore_fixture_dacl(handle: HANDLE, descriptor: &[u8]) -> Result<(), String> {
        let dacl_protected = descriptor_dacl_protected(descriptor)?;
        apply_descriptor_security_info(
            handle,
            descriptor,
            dacl_protected,
            "通过预留句柄恢复 fixture 原始安全描述符",
        )
    }

    struct FixtureAclGuard {
        root_handle: OwnedHandle,
        broker_handle: OwnedHandle,
        root_original_dacl: Vec<u8>,
        broker_original_dacl: Vec<u8>,
    }

    impl FixtureAclGuard {
        fn open(root: &Path, broker: &Path) -> Result<Self, String> {
            let root_handle = open_fixture_security_handle(root, true)?;
            let broker_handle = open_fixture_security_handle(broker, false)?;
            let root_original_dacl = fixture_security_descriptor(root_handle.0)?;
            let broker_original_dacl = fixture_security_descriptor(broker_handle.0)?;
            ensure_supported_descriptor(
                &root_original_dacl,
                &format!("fixture 原始安全描述符 {}", root.display()),
            )?;
            ensure_supported_descriptor(
                &broker_original_dacl,
                &format!("fixture 原始安全描述符 {}", broker.display()),
            )?;
            Ok(Self {
                root_handle,
                broker_handle,
                root_original_dacl,
                broker_original_dacl,
            })
        }

        fn restore_original_dacl(&self) -> Result<(), String> {
            restore_fixture_dacl(self.root_handle.0, &self.root_original_dacl)?;
            restore_fixture_dacl(self.broker_handle.0, &self.broker_original_dacl)
        }
    }

    fn set_system_only_dacl(handle: HANDLE, inherit: bool) -> Result<(), String> {
        use windows::Win32::Security::{
            AddAccessAllowedAceEx, CreateWellKnownSid, InitializeAcl, WinLocalSystemSid, ACE_FLAGS,
            ACL, ACL_REVISION, PSID,
        };
        use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

        let mut sid = [0u8; 68];
        let mut sid_len = sid.len() as u32;
        unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                None,
                Some(PSID(sid.as_mut_ptr() as *mut _)),
                &mut sid_len,
            )
            .map_err(|error| format!("构造 SYSTEM SID 失败：{error}"))?;
        }
        let mut acl = vec![0u8; 1024];
        let acl_ptr = acl.as_mut_ptr() as *mut ACL;
        unsafe {
            InitializeAcl(acl_ptr, acl.len() as u32, ACL_REVISION)
                .map_err(|error| format!("初始化 SYSTEM-only ACL 失败：{error}"))?;
            AddAccessAllowedAceEx(
                acl_ptr,
                ACL_REVISION,
                ACE_FLAGS(if inherit { 0x3 } else { 0 }),
                FILE_ALL_ACCESS.0,
                PSID(sid.as_mut_ptr() as *mut _),
            )
            .map_err(|error| format!("添加 SYSTEM Full Control ACE 失败：{error}"))?;
            set_security_info_checked(
                handle,
                (DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION).0,
                None,
                Some(acl_ptr as *const ACL),
                "通过预留句柄设置 SYSTEM-only DACL",
            )?;
        }
        let (_, protected) = security_descriptor_snapshot(handle)?;
        if !protected {
            return Err("设置 SYSTEM-only DACL 后未读回 DACL protection".into());
        }
        Ok(())
    }

    fn set_system_owner_one(path: &Path) -> Result<(), String> {
        let path = path
            .to_str()
            .ok_or_else(|| format!("owner 设置路径不是 UTF-8：{}", path.display()))?;
        let output = hidden("icacls.exe", &[path, "/setowner", "*S-1-5-18", "/Q"])?;
        if !output.status.success() {
            return Err(format!(
                "隔离 SYSTEM owner 构造失败（{}），exit_code={:?}：{} {}",
                path,
                output.status.code(),
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(())
    }

    fn token_privilege_enabled(name: PCWSTR) -> Result<Option<bool>, String> {
        use windows::Win32::Security::{
            GetTokenInformation, TokenPrivileges, LUID_AND_ATTRIBUTES, TOKEN_PRIVILEGES,
        };
        let mut token = HANDLE::default();
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
            .map_err(|error| format!("打开 QA 令牌失败：{error}"))?;
        }
        let token = OwnedHandle(token);
        let mut required = 0u32;
        unsafe {
            let _ = GetTokenInformation(token.0, TokenPrivileges, None, 0, &mut required);
        }
        if required < std::mem::size_of::<TOKEN_PRIVILEGES>() as u32 {
            return Err("读取 QA 令牌权限大小失败".into());
        }
        let mut bytes = vec![0u8; required as usize];
        unsafe {
            GetTokenInformation(
                token.0,
                TokenPrivileges,
                Some(bytes.as_mut_ptr() as *mut _),
                bytes.len() as u32,
                &mut required,
            )
            .map_err(|error| format!("读取 QA 令牌权限失败：{error}"))?;
            let count = *(bytes.as_ptr() as *const u32) as usize;
            let entries =
                bytes.as_ptr().add(std::mem::size_of::<u32>()) as *const LUID_AND_ATTRIBUTES;
            let mut found = None;
            let mut luid = LUID::default();
            LookupPrivilegeValueW(None, name, &mut luid)
                .map_err(|error| format!("查询 QA 令牌权限失败：{error}"))?;
            for index in 0..count {
                let entry = entries.add(index).read_unaligned();
                if entry.Luid.LowPart == luid.LowPart && entry.Luid.HighPart == luid.HighPart {
                    found = Some(entry.Attributes.contains(SE_PRIVILEGE_ENABLED));
                    break;
                }
            }
            Ok(found)
        }
    }

    fn disable_qa_privilege(name: PCWSTR) -> Result<(), String> {
        let mut token = HANDLE::default();
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
            .map_err(|error| format!("打开 QA 令牌失败：{error}"))?;
        }
        let token = OwnedHandle(token);
        let mut luid = LUID::default();
        unsafe {
            LookupPrivilegeValueW(None, name, &mut luid)
                .map_err(|error| format!("查询 QA 令牌权限失败：{error}"))?;
            let privileges = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: windows::Win32::Security::TOKEN_PRIVILEGES_ATTRIBUTES(0),
                }],
            };
            AdjustTokenPrivileges(token.0, false, Some(&privileges), 0, None, None)
                .map_err(|error| format!("禁用 QA 令牌权限失败：{error}"))?;
            if GetLastError() == ERROR_NOT_ALL_ASSIGNED {
                return Err("QA 令牌未分配所需权限".into());
            }
        }
        if token_privilege_enabled(name)? != Some(false) {
            return Err("QA 子进程启动时所需权限未处于 disabled 状态".into());
        }
        Ok(())
    }

    fn assert_qa_child_privileges_disabled() -> Result<(), String> {
        disable_qa_privilege(SE_BACKUP_NAME)?;
        disable_qa_privilege(SE_RESTORE_NAME)?;
        if token_privilege_enabled(SE_BACKUP_NAME)? != Some(false)
            || token_privilege_enabled(SE_RESTORE_NAME)? != Some(false)
        {
            return Err("QA 子进程初始 SeBackup/SeRestore 权限未关闭".into());
        }
        Ok(())
    }

    fn require_acl_qa_gate_value(value: Option<&str>) -> Result<(), String> {
        if value == Some("1") {
            Ok(())
        } else {
            Err("set MICONTROL_ACL_QA=1 to run the isolated ACL recovery test".into())
        }
    }

    fn require_acl_qa_gate() -> Result<(), String> {
        require_acl_qa_gate_value(std::env::var("MICONTROL_ACL_QA").ok().as_deref())
    }

    fn validate_acl_qa_child_inputs(root: &Path, owner: &str) -> Result<(), String> {
        if !root.is_absolute()
            || root
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err("ACL QA 子进程 root 不是安全绝对路径".into());
        }
        if !valid_sid(owner) {
            return Err("ACL QA 子进程 owner SID 无效".into());
        }
        sid_bytes(owner)?;
        let temp = std::env::temp_dir();
        let temp_metadata = std::fs::symlink_metadata(&temp)
            .map_err(|error| format!("ACL QA TEMP 属性读取失败：{error}"))?;
        if is_reparse_point(&temp_metadata) || !temp_metadata.is_dir() {
            return Err("ACL QA TEMP 不是普通目录".into());
        }
        let canonical_temp = std::fs::canonicalize(&temp)
            .map_err(|error| format!("ACL QA TEMP 路径解析失败：{error}"))?;
        let parent = root.parent().ok_or("ACL QA root 缺少父目录")?;
        let canonical_parent = std::fs::canonicalize(parent)
            .map_err(|error| format!("ACL QA root 父目录解析失败：{error}"))?;
        if canonical_parent != canonical_temp {
            return Err("ACL QA 子进程 root 不在当前 TEMP 直系目录".into());
        }
        let name = root
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or("ACL QA root 文件名无效")?;
        let suffix = name
            .strip_prefix("MiControl-acl-qa-")
            .ok_or("ACL QA root 名称前缀无效")?;
        let mut parts = suffix.split('-');
        let pid = parts.next().unwrap_or_default();
        let nonce = parts.next().unwrap_or_default();
        if pid.is_empty()
            || nonce.is_empty()
            || parts.next().is_some()
            || !pid.bytes().all(|value| value.is_ascii_digit())
            || !nonce.bytes().all(|value| value.is_ascii_digit())
        {
            return Err("ACL QA root 名称缺少随机进程与 nonce 分量".into());
        }
        // The root itself is intentionally SYSTEM-only at this point, so an
        // ordinary metadata probe would be an access check rather than a safe
        // type check.  restore_administrator_maintenance performs the native,
        // no-follow root type/reparse validation after enabling SeBackup.
        Ok(())
    }

    fn run_acl_recovery_child(root: &Path, owner: &str) -> Result<(), String> {
        let executable = std::env::current_exe().map_err(|error| error.to_string())?;
        let output = std::process::Command::new(executable)
            .args([
                "--exact",
                "hid_tap::windows::service::tests::isolated_acl_recovery_qa",
                "--ignored",
                "--nocapture",
            ])
            .env("MICONTROL_ACL_QA_CHILD", "1")
            .env("MICONTROL_ACL_QA_ROOT", root)
            .env("MICONTROL_ACL_QA_OWNER", owner)
            .env_remove("MICONTROL_ACL_QA_CLEANUP_RESIDUE")
            .creation_flags(0x08000000)
            .output()
            .map_err(|error| format!("启动 ACL 恢复子进程失败：{error}"))?;
        if !output.status.success() {
            return Err(format!(
                "ACL 恢复子进程失败，exit_code={:?}：stdout={} stderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        eprintln!(
            "ACL QA stage passed: stage=isolated_recovery_child exit_code={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(())
    }

    fn assert_ordinary_open_denied(path: &Path, directory: bool) -> Result<(), String> {
        let path = wide(path);
        let flags = if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            Default::default()
        };
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path.as_ptr()),
                FILE_READ_ATTRIBUTES.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                flags,
                None,
            )
        };
        if handle.is_ok() {
            drop(OwnedHandle(handle.unwrap()));
            return Err("SYSTEM-only 对象仍可由普通句柄打开".into());
        }
        Ok(())
    }

    fn validate_acl_qa_fixture_root_name(root: &Path) -> Result<(), String> {
        if !root.is_absolute()
            || root
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err("ACL QA fixture root 不是安全绝对路径".into());
        }
        let name = root
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or("ACL QA fixture root 文件名无效")?;
        let suffix = name
            .strip_prefix("MiControl-acl-qa-")
            .ok_or("ACL QA fixture root 名称前缀无效")?;
        let mut parts = suffix.split('-');
        let pid = parts.next().unwrap_or_default();
        let nonce = parts.next().unwrap_or_default();
        if pid.is_empty()
            || nonce.is_empty()
            || parts.next().is_some()
            || !pid.bytes().all(|value| value.is_ascii_digit())
            || !nonce.bytes().all(|value| value.is_ascii_digit())
        {
            return Err("ACL QA fixture root 名称缺少随机进程与 nonce 分量".into());
        }
        Ok(())
    }

    fn unlink_expected_acl_qa_junction(root: &Path, expected_target: &Path) -> Result<(), String> {
        match std::fs::symlink_metadata(root) {
            Ok(root_metadata) => {
                if is_reparse_point(&root_metadata) || !root_metadata.is_dir() {
                    return Err(format!(
                        "拒绝清理 fixture junction：root 不是普通目录：{}",
                        root.display()
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(format!("读取 fixture root 失败：{error}")),
        }
        validate_acl_qa_fixture_root_name(root)?;
        let junction = root.join("escape");
        let metadata = match std::fs::symlink_metadata(&junction) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(format!("读取 fixture junction 失败：{error}")),
        };
        if !is_reparse_point(&metadata) {
            return Err(format!(
                "拒绝清理 fixture junction：escape 不是 reparse 对象：{}",
                junction.display()
            ));
        }
        let handle = open_recovery_handle(&junction, true)?;
        let (is_directory, is_reparse) = recovery_attributes(handle.0)
            .map_err(|error| format!("读取 fixture junction nofollow 属性失败：{error}"))?;
        if !is_directory || !is_reparse {
            return Err(format!(
                "拒绝清理 fixture junction：escape 不是 nofollow reparse 目录：{}",
                junction.display()
            ));
        }
        let target = std::fs::read_link(&junction)
            .map_err(|error| format!("读取 fixture junction target 失败：{error}"))?;
        let target = if target.is_absolute() {
            target
        } else {
            junction
                .parent()
                .ok_or("fixture junction 缺少父目录")?
                .join(target)
        };
        let expected_target = std::fs::canonicalize(expected_target)
            .map_err(|error| format!("解析 fixture junction 预期 target 失败：{error}"))?;
        let actual_target = std::fs::canonicalize(&target)
            .map_err(|error| format!("解析 fixture junction 实际 target 失败：{error}"))?;
        if actual_target != expected_target {
            return Err(format!(
                "拒绝清理 fixture junction：target 不匹配：actual={} expected={}",
                actual_target.display(),
                expected_target.display()
            ));
        }
        // RemoveDirectoryW removes this directory reparse point itself and
        // never walks the target.  Keep this non-recursive after the exact
        // name, type, reparse tag and target checks above.
        let junction_path = wide(&junction);
        unsafe {
            windows::Win32::Storage::FileSystem::RemoveDirectoryW(PCWSTR(junction_path.as_ptr()))
        }
        .map_err(|error| format!("原生移除 fixture junction 失败：{error}"))?;
        if std::fs::symlink_metadata(&junction).is_ok() {
            return Err("原生移除 fixture junction 后对象仍存在".into());
        }
        Ok(())
    }

    #[test]
    fn unlink_expected_acl_qa_junction_real_temp_fixture() {
        let root = std::env::temp_dir().join(format!(
            "MiControl-acl-qa-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock before unix epoch")
                .as_nanos()
        ));
        let outside = root.with_file_name(format!(
            "{}-outside",
            root.file_name()
                .expect("fixture root filename")
                .to_string_lossy()
        ));
        let junction = root.join("escape");
        let sentinel = outside.join("sentinel.txt");
        std::fs::create_dir_all(&root).expect("create fixture root");
        std::fs::create_dir_all(&outside).expect("create fixture target");
        let sentinel_bytes = b"ordinary junction unlink sentinel\n";
        std::fs::write(&sentinel, sentinel_bytes).expect("write fixture sentinel");
        let before = fixture_security_identity(&sentinel, false).expect("snapshot sentinel ACL");
        let junction_text = junction
            .to_str()
            .expect("junction path is UTF-8")
            .replace('"', "\"\"");
        let outside_text = outside
            .to_str()
            .expect("target path is UTF-8")
            .replace('"', "\"\"");
        let command = format!(
            "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path \"{junction_text}\" -Target \"{outside_text}\" | Out-Null"
        );
        let result = (|| -> Result<(), String> {
            let created = hidden(
                r"WindowsPowerShell\v1.0\powershell.exe",
                &["-NoProfile", "-NonInteractive", "-Command", &command],
            )?;
            if !created.status.success() {
                return Err(format!(
                    "无法创建普通 TEMP junction，exit_code={:?} stdout={} stderr={}",
                    created.status.code(),
                    String::from_utf8_lossy(&created.stdout).trim(),
                    String::from_utf8_lossy(&created.stderr).trim()
                ));
            }
            unlink_expected_acl_qa_junction(&root, &outside)?;
            if std::fs::symlink_metadata(&junction).is_ok() {
                return Err("实际 unlink 后 junction 仍存在".into());
            }
            if std::fs::read(&sentinel).map_err(|error| error.to_string())? != sentinel_bytes {
                return Err("实际 unlink 改变了 target sentinel 内容".into());
            }
            let after = fixture_security_identity(&sentinel, false)?;
            if after != before {
                return Err(format!(
                    "实际 unlink 改变了 target sentinel ACL：before={before:?} after={after:?}"
                ));
            }
            Ok(())
        })();
        if std::fs::symlink_metadata(&junction).is_ok() {
            let _ = unlink_expected_acl_qa_junction(&root, &outside);
        }
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
        result.expect("普通 TEMP junction unlink fixture failed");
    }

    #[test]
    fn acl_qa_gate_and_child_path_validation_are_fail_closed() {
        assert!(require_acl_qa_gate_value(None).is_err());
        assert!(require_acl_qa_gate_value(Some("0")).is_err());
        assert!(require_acl_qa_gate_value(Some("1")).is_ok());

        let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let legal = temp.join("MiControl-acl-qa-12345-67890");
        let owner = "S-1-5-21-1-2-3";
        assert!(validate_acl_qa_child_inputs(&legal, owner).is_ok());

        let outside = temp
            .parent()
            .unwrap_or(&temp)
            .join("MiControl-acl-qa-12345-67890");
        assert!(validate_acl_qa_child_inputs(&outside, owner).is_err());
    }

    #[test]
    #[ignore = "requires an elevated token and an isolated temporary directory"]
    fn isolated_acl_recovery_qa() {
        require_acl_qa_gate().unwrap_or_else(|error| panic!("ACL QA 总门禁失败：{error}"));
        if std::env::var("MICONTROL_ACL_QA_CHILD").as_deref() == Ok("1") {
            assert_qa_child_privileges_disabled()
                .unwrap_or_else(|error| panic!("ACL QA 子进程启动权限检查失败：{error}"));
            let root = PathBuf::from(
                std::env::var_os("MICONTROL_ACL_QA_ROOT").expect("ACL QA 子进程缺少 root 环境变量"),
            );
            let owner =
                std::env::var("MICONTROL_ACL_QA_OWNER").expect("ACL QA 子进程缺少 owner 环境变量");
            validate_acl_qa_child_inputs(&root, &owner)
                .unwrap_or_else(|error| panic!("ACL QA 子进程输入门禁失败：{error}"));
            restore_administrator_maintenance(&root)
                .unwrap_or_else(|error| panic!("ACL QA 子进程恢复管理员维护权限失败：{error}"));
            eprintln!("ACL QA stage passed: stage=child_restore");
            protect(&root, &owner)
                .unwrap_or_else(|error| panic!("ACL QA 子进程 protect1 失败：{error}"));
            eprintln!("ACL QA stage passed: stage=child_protect1");
            protect(&root, &owner)
                .unwrap_or_else(|error| panic!("ACL QA 子进程 protect2 失败：{error}"));
            eprintln!("ACL QA stage passed: stage=child_protect2");
            return;
        }
        let root = std::env::temp_dir().join(format!(
            "MiControl-acl-qa-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let outside = root.with_file_name(format!(
            "{}-outside",
            root.file_name().unwrap().to_string_lossy()
        ));
        let fresh_root = root.with_file_name(format!(
            "{}-fresh",
            root.file_name().unwrap().to_string_lossy()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(&fresh_root).unwrap();
        let outside_sentinel = outside.join("sentinel.txt");
        let outside_sentinel_bytes = b"ACL-QA external sentinel v1\n";
        std::fs::write(&outside_sentinel, outside_sentinel_bytes).unwrap();
        std::fs::write(root.join("broker.json"), b"restricted").unwrap();
        std::fs::write(fresh_root.join("broker.json"), b"fresh").unwrap();
        let mut fixture_guard: Option<FixtureAclGuard> = None;
        let result = (|| -> Result<(), String> {
            let root_text = root.to_str().ok_or("temporary path is not UTF-8")?;
            let outside_text = outside
                .to_str()
                .ok_or("temporary outside path is not UTF-8")?;
            let junction = root.join("escape");
            let junction_text = junction
                .to_str()
                .ok_or("temporary junction path is not UTF-8")?;
            let junction_literal = junction_text.replace('\'', "''");
            let outside_literal = outside_text.replace('\'', "''");
            let outside_before = fixture_security_identity(&outside_sentinel, false)?;
            let command = format!(
                "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path '{junction_literal}' -Target '{outside_literal}' | Out-Null"
            );
            let junction_result = hidden(
                r"WindowsPowerShell\v1.0\powershell.exe",
                &["-NoProfile", "-NonInteractive", "-Command", &command],
            )?;
            if !junction_result.status.success() {
                return Err(format!(
                    "无法创建隔离 junction，exit_code={:?}：stdout={} stderr={}",
                    junction_result.status.code(),
                    String::from_utf8_lossy(&junction_result.stdout).trim(),
                    String::from_utf8_lossy(&junction_result.stderr).trim(),
                ));
            }
            let reparse_error = match validate_managed_tree_for_recovery(&root) {
                Ok(()) => return Err("隔离 junction 未被恢复前安全校验拒绝".into()),
                Err(error) => error,
            };
            if !reparse_error.contains("reparse") {
                return Err(format!("隔离 junction 错误类型不明确：{reparse_error}"));
            }
            if std::fs::read(&outside_sentinel)
                .map_err(|error| format!("读取 external sentinel 失败：{error}"))?
                != outside_sentinel_bytes
            {
                return Err("reparse 拒绝路径改变了 external sentinel".into());
            }
            let outside_after_reparse = fixture_security_identity(&outside_sentinel, false)?;
            if outside_after_reparse != outside_before {
                return Err(format!(
                    "reparse 拒绝路径改变了 external sentinel 安全摘要：before={outside_before:?} after={outside_after_reparse:?}"
                ));
            }
            unlink_expected_acl_qa_junction(&root, &outside)?;
            let who = hidden("whoami.exe", &["/user", "/fo", "csv", "/nh"])?;
            let owner = String::from_utf8_lossy(&who.stdout)
                .split('"')
                .find(|part| valid_sid(part))
                .ok_or("无法取得隔离测试 owner SID")?
                .to_owned();
            // Hold handles only while constructing and asserting the fixture.
            // They are explicitly dropped before the independent recovery
            // child starts, so the child cannot borrow a parent handle.
            fixture_guard = Some(FixtureAclGuard::open(&root, &root.join("broker.json"))?);
            let guard = fixture_guard.as_ref().ok_or("fixture ACL guard 未初始化")?;
            record_fixture_owner_and_sddl(guard.root_handle.0, &root, "initial_fixture_root")?;
            record_fixture_owner_and_sddl(
                guard.broker_handle.0,
                &root.join("broker.json"),
                "initial_fixture_broker",
            )?;
            // Exercise exact raw-descriptor restore for both protection states
            // before constructing the SYSTEM-only residue used by recovery.
            set_fixture_dacl_protection(
                guard.root_handle.0,
                true,
                "fixture protected=true baseline",
            )?;
            let protected_snapshot = fixture_security_descriptor(guard.root_handle.0)?;
            let protected_identity =
                descriptor_acl_identity(&protected_snapshot, "fixture protected=true snapshot")?;
            set_system_only_dacl(guard.root_handle.0, true)?;
            restore_fixture_dacl(guard.root_handle.0, &protected_snapshot)?;
            let protected_restored = fixture_security_descriptor(guard.root_handle.0)?;
            if descriptor_acl_identity(&protected_restored, "fixture protected=true restore")?
                != protected_identity
            {
                return Err("fixture protected=true 原始 owner/DACL/protection 恢复不精确".into());
            }
            set_fixture_dacl_protection(
                guard.root_handle.0,
                false,
                "fixture protected=false baseline",
            )?;
            let unprotected_snapshot = fixture_security_descriptor(guard.root_handle.0)?;
            let unprotected_identity =
                descriptor_acl_identity(&unprotected_snapshot, "fixture protected=false snapshot")?;
            set_system_only_dacl(guard.root_handle.0, true)?;
            restore_fixture_dacl(guard.root_handle.0, &unprotected_snapshot)?;
            let unprotected_restored = fixture_security_descriptor(guard.root_handle.0)?;
            if descriptor_acl_identity(&unprotected_restored, "fixture protected=false restore")?
                != unprotected_identity
            {
                return Err("fixture protected=false 原始 owner/DACL/protection 恢复不精确".into());
            }
            set_system_owner_one(&root)?;
            set_system_owner_one(&root.join("broker.json"))?;
            set_system_only_dacl(guard.root_handle.0, true)?;
            set_system_only_dacl(guard.broker_handle.0, false)?;
            assert_fixture_owner_and_acl(
                guard.root_handle.0,
                &root,
                "system_only_root",
                true,
                None,
            )?;
            assert_fixture_owner_and_acl(
                guard.broker_handle.0,
                &root.join("broker.json"),
                "system_only_broker",
                true,
                None,
            )?;
            // Junction validation and fixture construction may have enabled a
            // privilege in this parent process.  Disable both before the
            // ordinary-open proof so that it cannot bypass the SYSTEM-only
            // ACL, and make the child perform the same check independently.
            assert_qa_child_privileges_disabled()?;
            // Ordinary opens of both the restricted root and broker must be
            // denied before handing the tree to the recovery child.
            assert_ordinary_open_denied(&root, true)?;
            assert_ordinary_open_denied(&root.join("broker.json"), false)?;
            eprintln!("ACL QA stage passed: stage=system_only_broker_denies_ordinary_open");
            drop(fixture_guard.take());
            eprintln!("ACL QA stage passed: stage=fixture_handles_closed");
            run_acl_recovery_child(&root, &owner)?;
            if std::fs::read(&outside_sentinel)
                .map_err(|error| format!("恢复后读取 external sentinel 失败：{error}"))?
                != outside_sentinel_bytes
            {
                return Err("ACL 恢复路径改变了 external sentinel".into());
            }
            let outside_after_recovery = fixture_security_identity(&outside_sentinel, false)?;
            if outside_after_recovery != outside_before {
                return Err(format!(
                    "ACL 恢复路径改变了 external sentinel 安全摘要：before={outside_before:?} after={outside_after_recovery:?}"
                ));
            }
            let saved = root.with_extension("acl");
            let saved_text = saved.to_str().ok_or("ACL snapshot path is not UTF-8")?;
            let snapshot = hidden("icacls.exe", &[root_text, "/save", saved_text, "/T", "/Q"])?;
            if !snapshot.status.success() {
                return Err("隔离最终 ACL 快照失败".into());
            }
            let acl_bytes = std::fs::read(&saved).map_err(|e| e.to_string())?;
            let acl_text = decode_icacls_snapshot(&acl_bytes);
            // icacls /save writes SDDL ACEs with object flags such as OICI or
            // ID.  Parse the ACE fields instead of matching one exact
            // `(A;;FA;;;SID)` spelling; flags do not change the full-control
            // check for the trustee.
            let parsed_aces: Vec<(String, String, String)> = acl_text
                .split('(')
                .filter_map(|part| part.split_once(')').map(|(ace, _)| ace))
                .filter_map(|ace| {
                    let fields: Vec<&str> = ace.split(';').map(str::trim).collect();
                    if fields.len() < 6 || fields[0] != "A" {
                        return None;
                    }
                    Some((
                        fields[1].to_owned(),
                        fields[2].to_owned(),
                        fields[5].to_owned(),
                    ))
                })
                .collect();
            let has_full_control_ace = |principal: &str, sid: &str| {
                parsed_aces.iter().any(|(_flags, rights, trustee)| {
                    rights.split(',').map(str::trim).any(|right| right == "FA")
                        && (trustee == principal || trustee == sid)
                })
            };
            if !has_full_control_ace("SY", "S-1-5-18")
                || !has_full_control_ace("BA", "S-1-5-32-544")
            {
                return Err(format!(
                    "最终 ACL 快照未确认 SYSTEM F 或 Administrators F：parsed_aces={parsed_aces:?} raw_sddl={}",
                    acl_text.trim()
                ));
            }
            eprintln!(
                "ACL QA stage passed: stage=final_acl_snapshot system_full={} admin_full={} ace_count={}",
                has_full_control_ace("SY", "S-1-5-18"),
                has_full_control_ace("BA", "S-1-5-32-544"),
                parsed_aces.len()
            );
            let final_guard = FixtureAclGuard::open(&root, &root.join("broker.json"))?;
            assert_fixture_owner_and_acl(
                final_guard.root_handle.0,
                &root,
                "after_child_protect2_root",
                false,
                Some(&owner),
            )?;
            assert_fixture_owner_and_acl(
                final_guard.broker_handle.0,
                &root.join("broker.json"),
                "after_child_protect2_broker",
                false,
                Some(&owner),
            )?;
            assert_no_broad_acl_aces(final_guard.root_handle.0)?;
            assert_no_broad_acl_aces(final_guard.broker_handle.0)?;
            drop(final_guard);
            // Run the clean-directory first-protect case last so enabling
            // SeRestorePrivilege cannot change the old-tree recovery setup.
            protect(&fresh_root, &owner)?;
            let fresh_guard = FixtureAclGuard::open(&fresh_root, &fresh_root.join("broker.json"))?;
            assert_fixture_owner_and_acl(
                fresh_guard.root_handle.0,
                &fresh_root,
                "fresh_root",
                false,
                Some(&owner),
            )?;
            assert_fixture_owner_and_acl(
                fresh_guard.broker_handle.0,
                &fresh_root.join("broker.json"),
                "fresh_broker",
                false,
                Some(&owner),
            )?;
            assert_no_broad_acl_aces(fresh_guard.root_handle.0)?;
            assert_no_broad_acl_aces(fresh_guard.broker_handle.0)?;
            drop(fresh_guard);
            std::fs::remove_file(&saved)
                .map_err(|error| format!("ACL 快照删除失败：{}: {error}", saved.display()))?;
            Ok(())
        })();
        let cleanup_root = |path: &Path| -> Result<(), String> {
            match std::fs::symlink_metadata(path) {
                Ok(metadata) => {
                    if is_reparse_point(&metadata) || !metadata.is_dir() {
                        return Err(format!(
                            "拒绝清理 fixture root：不是普通目录：{}",
                            path.display()
                        ));
                    }
                    // Recovery validates every child with no-follow handles,
                    // then restores Administrator maintenance rights before
                    // the recursive delete.  A failed validation is reported
                    // and leaves the tree in place for inspection.
                    validate_managed_tree_for_recovery(path)?;
                    restore_administrator_maintenance(path)?;
                    validate_managed_tree(path)?;
                    std::fs::remove_dir_all(path)
                        .map_err(|error| format!("{}: {error}", path.display()))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(format!("读取 {} 失败：{error}", path.display())),
            }
        };
        let cleanup_outside = |path: &Path| -> Result<(), String> {
            match std::fs::symlink_metadata(path) {
                Ok(metadata) => {
                    if is_reparse_point(&metadata) || !metadata.is_dir() {
                        return Err(format!(
                            "拒绝清理 fixture outside：不是普通目录：{}",
                            path.display()
                        ));
                    }
                    validate_managed_tree(path)?;
                    std::fs::remove_dir_all(path)
                        .map_err(|error| format!("{}: {error}", path.display()))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(format!("读取 {} 失败：{error}", path.display())),
            }
        };
        let mut failures = Vec::new();
        if let Err(error) = result {
            failures.push(format!("ACL QA 失败：{error}"));
        }
        if let Some(guard) = fixture_guard.take() {
            if let Err(error) = guard.restore_original_dacl() {
                failures.push(format!("ACL QA fixture 原始 DACL 恢复失败：{error}"));
            }
            drop(guard);
        }
        if let Err(error) = unlink_expected_acl_qa_junction(&root, &outside) {
            failures.push(format!("ACL QA 临时 junction 清理失败：{error}"));
        }
        if let Err(error) = cleanup_root(&root) {
            failures.push(format!("ACL QA 临时根目录清理失败：{error}"));
        }
        if let Err(error) = cleanup_root(&fresh_root) {
            failures.push(format!("ACL QA fresh 临时根目录清理失败：{error}"));
        }
        if let Err(error) = cleanup_outside(&outside) {
            failures.push(format!("ACL QA 临时 outside 目录清理失败：{error}"));
        }
        assert!(failures.is_empty(), "{}", failures.join("; "));
    }

    #[test]
    fn elevated_request_accepts_only_valid_explicit_operation_id() {
        assert!(valid_operation_id("setup-123-0001"));
        assert!(!valid_operation_id(""));
        assert!(!valid_operation_id("setup id"));
        assert!(!valid_operation_id("setup;whoami"));
        assert_eq!(
            crate::installer_compat::classify_runas_error(1223),
            "uac_cancel"
        );
        assert_eq!(
            crate::installer_compat::classify_runas_error(3),
            "launcherror"
        );
        let legacy = ["app.exe", INSTALL, "gadget.dll", "S-1-5-18"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert_eq!(parse_operation_suffix(&legacy).unwrap(), None);
        let explicit = [
            "app.exe",
            INSTALL,
            "gadget.dll",
            "S-1-5-18",
            OPERATION_ID_ARG,
            "setup-123-0001",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        assert_eq!(
            parse_operation_suffix(&explicit).unwrap(),
            Some("setup-123-0001")
        );
        assert_eq!(
            build_runas_arguments("gadget.dll", "S-1-5-18", false, None),
            "--micontrol-rc003-remove-service \"gadget.dll\" S-1-5-18"
        );
        assert_eq!(
            build_runas_arguments("gadget.dll", "S-1-5-18", false, Some("setup-123-0001")),
            "--micontrol-rc003-remove-service \"gadget.dll\" S-1-5-18 --micontrol-operation-id setup-123-0001"
        );
        assert_eq!(
            build_runas_arguments("gadget.dll", "S-1-5-18", false, Some("setup;whoami")),
            "--micontrol-rc003-remove-service \"gadget.dll\" S-1-5-18"
        );
        let malformed = [
            "app.exe",
            INSTALL,
            "gadget.dll",
            "S-1-5-18",
            OPERATION_ID_ARG,
            "setup;whoami",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        assert!(parse_operation_suffix(&malformed).is_err());
    }

    #[test]
    fn legacy_log_context_is_explicitly_unknown_without_environment_fallback() {
        set_request_operation_id(None);
        assert!(operation_log_line("phase=test").starts_with("operation_id=unknown "));
        set_request_operation_id(Some("setup-123"));
        assert!(operation_log_line("phase=test").starts_with("operation_id=setup-123 "));
        set_request_operation_id(None);
    }
}
