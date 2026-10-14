//! RC003 WUDFHost HID tap. Transport/script adapted from Vibe-Remote and
//! remote-bridge-hub; native helper implementation belongs to MiControl.
use super::{decode_tap_report, HidTapPhase, HidTapSnapshot, GADGET_SHA256};
use crate::button_mapping::EngineMessage;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::File,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    os::windows::{ffi::OsStrExt, io::FromRawHandle, process::CommandExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering},
        mpsc::Sender,
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use windows::{
    core::{w, PCSTR, PCWSTR, PWSTR},
    Win32::{
        Foundation::{
            CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND,
            ERROR_INVALID_PARAMETER, ERROR_NOT_ALL_ASSIGNED, ERROR_NO_MORE_FILES,
            ERROR_PATH_NOT_FOUND, FILETIME, HANDLE, LUID, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Security::{
            AdjustTokenPrivileges,
            Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG},
            LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
        },
        Storage::FileSystem::{
            CreateFileW, DeleteFileW, FileAttributeTagInfo, GetFileInformationByHandleEx,
            CREATE_NEW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
            FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, OPEN_EXISTING,
        },
        System::{
            Diagnostics::{
                Debug::WriteProcessMemory,
                ToolHelp::{
                    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
                    TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
                },
            },
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
                TerminateJobObject, JOBOBJECTINFOCLASS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Memory::{
                VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
            },
            Registry::{
                RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY,
                HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, REG_QWORD,
            },
            Threading::{
                CreateProcessW, CreateRemoteThread, GetCurrentProcess, GetExitCodeProcess,
                GetExitCodeThread, GetProcessTimes, GetThreadId, GetThreadTimes, OpenProcess,
                OpenProcessToken, QueryFullProcessImageNameW, ResumeThread, TerminateProcess,
                WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, PROCESS_CREATE_THREAD,
                PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, PROCESS_NAME_WIN32,
                PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_OPERATION,
                PROCESS_VM_READ, PROCESS_VM_WRITE, STARTF_USESHOWWINDOW, STARTUPINFOW,
            },
        },
        UI::{
            Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW},
            WindowsAndMessaging::SW_HIDE,
        },
    },
};

const HELPER_FLAG: &str = "--micontrol-rc003-hid-tap-helper";
const SCRIPT: &str = include_str!("rc003_hid_tap.js");
const RUNTIME_VERSION: &str = "17.15.3-three-key-v1";
const INJECT_DEADLINE: Duration = Duration::from_secs(45);
const ACL_STAGE_DEADLINE: Duration = Duration::from_secs(10);
const REMOTE_WAIT_DEADLINE: Duration = Duration::from_secs(20);
const PENDING_INJECTION_NAME: &str = ".rc003-injection-pending.json";
static PENDING_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PendingInjection {
    pid: u32,
    process_creation_time: u64,
    allocation_address: Option<usize>,
    thread_id: Option<u32>,
    thread_creation_time: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingDecision {
    ClearIdentityChanged,
    ReuseLoaded,
    RejectPending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreviousTarget {
    Alive(u64),
    Gone,
    Denied,
}

fn pending_decision(
    pending: &PendingInjection,
    pid: u32,
    process_creation_time: u64,
    already_loaded: bool,
    previous_target: PreviousTarget,
) -> PendingDecision {
    if pending.pid == pid && pending.process_creation_time == process_creation_time {
        if already_loaded {
            PendingDecision::ReuseLoaded
        } else {
            PendingDecision::RejectPending
        }
    } else if pending.pid == pid {
        PendingDecision::ClearIdentityChanged
    } else {
        match previous_target {
            PreviousTarget::Alive(creation_time)
                if creation_time == pending.process_creation_time =>
            {
                PendingDecision::RejectPending
            }
            PreviousTarget::Denied => PendingDecision::RejectPending,
            PreviousTarget::Alive(_) | PreviousTarget::Gone => {
                PendingDecision::ClearIdentityChanged
            }
        }
    }
}

fn previous_target_state(pid: u32) -> PreviousTarget {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
    let Ok(handle) = handle else {
        let code = unsafe { GetLastError() };
        return if code == ERROR_INVALID_PARAMETER {
            PreviousTarget::Gone
        } else if code == ERROR_ACCESS_DENIED {
            PreviousTarget::Denied
        } else {
            PreviousTarget::Denied
        };
    };
    let process = OwnedHandle(handle);
    match process_creation_time(process.0) {
        Ok(creation_time) => PreviousTarget::Alive(creation_time),
        Err(_) => PreviousTarget::Denied,
    }
}

fn filetime_value(value: FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

fn process_creation_time(process: HANDLE) -> Result<u64, String> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) }
        .map_err(|e| format!("读取目标进程创建时间失败：{e}"))?;
    Ok(filetime_value(creation))
}

fn thread_creation_time(thread: HANDLE) -> Result<u64, String> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe { GetThreadTimes(thread, &mut creation, &mut exit, &mut kernel, &mut user) }
        .map_err(|e| format!("读取远程线程创建时间失败：{e}"))?;
    Ok(filetime_value(creation))
}

fn pending_injection_path(root: &Path) -> PathBuf {
    root.join(PENDING_INJECTION_NAME)
}

fn service_runtime_path(service_root: &Path) -> PathBuf {
    service_root.join("runtime")
}

fn validate_pending_parent(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("旁路 pending 路径没有受管父目录：{}", path.display()))?;
    let metadata = std::fs::symlink_metadata(parent)
        .map_err(|e| format!("读取旁路 pending 父目录失败 path={}：{e}", parent.display()))?;
    use std::os::windows::fs::MetadataExt;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.file_attributes() & 0x400 != 0
    {
        return Err(format!(
            "旁路 pending 父目录不是固定非 reparse 目录：{}",
            parent.display()
        ));
    }
    let canonical = std::fs::canonicalize(parent)
        .map_err(|e| format!("解析旁路 pending 父目录失败 path={}：{e}", parent.display()))?;
    if normalize_windows_path(&canonical) != normalize_windows_path(parent) {
        return Err(format!(
            "旁路 pending 父目录解析到了受管路径之外：{}",
            parent.display()
        ));
    }
    Ok(())
}

fn normalize_windows_path(path: &Path) -> PathBuf {
    let value = path.to_string_lossy();
    if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{}", rest))
    } else if let Some(rest) = value.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path.to_owned()
    }
}

fn open_pending_file(path: &Path, write: bool, create_new: bool) -> Result<Option<File>, String> {
    validate_pending_parent(path)?;
    let name = wide(path);
    let access = FILE_GENERIC_READ.0 | if write { FILE_GENERIC_WRITE.0 } else { 0 };
    let disposition = if create_new {
        CREATE_NEW
    } else {
        OPEN_EXISTING
    };
    let result = unsafe {
        CreateFileW(
            PCWSTR(name.as_ptr()),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            disposition,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    };
    let handle = match result {
        Ok(handle) => handle,
        Err(error) if !create_new => {
            let last_error = unsafe { GetLastError() };
            if last_error == ERROR_FILE_NOT_FOUND || last_error == ERROR_PATH_NOT_FOUND {
                return Ok(None);
            }
            return Err(format!(
                "打开旁路 pending 文件失败 path={}：{error}",
                path.display()
            ));
        }
        Err(error) => {
            return Err(format!(
                "创建旁路 pending 文件失败 path={}：{error}",
                path.display()
            ));
        }
    };
    let mut info = windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_TAG_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            &mut info as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of_val(&info) as u32,
        )
    }
    .map_err(|error| format!("校验旁路 pending 文件失败 path={}：{error}", path.display()))?;
    if info.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_REPARSE_POINT.0) != 0 {
        unsafe {
            let _ = CloseHandle(handle);
        }
        return Err(format!("旁路 pending 不是普通文件：{}", path.display()));
    }
    let raw = handle.0;
    unsafe { Ok(Some(File::from_raw_handle(raw as *mut _))) }
}

fn pending_present(path: &Path) -> Result<bool, String> {
    if let Some(parent) = path.parent() {
        match std::fs::symlink_metadata(parent) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(format!(
                    "读取旁路 pending 父目录失败 path={}：{error}",
                    parent.display()
                ));
            }
        }
    }
    Ok(open_pending_file(path, false, false)?.is_some())
}

fn write_pending_injection(
    path: &Path,
    pending: &PendingInjection,
    create: bool,
) -> Result<(), String> {
    let bytes = serde_json::to_vec(pending).map_err(|e| e.to_string())?;
    if create {
        let mut file = open_pending_file(path, true, true)?
            .ok_or_else(|| format!("创建旁路 pending 文件失败 path={}", path.display()))?;
        file.write_all(&bytes)
            .map_err(|e| format!("写入旁路 pending intent 失败 path={}：{e}", path.display()))?;
        return file.sync_all().map_err(|e| {
            format!(
                "持久化旁路 pending intent 失败 path={}：{e}",
                path.display()
            )
        });
    }
    let sequence = PENDING_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = path.with_file_name(format!(
        "{PENDING_INJECTION_NAME}.{}.{}.tmp",
        std::process::id(),
        sequence
    ));
    let mut file = open_pending_file(&temporary, true, true)?
        .ok_or_else(|| format!("创建旁路 pending 临时文件失败 path={}", temporary.display()))?;
    file.write_all(&bytes).map_err(|e| {
        format!(
            "写入旁路 pending 临时文件失败 path={}：{e}",
            temporary.display()
        )
    })?;
    file.sync_all().map_err(|e| {
        format!(
            "持久化旁路 pending 临时文件失败 path={}：{e}",
            temporary.display()
        )
    })?;
    drop(file);
    if open_pending_file(path, false, false)?.is_none() {
        return Err(format!("更新旁路 pending 时原记录消失：{}", path.display()));
    }
    let from = wide(&temporary);
    let to = wide(path);
    unsafe {
        windows::Win32::Storage::FileSystem::MoveFileExW(
            PCWSTR(from.as_ptr()),
            PCWSTR(to.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(|error| format!("原子替换旁路 pending 失败 path={}：{error}", path.display()))
}

fn read_pending_injection(path: &Path) -> Result<PendingInjection, String> {
    let mut file = open_pending_file(path, false, false)?
        .ok_or_else(|| format!("旁路 pending 文件不存在 path={}", path.display()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("读取旁路 pending intent 失败 path={}：{e}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("旁路 pending intent 损坏 path={}：{e}", path.display()))
}

fn remove_pending_injection(path: &Path) -> Result<(), String> {
    validate_pending_parent(path)?;
    let name = wide(path);
    unsafe { DeleteFileW(PCWSTR(name.as_ptr())) }.map_err(|error| {
        format!(
            "删除旁路 pending intent 失败 path={}：{error}",
            path.display()
        )
    })
}
#[path = "hid_tap_service.rs"]
mod service;
pub use service::{handle_mode, manage_service, service_installed};

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}
fn hash_file(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}
struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AclChildLifecycleDecision {
    SafeToContinue,
    PreserveAndRefuse,
}

fn acl_child_startup_decision(
    job_configured: bool,
    process_assigned: bool,
    thread_resumed: bool,
) -> AclChildLifecycleDecision {
    if job_configured && process_assigned && thread_resumed {
        AclChildLifecycleDecision::SafeToContinue
    } else {
        AclChildLifecycleDecision::PreserveAndRefuse
    }
}

fn acl_child_termination_decision(
    job_terminated: bool,
    process_reaped: bool,
) -> AclChildLifecycleDecision {
    if job_terminated && process_reaped {
        AclChildLifecycleDecision::SafeToContinue
    } else {
        AclChildLifecycleDecision::PreserveAndRefuse
    }
}

struct AclChildGuard {
    process: OwnedHandle,
    thread: OwnedHandle,
    job: OwnedHandle,
    job_assigned: bool,
    #[cfg(test)]
    pid: u32,
}

// Windows kernel handles may be moved between the short-lived ACL operation
// and the stale-child guard.  The handles themselves are the synchronization
// boundary; no borrowed process memory crosses the thread boundary.
unsafe impl Send for AclChildGuard {}

impl Drop for AclChildGuard {
    fn drop(&mut self) {
        if !self.job_assigned {
            let _ = unsafe { TerminateProcess(self.process.0, 1) };
        }
    }
}

static STALE_ACL_CHILD: Mutex<Option<AclChildGuard>> = Mutex::new(None);
static ACTIVE_ACL_CHILD: Mutex<()> = Mutex::new(());

fn acl_win32_error(operation: &str) -> String {
    format!("{operation} Win32 error={}", unsafe { GetLastError().0 })
}

fn acl_child_is_terminated(child: &AclChildGuard) -> Result<bool, String> {
    let result = unsafe { WaitForSingleObject(child.process.0, 0) };
    if result == WAIT_OBJECT_0 {
        Ok(true)
    } else if result == WAIT_TIMEOUT {
        Ok(false)
    } else if result == WAIT_FAILED {
        Err(acl_win32_error("等待 ACL helper 进程"))
    } else {
        Err(format!("等待 ACL helper 进程返回未知状态={}", result.0))
    }
}

fn terminate_acl_child(child: &mut AclChildGuard) -> bool {
    let terminated = unsafe { TerminateJobObject(child.job.0, 1) }.is_ok();
    if !terminated {
        return false;
    }
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        match acl_child_is_terminated(child) {
            Ok(true) => {
                return acl_child_termination_decision(true, true)
                    == AclChildLifecycleDecision::SafeToContinue;
            }
            Ok(false) => thread::sleep(Duration::from_millis(20)),
            Err(_) => return false,
        }
    }
    acl_child_termination_decision(
        terminated,
        matches!(acl_child_is_terminated(child), Ok(true)),
    ) == AclChildLifecycleDecision::SafeToContinue
}

fn preserve_unreaped_acl_child(child: AclChildGuard) {
    let Ok(mut stale) = STALE_ACL_CHILD.lock() else {
        // The process-wide mutex cannot be poisoned by an ordinary helper
        // failure.  Closing the guard still kills the job (or directly
        // terminates an unassigned process) rather than permitting a second
        // ACL mutator without a lifetime owner.
        drop(child);
        return;
    };
    if stale.is_none() {
        *stale = Some(child);
    } else {
        // There must never be two ACL mutators.  The caller already refused a
        // new request while an old guard was present; this is only a defensive
        // path for a future caller; close the new job guard so it cannot
        // outlive the operation without a corresponding slot.
        drop(child);
    }
}

fn ensure_acl_child_slot_available() -> Result<(), String> {
    let Ok(mut stale) = STALE_ACL_CHILD.lock() else {
        return Err("ACL helper 生命周期锁不可用，拒绝新的 ACL 操作".into());
    };
    let Some(child) = stale.as_ref() else {
        return Ok(());
    };
    match acl_child_is_terminated(child) {
        Ok(true) => {
            stale.take();
            Ok(())
        }
        Ok(false) => Err("上一个 ACL helper 尚未确认终止，拒绝新的 ACL 操作".into()),
        Err(error) => Err(format!(
            "上一个 ACL helper 终止状态未知，拒绝新的 ACL 操作：{error}"
        )),
    }
}

fn terminate_unassigned_acl_child(child: &mut AclChildGuard) -> bool {
    if unsafe { TerminateProcess(child.process.0, 1) }.is_err() {
        return false;
    }
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        let result = unsafe { WaitForSingleObject(child.process.0, 20) };
        if result == WAIT_OBJECT_0 {
            return true;
        }
    }
    matches!(acl_child_is_terminated(child), Ok(true))
}

fn quote_acl_command_arg(value: &str) -> String {
    let mut result = String::with_capacity(value.len() + 2);
    result.push('"');
    let mut backslashes = 0;
    for character in value.chars() {
        if character == '\\' {
            backslashes += 1;
        } else if character == '"' {
            result.push_str(&"\\".repeat(backslashes * 2 + 1));
            result.push('"');
            backslashes = 0;
        } else {
            if backslashes != 0 {
                result.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
            }
            result.push(character);
        }
    }
    result.push_str(&"\\".repeat(backslashes * 2));
    result.push('"');
    result
}

fn spawn_acl_process(executable: &Path, arguments: &[&str]) -> Result<AclChildGuard, String> {
    let executable_text = executable
        .to_str()
        .ok_or_else(|| "ACL helper executable path is not valid Unicode".to_owned())?;
    let mut command_line = quote_acl_command_arg(executable_text);
    for argument in arguments {
        command_line.push(' ');
        command_line.push_str(&quote_acl_command_arg(argument));
    }
    let executable_wide = wide(&executable);
    let mut command_line_wide = wide(command_line);
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESHOWWINDOW,
        wShowWindow: SW_HIDE.0 as u16,
        ..Default::default()
    };
    let mut process_info = PROCESS_INFORMATION::default();
    let flags = PROCESS_CREATION_FLAGS(CREATE_NO_WINDOW.0 | CREATE_SUSPENDED.0);
    unsafe {
        CreateProcessW(
            PCWSTR(executable_wide.as_ptr()),
            Some(PWSTR(command_line_wide.as_mut_ptr())),
            None,
            None,
            false,
            flags,
            None,
            PCWSTR(std::ptr::null()),
            &startup,
            &mut process_info,
        )
    }
    .map_err(|error| format!("CreateProcessW ACL helper failed: {error}"))?;

    let process = OwnedHandle(process_info.hProcess);
    let thread_handle = OwnedHandle(process_info.hThread);
    let job_handle = match unsafe { CreateJobObjectW(None, PCWSTR(std::ptr::null())) } {
        Ok(handle) if !handle.is_invalid() => handle,
        result => {
            let error = result
                .err()
                .map(|error| error.to_string())
                .unwrap_or_else(|| "invalid job handle".to_owned());
            let mut child = AclChildGuard {
                process,
                thread: thread_handle,
                job: OwnedHandle(HANDLE::default()),
                job_assigned: false,
                #[cfg(test)]
                pid: process_info.dwProcessId,
            };
            if !terminate_unassigned_acl_child(&mut child) {
                preserve_unreaped_acl_child(child);
                return Err(
                    "CreateJobObjectW ACL helper failed; child termination is unconfirmed".into(),
                );
            }
            return Err(format!("CreateJobObjectW ACL helper failed: {error}"));
        }
    };
    let job = OwnedHandle(job_handle);
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let configure_error = unsafe {
        SetInformationJobObject(
            job.0,
            JOBOBJECTINFOCLASS(9),
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
        .err()
        .map(|error| error.to_string())
    };
    let mut child = AclChildGuard {
        process,
        thread: thread_handle,
        job,
        job_assigned: false,
        #[cfg(test)]
        pid: process_info.dwProcessId,
    };
    if let Some(error) = configure_error {
        if !terminate_unassigned_acl_child(&mut child) {
            preserve_unreaped_acl_child(child);
            return Err(
                "SetInformationJobObject ACL helper failed; child termination is unconfirmed"
                    .into(),
            );
        }
        return Err(format!(
            "SetInformationJobObject ACL helper failed: {error}"
        ));
    }
    let assign_error = unsafe { AssignProcessToJobObject(child.job.0, child.process.0) }
        .err()
        .map(|error| error.to_string());
    if let Some(error) = assign_error {
        if !terminate_unassigned_acl_child(&mut child) {
            preserve_unreaped_acl_child(child);
            return Err(
                "AssignProcessToJobObject ACL helper failed; child termination is unconfirmed"
                    .into(),
            );
        }
        return Err(format!(
            "AssignProcessToJobObject ACL helper failed: {error}"
        ));
    }
    child.job_assigned = true;
    let resume_result = unsafe { ResumeThread(child.thread.0) };
    let resume_error = (resume_result == u32::MAX).then(|| unsafe { GetLastError().0 });
    let thread_resumed = resume_error.is_none();
    if acl_child_startup_decision(true, true, thread_resumed)
        != AclChildLifecycleDecision::SafeToContinue
    {
        if !terminate_acl_child(&mut child) {
            preserve_unreaped_acl_child(child);
            return Err("ResumeThread ACL helper failed; termination is unconfirmed".into());
        }
        return Err(format!(
            "ResumeThread ACL helper failed Win32 error={}",
            resume_error.unwrap_or_default()
        ));
    }
    Ok(child)
}

fn spawn_acl_child(target_arg: &str, owner_sid: &str) -> Result<AclChildGuard, String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    spawn_acl_process(&executable, &[service::ACL_HELPER, target_arg, owner_sid])
}
struct RegistryKey(HKEY);
impl Drop for RegistryKey {
    fn drop(&mut self) {
        unsafe {
            let _ = RegCloseKey(self.0);
        }
    }
}
fn open_key(parent: HKEY, path: &str) -> Result<RegistryKey, String> {
    let name = wide(path);
    let mut key = HKEY::default();
    unsafe { RegOpenKeyExW(parent, PCWSTR(name.as_ptr()), None, KEY_READ, &mut key) }
        .ok()
        .map_err(|e| e.to_string())?;
    Ok(RegistryKey(key))
}
fn subkeys(key: HKEY) -> Result<Vec<String>, String> {
    let mut result = Vec::new();
    for index in 0.. {
        let mut buffer = [0u16; 1024];
        let mut length = buffer.len() as u32;
        let status = unsafe {
            RegEnumKeyExW(
                key,
                index,
                Some(PWSTR(buffer.as_mut_ptr())),
                &mut length,
                None,
                None,
                None,
                None,
            )
        };
        if status.0 == 259 {
            break;
        } // ERROR_NO_MORE_ITEMS
        status.ok().map_err(|e| e.to_string())?;
        result.push(String::from_utf16_lossy(&buffer[..length as usize]));
    }
    Ok(result)
}

/// Fail on multiple paired RC003 HID instances; never inject into an arbitrary
/// host just because its process name or VID/PID looks similar.
fn decode_host_pid(kind: u32, bytes: &[u8]) -> Option<u32> {
    let value = if kind == REG_DWORD.0 {
        u32::from_le_bytes(bytes.try_into().ok()?) as u64
    } else if kind == REG_QWORD.0 {
        u64::from_le_bytes(bytes.try_into().ok()?)
    } else {
        return None;
    };
    let pid = u32::try_from(value).ok()?;
    (pid > 0).then_some(pid)
}

fn host_pid() -> Result<u32, String> {
    let root = open_key(
        HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Enum\BTHLEDevice",
    )?;
    let mut matches = Vec::new();
    for service in subkeys(root.0)? {
        let folded = service.to_ascii_lowercase();
        if !folded.starts_with("{00001812-0000-1000-8000-00805f9b34fb}")
            || !folded.contains("dev_vid&012717_pid&32b8_rev&00a4")
        {
            continue;
        }
        let key = open_key(root.0, &service)?;
        for instance in subkeys(key.0)? {
            let Ok(diag) = open_key(
                key.0,
                &format!(r"{instance}\Device Parameters\WUDFDiagnosticInfo"),
            ) else {
                continue;
            };
            // Windows versions/drivers store HostPid as DWORD or QWORD.
            // An eight-byte buffer avoids ERROR_MORE_DATA for REG_QWORD.
            let mut bytes = [0u8; 8];
            let mut length = bytes.len() as u32;
            let mut kind = REG_DWORD;
            let status = unsafe {
                RegQueryValueExW(
                    diag.0,
                    w!("HostPid"),
                    None,
                    Some(&mut kind),
                    Some(bytes.as_mut_ptr()),
                    Some(&mut length),
                )
            };
            if status.is_ok() && length <= bytes.len() as u32 {
                if let Some(pid) = decode_host_pid(kind.0, &bytes[..length as usize]) {
                    matches.push(pid);
                }
            }
        }
    }
    match matches.as_slice() {
        [pid] => Ok(*pid),
        [] => {
            Err("未找到 RC003 的 HID 驱动宿主。请先配对并唤醒遥控器（目前支持 REV_00A4）。".into())
        }
        _ => Err("检测到多个 RC003 HID 接口。请仅保留目标遥控器后重新启用。".into()),
    }
}

fn runtime_directory() -> Result<PathBuf, String> {
    if std::env::args().nth(1).as_deref() == Some("--micontrol-rc003-service") {
        return service::service_runtime_dir();
    }
    let data = std::env::var_os("ProgramData").ok_or("ProgramData is unavailable")?;
    Ok(PathBuf::from(data)
        .join("MiControl")
        .join("hid-tap")
        .join(RUNTIME_VERSION))
}

pub struct HidTapRuntime {
    snapshot: Arc<Mutex<HidTapSnapshot>>,
    control: Mutex<Option<(Arc<AtomicBool>, JoinHandle<()>)>>,
    lifecycle: Mutex<()>,
    engine: Sender<EngineMessage>,
}
impl HidTapRuntime {
    pub fn new(engine: Sender<EngineMessage>) -> Self {
        Self {
            snapshot: Arc::new(Mutex::new(HidTapSnapshot::default())),
            control: Mutex::new(None),
            lifecycle: Mutex::new(()),
            engine,
        }
    }
    pub fn snapshot(&self) -> HidTapSnapshot {
        let mut result = self.snapshot.lock().unwrap().clone();
        result.service_installed = service_installed();
        result
    }
    pub fn start(&self, source: PathBuf) -> Result<HidTapSnapshot, String> {
        if std::env::consts::ARCH != "x86_64" {
            return Err("完整按键旁路目前仅支持 Windows x64".into());
        }
        let _guard = self.lifecycle.lock().unwrap();
        self.stop_inner();
        if hash_file(&source)? != GADGET_SHA256 {
            return Err("Frida Gadget 缺失或 SHA-256 校验失败".into());
        }
        let pid = host_pid()?;
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let mut nonce = [0u8; 32];
        unsafe { BCryptGenRandom(None, &mut nonce, BCRYPT_USE_SYSTEM_PREFERRED_RNG) }
            .ok()
            .map_err(|e| e.to_string())?;
        let token: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        *self.snapshot.lock().unwrap() = HidTapSnapshot {
            enabled: true,
            phase: HidTapPhase::Preparing,
            host_pid: Some(pid),
            ..HidTapSnapshot::default()
        };
        let service_mode = service_installed();
        let process = match if service_mode {
            service::request(pid, port, &token).map(|_| None)
        } else {
            launch_helper(pid, port, &token, &source).map(Some)
        } {
            Ok(process) => process,
            Err(error) => {
                let mut snapshot = self.snapshot.lock().unwrap();
                snapshot.phase = HidTapPhase::Failed;
                snapshot.enabled = false;
                snapshot.last_error = Some(error.clone());
                return Err(error);
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let snapshot = self.snapshot.clone();
        let engine = self.engine.clone();
        // HANDLE is owned by the worker; pass the pointer value across spawn.
        let handle = process.map(|process| {
            let handle = process.0 .0 as usize;
            std::mem::forget(process);
            handle
        });
        let worker = thread::Builder::new()
            .name("micontrol-rc003-hid-tap".into())
            .spawn(move || {
                let process = handle.map(|handle| OwnedHandle(HANDLE(handle as *mut _)));
                run_receiver(
                    listener,
                    pid,
                    port,
                    token,
                    process,
                    service_mode,
                    &thread_stop,
                    &snapshot,
                    &engine,
                );
                let _ = engine.send(EngineMessage::TapDisconnected);
            })
            .map_err(|e| {
                unsafe {
                    if let Some(handle) = handle {
                        let _ = CloseHandle(HANDLE(handle as *mut _));
                    }
                }
                e.to_string()
            })?;
        *self.control.lock().unwrap() = Some((stop, worker));
        Ok(self.snapshot())
    }
    pub fn stop(&self) {
        let _guard = self.lifecycle.lock().unwrap();
        self.stop_inner();
    }
    fn stop_inner(&self) {
        if let Some((stop, worker)) = self.control.lock().unwrap().take() {
            stop.store(true, Ordering::Relaxed);
            let _ = worker.join();
        }
        let _ = self.engine.send(EngineMessage::TapDisconnected);
        let mut snapshot = self.snapshot.lock().unwrap();
        snapshot.enabled = false;
        snapshot.phase = HidTapPhase::Disabled;
        snapshot.last_error = None;
    }
}
impl Drop for HidTapRuntime {
    fn drop(&mut self) {
        self.stop();
    }
}

fn failure(snapshot: &Mutex<HidTapSnapshot>, message: String) {
    crate::gatt_note(format!("hid_tap phase=failed reason={message}"));
    let mut snapshot = snapshot.lock().unwrap();
    snapshot.phase = HidTapPhase::Failed;
    snapshot.last_error = Some(message);
}

fn run_receiver(
    listener: TcpListener,
    pid: u32,
    port: u16,
    token: String,
    process: Option<OwnedHandle>,
    service_mode: bool,
    stop: &AtomicBool,
    snapshot: &Mutex<HidTapSnapshot>,
    engine: &Sender<EngineMessage>,
) {
    let started = Instant::now();
    let mut had_connection = false;
    let mut reinject_at = None;
    let mut reinject_delay = Duration::from_secs(1);
    while !stop.load(Ordering::Relaxed) {
        if service_mode {
            if let Some(deadline) = reinject_at {
                if Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
                match service::request(pid, port, &token) {
                    Ok(()) => {
                        reinject_at = None;
                        reinject_delay = Duration::from_secs(1);
                        let mut state = snapshot.lock().unwrap();
                        state.phase = HidTapPhase::Waiting;
                        state.last_error = None;
                        crate::gatt_note(
                            "hid_tap_reconnect phase=broker_reauthenticated terminal_result=passed"
                                .into(),
                        );
                    }
                    Err(error) => {
                        let next_delay = reinject_delay;
                        reinject_delay = (reinject_delay * 2).min(Duration::from_secs(15));
                        reinject_at = Some(Instant::now() + next_delay);
                        let mut state = snapshot.lock().unwrap();
                        state.phase = HidTapPhase::Failed;
                        state.last_error = Some(format!("旁路服务重连失败：{error}"));
                        crate::gatt_note(format!(
                            "hid_tap_reconnect phase=broker_reauthenticate terminal_result=failed retry_after_ms={} detail={error}",
                            next_delay.as_millis()
                        ));
                    }
                }
                continue;
            }
        }
        if host_pid().ok() != Some(pid) {
            failure(
                snapshot,
                "RC003 驱动宿主已变化，请重新启用完整按键。".into(),
            );
            return;
        }
        let mut exit = 259u32;
        unsafe {
            if let Some(process) = &process {
                let _ = GetExitCodeProcess(process.0, &mut exit);
            }
        }
        if exit != 259 && exit != 0 {
            failure(
                snapshot,
                format!("旁路准备失败（辅助程序退出码 {exit}），请查看诊断日志。"),
            );
            return;
        }
        if !had_connection && started.elapsed() > Duration::from_secs(30) {
            failure(
                snapshot,
                "等待 HID 旁路连接超时，请检查权限、配对状态与安全软件记录。".into(),
            );
            return;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                had_connection |= read_connection(stream, pid, &token, stop, snapshot, engine);
                let _ = engine.send(EngineMessage::TapDisconnected);
                if snapshot.lock().unwrap().phase == HidTapPhase::Failed {
                    return;
                }
                if !stop.load(Ordering::Relaxed) {
                    snapshot.lock().unwrap().phase = HidTapPhase::Waiting;
                    if service_mode && had_connection {
                        reinject_at = Some(Instant::now());
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100))
            }
            Err(e) => {
                failure(snapshot, e.to_string());
                return;
            }
        }
    }
}

fn read_connection(
    stream: TcpStream,
    pid: u32,
    token: &str,
    stop: &AtomicBool,
    snapshot: &Mutex<HidTapSnapshot>,
    engine: &Sender<EngineMessage>,
) -> bool {
    if stream
        .set_read_timeout(Some(Duration::from_millis(250)))
        .is_err()
    {
        return false;
    }
    let Ok(mut controls) = stream.try_clone() else {
        return false;
    };
    if controls
        .set_write_timeout(Some(Duration::from_millis(250)))
        .is_err()
    {
        return false;
    }
    let mut reader = BufReader::new(stream);
    let mut pending = Vec::new();
    let mut heartbeat = Instant::now();
    let mut active_since = None;
    let mut hold_expired = false;
    let mut authenticated = false;
    let mut host_check = Instant::now();
    loop {
        if stop.load(Ordering::Relaxed) {
            return authenticated;
        }
        if host_check.elapsed() >= Duration::from_secs(1) {
            if host_pid().ok() != Some(pid) {
                return authenticated;
            }
            host_check = Instant::now();
        }
        if heartbeat.elapsed() > Duration::from_secs(12) {
            return authenticated;
        }
        // A lost release must not leave volume repeating forever. The tap is
        // specifically a volume/back compatibility mode, with a 10s hold cap.
        if active_since.is_some_and(|start: Instant| start.elapsed() >= Duration::from_secs(10)) {
            let _ = engine.send(EngineMessage::TapDisconnected);
            active_since = None;
            hold_expired = true;
        }
        match reader.fill_buf() {
            Ok([]) => return authenticated,
            Ok(bytes) => {
                let consumed = bytes
                    .iter()
                    .position(|b| *b == b'\n')
                    .map(|p| p + 1)
                    .unwrap_or(bytes.len());
                pending.extend_from_slice(&bytes[..consumed]);
                let complete = bytes[consumed - 1] == b'\n';
                reader.consume(consumed);
                if pending.len() > 4096 {
                    return authenticated;
                }
                if !complete {
                    continue;
                }
                let message: serde_json::Value = match serde_json::from_slice(&pending) {
                    Ok(value) => value,
                    Err(_) => return authenticated,
                };
                pending.clear();
                if message["token"].as_str() != Some(token)
                    || message["pid"].as_u64() != Some(pid as u64)
                {
                    return authenticated;
                }
                authenticated = true;
                heartbeat = Instant::now();
                match message["kind"].as_str() {
                    Some("ready" | "heartbeat") => {
                        if message["protocol"].as_u64() != Some(3) {
                            failure(
                                snapshot,
                                "驱动宿主仍加载旧版旁路。请重启电脑，再启用新版完整按键。".into(),
                            );
                            return authenticated;
                        }
                        if writeln!(
                            controls,
                            "{}",
                            serde_json::json!({"kind":"voice_guard", "token":token})
                        )
                        .is_err()
                        {
                            return authenticated;
                        }
                        let mut state = snapshot.lock().unwrap();
                        if state.phase == HidTapPhase::Preparing {
                            state.phase = HidTapPhase::Waiting;
                        }
                    }
                    Some("gatt_read") => {
                        if message["voiceFiltered"].as_bool() == Some(true) {
                            crate::gatt_note("hid_tap voice_f5_filtered=true".into());
                        }
                        let Some(raw) = message["raw"].as_str() else {
                            continue;
                        };
                        if let Ok(usages) = decode_tap_report(raw) {
                            if usages.is_empty() {
                                active_since = None;
                                hold_expired = false;
                            } else if !hold_expired && active_since.is_none() {
                                active_since = Some(Instant::now());
                            }
                            let mut state = snapshot.lock().unwrap();
                            if state.phase != HidTapPhase::Ready {
                                crate::gatt_note(format!(
                                    "hid_tap phase=ready host_pid={pid} io_verified=true"
                                ));
                            }
                            state.phase = HidTapPhase::Ready;
                            state.report_count += 1;
                            state.last_error = None;
                            drop(state);
                            if !hold_expired {
                                // Some driver versions may also emit a native
                                // volume VK. Arm only these three buttons, on
                                // this independent thread, before dispatch.
                                for usage in &usages {
                                    if let Some(button) = crate::raw_input::button_for_usage(*usage)
                                    {
                                        crate::key_gate::arm_button(button, 180);
                                    }
                                }
                                let _ = engine.send(EngineMessage::TapUsages(usages));
                            }
                        }
                    }
                    Some("error" | "helper_error") => {
                        failure(
                            snapshot,
                            message["message"].as_str().unwrap_or("旁路失败").to_owned(),
                        );
                        return authenticated;
                    }
                    _ => {}
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return authenticated,
        }
    }
}

fn launch_helper(pid: u32, port: u16, token: &str, source: &Path) -> Result<OwnedHandle, String> {
    let executable = wide(std::env::current_exe().map_err(|e| e.to_string())?);
    let source = source.to_str().ok_or("Gadget 路径不是有效 Unicode")?;
    if source.contains('"') {
        return Err("Invalid Gadget path".into());
    }
    let arguments = wide(format!("{HELPER_FLAG} {pid} {port} {token} \"{source}\""));
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(executable.as_ptr()),
        lpParameters: PCWSTR(arguments.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    unsafe { ShellExecuteExW(&mut info) }.map_err(|e| format!("管理员授权未完成：{e}"))?;
    if info.hProcess.is_invalid() {
        return Err("未取得旁路辅助程序句柄".into());
    }
    Ok(OwnedHandle(info.hProcess))
}

/// Called before Tauri initialization, so the elevated helper never opens a
/// second GUI, BLE connection, tray, or keyboard hook.
pub fn run_helper_if_requested() -> Option<i32> {
    let args: Vec<String> = std::env::args().collect();
    if let Some(code) = service::handle_mode(&args) {
        return Some(code);
    }
    if args.get(1).map(String::as_str) != Some(HELPER_FLAG) {
        return None;
    }
    let parsed = (|| {
        if args.len() != 6 {
            return Err("Invalid helper arguments".to_owned());
        }
        let pid = args[2].parse::<u32>().map_err(|e| e.to_string())?;
        let port = args[3].parse::<u16>().map_err(|e| e.to_string())?;
        let token = &args[4];
        if port == 0 || token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Invalid helper endpoint".to_owned());
        }
        if host_pid()? != pid {
            return Err("RC003 宿主变化，拒绝加载".into());
        }
        inject(
            pid,
            port,
            token,
            Path::new(&args[5]),
            None,
            Instant::now() + INJECT_DEADLINE,
        )
    })();
    if let Err(error) = parsed {
        if args.len() == 6 {
            if let (Ok(pid), Ok(port)) = (args[2].parse::<u32>(), args[3].parse::<u16>()) {
                if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
                    let _ = writeln!(
                        stream,
                        "{}",
                        serde_json::json!({"kind":"helper_error", "pid":pid,
                        "token":args[4], "message":error})
                    );
                }
            }
        }
        return Some(1);
    }
    Some(0)
}

fn current_user_sid() -> Result<String, String> {
    let output = std::process::Command::new(
        PathBuf::from(std::env::var_os("WINDIR").ok_or("Windows directory unavailable")?)
            .join("System32")
            .join("whoami.exe"),
    )
    .args(["/user", "/fo", "csv", "/nh"])
    .creation_flags(0x08000000)
    .output()
    .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("无法读取当前 Windows 用户 SID".into());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let sid = text
        .split(|c: char| c == ',' || c == '"' || c.is_whitespace())
        .find(|part| part.starts_with("S-1-"))
        .ok_or("whoami 未返回有效用户 SID")?;
    if sid.len() >= 184
        || !sid
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
    {
        return Err("当前用户 SID 格式无效".into());
    }
    Ok(sid.to_owned())
}

fn wait_for_acl_child_guard(
    mut child: AclChildGuard,
    target: &str,
    stage_deadline: Instant,
) -> Result<(), String> {
    loop {
        let result = unsafe { WaitForSingleObject(child.process.0, 25) };
        if result == WAIT_OBJECT_0 {
            let mut exit_code = 1u32;
            unsafe { GetExitCodeProcess(child.process.0, &mut exit_code) }.map_err(|error| {
                format!("读取 service ACL helper 退出码失败 target={target}：{error}")
            })?;
            if exit_code == 0 {
                return Ok(());
            }
            return Err(format!(
                "service ACL helper 失败 target={target} exit_code={exit_code}"
            ));
        }
        if result == WAIT_FAILED {
            let reaped = terminate_acl_child(&mut child);
            if !reaped {
                preserve_unreaped_acl_child(child);
            }
            return Err(format!(
                "读取 service ACL helper 状态失败 target={target} child_reaped={reaped}"
            ));
        }
        if result != WAIT_TIMEOUT {
            let reaped = terminate_acl_child(&mut child);
            if !reaped {
                preserve_unreaped_acl_child(child);
            }
            return Err(format!(
                "service ACL helper 等待状态异常 target={target} result={} child_reaped={reaped}",
                result.0
            ));
        }
        if Instant::now() >= stage_deadline {
            let reaped = terminate_acl_child(&mut child);
            if !reaped {
                preserve_unreaped_acl_child(child);
            }
            return Err(format!(
                "ACL 阶段超时 target={target} budget_ms={} child_reaped={reaped}",
                ACL_STAGE_DEADLINE.as_millis()
            ));
        }
    }
}

fn run_bounded_service_acl(
    path: &Path,
    target: service::RuntimeAclTarget,
    owner_sid: &str,
    stage_deadline: Instant,
) -> Result<(), String> {
    if Instant::now() >= stage_deadline {
        return Err(format!(
            "ACL 阶段预算已耗尽，未启动 service ACL helper path={} budget_ms=0",
            path.display()
        ));
    }
    let target_arg = service::runtime_acl_helper_target(path, target)?;
    if Instant::now() >= stage_deadline {
        return Err(format!(
            "ACL 阶段预算已耗尽，未启动 service ACL helper target={} budget_ms=0",
            target_arg
        ));
    }
    let _active = ACTIVE_ACL_CHILD
        .try_lock()
        .map_err(|_| "已有 ACL helper 操作正在进行，拒绝新的 ACL 操作".to_owned())?;
    ensure_acl_child_slot_available()?;
    let child = spawn_acl_child(target_arg, owner_sid).map_err(|error| {
        format!(
            "启动 service ACL helper 失败 target={} path={}：{error}",
            target_arg,
            path.display()
        )
    })?;
    wait_for_acl_child_guard(child, target_arg, stage_deadline)
}

fn secure_acl(
    path: &Path,
    directory: bool,
    owner_sid: &str,
    owner_access: &str,
    service_mode: bool,
    deadline: Instant,
) -> Result<(), String> {
    let stage_deadline = deadline.min(Instant::now() + ACL_STAGE_DEADLINE);
    if Instant::now() >= stage_deadline {
        return Err(format!(
            "ACL 阶段预算已耗尽，未启动 ACL path={} budget_ms=0",
            path.display()
        ));
    }
    if service_mode {
        let target = if directory {
            service::RuntimeAclTarget::RuntimeDirectory
        } else if path.file_name().is_some_and(|name| {
            name.to_string_lossy()
                .eq_ignore_ascii_case("MiControlRC003HidTap.dll")
        }) {
            service::RuntimeAclTarget::RuntimeDll
        } else {
            service::RuntimeAclTarget::RuntimeReadFile
        };
        if owner_access != "RX" {
            return Err(format!(
                "service ACL helper owner 权限契约无效：expected=RX actual={owner_access}"
            ));
        }
        return run_bounded_service_acl(path, target, owner_sid, stage_deadline);
    }
    let suffix = if directory { "(OI)(CI)" } else { "" };
    let mut child = std::process::Command::new(
        PathBuf::from(std::env::var_os("WINDIR").ok_or("Windows directory unavailable")?)
            .join("System32")
            .join("icacls.exe"),
    )
    .arg(path)
    .args([
        "/inheritance:r",
        "/grant:r",
        &format!("*S-1-5-18:{suffix}F"),
        &format!("*S-1-5-32-544:{suffix}F"),
        &format!("*{owner_sid}:{suffix}{owner_access}"),
        "/Q",
    ])
    .creation_flags(0x08000000)
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null())
    .spawn()
    .map_err(|e| format!("启动 ACL 阶段失败 path={}：{e}", path.display()))?;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| format!("读取 ACL 阶段状态失败 path={}：{e}", path.display()))?
        {
            if status.success() {
                return Ok(());
            }
            return Err(format!(
                "ACL 阶段退出失败 path={} exit_code={:?}",
                path.display(),
                status.code()
            ));
        }
        if Instant::now() >= stage_deadline {
            let _ = child.kill();
            let reap_deadline = Instant::now() + Duration::from_secs(1);
            while Instant::now() < reap_deadline {
                if child.try_wait().ok().flatten().is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            return Err(format!(
                "ACL 阶段超时 path={} budget_ms={} exit_code={:?}",
                path.display(),
                ACL_STAGE_DEADLINE.as_millis(),
                child.try_wait().ok().flatten().and_then(|s| s.code())
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn runtime_owner_access(service_mode: bool) -> &'static str {
    if service_mode {
        "RX"
    } else {
        "M"
    }
}

fn debug_privilege() -> Result<(), String> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .map_err(|e| e.to_string())?;
        let token = OwnedHandle(token);
        let mut luid = LUID::default();
        LookupPrivilegeValueW(None, w!("SeDebugPrivilege"), &mut luid)
            .map_err(|e| e.to_string())?;
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        AdjustTokenPrivileges(token.0, false, Some(&privileges), 0, None, None)
            .map_err(|e| e.to_string())?;
        if GetLastError() == ERROR_NOT_ALL_ASSIGNED {
            return Err("没有 SeDebugPrivilege 权限".into());
        }
    }
    Ok(())
}

fn already_loaded(pid: u32, path: &Path) -> Result<bool, String> {
    let modules = OwnedHandle(
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) }
            .map_err(|e| e.to_string())?,
    );
    let mut module = MODULEENTRY32W {
        dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };
    if let Err(error) = unsafe { Module32FirstW(modules.0, &mut module) } {
        let win32_error = unsafe { GetLastError() };
        if win32_error == ERROR_NO_MORE_FILES {
            return Ok(false);
        }
        return Err(format!(
            "枚举 WUDFHost 模块首项失败 win32_error={} detail={error}",
            win32_error.0
        ));
    }
    loop {
        let length = module
            .szExePath
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(module.szExePath.len());
        let name = String::from_utf16_lossy(&module.szExePath[..length]);
        if name.eq_ignore_ascii_case(&path.to_string_lossy()) {
            return Ok(true);
        }
        if Path::new(&name).file_name().is_some_and(|n| {
            n.to_string_lossy()
                .eq_ignore_ascii_case("MiControlRC003HidTap.dll")
        }) {
            return Err("驱动宿主仍驻留旧路径的旁路。首次升级服务模式请重启电脑一次，然后自动恢复完整按键。".into());
        }
        if let Err(error) = unsafe { Module32NextW(modules.0, &mut module) } {
            let win32_error = unsafe { GetLastError() };
            if win32_error == ERROR_NO_MORE_FILES {
                break;
            }
            return Err(format!(
                "枚举 WUDFHost 后续模块失败 win32_error={} detail={error}",
                win32_error.0
            ));
        }
    }
    Ok(false)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteWaitResult {
    Completed,
    TimedOut,
    Failed,
    Unexpected(u32),
}

fn classify_wait_result(status: u32) -> RemoteWaitResult {
    match status {
        value if value == WAIT_OBJECT_0.0 => RemoteWaitResult::Completed,
        value if value == WAIT_TIMEOUT.0 => RemoteWaitResult::TimedOut,
        value if value == WAIT_FAILED.0 => RemoteWaitResult::Failed,
        value => RemoteWaitResult::Unexpected(value),
    }
}

fn read_remote_thread_exit_code(thread: HANDLE) -> Result<u32, String> {
    let mut exit_code = 0;
    unsafe { GetExitCodeThread(thread, &mut exit_code) }.map_err(|error| {
        let win32_error = unsafe { GetLastError() };
        format!(
            "读取 Gadget 远程线程退出码失败 win32_error={} detail={error}",
            win32_error.0
        )
    })?;
    Ok(exit_code)
}

fn remote_exit_diagnostic(exit_code: &Result<u32, String>) -> String {
    match exit_code {
        Ok(code) => format!("remote_thread_exit_code={code}"),
        Err(error) => format!("remote_thread_exit_code_query_failed={error}"),
    }
}

fn format_gadget_module_missing(exit_code: &Result<u32, String>) -> String {
    format!(
        "Gadget 未加载，请查看安全软件记录；{}",
        remote_exit_diagnostic(exit_code)
    )
}

fn format_gadget_module_probe_failed(exit_code: &Result<u32, String>, error: &str) -> String {
    format!(
        "Gadget 模块枚举失败；{}；module_probe_error={error}",
        remote_exit_diagnostic(exit_code)
    )
}

fn inject(
    pid: u32,
    port: u16,
    token: &str,
    source: &Path,
    configured_owner_sid: Option<&str>,
    deadline: Instant,
) -> Result<(), String> {
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| "旁路 inject 总 deadline 已到期".to_owned())
    };
    remaining()?;
    if std::env::consts::ARCH != "x86_64" || hash_file(source)? != GADGET_SHA256 {
        return Err("Gadget 架构或 SHA-256 校验失败".into());
    }
    debug_privilege()?;
    let rights = PROCESS_QUERY_INFORMATION
        | PROCESS_CREATE_THREAD
        | PROCESS_VM_OPERATION
        | PROCESS_VM_WRITE
        | PROCESS_VM_READ;
    let process =
        OwnedHandle(unsafe { OpenProcess(rights, false, pid) }.map_err(|e| e.to_string())?);
    let mut name = [0u16; 32768];
    let mut length = name.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            process.0,
            PROCESS_NAME_WIN32,
            PWSTR(name.as_mut_ptr()),
            &mut length,
        )
    }
    .map_err(|e| e.to_string())?;
    let name = PathBuf::from(String::from_utf16_lossy(&name[..length as usize]));
    let system_host =
        PathBuf::from(std::env::var_os("WINDIR").ok_or("Windows directory unavailable")?)
            .join("System32")
            .join("WUDFHost.exe");
    if !name
        .to_string_lossy()
        .eq_ignore_ascii_case(&system_host.to_string_lossy())
    {
        return Err("拒绝加载到非 WUDFHost 进程".into());
    }
    let root = runtime_directory()?;
    std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let target_creation_time = process_creation_time(process.0)?;
    // The persistent guard is only trusted in the administrator-protected
    // service runtime. The interactive helper has no cross-restart service
    // ownership boundary, so it must not consume a user-writable marker.
    let pending_path = configured_owner_sid.map(|_| pending_injection_path(&root));
    let dll = root.join("MiControlRC003HidTap.dll");
    if let Some(pending_path) = pending_path.as_ref() {
        if pending_present(pending_path)? {
            let pending = read_pending_injection(pending_path)?;
            let same_target =
                pending.pid == pid && pending.process_creation_time == target_creation_time;
            match pending_decision(
                &pending,
                pid,
                target_creation_time,
                same_target && already_loaded(pid, &dll)?,
                if same_target {
                    PreviousTarget::Gone
                } else {
                    previous_target_state(pending.pid)
                },
            ) {
                PendingDecision::ClearIdentityChanged => {
                    // A PID reuse/target restart proves the old allocation belongs
                    // to a different process instance; that process owns reclamation.
                    remove_pending_injection(pending_path)?;
                }
                PendingDecision::ReuseLoaded => {
                    // Keep the marker until endpoint/configuration writes finish;
                    // a visible module alone does not prove the prior thread ended.
                }
                PendingDecision::RejectPending => {
                    return Err(
                        "同一 WUDFHost 进程存在未确认完成的远程加载，等待宿主退出后再重试".into(),
                    );
                }
            }
        }
    }
    let owner_sid = configured_owner_sid
        .map(ToOwned::to_owned)
        .or_else(|| current_user_sid().ok())
        .ok_or("无法确定 HID 旁路运行目录的 owner SID")?;
    // The service runs as SYSTEM and must keep its Program Files runtime
    // immutable to the desktop user. The helper mode owns a ProgramData
    // runtime and needs to refresh its endpoint/config files itself.
    let owner_access = runtime_owner_access(configured_owner_sid.is_some());
    secure_acl(
        &root,
        true,
        &owner_sid,
        owner_access,
        configured_owner_sid.is_some(),
        deadline,
    )?;
    if !dll.is_file() || hash_file(&dll)? != GADGET_SHA256 {
        std::fs::copy(source, &dll).map_err(|e| e.to_string())?;
    }
    if hash_file(&dll)? != GADGET_SHA256 {
        return Err("Gadget 复制后校验失败".into());
    }
    let endpoint = root.join("endpoint.json");
    let config = serde_json::json!({"interaction":{"type":"script", "path":"rc003_hid_tap.js",
        "parameters":{"endpoint": endpoint}, "on_change":"ignore"}, "runtime":"qjs", "teardown":"minimal"});
    for (path, bytes) in [
        (
            root.join("MiControlRC003HidTap.config"),
            serde_json::to_vec(&config).unwrap(),
        ),
        (root.join("rc003_hid_tap.js"), SCRIPT.as_bytes().to_vec()),
        (
            endpoint.clone(),
            serde_json::to_vec(&serde_json::json!({"port":port,"token":token})).unwrap(),
        ),
    ] {
        // Atomic endpoint replacement lets an already-loaded Gadget reconnect
        // to a new GUI session without incrementing its LoadLibrary refcount.
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, bytes).map_err(|e| e.to_string())?;
        secure_acl(
            &temporary,
            false,
            &owner_sid,
            owner_access,
            configured_owner_sid.is_some(),
            deadline,
        )?;
        // Windows rename does not replace: use MoveFileExW below.
        use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_REPLACE_EXISTING};
        let from = wide(&temporary);
        let to = wide(&path);
        unsafe {
            MoveFileExW(
                PCWSTR(from.as_ptr()),
                PCWSTR(to.as_ptr()),
                MOVEFILE_REPLACE_EXISTING,
            )
        }
        .map_err(|e| e.to_string())?;
    }
    secure_acl(
        &dll,
        false,
        &owner_sid,
        owner_access,
        configured_owner_sid.is_some(),
        deadline,
    )?;
    remaining()?;
    if already_loaded(pid, &dll)? {
        return Ok(());
    }
    if host_pid()? != pid {
        return Err("HID 宿主在加载前发生变化".into());
    }
    let mut pending = PendingInjection {
        pid,
        process_creation_time: target_creation_time,
        allocation_address: None,
        thread_id: None,
        thread_creation_time: None,
    };
    // Claim before VirtualAllocEx. A crash after this point leaves a durable
    // guard that blocks a second load into the same target instance.
    if let Some(pending_path) = pending_path.as_ref() {
        write_pending_injection(pending_path, &pending, true)?;
    }
    let dll_wide = wide(&dll);
    let bytes = dll_wide.len() * 2;
    unsafe {
        let remote = VirtualAllocEx(
            process.0,
            None,
            bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote.is_null() {
            return Err("VirtualAllocEx failed".into());
        }
        pending.allocation_address = Some(remote as usize);
        if let Some(pending_path) = pending_path.as_ref() {
            write_pending_injection(pending_path, &pending, false)?;
        }
        let mut written = 0;
        if let Err(e) = WriteProcessMemory(
            process.0,
            remote,
            dll_wide.as_ptr().cast(),
            bytes,
            Some(&mut written),
        ) {
            let _ = VirtualFreeEx(process.0, remote, 0, MEM_RELEASE);
            return Err(e.to_string());
        }
        if written != bytes {
            let _ = VirtualFreeEx(process.0, remote, 0, MEM_RELEASE);
            return Err("Incomplete DLL path write".into());
        }
        let loader = GetProcAddress(
            GetModuleHandleW(w!("kernel32.dll")).map_err(|e| e.to_string())?,
            PCSTR(b"LoadLibraryW\0".as_ptr()),
        );
        let Some(loader) = loader else {
            let _ = VirtualFreeEx(process.0, remote, 0, MEM_RELEASE);
            return Err("LoadLibraryW unavailable".into());
        };
        remaining()?;
        let entry = std::mem::transmute::<
            unsafe extern "system" fn() -> isize,
            unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
        >(loader);
        let thread =
            match CreateRemoteThread(process.0, None, 0, Some(entry), Some(remote), 0, None) {
                Ok(thread) => OwnedHandle(thread),
                Err(e) => {
                    let _ = VirtualFreeEx(process.0, remote, 0, MEM_RELEASE);
                    return Err(e.to_string());
                }
            };
        let thread_id = GetThreadId(thread.0);
        if thread_id == 0 {
            return Err("读取远程线程 ID 失败，保留 pending intent 等待宿主退出".into());
        }
        pending.thread_id = Some(thread_id);
        pending.thread_creation_time = Some(thread_creation_time(thread.0)?);
        if let Some(pending_path) = pending_path.as_ref() {
            write_pending_injection(pending_path, &pending, false)?;
        }
        let wait_ms = remaining()?
            .min(REMOTE_WAIT_DEADLINE)
            .as_millis()
            .min(u32::MAX as u128) as u32;
        if wait_ms == 0 {
            // Do not free a parameter still used by a running remote thread.
            return Err(format!(
                "Gadget 远程加载超时 pid={} wait_budget_ms={wait_ms}",
                pid
            ));
        }
        match classify_wait_result(WaitForSingleObject(thread.0, wait_ms).0) {
            RemoteWaitResult::Completed => {}
            RemoteWaitResult::TimedOut => {
                // Do not free a parameter still used by a running remote thread.
                return Err(format!(
                    "Gadget 远程加载超时 pid={} wait_budget_ms={wait_ms}",
                    pid
                ));
            }
            RemoteWaitResult::Failed => {
                let win32_error = GetLastError();
                // Do not free a parameter still used by a possibly running remote thread.
                return Err(format!(
                    "等待 Gadget 远程线程失败 pid={} wait_budget_ms={} win32_error={}",
                    pid, wait_ms, win32_error.0
                ));
            }
            RemoteWaitResult::Unexpected(status) => {
                // Do not free a parameter still used by a possibly running remote thread.
                return Err(format!(
                    "等待 Gadget 远程线程返回未知状态 pid={} wait_budget_ms={} wait_status={status}",
                    pid, wait_ms
                ));
            }
        }
        let remote_exit_code = read_remote_thread_exit_code(thread.0);
        let _ = VirtualFreeEx(process.0, remote, 0, MEM_RELEASE);
        match already_loaded(pid, &dll) {
            Ok(true) => {}
            Ok(false) => {
                if let Some(pending_path) = pending_path.as_ref() {
                    let _ = remove_pending_injection(pending_path);
                }
                return Err(format_gadget_module_missing(&remote_exit_code));
            }
            Err(error) => return Err(format_gadget_module_probe_failed(&remote_exit_code, &error)),
        }
        if let Some(pending_path) = pending_path.as_ref() {
            remove_pending_injection(pending_path)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Shutdown;

    #[test]
    fn service_runtime_owner_cannot_modify_system_loaded_assets() {
        assert_eq!(runtime_owner_access(true), "RX");
        assert_eq!(runtime_owner_access(false), "M");
    }

    #[test]
    fn service_acl_child_timeout_kills_controlled_fake_child() {
        let powershell = PathBuf::from(std::env::var_os("WINDIR").expect("WINDIR"))
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        let child = spawn_acl_process(
            &powershell,
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 5",
            ],
        )
        .expect("启动 ACL fake child");
        let error = wait_for_acl_child_guard(
            child,
            "fake-timeout",
            Instant::now() + Duration::from_millis(100),
        )
        .expect_err("fake ACL child should hit the bounded deadline");
        assert!(error.contains("ACL 阶段超时 target=fake-timeout"));
        assert!(error.contains("child_reaped=true"));
    }

    #[test]
    fn acl_child_job_close_terminates_controlled_fake_child() {
        let powershell = PathBuf::from(std::env::var_os("WINDIR").expect("WINDIR"))
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        let child = spawn_acl_process(
            &powershell,
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 5",
            ],
        )
        .expect("启动 ACL fake child");
        let pid = child.pid;
        drop(child);
        let opened = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION
                    | windows::Win32::System::Threading::PROCESS_SYNCHRONIZE,
                false,
                pid,
            )
        };
        if let Ok(handle) = opened {
            let handle = OwnedHandle(handle);
            assert_eq!(
                unsafe { WaitForSingleObject(handle.0, 1_000) },
                WAIT_OBJECT_0,
                "Job Object close must terminate the fake child"
            );
        }
    }

    #[test]
    fn ensure_acl_child_slot_rejects_live_guard_then_releases_reaped_guard() {
        let powershell = PathBuf::from(std::env::var_os("WINDIR").expect("WINDIR"))
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        let child = spawn_acl_process(
            &powershell,
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 5",
            ],
        )
        .expect("启动 ACL fake child");
        {
            let mut stale = STALE_ACL_CHILD.lock().expect("ACL stale guard lock");
            assert!(stale.is_none(), "previous ACL child leaked into test");
            *stale = Some(child);
        }
        assert!(ensure_acl_child_slot_available().is_err());
        {
            let mut stale = STALE_ACL_CHILD.lock().expect("ACL stale guard lock");
            assert!(
                terminate_acl_child(stale.as_mut().expect("live ACL stale guard")),
                "controlled fake child should be terminated"
            );
        }
        assert!(ensure_acl_child_slot_available().is_ok());
    }

    #[test]
    fn acl_child_unreaped_state_blocks_next_request() {
        assert_eq!(
            acl_child_termination_decision(true, false),
            AclChildLifecycleDecision::PreserveAndRefuse
        );
        assert_eq!(
            acl_child_termination_decision(false, true),
            AclChildLifecycleDecision::PreserveAndRefuse
        );
        assert_eq!(
            acl_child_termination_decision(false, false),
            AclChildLifecycleDecision::PreserveAndRefuse
        );
        assert_eq!(
            acl_child_termination_decision(true, true),
            AclChildLifecycleDecision::SafeToContinue
        );
    }

    #[test]
    fn acl_child_startup_failures_never_allow_unmanaged_process() {
        assert_eq!(
            acl_child_startup_decision(false, true, true),
            AclChildLifecycleDecision::PreserveAndRefuse
        );
        assert_eq!(
            acl_child_startup_decision(true, false, true),
            AclChildLifecycleDecision::PreserveAndRefuse
        );
        assert_eq!(
            acl_child_startup_decision(true, true, false),
            AclChildLifecycleDecision::PreserveAndRefuse
        );
        assert_eq!(
            acl_child_startup_decision(true, true, true),
            AclChildLifecycleDecision::SafeToContinue
        );
    }

    #[test]
    fn remote_wait_classification_preserves_terminal_statuses() {
        assert_eq!(
            classify_wait_result(WAIT_OBJECT_0.0),
            RemoteWaitResult::Completed
        );
        assert_eq!(
            classify_wait_result(WAIT_TIMEOUT.0),
            RemoteWaitResult::TimedOut
        );
        assert_eq!(
            classify_wait_result(WAIT_FAILED.0),
            RemoteWaitResult::Failed
        );
        assert_eq!(
            classify_wait_result(0x1234),
            RemoteWaitResult::Unexpected(0x1234)
        );
    }

    #[test]
    fn missing_module_diagnostic_keeps_exit_code_without_treating_it_as_proof() {
        let exit_zero = Ok(0);
        let exit_nonzero = Ok(0x1234);
        let zero_message = format_gadget_module_missing(&exit_zero);
        let nonzero_message = format_gadget_module_missing(&exit_nonzero);
        assert!(zero_message.contains("Gadget 未加载"));
        assert!(zero_message.contains("remote_thread_exit_code=0"));
        assert!(nonzero_message.contains("Gadget 未加载"));
        assert!(nonzero_message.contains("remote_thread_exit_code=4660"));
    }

    #[test]
    fn module_probe_diagnostic_keeps_exit_code_or_query_error() {
        let exit_code = Ok(1);
        let probe_message = format_gadget_module_probe_failed(&exit_code, "access denied");
        assert!(probe_message.contains("remote_thread_exit_code=1"));
        assert!(probe_message.contains("module_probe_error=access denied"));

        let query_error: Result<u32, String> = Err("win32_error=5".into());
        let missing_message = format_gadget_module_missing(&query_error);
        assert!(missing_message.contains("remote_thread_exit_code_query_failed=win32_error=5"));
    }

    #[test]
    fn pending_injection_guard_blocks_duplicate_and_only_clears_identity_change() {
        let pending = PendingInjection {
            pid: 42,
            process_creation_time: 7,
            allocation_address: Some(0x1000),
            thread_id: Some(9),
            thread_creation_time: Some(11),
        };
        assert_eq!(
            pending_decision(&pending, 42, 7, false, PreviousTarget::Gone),
            PendingDecision::RejectPending
        );
        assert_eq!(
            pending_decision(&pending, 42, 7, true, PreviousTarget::Gone),
            PendingDecision::ReuseLoaded
        );
        assert_eq!(
            pending_decision(&pending, 42, 8, false, PreviousTarget::Gone),
            PendingDecision::ClearIdentityChanged
        );
        assert_eq!(
            pending_decision(&pending, 43, 7, false, PreviousTarget::Alive(8)),
            PendingDecision::ClearIdentityChanged
        );
        assert_eq!(
            pending_decision(&pending, 43, 7, false, PreviousTarget::Alive(7)),
            PendingDecision::RejectPending
        );
        assert_eq!(
            pending_decision(&pending, 43, 7, false, PreviousTarget::Denied),
            PendingDecision::RejectPending
        );
    }

    #[test]
    fn host_pid_accepts_dword_and_qword_but_rejects_invalid_values() {
        assert_eq!(
            decode_host_pid(REG_DWORD.0, &24260u32.to_le_bytes()),
            Some(24260)
        );
        assert_eq!(
            decode_host_pid(REG_QWORD.0, &24260u64.to_le_bytes()),
            Some(24260)
        );
        assert_eq!(decode_host_pid(REG_QWORD.0, &0u64.to_le_bytes()), None);
        assert_eq!(
            decode_host_pid(REG_QWORD.0, &(u32::MAX as u64 + 1).to_le_bytes()),
            None
        );
        assert_eq!(decode_host_pid(REG_QWORD.0, &24260u32.to_le_bytes()), None);
        assert_eq!(decode_host_pid(REG_DWORD.0, &24260u64.to_le_bytes()), None);
        assert_eq!(decode_host_pid(1, &24260u32.to_le_bytes()), None);
    }

    #[test]
    #[ignore = "requires a paired RC003; reads registry only, never injects"]
    fn live_host_lookup_is_read_only() {
        let pid = host_pid().expect("paired RC003 host should be discoverable");
        println!("Detected RC003 WUDFHost PID: {pid}");
        assert!(pid > 0);
    }

    fn receive(messages: &[serde_json::Value]) -> (HidTapSnapshot, Vec<EngineMessage>, bool) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        for message in messages {
            writeln!(client, "{message}").unwrap();
        }
        client.shutdown(Shutdown::Write).unwrap();
        let state = Mutex::new(HidTapSnapshot {
            phase: HidTapPhase::Preparing,
            ..Default::default()
        });
        let (sender, receiver) = std::sync::mpsc::channel();
        let authenticated =
            read_connection(server, 42, "test", &AtomicBool::new(false), &state, &sender);
        (
            state.into_inner().unwrap(),
            receiver.try_iter().collect(),
            authenticated,
        )
    }

    #[test]
    fn heartbeat_is_not_hardware_readiness_and_invalid_frames_are_ignored() {
        let (state, events, authenticated) = receive(&[
            serde_json::json!({"kind":"ready", "pid":42,"token":"test", "protocol":3}),
            serde_json::json!({"kind":"gatt_read", "pid":42,"token":"test","raw":"bad"}),
        ]);
        assert!(authenticated);
        assert_eq!(state.phase, HidTapPhase::Waiting);
        assert_eq!(state.report_count, 0);
        assert!(events.is_empty());
    }

    #[test]
    fn old_resident_script_requires_restart_instead_of_claiming_voice_protection() {
        let (state, events, authenticated) =
            receive(&[serde_json::json!({"kind":"ready", "pid":42,"token":"test"})]);
        assert!(authenticated);
        assert_eq!(state.phase, HidTapPhase::Failed);
        assert!(state.last_error.unwrap().contains("重启电脑"));
        assert!(events.is_empty());
    }

    #[test]
    fn authenticated_ready_and_heartbeat_renew_voice_guard_lease() {
        use std::io::Read;
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        for kind in ["ready", "heartbeat"] {
            writeln!(
                client,
                "{}",
                serde_json::json!({"kind":kind,"pid":42,"token":"test","protocol":3})
            )
            .unwrap();
        }
        client.shutdown(Shutdown::Write).unwrap();
        let state = Mutex::new(HidTapSnapshot {
            phase: HidTapPhase::Preparing,
            ..Default::default()
        });
        let (sender, _) = std::sync::mpsc::channel();
        assert!(read_connection(
            server,
            42,
            "test",
            &AtomicBool::new(false),
            &state,
            &sender
        ));
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut received = String::new();
        client.read_to_string(&mut received).unwrap();
        let messages: Vec<serde_json::Value> = received
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(messages.len(), 2);
        assert!(messages
            .iter()
            .all(|message| message["kind"] == "voice_guard" && message["token"] == "test"));
    }

    #[test]
    fn authenticated_report_reaches_the_engine_but_wrong_peer_does_not() {
        let frame = serde_json::json!({"kind":"gatt_read","pid":42,"token":"test","raw":"010000f10080008100"});
        let (state, events, _) = receive(&[frame.clone()]);
        assert_eq!(state.phase, HidTapPhase::Ready);
        assert_eq!(state.report_count, 1);
        assert!(matches!(&events[0], EngineMessage::TapUsages(usages) if usages.len() == 3));
        let mut wrong = frame;
        wrong["pid"] = 43.into();
        let (_, events, authenticated) = receive(&[wrong]);
        assert!(!authenticated);
        assert!(events.is_empty());
    }
}
