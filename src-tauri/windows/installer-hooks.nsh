!include WinVer.nsh

!define MICONTROL_MINIMUM_WINDOWS_BUILD 17763
!define MICONTROL_DOWNGRADE_ERROR_LEVEL 1638
!define MICONTROL_VB_CABLE_SERVICE_KEY "SYSTEM\CurrentControlSet\Services\VBAudioVACMME"
!define MICONTROL_VB_CABLE_DOWNLOAD_URL "https://vb-audio.com/Cable/"
; The cleanup helper is embedded in the uninstaller and extracted to the
; per-run plugin directory.  It must remain usable when Defender has removed
; micontrol-windows-app.exe from $INSTDIR.
; Tauri compiles installer.nsi from target/{profile}/nsis/x64. The hook is
; included by absolute path, so File paths resolve relative to installer.nsi.
!define MICONTROL_CLEANUP_HELPER_SOURCE "..\..\..\..\target\release\micontrol-service-cleanup.exe"

; ── 部署前先请应用优雅退出（2026-09-16）───────────────────────────────
;
; 背景：Tauri 默认模板的 `CheckIfAppIsRunning`（utils.nsh）在检测到应用正在
; 运行时不会给应用任何退出机会，而是直接强杀。**本仓库构建产物的实际分支**
; （原文见 `target/release/nsis/x64/utils.nsh`，构建时生成）：
;
;   nsis_tauri_utils::FindProcessCurrentUser → $R0 = 0 表示有实例在跑
;     IfSilent kill_...              ; 静默安装（/S）：不提示，直接杀
;     ${IfThen} $PassiveMode != 1 ${|} MessageBox MB_OKCANCEL ... ${|}
;         kill_...:  KillProcessCurrentUser + Sleep 500   ; 交互点"确定" → 强杀
;         cancel_...: Abort $R1                            ; 交互点"取消" → 安装中止
;
; 弹窗文案取自 SimpChinese.nsh：`{{product_name}} 正在运行！$\n点击确定以终止运行。`
; 也就是说：**交互安装时用户手里本来就有一次"安全选择"（取消 = 什么都不装、
; 不碰应用），只有点"确定"才会强杀**；静默/被动模式则没有这个选择。
;
; 而应用在持有活动 BLE GATT 会话时被强杀，会留下未正常关闭的会话，使系统
; 蓝牙栈进入僵死态：此后所有 WinRT 入口（`GetRadiosAsync`、设备查询、
; `FromBluetoothAddressAsync`）一律返回 `0x80070008`；应用内全部自动恢复手段
; （普通重连 / 无线电 Off/On / 提权 PnP 重启）与睡眠都无效，**只有重启电脑能恢复**
; （2026-09-16 现场逐项实测）。
; 原则：部署不得强杀正在连接的应用（2026-09-05 实证）。
;
; 注意（升级 CLI 时必须复核）：tauri `dev` 分支已把该宏改成走 Restart Manager
; （`RSTRTMGR::RmShutdown` + `RmForceShutdown`，交互取消同样是 `Abort`）。两种实现
; 都**不会**请求应用自行退出，因此本钩子对两者都成立；但升级 `@tauri-apps/cli` 后
; 必须重新查看生成的 `utils.nsh` 并重跑契约测试与端到端测试。
;
; 本宏在 `NSIS_HOOK_PREINSTALL` / `NSIS_HOOK_PREUNINSTALL` 中执行，而 Tauri 的
; `CheckIfAppIsRunning` 在 `Section Install` 里**紧随其后**才跑。因此应用只要能
; 在这段宽限期内自行退出，后续检测自然落空、连弹窗都不会出现；超时才落回原有行为。
;
; 信号用**会话内**命名事件：非提权进程没有 `SeCreateGlobalPrivilege`，无法创建
; `Global\` 命名对象；而安装器与应用同处一个登录会话，`Local\` 命名空间对两者
; 都可见。事件由应用在启动时创建（只有运行中的实例才持有句柄），因此
; `OpenEventW` 打不开 + 进程确实在跑 = 运行的是没有监听线程的旧版。
; 事件名必须与 crates/micontrol-windows/src/graceful_exit.rs 的常量一致。
;
; 三种结局：
;   1. 没有实例在跑 → 零等待直接返回（最常见，也是应用内更新路径的常态）；
;   2. 有实例且能打开事件 → 置位 + 轮询等到它退出，`CheckIfAppIsRunning` 落空，
;      连弹窗都不会出现；
;   3. 有实例但打不开事件（旧版）→ 不杀也不装，中止并引导走应用内更新
;      （见宏内说明）。
!define MICONTROL_GRACEFUL_EXIT_EVENT "Local\MiControl-GracefulExit"
!define MICONTROL_GRACEFUL_EXIT_SETTLE_MS 1500
!define MICONTROL_GRACEFUL_EXIT_POLL_INTERVAL_MS 500
; 轮询总预算必须 ≥ 应用侧 GRACEFUL_EXIT_TIMEOUT（5s）+ 退出开销，否则进程还没
; 退干净就轮到 Tauri 的 CheckIfAppIsRunning，弹窗必然出现（2026-09-16 实测）。
!define MICONTROL_GRACEFUL_EXIT_MAX_WAIT_MS 20000
!define MICONTROL_EVENT_MODIFY_STATE 0x0002
; 旧版（无监听线程）正在运行时的退出码：不装、不杀，交给应用内更新。
!define MICONTROL_LEGACY_RUNNING_ERROR_LEVEL 1639

!macro MiControlRequestGracefulExit _uid
  Push $R8
  Push $R9
  ; 先确认是否真有实例在跑。`FindProcessCurrentUser` 的返回值语义由实测确定
  ; （0 = 在跑，1 = 不在跑；用 makensis 编译的最小探针跑出来的 ground truth，
  ; 经最小探针程序实测确认）。**旧实现把这里写成 `!= 0`，语义正好反了**：
  ; 进程已退出时白等 6.5s，而进程还在跑（BLE 关闭最多要 5s）时反而不等，
  ; 直接落到 Tauri 的强杀弹窗——2026-09-16 用户现场看到的弹窗就是这个原因，
  ; 与"运行的是不是旧版本"无关。
  ; **必须传裸进程名，不能传全路径**：实测传 `"$INSTDIR\xxx.exe"` 时插件永远
  ; 返回 1（当作"没有在跑"），整个等待逻辑会被静默跳过（2026-09-16 探针实测，
  ; 探针结果留档）。Tauri 自己的
  ; `CheckIfAppIsRunning` 也是传裸名（installer.nsi 第 638 行）。
  nsis_tauri_utils::FindProcessCurrentUser "${MAINBINARYNAME}.exe"
  Pop $R9
  ${If} $R9 = 0
    ; **寄存器大小写决定写进哪个变量**：`.R8` 写 `$R8`，`.r8` 写 `$8`（2026-09-16
    ; 探针实测）。旧实现用 `.r8`
    ; 却判断 `$R8`，后者永远是空值，而空值 `!= 0` 在 NSIS 里为真——于是"事件存在"
    ; 这个分支恒真，旧版检测从来没生效过。事件不存在时输出的是字面 `0`。
    ; 句柄返回值必须用 p（指针宽度）；用 i 在 x64 上会截断。
    System::Call 'kernel32::OpenEventW(i ${MICONTROL_EVENT_MODIFY_STATE}, i 0, w "${MICONTROL_GRACEFUL_EXIT_EVENT}") p .R8'
    ${If} $R8 != 0
      System::Call 'kernel32::SetEvent(p R8) i .R9'
      System::Call 'kernel32::CloseHandle(p R8)'
      ; 先固定静默一段时间，让应用关闭 GATT 会话并等 `ble_session_cleanup` 落盘。
      Sleep ${MICONTROL_GRACEFUL_EXIT_SETTLE_MS}
      ; 之后轮询到进程真正消失为止（预算耗尽才放弃），不再用"睡固定时长"。
      ; 标签后缀由调用方传入：`${__LINE__}` 在安装器与卸载器两次汇编中会展开成
      ; `752.2.16` 这类复合 token，导致卸载段标签解析失败（2026-09-16 构建实测）。
      StrCpy $R9 ${MICONTROL_GRACEFUL_EXIT_MAX_WAIT_MS}
      micontrol_wait_${_uid}:
        nsis_tauri_utils::FindProcessCurrentUser "${MAINBINARYNAME}.exe"
        Pop $R8
        ${If} $R8 != 0
          Goto micontrol_done_${_uid}
        ${EndIf}
        Sleep ${MICONTROL_GRACEFUL_EXIT_POLL_INTERVAL_MS}
        IntOp $R9 $R9 - ${MICONTROL_GRACEFUL_EXIT_POLL_INTERVAL_MS}
        ${If} $R9 > 0
          Goto micontrol_wait_${_uid}
        ${EndIf}
      micontrol_done_${_uid}:
    ${Else}
      ; 进程在跑但事件打不开 = 运行的是没有监听线程的旧版（0.2.10 及更早）。
      ; 两条路都不能走：
      ;   强杀 → 残留未关闭的 GATT 会话，蓝牙栈僵死，只有重启 Windows 能恢复
      ;           （2026-09-16 逐项实测）；
      ;   装下去 → 旧进程仍占着蓝牙链路，新版本连不上。
      ; 因此主动中止并引导走应用内更新：旧版的 `on_before_exit` 会先断开 BLE
      ; 再拉起安装器（tauri-plugin-updater 的 install_inner：on_before_exit 在
      ; ShellExecuteW 之前执行），既不重启也不需要用户手动退出应用。
      ${If} ${Silent}
        SetErrorLevel ${MICONTROL_LEGACY_RUNNING_ERROR_LEVEL}
      ${Else}
        MessageBox MB_ICONINFORMATION|MB_OK "正在运行的 MiControl 是较早的版本，直接覆盖安装会中断蓝牙链路。$\r$\n请打开 MiControl，在「设置」里点「检查更新」完成升级（应用会自己断开蓝牙并重启）。$\r$\n$\r$\nMiControl is running an older build. Please upgrade from Settings → Check for updates inside the app."
      ${EndIf}
      Abort
    ${EndIf}
  ${EndIf}
  Pop $R9
  Pop $R8
!macroend

!macro NSIS_HOOK_PREINSTALL
  ${IfNot} ${AtLeastBuild} ${MICONTROL_MINIMUM_WINDOWS_BUILD}
    MessageBox MB_ICONSTOP|MB_OK "MiControl 需要 Windows 10 1809（内部版本 17763）或更高版本。$\r$\nMiControl requires Windows 10 1809 (build 17763) or later."
    SetErrorLevel 1633
    Quit
  ${EndIf}

  Push $R8
  Push $R9
  ReadRegStr $R8 SHCTX "${UNINSTKEY}" "DisplayVersion"
  ${If} $R8 != ""
    nsis_tauri_utils::SemverCompare "${VERSION}" $R8
    Pop $R9
    ${If} $R9 = -1
      ${IfNot} ${Silent}
        MessageBox MB_ICONSTOP|MB_OK "已安装较新版本的 MiControl，不能用此旧版本覆盖。$\r$\nA newer version of MiControl is already installed. This older installer cannot replace it."
      ${EndIf}
      SetErrorLevel ${MICONTROL_DOWNGRADE_ERROR_LEVEL}
      Quit
    ${EndIf}
  ${EndIf}
  Pop $R9
  Pop $R8

  ; 版本校验通过后才请正在运行的实例优雅退出：升级路径的关键一步。
  !insertmacro MiControlRequestGracefulExit install
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; 卸载同样不得强杀正在连接的应用。
  !insertmacro MiControlRequestGracefulExit uninstall
  ; 始终运行独立 helper：SCM 注册可能已被安全软件或一次失败安装删除，
  ; 但固定 Program Files 目录仍可能残留 SYSTEM-owned 文件。helper 的
  ; fixed-root/nofollow 清理必须覆盖“无 SCM 项”的卸载路径。
  Push $R8
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File "${MICONTROL_CLEANUP_HELPER_SOURCE}"
  ClearErrors
  ExecWait '"$PLUGINSDIR\micontrol-service-cleanup.exe" --micontrol-service-cleanup' $R8
  ${If} ${Errors}
    SetErrorLevel 1
    ${IfNot} ${Silent}
      MessageBox MB_ICONSTOP|MB_OK "后台服务卸载助手无法启动。请重试卸载，并查看 $LOCALAPPDATA\MiControl\Logs\install-stage.log。"
    ${EndIf}
    Abort
  ${EndIf}
  ${If} $R8 != 0
    SetErrorLevel 1
    ${IfNot} ${Silent}
      MessageBox MB_ICONSTOP|MB_OK "后台服务卸载未完成，卸载助手退出码为 $R8。请查看 $LOCALAPPDATA\MiControl\Logs\install-stage.log。"
    ${EndIf}
    Abort
  ${EndIf}
  Pop $R8
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; 安装完成后请求管理员安装固定服务。服务命令只有在 SCM RUNNING 且
  ; broker 通过 protocol4 鉴权握手后才返回成功；失败必须让安装器失败。
  Push $R4
  Push $R5
  Push $R6
  Push $R7
  Push $R8
  Push $R9
  ; 先记录安装器刚完成复制时的文件状态。若主程序被安全软件或外部流程
  ; 在 ExecWait 前移除，Rust helper 根本不会启动，必须给出可区分的诊断。
  StrCpy $R4 "false"
  StrCpy $R5 "0"
  StrCpy $R6 "0"
  StrCpy $R7 "false"
  StrCpy $R9 "false"
  CreateDirectory "$LOCALAPPDATA\MiControl\Logs"
  ClearErrors
  FileOpen $R8 "$LOCALAPPDATA\MiControl\Logs\install-stage.log" a
  ${IfNot} ${Errors}
    StrCpy $R4 "true"
  ${EndIf}
  ; 文件存在/大小检查必须在日志打开结果之外执行；日志路径不可写时也要
  ; 得到可靠的 preflight 结论，不能沿用旧寄存器值误报主程序缺失。
    IfFileExists "$INSTDIR\micontrol-windows-app.exe" micontrol_nsis_main_exists micontrol_nsis_main_missing
micontrol_nsis_main_exists:
    StrCpy $R7 "true"
    ${GetSize} "$INSTDIR" "/M=micontrol-windows-app.exe /S=0B /G=0" $R6 $0 $1
    Goto micontrol_nsis_main_logged
micontrol_nsis_main_missing:
    StrCpy $R7 "false"
    StrCpy $R6 "0"
micontrol_nsis_main_logged:
    StrCpy $R9 "false"
    IfFileExists "$INSTDIR\hid-tap\frida-gadget.dll" micontrol_nsis_gadget_exists micontrol_nsis_gadget_missing
micontrol_nsis_gadget_exists:
    StrCpy $R9 "true"
    ${GetSize} "$INSTDIR\hid-tap" "/M=frida-gadget.dll /S=0B /G=0" $R5 $0 $1
    Goto micontrol_nsis_gadget_logged
micontrol_nsis_gadget_missing:
    StrCpy $R9 "false"
    StrCpy $R5 "0"
micontrol_nsis_gadget_logged:
  ${If} $R4 == "true"
    FileWrite $R8 "phase=nsis_execwait_preflight main_exists=$R7 main_size=$R6 gadget_exists=$R9 gadget_size=$R5$\r$\n"
    FileClose $R8
  ${EndIf}
  ${If} $R7 != "true"
    SetErrorLevel 1
    ${IfNot} ${Silent}
      MessageBox MB_ICONSTOP|MB_OK "MiControl 安装未完成：安装目录中的主程序缺失，未启动旁路服务请求。请查看 $LOCALAPPDATA\MiControl\Logs\install-stage.log，并检查 Windows 安全软件保护历史。"
    ${EndIf}
    Pop $R9
    Pop $R8
    Pop $R7
    Pop $R6
    Pop $R5
    Pop $R4
    Abort
  ${EndIf}
  ${If} $R9 != "true"
    SetErrorLevel 1
    ${IfNot} ${Silent}
      MessageBox MB_ICONSTOP|MB_OK "MiControl 安装未完成：hid-tap\frida-gadget.dll 缺失，未启动旁路服务请求。请查看 $LOCALAPPDATA\MiControl\Logs\install-stage.log，并检查 Windows 安全软件保护历史。"
    ${EndIf}
    Pop $R9
    Pop $R8
    Pop $R7
    Pop $R6
    Pop $R5
    Pop $R4
    Abort
  ${EndIf}
  ; 修复仅针对当前安装目录主程序的旧 RUNASADMIN 兼容层。helper 会检查
  ; HKCU 两个 registry view、保留其它 token，并在 HKLM 命中或读写失败时
  ; fail-closed；它不会扫描其它应用、其它路径或修改全局兼容层。
  ClearErrors
  ExecWait '"$INSTDIR\micontrol-service-cleanup.exe" --micontrol-appcompat-cleanup' $R8
  ${If} ${Errors}
    SetErrorLevel 1
    ${IfNot} ${Silent}
      MessageBox MB_ICONSTOP|MB_OK "MiControl 安装未完成：旧版兼容设置清理助手无法启动。请查看 $LOCALAPPDATA\MiControl\Logs\install-stage.log。"
    ${EndIf}
    Pop $R9
    Pop $R8
    Pop $R7
    Pop $R6
    Pop $R5
    Pop $R4
    Abort
  ${EndIf}
  ${If} $R8 != 0
    SetErrorLevel $R8
    ${IfNot} ${Silent}
      MessageBox MB_ICONSTOP|MB_OK "MiControl 安装未完成：旧版兼容设置清理失败（helper 退出码 $R8）。请查看 $LOCALAPPDATA\MiControl\Logs\install-stage.log；不会绕过 UAC 或修改全局安全策略。"
    ${EndIf}
    Pop $R9
    Pop $R8
    Pop $R7
    Pop $R6
    Pop $R5
    Pop $R4
    Abort
  ${EndIf}
  ClearErrors
  ; 通过固定 helper 的 CreateProcessW 边界启动主程序。helper 立即记录
  ; launcherror 的真实 GetLastError；主程序退出码、UAC cancel、超时和等待
  ; 失败在日志中分开记录，避免 ExecWait 后再读取 sticky error。
  ExecWait '"$INSTDIR\micontrol-service-cleanup.exe" --micontrol-launch-setup' $R8
  ${If} ${Errors}
    SetErrorLevel 1
    ${IfNot} ${Silent}
      MessageBox MB_ICONSTOP|MB_OK "MiControl 安装未完成：旁路服务启动包装器无法启动。请查看 $LOCALAPPDATA\MiControl\Logs\install-stage.log，再重试安装并完成管理员授权。"
    ${EndIf}
    Pop $R9
    Pop $R8
    Pop $R7
    Pop $R6
    Pop $R5
    Pop $R4
    Abort
  ${EndIf}
  ${If} $R8 != 0
    ${IfNot} ${Silent}
      MessageBox MB_ICONSTOP|MB_OK "MiControl 安装未完成：旁路服务启动包装器退出码为 $R8。日志会区分启动错误、主程序退出码、UAC 取消和超时；请查看 $LOCALAPPDATA\MiControl\Logs\install-stage.log。"
    ${EndIf}
    SetErrorLevel $R8
    Pop $R9
    Pop $R8
    Pop $R7
    Pop $R6
    Pop $R5
    Pop $R4
    Abort
  ${EndIf}
  Pop $R9
  Pop $R8
  Pop $R7
  Pop $R6
  Pop $R5
  Pop $R4
  Push $R8
  ReadRegStr $R8 HKLM "${MICONTROL_VB_CABLE_SERVICE_KEY}" "DisplayName"
  ${If} $R8 == ""
    ${IfNot} ${Silent}
      MessageBox MB_ICONINFORMATION|MB_YESNO "MiControl 需要 VB-CABLE 把遥控器语音传给输入法和语音软件。VB-CABLE 由 VB-Audio 提供，属于 Donationware，安装需要管理员权限，完成后必须重启 Windows。$\r$\n$\r$\n是否现在打开 VB-CABLE 官方下载页面？$\r$\n$\r$\nMiControl requires VB-CABLE for speech input. Installation requires administrator permission and a Windows restart. Open the official download page now?" IDYES micontrol_vb_cable_open IDNO micontrol_vb_cable_done
micontrol_vb_cable_open:
      ExecShell "open" "${MICONTROL_VB_CABLE_DOWNLOAD_URL}"
micontrol_vb_cable_done:
    ${EndIf}
  ${EndIf}
  Pop $R8
!macroend
