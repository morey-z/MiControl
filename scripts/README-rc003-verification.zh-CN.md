# MiControl 2.0.6 RC003 候选包验收

以下步骤只使用 Windows 内置 PowerShell、SCM、TCP loopback 和 ACL 查询，不需要联网。请在新装 Windows 11 验收机执行；当前正在运行 MiControl 的电脑不要执行启停参数。

## 安装与升级

1. 校验 `micontrol-2.0.6-x64-manifest.json` 中安装包 SHA-256，再运行 `MiControl_2.0.6_x64-setup.exe`。
2. 安装器需要一次管理员授权来注册固定 RC003 服务。安装器只有在服务进入 `RUNNING` 且 broker protocol 4 鉴权 health 成功后才报告安装成功；取消授权、启动失败或 health 超时都应使安装失败。
   若安装请求失败，请保留安装目录并读取 `%LOCALAPPDATA%\MiControl\Logs\install-stage.log`；日志按脱敏阶段记录 hash、SID、runas、SCM/icacls、broker health 和退出码。
3. 安装完成后先打开 MiControl，确认 RC003 连接页显示服务已运行；设备按键真实可用需继续使用遥控器进行验收。
4. 升级前关闭应用或让安装器请求应用优雅退出。安装器发现旧实例没有退出监听时应中止，不应强杀正在使用蓝牙链路的旧实例。

## SCM、ACL 与 broker 验收

在安装目录为默认路径时执行：

请先在 PowerShell 切换到本 README 与 `verify-micontrol-rc003.ps1` 所在的同一目录；源码快照中是 `scripts` 目录，交付目录中是候选包根目录。下面命令都从该目录执行。

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\verify-micontrol-rc003.ps1 `
  -ServiceName MiControlRC003HidTap `
  -InstallRoot "$env:ProgramFiles\MiControlRC003HidService" `
  -StartIfStopped `
  -AllowProductionService
```

这个普通 owner 阶段只检查服务 ImagePath、SCM 状态、broker protocol 4 和 loopback health；`StartIfStopped` 启动后会重新读取原子更新的 `broker.json`，再使用新端口完成 health。脚本不输出 broker secret。ACL 查询需要管理员 token，单独执行下面的阶段：

普通 owner 的权限范围只有服务查询和启动。`sc.exe stop`、脚本的 `-StopAfter` 以及 `-CheckAcl` 都必须在管理员 PowerShell 中执行；不要为了停止服务给普通 owner 增加权限。

```powershell
.\verify-micontrol-rc003.ps1 `
  -ServiceName MiControlRC003HidTap `
  -InstallRoot "$env:ProgramFiles\MiControlRC003HidService" `
  -CheckAcl `
  -AllowProductionService
```

ACL 阶段才检查服务 DACL 的 owner `LCRP`（查询状态/启动）ACE、owner 对服务目录及 runtime 没有写入/修改/删除权限，以及 SYSTEM 和 Administrators 的 FullControl。若普通 token 执行 `-CheckAcl` 失败，请在管理员 PowerShell 中重试；不要为此放宽服务 owner 权限。

## Stopped 自动恢复

在新机上先执行：

```powershell
sc.exe stop MiControlRC003HidTap
sc.exe query MiControlRC003HidTap
```

保持 MiControl 运行并等待监督器轮询，或重新连接 RC003。桌面应用应在有界时间内将 SCM 从 `STOPPED` 恢复到 `RUNNING`，重新读取原子 broker.json 的随机端口，并完成 protocol 4 health；随后才尝试真实 HID 会话。若 owner 权限被拒绝，日志应明确提示“修复旁路服务并完成管理员授权”，不应无限等待。

恢复后再次运行上面的验收脚本确认 health。完成验收后可显式清理候选服务：

```powershell
.\verify-micontrol-rc003.ps1 `
  -ServiceName MiControlRC003HidTap `
  -InstallRoot "$env:ProgramFiles\MiControlRC003HidService" `
  -StopAfter `
  -AllowProductionService
```

最后从“应用和功能”卸载 MiControl；若服务停止、删除或管理员授权失败，卸载器必须中止并保留可诊断状态，不能留下仍引用旧二进制的 SCM 项。
