# Changelog

## 2.0.8

- 修复 Windows 音频端点推荐：仅将符合 VB-Audio 驱动标识和角色化名称规则的 `CABLE Input` 作为标准候选；多个候选时不再静默选第一个，避免误选 16ch 或普通扬声器端。
- 端点恢复失败（包括保存的设备 ID 已失效）时允许重新选择同一设备；只有仍处于可用流状态时才禁用当前端点按钮。
- 修复语音输入过程中 WeType 状态探测误报导致的重启/重发快捷键：Streaming 期间不再 cycle 输入法或重试 Ctrl+Win，避免输入法窗口被提前切换关闭。
- 生产 Tauri 构建启用 `custom-protocol`，避免把正式程序构建成依赖开发服务器的 localhost 页面。
- 已知限制：遥控器固件对单段语音约有 60 秒上限；长内容请分段说。本版本不自动重启输入法或续录，也未宣称已消除该固件限制。

本版本以远端 `main` 的 `v2.0.7-rc1` 为历史基线，源码变更和构建证据见发布包内的 `RELEASE_NOTES_2.0.8.md`、`RELEASE_MANIFEST.json` 与 `TEST_REPORT.md`。

## 2.0.7-rc1

- 保留返回、音量加、音量减三类按键的单击、双击、长按配置，并覆盖保存、加载、导出、导入 round-trip。
- 增强安装器兼容参数解析：支持带 operation id 的参数形态，保留旧形态，并对路径、SID、operation id 和参数数量做 fail-closed 校验。
- 为安装、卸载、服务和 broker health 流程保留阶段化错误日志，便于定位权限、helper、SCM 和跨进程调用边界。
- 发布候选为 Windows 源码和安装包；现场硬件、真实安装/UAC/SCM 和新机可复现构建仍需在目标环境独立验收。

## 发布校验

- 源码归档：`MiControl_2.0.7-rc1_Source.zip`
- 源码归档 SHA-256：`B87C0A760F77F8939A5858C6680D1850D605FFBFCD495B2589EB591007246B10`
- 安装包：`MiControl_2.0.7-rc1_x64-setup.exe`
- 安装包 SHA-256：`083B44F35B05A1320149DFAFDC8A6993A232D64E33C87F6D13DE3B99AE407A7E`
