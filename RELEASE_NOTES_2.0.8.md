# MiControl 2.0.8 发布说明

## 基线与范围

本版从远端 `morey-z/MiControl` 的 `main`（历史标签 `v2.0.7-rc1`）建立，保留原有 Git 历史。发布内容只包含本版本源码修复、正式版本元数据和构建产物；不包含用户配置、日志、录音、凭据、`node_modules` 或 Cargo 构建缓存。

## 修复

- 以 VB-Audio 驱动标识和角色化 friendly name 识别标准 `CABLE Input`，避免把 16ch 端或泛化的 VB-Audio 扬声器端点自动当作正确输入；独立通道元数据未在本版宣称可用。
- 多个标准候选不再自动选择第一个，交由用户明确选择。
- 设备恢复为 Failed 时允许重新选择相同端点；Ready/Streaming/Draining 且 ID 相同才禁用当前选择。
- Streaming 期间 WeType 探测只作诊断，不触发输入法 profile cycle、Ctrl+Win 重试或其它会关闭输入窗口的恢复动作。
- Tauri release feature 启用 `custom-protocol`，生产包使用内置前端资源。

## 已知限制

RC001/RC003 类遥控器单段语音存在约 60 秒的设备/固件上限；长内容需要分段。现场 rc4 记录显示停止包在约 60 秒由设备发出，应用随后正常释放语音会话。本版不修改协议、不伪造延长语义、不在停止后自动重开输入法。未进行长期连续说话或真实转写质量承诺。

## 构建

Windows 生产包使用 `pnpm tauri build`，并通过 `src-tauri/Cargo.toml` 的 `custom-protocol` feature 构建。完整命令、测试结果和产物哈希见 `TEST_REPORT.md` 与 `RELEASE_MANIFEST.json`。

