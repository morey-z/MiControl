# MiControl 2.0.8 构建与测试报告

本报告对应发布包 `RELEASE_MANIFEST.json` 所记录的最终 `sourceCommit`。路径使用发布包内的相对路径，不记录本机绝对路径、用户配置、设备 GUID、日志或录音。

## 预期验证项

- `pnpm build`
- `pnpm test`
- `cargo fmt --all -- --check`
- `cargo test -p micontrol-windows wetype_revive -- --nocapture`
- `pnpm tauri build`（Windows NSIS，production `custom-protocol`）
- 检查版本元数据均为 `2.0.8`，并核对安装包、主程序、源码 ZIP 的 SHA-256。

## 运行验收边界

已完成的设备验收来自 rc4：标准 CABLE Input 的明确选择、保存、重启恢复和共享开流均通过；Streaming 期间不再触发输入法 cycle/retry。2.0.8 发布打包不覆盖当前安装目录，也不重新执行设备操作。60 秒固件停止限制未修改；未做长期连续说话或真实转写验收。

## 实际结果

- `corepack pnpm install --frozen-lockfile`：PASS，使用项目声明的 pnpm 10.15.0。
- `corepack pnpm build`：PASS，Vue/TypeScript 检查与 Vite production bundle 完成。
- `corepack pnpm test`：PASS，12 个测试文件、78 个测试通过。
- `cargo fmt --all -- --check`：PASS。
- `cargo check --workspace --offline`：PASS；仅有既有未使用代码警告。
- `cargo test -p micontrol-windows wetype_revive -- --nocapture`：PASS，5 passed、1 ignored（需要现场 WeType 历史数据）。
- `cargo test -p micontrol-windows recognizes_virtual_cable_output_without_auto_selecting_other_devices -- --nocapture`：PASS，标准 2ch/本地化扬声器端通过，16ch/泛端点被排除。
- `corepack pnpm tauri build`：PASS，production NSIS 安装器生成；构建经过 `custom-protocol` feature 和内置前端资源流程。

产物文件名和 SHA-256 见发布包内的 `RELEASE_MANIFEST.json` 与 `SHA256SUMS`。完整 Rust workspace 测试未作为本版 PASS 声明；Windows socket 测试此前存在环境相关 10054 失败。正式打包未覆盖当前安装目录。
