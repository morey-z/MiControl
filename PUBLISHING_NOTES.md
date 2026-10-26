# GitHub 发布说明

本版正式发布 `MiControl 2.0.8`，源码基线为远端 `morey-z/MiControl` 的 `main` 提交 `ce5a9de934c95062a6bc303cc22b44a0e1cfb63f`。远端历史标签 `v2.0.7-rc1` 保留不变。

本版同步标准 CABLE Input 识别、音频端点多候选/失效恢复、Streaming 期间输入法稳定性和 Tauri `custom-protocol` 生产构建修复。具体文件与已知 60 秒设备/固件限制见 `RELEASE_NOTES_2.0.8.md`。

`SOURCE_MANIFEST.json` 由 `scripts/write-source-manifest.ps1` 生成，包含包内相对路径、字节数和 SHA-256，排除自身与构建/依赖输出。`VERSION_BUILD_INFO.json` 记录版本与可复现构建入口，不包含本机绝对路径、旧版本产物哈希或用户状态。

发布资产（安装包、主程序、源码 ZIP、`SHA256SUMS` 和 `RELEASE_MANIFEST.json`）仅进入 GitHub Release，不写入 Git 历史。发布前应运行 `corepack pnpm build`、`corepack pnpm test`、`cargo fmt --all -- --check`、目标 Rust 测试和 `corepack pnpm tauri build`；测试边界记录在 `TEST_REPORT.md`。

不会上传 `node_modules`、Cargo `target`、日志、录音、配置、设备 GUID、凭据或本机绝对路径。
