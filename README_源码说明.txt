MiControl 2.0.7-rc1 源码交付说明
================================

本目录是可开发、可构建的源码包，顶层目录名为 MiControl-2.0.7-rc1-source。
它对应静态构建证据中的 MiControl_2.0.7-rc1_x64-setup.exe，安装包 SHA-256 为：
083B44F35B05A1320149DFAFDC8A6993A232D64E33C87F6D13DE3B99AE407A7E。
安装包构建报告记录的 20 个冻结源文件在打包前后均无哈希漂移。

源码布局
--------
src/                    Vue 3 前端源码与测试
src-tauri/              Tauri 壳、Windows 启动/服务集成、图标和 NSIS hook
crates/                 micontrol-core 与 micontrol-windows workspace
public/                 前端静态图片资源
src-tauri/resources/    构建需要的 Frida gadget DLL 与许可证
scripts/                候选构建、验证和资源获取脚本
Cargo.lock/pnpm-lock.yaml

构建前置
--------
* Windows 10 1809（build 17763）或更高版本。
* Node.js 20+；项目 package.json 声明 pnpm@10.15.0。建议使用 Corepack 固定该版本，
  当前打包环境的 pnpm 11.25.0 仅作为环境读数，未用它重跑产品构建。
* Rust MSVC toolchain、Cargo、Visual Studio C++ Build Tools（MSVC、Windows SDK）。
  cl.exe 必须在开发者命令行或等价环境中可用；打包时未在 PATH 中发现 cl.exe。
* Tauri 2 所需 WebView2 Runtime。安装包配置为 downloadBootstrapper；离线交付应预置
  WebView2 Runtime。打包环境注册表读数为 155.0.4283.45，不能替代现场验收。
* NSIS/makensis 由 Tauri CLI 管理；候选静态审计另使用支持 NSIS 的 7-Zip 26.03，
  其 exe/dll 哈希见 scripts/build-micontrol-candidate.ps1 与原 build report。
* 首次构建需要从 crates.io、npm registry 和 Tauri 依赖源下载 Cargo/pnpm 依赖；本包
  不包含 node_modules、Cargo target 或 pnpm store。

标准开发/构建命令
------------------
在本目录执行：

  corepack enable
  corepack prepare pnpm@10.15.0 --activate
  pnpm install
  pnpm build
  cargo test --workspace
  pnpm test
  pnpm tauri build

pnpm tauri build 的 beforeBuildCommand 会先运行 pnpm build，再编译
crates/micontrol-windows 中的 micontrol-service-cleanup helper；默认输出在 target/。
需要复现 2.0.7-rc1 静态候选审计时，使用：

  powershell -ExecutionPolicy Bypass -File .\\scripts\\build-micontrol-candidate.ps1 `
    -Version 2.0.7 -CandidateLabel rc1 `
    -TargetDirectory .\\target-candidate-2.0.7-rc1 `
    -ReportPath .\\candidate-build-2.0.7-rc1-report.json `
    -NsisExtractorPath <path-to-7z.exe>

脚本会使用自身所在仓库根目录解析相对路径，并要求候选 target-candidate-2.0.7-rc1
目录；不要把现有 target/ 或生产目录作为 TargetDirectory。脚本的临时 config、NSIS
hook 和 report 只属于一次构建，不会被本源码包预填。

本地资源与可移植性
------------------
src-tauri/tauri.conf.json 默认将 helper 资源指向 ../target/release；普通 tauri build
会由 beforeBuildCommand 先生成它。候选构建脚本会改用隔离的 target-candidate 路径，并
生成临时配置以避免旧 target fallback。不要悄改冻结源脚本或源算法来修复本地路径；如需
其他输出位置，请通过脚本参数和环境变量配置并把参数记录到独立报告。

frida-gadget.dll 是构建输入，不应删除或替换。它的 SHA-256 为
6FCA4007B2284C765A6C15C967A741F536B5865BF83867326A54029A3B752748，许可证在同目录
frida-COPYING.txt。若重新获取资源，使用 scripts/fetch-hid-tap.ps1 并核对脚本内的
下载归档和解压后哈希；该过程需要网络和 Python 3。

证据边界
--------
原 2.0.7-rc1 证据只完成构建产物与静态 payload 绑定校验，未完成新机安装、UAC、SCM、
真实服务、硬件或现场验收。本源码包没有宣称 bit-identical 重建；需在目标环境重新执行
构建并保存完整参数、工具版本、产物和哈希后再作该结论。SOURCE_MANIFEST.json 列出本包
每个文件的相对路径、字节数和 SHA-256；为避免自引用，清单文件自身不计入 entries。
