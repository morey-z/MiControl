MiControl 2.0.8 源码交付说明
================================

本目录是可开发、可构建的 MiControl 2.0.8 源码包。
正式安装包、主程序和源码 ZIP 的实际 SHA-256 由发布包中的 RELEASE_MANIFEST.json
和 SHA256SUMS 记录；本源码文件不嵌入某台电脑的绝对路径或用户配置。

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
* Node.js 20+；项目 package.json 声明 pnpm@10.15.0，建议使用 Corepack 固定该版本。
* Rust MSVC toolchain、Cargo、Visual Studio C++ Build Tools（MSVC、Windows SDK）。
  cl.exe 必须在开发者命令行或等价环境中可用；打包时未在 PATH 中发现 cl.exe。
* Tauri 2 所需 WebView2 Runtime。安装包配置为 downloadBootstrapper；离线交付应预置
  WebView2 Runtime。打包环境注册表读数为 155.0.4283.45，不能替代现场验收。
* NSIS/makensis 由 Tauri CLI 管理；正式包使用 production custom-protocol 构建。
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
正式构建使用 `pnpm tauri build`；其 beforeBuildCommand 会先生成前端和
micontrol-service-cleanup helper，生产 feature 由 `src-tauri/Cargo.toml` 的
`custom-protocol` 启用。不要直接使用不带该 feature 的开发 cargo 构建作为正式包。

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

已知限制与证据边界
------------------
遥控器单段语音约有 60 秒的设备/固件上限，长内容请分段；本版不自动续录或强制重开
输入法。此前 rc4 已完成标准 CABLE Input 选择、保存、重启恢复和共享开流验收；本次
正式打包不覆盖安装目录，也不重复硬件操作。源码级测试、安装包构建与既有设备验收不
等同于任意新电脑上的安装、蓝牙或长期连续转写验收。SOURCE_MANIFEST.json 列出本包
每个文件的相对路径、字节数和 SHA-256；为避免自引用，清单文件自身不计入 entries。
