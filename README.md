# MiControl

## 2.0.7-rc1 发布说明

MiControl 是面向 Windows 的小米 RC001 / RC003 蓝牙语音遥控器桥接工具：它提供遥控器按键映射、语音输入桥接和设备连接管理，适合把遥控器接入 Windows 工作站或展陈控制终端。

本次 `v2.0.7-rc1` 包含以下已交付的源码变更：

- 返回、音量加、音量减三类按键支持单击、双击、长按配置，并在保存、加载、导出、导入时保持三类触发配置。
- 安装器兼容逻辑支持带 operation id 的新参数形态，同时保留旧参数形态，拒绝非法参数和不匹配的 helper 路径。
- 安装、服务和诊断路径补充阶段化错误日志，便于区分参数校验、权限、helper、SCM 和 broker health 阶段。

安装包和源码归档从本仓库的 [`v2.0.7-rc1` Release](https://github.com/morey-z/MiControl/releases/tag/v2.0.7-rc1) 页面下载：

- `MiControl_2.0.7-rc1_x64-setup.exe`（SHA-256：`083B44F35B05A1320149DFAFDC8A6993A232D64E33C87F6D13DE3B99AE407A7E`）
- `MiControl_2.0.7-rc1_Source.zip`（SHA-256：`B87C0A760F77F8939A5858C6680D1850D605FFBFCD495B2589EB591007246B10`）

本仓库中的源码来自已核验的 2.0.7-rc1 源码交付包。静态清单和候选构建关联已记录在 `SOURCE_MANIFEST.json` 与 `VERSION_BUILD_INFO.json`；这些材料不等同于任意新电脑上的可复现构建、安装成功、真实硬件连接或现场验收。

## 构建前置条件

- Windows 10 1809（build 17763）或更高版本。
- Node.js `>=22.12.0`，或满足 `^20.19.0` 的 Node.js 20.x；项目使用 pnpm `10.15.0`。
- Rust MSVC toolchain、Cargo、Visual Studio C++ Build Tools（含 MSVC）和 Windows SDK。
- NSIS（`makensis`，通常由 Tauri CLI 的 Windows 打包链提供或由本机工具链提供）。
- WebView2 Runtime；离线环境需要提前准备运行时。

源码包不包含 `node_modules`、Cargo `target` 或 pnpm store。首次构建需要从 npm registry、crates.io 和 Tauri 依赖源获取依赖。源码级静态检查和测试结果不能替代真实 RC001/RC003 硬件、蓝牙、音频、服务、UAC、SCM 或现场验收。

<p align="center">
  <img src="public/app-logo.png" alt="MiControl" width="96">
</p>

<p align="center"><b>小米蓝牙遥控器（RC001 / RC003）的 Windows 语音与按键桥接工具</b></p>

MiControl 通过蓝牙 LE 连接小米蓝牙语音遥控器，把遥控器变成电脑的随身控制器：按住语音键说话，语音实时桥接到电脑；遥控器每个按键都能自由映射成快捷键、应用启动或多媒体控制。

<p align="center">
  <img src="Screenshots/key-mapping.png" alt="MiControl 按键映射界面（深色科技主题）" width="880">
</p>

## 为什么需要它

这些场景你大概不陌生：

- **想动嘴，不想动手**：输入法自带的语音输入，得先把光标点进输入框、再点开麦克风按钮，说完还要回到鼠标；长语音时凑在电脑麦克风前，姿势别扭，还容易被环境噪音干扰。
- **人不在电脑前**：窝在沙发、躺在床上，或者站在大屏 / 投影前讲东西，为了发一句话、切一个画面，不得不起身走到电脑跟前。
- **快捷键记不住、够不着**：剪辑、修图、演示时快捷键一大把，双手忙起来的时候，想触发一个动作只能低头找键盘。

一个放在茶几上的小米遥控器，正好补上这些空隙：

- **语音即按即说**：按住语音键说话，松开即结束，文字实时进入当前输入框。遥控器麦克风离嘴更近，比电脑远场麦克风拾音更干净；不用碰键盘鼠标，窝在沙发里三米外照样用。
- **一键直达应用**：把"打开豆包""打开 Chrome"这类常用动作映射到按键上，想问 AI 一个问题，单手盲按一下就开说。
- **随身的快捷键盘**：12 个实体键 × 单击 / 双击 / 长按，把最高频的快捷键放进去——复制粘贴、媒体控制、PPT 翻页，全在指尖，不用记、不用看。

## 功能

- **可视化按键映射**：每个遥控器按键支持单击 / 双击 / 长按三种触发，可映射为任意键盘快捷键、启动应用（内置豆包 / Chrome / 微信等预设，也支持自定义 exe）或多媒体键；按下遥控器按键时界面实时高亮对应连线与卡片，配置支持导入 / 导出 / 恢复默认。
- **语音桥接**：按住遥控器语音键说话，语音经 ATVV 通道实时传输到电脑并输出到所选音频端点（推荐 VB-Cable 虚拟麦克风），可配合主流输入法的语音输入使用。
- **设备管理**：已配对遥控器自动识别（RC001 / RC003）、断线指数退避自动重连、遥控器电量显示。
- **使用统计**：本机保存每日按键与语音使用统计（今日 / 本周 / 全部）。
- **其他**：开机自启、深色 / 浅色 / 跟随系统主题。

## 系统要求

- Windows 10 1809（build 17763）或更高版本
- 蓝牙 4.0+ 适配器（BLE）
- 语音桥接需要 [VB-Audio Virtual Cable](https://vb-audio.com/Cable/)（应用内提供检测与官方下载入口）

## 从源码构建

技术栈：Rust + Tauri 2 + Vue 3。

```powershell
# 前置：安装 Rust (MSVC)、Node.js >=22.12 或 ^20.19、pnpm 10.15.0、Windows SDK、NSIS、WebView2 Runtime
pnpm install
pnpm tauri build        # 安装包输出在 src-tauri/target/release/bundle/nsis/
pnpm tauri dev          # 开发模式运行
pnpm test               # 前端测试
cargo test --workspace  # Rust 测试
```

## 目录结构

```
src/                      Vue 3 前端界面
src-tauri/                Tauri 2 应用壳（窗口、托盘、IPC、诊断日志）
crates/micontrol-core/    平台无关核心：ATVV 会话、IMA-ADPCM 编解码、语音管线
crates/micontrol-windows/ Windows 平台层：BLE GATT、Raw Input、SendInput、WASAPI
```

## 许可

本项目代码以 [GPL-3.0-only](LICENSE) 许可发布。

第三方素材与依赖的权利说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)（其中捆绑的 RC003 产品照片及小米商标权利归其各自权利人所有）。
