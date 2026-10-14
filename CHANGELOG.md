# Changelog

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
