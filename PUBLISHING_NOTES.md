# GitHub 发布 staging 说明

本目录由已核验的 `MiControl_2.0.7-rc1_Source.zip` 解压得到，源码基线为 ZIP 顶层 `MiControl-2.0.7-rc1-source` 的 115 个文件。原始 ZIP、安装包和原源码仓库均未被修改。

为使仓库适合开发者直接阅读，本 staging 目录只增加或调整以下内容：

- `README.md`：在原有项目说明前增加 2.0.7-rc1 发布说明、Release 下载入口、精确构建前置条件和证据边界；原项目功能、目录和 GPL-3.0-only 许可内容保留。
- `CHANGELOG.md`：记录本候选版本的三类变更和发布哈希。
- `PUBLISHING_NOTES.md`：记录本 staging 与原始 manifest 的关系。
- `.gitignore`：在原忽略项基础上补充 cache、caches、userstate 和本地用户状态路径。

`SOURCE_MANIFEST.json` 的 114 个 entries 与原始源码交付包逐项保持；发布仓库的 Git 元数据、上述发布文档和 `.gitignore` 调整属于 staging 层新增/差异。`frida-gadget.dll` 与同目录 `frida-COPYING.txt` 保留，因为它们是构建输入及其许可证。安装 EXE、源码 ZIP 和 `SHA256SUMS` 只作为 Release assets，不写入 Git 历史。

在提交前以 `SOURCE_MANIFEST.json` 的相对路径、字节数和 SHA-256 逐项复核：114 个原始 entries 中有 112 个保持原值；`.gitignore` 从 262 字节变为 320 字节（新 SHA-256：`1995C4090C9C532E4C15626FC66C79A50A37B3974D85C1579BB6BDE1C83E56ED`），`README.md` 从 3,935 字节变为 6,080 字节（新 SHA-256：`AE32F8780A511223EDEE69FD6F9078BE96B0B749C48A70E1CDA1FE433B934F8A`）；新增 `CHANGELOG.md` 和本文件各 1 个。未发现缺失文件或额外源码目录。

本发布不添加 GitHub Actions 或其它自动部署工作流，也不上传日志、备份注册表、`.env`、凭据、密钥、缓存、`target`、`node_modules`、历史包或用户状态。

README 下载链接固定指向 `https://github.com/morey-z/MiControl/releases/tag/v2.0.7-rc1`，因为该版本是 prerelease，不能依赖 `/releases/latest`。
