<div align="center">

# codex-unlock

[English](README.md) · [한국어](README.ko.md) · [日本語](README.ja.md)

[![npm version](https://img.shields.io/npm/v/codex-unlock?color=cb3837&logo=npm)](https://www.npmjs.com/package/codex-unlock)
[![npm downloads](https://img.shields.io/npm/dm/codex-unlock?color=cb3837&logo=npm)](https://www.npmjs.com/package/codex-unlock)
[![CI](https://github.com/abruption/codex-unlock/actions/workflows/ci.yml/badge.svg)](https://github.com/abruption/codex-unlock/actions/workflows/ci.yml)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![node](https://img.shields.io/node/v/codex-unlock?color=339933&logo=node.js)](https://www.npmjs.com/package/codex-unlock)
[![platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)](docs/platform-support.md)
[![license](https://img.shields.io/npm/l/codex-unlock?color=blue)](LICENSE)

**诊断 Codex 原生线程写入锁并协助安全恢复；如果恢复所需证据不足，就不会执行恢复。**

</div>

## 演示

查找线程，并检查写入进程是否符合安全恢复条件：

![codex-unlock v0.4.2 的 list 和 inspect 诊断界面，显示锁持有进程仍在运行，当前无法安全解除锁](https://raw.githubusercontent.com/abruption/codex-unlock/main/docs/assets/codex-unlock-v0.4.2-demo.gif)

*这是在 macOS 上运行 v0.4.2 时的真实 `list`/`inspect` 输出，经过重新渲染并隐去了个人身份信息。锁持有进程仍在运行，当前无法安全解除锁；此演示中未终止任何会话。*

```text
codex-unlock list
codex-unlock inspect <thread-id>
```

将 `<thread-id>` 替换为 `list` 显示的 UUID。添加 `--json` 可输出结构化数据。
对于符合条件的已完成会话，只有通过全部安全检查后，`codex-unlock unlock <thread-id>` 才会请求恢复。

## 快速开始

需要 macOS 或 Linux、Node.js **22.13+（22.x）或 24.x**，以及 `lsof`。
不支持 Windows 和 Node.js 26。

`list` 和 `inspect` 不会修改 Codex 原生锁文件或对话记录文件的内容，但每次探测都会短暂获取 Codex 的协调锁。
在交互式命令输出主要结果后，`codex-unlock` 可能会单独刷新更新提示缓存。详见[更新行为](docs/cli-reference.md#updates)。
只有重新验证确认目标锁仅由一个属于同一用户的 Codex 进程持有时，`unlock` 才会发送 `SIGTERM`。
该进程必须恰好持有一个线程锁，并且其稳定的对话记录（transcript）必须以 `task_complete` 结束。
对于共享 app-server、Remote Control、daemon，或所有者判定存在不确定性的情况，`unlock` 都会拒绝恢复。它绝不会删除 Codex 原生锁文件、强制解除锁或发送 `SIGKILL`。
详见[安全模型](docs/cli-reference.md#safety-model)。

### 安装

```bash
npm install --global codex-unlock
codex-unlock --help
```

也可以不保留全局安装，直接运行：

```bash
npx --yes codex-unlock@latest list
```

### 更新

```bash
codex-unlock check-update
npm install --global codex-unlock@latest
```

`check-update` 只检查软件包注册表中的版本，不会安装更新。自动提示仅供参考。详见[更新行为](docs/cli-reference.md#updates)。

## 文档

详细参考文档目前仅提供英文版本。

- [CLI 参考](docs/cli-reference.md) — 命令、安全性、选项、退出码和从源码安装
- [JSON v1 与 TypeScript 类型](docs/json-v1.md) — 自动化集成可使用的接口规范
- [平台支持](docs/platform-support.md) — 已验证的操作系统、架构和 Node.js 组合
- [安全竞态测试范围](docs/safety-race-matrix.md)与[更新安全](docs/update-security.md)
- [v0.2 迁移指南](docs/v0.2-migration.md) — 历史集成基线
- [贡献指南](CONTRIBUTING.md)与[维护者发布流程](docs/maintainer-release.md)
- [上游交接提案](docs/upstream-handoff-proposal.md) — 仅为设计提案，并非已实现的后备方案

## 许可证

[MIT](LICENSE)。

## 支持与安全

如有疑问或需报告与安全无关的缺陷，请提交到 [GitHub Issues](https://github.com/abruption/codex-unlock/issues)。
请按照[安全政策](SECURITY.md)私下报告漏洞。
分享诊断信息前，请隐去本地路径、进程参数、线程 ID、对话记录和凭据；切勿公开未经脱敏的 JSON 输出。
