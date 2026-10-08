<div align="center">

# codex-unlock

[English](README.md) · [한국어](README.ko.md) · [简体中文](README.zh-CN.md)

[![npm version](https://img.shields.io/npm/v/codex-unlock?color=cb3837&logo=npm)](https://www.npmjs.com/package/codex-unlock)
[![npm downloads](https://img.shields.io/npm/dm/codex-unlock?color=cb3837&logo=npm)](https://www.npmjs.com/package/codex-unlock)
[![CI](https://github.com/abruption/codex-unlock/actions/workflows/ci.yml/badge.svg)](https://github.com/abruption/codex-unlock/actions/workflows/ci.yml)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![node](https://img.shields.io/node/v/codex-unlock?color=339933&logo=node.js)](https://www.npmjs.com/package/codex-unlock)
[![platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)](docs/platform-support.md)
[![license](https://img.shields.io/npm/l/codex-unlock?color=blue)](LICENSE)

**Codex 自身がスレッドに書き込む際に使うロックを診断し、安全な復旧を支援します。復旧に必要な根拠が十分でなければ、復旧は行いません。**

</div>

## デモ

スレッドを探し、書き込みプロセスが安全な復旧対象かどうかを確認します。

![codex-unlock v0.4.2 の list と inspect の診断画面。ロック所有プロセスは稼働中で、unlock が安全ではない状態を表示](https://raw.githubusercontent.com/abruption/codex-unlock/main/docs/assets/codex-unlock-v0.4.2-demo.gif)

*v0.4.2 を macOS 上で実行した `list` / `inspect` の実際の出力を、個人識別情報を伏せて再描画したものです。ロックの所有者は稼働中で、安全にロックを解除できる状態ではありません。このデモではセッションを終了していません。*

```text
codex-unlock list
codex-unlock inspect <thread-id>
```

`<thread-id>` は `list` に表示された UUID に置き換えてください。構造化出力には `--json` を追加します。
復旧対象となる完了済みセッションについては、すべての安全確認を通過した場合にのみ
`codex-unlock unlock <thread-id>` が復旧を要求します。

## クイックスタート

macOS または Linux、Node.js **22.13 以上（22.x）または 24.x**、および `lsof` が必要です。
Windows と Node.js 26 はサポートしていません。

`list` と `inspect` は Codex のネイティブロックファイルや会話記録ファイルの内容を変更しませんが、各プローブで Codex の調整ロックを短時間取得します。対話形式でコマンドを実行すると、主な結果を出力した後に `codex-unlock` の更新案内キャッシュを別途更新することがあります。詳しくは[更新の動作](docs/cli-reference.md#updates)を参照してください。
再検証により、対象ロックを所有しているのが同一ユーザーの Codex プロセス1つだけだと確認できた場合に限り、`unlock` は `SIGTERM` を送ります。
そのプロセスはスレッドロックをちょうど1つだけ保持し、安定した会話記録（transcript）が `task_complete` で終わっていなければなりません。
所有者が共有 app-server、Remote Control、daemon のいずれかである場合、または所有者の判定が不確かな場合、`unlock` は復旧を拒否します。ネイティブロックファイルの削除、強制解除、`SIGKILL` の送信は決して行いません。
[安全モデル](docs/cli-reference.md#safety-model)を参照してください。

### インストール

```bash
npm install --global codex-unlock
codex-unlock --help
```

グローバルにインストールせずに実行する方法：

```bash
npx --yes codex-unlock@latest list
```

### 更新

```bash
codex-unlock check-update
npm install --global codex-unlock@latest
```

`check-update` はパッケージレジストリで更新を確認するだけで、インストールは行いません。
自動通知は参考情報にすぎません。詳しくは[更新の動作](docs/cli-reference.md#updates)を参照してください。

## ドキュメント

詳細なリファレンス文書は現在英語のみです。

- [CLI リファレンス](docs/cli-reference.md) — コマンド、安全性、オプション、終了コード、ソースからのインストール
- [JSON v1 と TypeScript 型](docs/json-v1.md) — 自動化で利用できる正式な仕様
- [プラットフォームサポート](docs/platform-support.md) — 検証済みの OS、アーキテクチャ、Node.js の組み合わせ
- [安全性の競合テスト範囲](docs/safety-race-matrix.md)と[更新のセキュリティ](docs/update-security.md)
- [v0.2 移行ガイド](docs/v0.2-migration.md) — 過去の統合基準
- [コントリビューション](CONTRIBUTING.md)と[メンテナー向けリリース手順](docs/maintainer-release.md)
- [上流へのハンドオフ提案](docs/upstream-handoff-proposal.md) — 設計案であり、実装済みの代替手段ではありません

## ライセンス

[MIT](LICENSE)。

## サポートとセキュリティ

質問や、セキュリティに関わらないバグの報告は[GitHub Issues](https://github.com/abruption/codex-unlock/issues)へお寄せください。
脆弱性は[セキュリティポリシー](SECURITY.md)に従って非公開で報告してください。
診断情報を共有する前に、ローカルパス、プロセス引数、スレッド ID、会話記録、認証情報を伏せてください。
情報を伏せていない JSON 出力は決して公開しないでください。
