<div align="center">

# codex-unlock

[English](README.md)

[![npm version](https://img.shields.io/npm/v/codex-unlock?color=cb3837&logo=npm)](https://www.npmjs.com/package/codex-unlock)
[![npm downloads](https://img.shields.io/npm/dm/codex-unlock?color=cb3837&logo=npm)](https://www.npmjs.com/package/codex-unlock)
[![CI](https://github.com/abruption/codex-unlock/actions/workflows/ci.yml/badge.svg)](https://github.com/abruption/codex-unlock/actions/workflows/ci.yml)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![node](https://img.shields.io/node/v/codex-unlock?color=339933&logo=node.js)](https://www.npmjs.com/package/codex-unlock)
[![platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)](docs/platform-support.md)
[![license](https://img.shields.io/npm/l/codex-unlock?color=blue)](LICENSE)

**Codex의 스레드 기록 잠금을 진단하고 안전한 복구를 돕습니다. 복구에 필요한 근거가 충분하지 않으면 복구를 진행하지 않습니다.**

</div>

## 데모

스레드를 찾고 쓰기 프로세스가 안전한 복구 대상인지 확인합니다:

![codex-unlock v0.4.2의 list 및 inspect 진단 화면. 실행 중인 잠금 소유자가 있지만 현재는 잠금을 해제하기에 안전하지 않습니다](https://raw.githubusercontent.com/abruption/codex-unlock/main/docs/assets/codex-unlock-v0.4.2-demo.gif)

*v0.4.2에서 실제 macOS로 실행한 `list`/`inspect` 출력을 개인 식별 정보를 가려 다시 렌더링했습니다. 화면에 보이는 잠금 소유자는 실행 중이지만 잠금을 해제하기에 안전하지 않으며, 데모 중 어떤 세션도 종료하지 않았습니다.*

```text
codex-unlock list
codex-unlock inspect <thread-id>
```

`<thread-id>`를 `list`에서 확인한 UUID로 바꾸세요. 구조화된 출력을 원하면 `--json`을 추가합니다. 복구 대상이 될 수 있는 완료 세션의 경우에도 모든 안전 검사를 통과한 경우에만 `codex-unlock unlock <thread-id>`가 복구를 요청합니다.

## 빠른 시작

macOS 또는 Linux, Node.js **22.13 이상(22.x) 또는 24.x**, 그리고 `lsof`가 필요합니다. Windows와 Node.js 26은 지원하지 않습니다.

`list`와 `inspect`는 Codex의 네이티브 잠금 파일이나 대화 기록 파일의 내용을 바꾸지 않지만, 잠금을 검사할 때마다 Codex의 조정 잠금을 잠시 획득합니다. 대화형 명령에서는 기본 결과를 출력한 뒤 `codex-unlock`의 업데이트 안내 캐시를 별도로 갱신할 수 있습니다. 자세한 내용은 [업데이트 동작](docs/cli-reference.md#updates)을 참고하세요.

`unlock`은 재검증을 통해 대상 잠금의 소유자가 현재 사용자와 같은 계정의 Codex 프로세스 하나뿐임을 확인한 경우에만 `SIGTERM`을 보냅니다. 이 프로세스는 스레드 잠금을 정확히 하나만 보유해야 하며, 안정된 대화 기록(transcript)은 `task_complete`에서 끝나야 합니다. 공유 app-server, Remote Control, 백그라운드 서비스(daemon) 또는 소유자를 확실히 식별할 수 없는 경우에는 복구를 거부합니다. `unlock`은 Codex 자체 잠금 파일을 삭제하거나 강제로 잠금을 해제하거나 `SIGKILL`을 보내지 않습니다. [안전 모델](docs/cli-reference.md#safety-model)을 참고하세요.

### 설치

```bash
npm install --global codex-unlock
codex-unlock --help
```

전역 설치 없이 실행할 수도 있습니다.

```bash
npx --yes codex-unlock@latest list
```

### 업데이트

```bash
codex-unlock check-update
npm install --global codex-unlock@latest
```

`check-update`는 레지스트리에서 업데이트를 확인할 뿐, 설치하지는 않습니다. 자동 알림은 참고용입니다. [업데이트 동작](docs/cli-reference.md#updates)을 참고하세요.

## 문서

- [CLI 참고 문서](docs/cli-reference.md) — 명령, 안전성, 옵션, 종료 코드, 소스 설치
- [JSON v1 및 TypeScript 타입](docs/json-v1.md) — 지원되는 자동화 인터페이스
- [플랫폼 지원](docs/platform-support.md) — 검증된 OS·아키텍처·Node.js 조합
- [안전성 경합 테스트 범위](docs/safety-race-matrix.md) 및 [업데이트 보안](docs/update-security.md)
- [v0.2 마이그레이션](docs/v0.2-migration.md) — 과거 통합 기준
- [기여 안내](CONTRIBUTING.md) 및 [릴리스 관리 안내](docs/maintainer-release.md)
- [업스트림 핸드오프 제안](docs/upstream-handoff-proposal.md) — 설계 제안이며 구현된 대체 수단은 아닙니다

## 라이선스

[MIT](LICENSE).

## 지원 및 보안

질문이나 민감하지 않은 버그는 [GitHub Issues](https://github.com/abruption/codex-unlock/issues)에 등록해 주세요. 취약점은 [보안 정책](SECURITY.md)에 따라 비공개로 제보해 주세요.

진단 정보를 공유하기 전에 로컬 경로, 프로세스 인자, 스레드 ID, 대화 기록(transcript), 자격 증명을 마스킹(가림 처리)하세요. 마스킹하지 않은 JSON 출력은 절대 게시하지 마세요.
