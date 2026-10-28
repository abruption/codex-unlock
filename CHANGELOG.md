# Changelog

## [0.4.9](https://github.com/abruption/codex-unlock/compare/v0.4.8...v0.4.9) (2026-10-28)


### ⚠ BREAKING CHANGES

* Node 22 versions below 22.23.4 and Node 24 versions below 24.22.1 are no longer supported.

### Bug Fixes

* require patched Node 22 and 24 security baselines ([#184](https://github.com/abruption/codex-unlock/issues/184)) ([0c9ecfc](https://github.com/abruption/codex-unlock/commit/0c9ecfc9ba78e1d977bfbec9be585d2e3a3d4bbc))


### Documentation

* document Node security hotfix compatibility ([ce84a24](https://github.com/abruption/codex-unlock/commit/ce84a245e657836e3f518eacdbbbe36883a53e52))

## [0.4.8](https://github.com/abruption/codex-unlock/compare/v0.4.7...v0.4.8) (2026-10-27)


### ⚠ BREAKING CHANGES

* **windows:** Windows RC and stable output use the codex-unlock-windows schema with explicit releaseChannel and maturity flags. Historical alpha parsing and the npm CLI JSON contract remain unchanged.

### Features

* **experimental:** add diagnostic-only Rust Windows prototype ([#164](https://github.com/abruption/codex-unlock/issues/164)) ([22857b3](https://github.com/abruption/codex-unlock/commit/22857b3eb14b89976673830c601e54f52a42c217))
* **experimental:** add standalone Windows diagnostic preview ([#170](https://github.com/abruption/codex-unlock/issues/170)) ([36e3bf6](https://github.com/abruption/codex-unlock/commit/36e3bf655cacddaac9b1c8ed3c80530199dd5ef5))
* prepare standalone Windows diagnostic alpha releases ([#172](https://github.com/abruption/codex-unlock/issues/172)) ([815c56e](https://github.com/abruption/codex-unlock/commit/815c56e047cca57b71f50805bb487c856f047526))
* **windows:** prepare diagnostic RC and stable qualification ([#177](https://github.com/abruption/codex-unlock/issues/177)) ([1bb8746](https://github.com/abruption/codex-unlock/commit/1bb8746d4ce80cd9c3915b7b617b6b8a289b8d45))
* **windows:** select stable release plan after qualified RC ([#179](https://github.com/abruption/codex-unlock/issues/179)) ([2893745](https://github.com/abruption/codex-unlock/commit/2893745bda171abc92b164127af87d4166d55acc))


### Bug Fixes

* **deps:** patch URI parsing advisories and refresh development dependencies ([37074a5](https://github.com/abruption/codex-unlock/commit/37074a5b1d3dc5b4e1976cd3f56af353519134a3))

## [0.4.7](https://github.com/abruption/codex-unlock/compare/v0.4.6...v0.4.7) (2026-10-18)


### Tests

* separate Linux attribution causes and guard-gap models ([#157](https://github.com/abruption/codex-unlock/issues/157)) ([acb1edb](https://github.com/abruption/codex-unlock/commit/acb1edb4ca49a1ed28de5b83a8b9ce2302d6bcfe))

## [0.4.6](https://github.com/abruption/codex-unlock/compare/v0.4.5...v0.4.6) (2026-10-14)


### Bug Fixes

* preserve lossless lock and transcript identities ([#135](https://github.com/abruption/codex-unlock/issues/135)) ([95ea586](https://github.com/abruption/codex-unlock/commit/95ea58692e2d44cef807f34122de887286194db7))
* recognize source-reviewed exec cyber access option ([#130](https://github.com/abruption/codex-unlock/issues/130)) ([38b7ad0](https://github.com/abruption/codex-unlock/commit/38b7ad094499b018abcc0fbdffcaf7d59587a660))

## [0.4.5](https://github.com/abruption/codex-unlock/compare/v0.4.4...v0.4.5) (2026-10-09)


### Bug Fixes

* refuse incomplete lsof discovery and measure attribution ([#115](https://github.com/abruption/codex-unlock/issues/115)) ([1fcb13e](https://github.com/abruption/codex-unlock/commit/1fcb13e36a7f4c73ac7ff7bb3ffa48fd38fa9bf7))

## [0.4.4](https://github.com/abruption/codex-unlock/compare/v0.4.3...v0.4.4) (2026-10-07)


### Bug Fixes

* align empty CODEX_HOME with upstream Codex ([#104](https://github.com/abruption/codex-unlock/issues/104)) ([c41b5ab](https://github.com/abruption/codex-unlock/commit/c41b5ab8cfe774558054f3f3f79d56a1d18a112a))
* harden final signal checks and failure evidence ([#105](https://github.com/abruption/codex-unlock/issues/105)) ([3b50921](https://github.com/abruption/codex-unlock/commit/3b50921339079d60d1cb457abba04425ca2f628d))
* refuse macOS exec-server and remote owners ([#103](https://github.com/abruption/codex-unlock/issues/103)) ([5630e9b](https://github.com/abruption/codex-unlock/commit/5630e9b494e82d3f09aa134066aaa06a9594ba68))

## [0.4.3](https://github.com/abruption/codex-unlock/compare/v0.4.2...v0.4.3) (2026-10-04)


### Bug Fixes

* bound concurrent list inspections ([#93](https://github.com/abruption/codex-unlock/issues/93)) ([1ba3290](https://github.com/abruption/codex-unlock/commit/1ba329074364f3ddba964bf376088b2ba6a923a8))
* classify Linux Codex service modes from verified argv ([#91](https://github.com/abruption/codex-unlock/issues/91)) ([f1915dd](https://github.com/abruption/codex-unlock/commit/f1915dd8522b032554c8e9584b5d03cce146c09f))
* redact malformed transcript parser errors ([#90](https://github.com/abruption/codex-unlock/issues/90)) ([ab33856](https://github.com/abruption/codex-unlock/commit/ab33856e4f944216a6999bd01e8c92c2ef5b1441))

## [0.4.2](https://github.com/abruption/codex-unlock/compare/v0.4.1...v0.4.2) (2026-09-29)


### Bug Fixes

* publish a runtime-only npm shrinkwrap ([#83](https://github.com/abruption/codex-unlock/issues/83)) ([d279732](https://github.com/abruption/codex-unlock/commit/d27973298bd8a91a1216a444a5439fbdc59a2bba)), closes [#82](https://github.com/abruption/codex-unlock/issues/82)

## [0.4.1](https://github.com/abruption/codex-unlock/compare/v0.4.0...v0.4.1) (2026-09-29)


### Bug Fixes

* classify post-signal owner exit and lock reacquisition ([#77](https://github.com/abruption/codex-unlock/issues/77)) ([98a25c7](https://github.com/abruption/codex-unlock/commit/98a25c78c935a15e5757c3ec441a406c16f63f29))
* coordinate native thread lock probes ([#79](https://github.com/abruption/codex-unlock/issues/79)) ([1d529c3](https://github.com/abruption/codex-unlock/commit/1d529c3bd5da9c49fafc095746d2d921e276ddc3))
* escape terminal controls and bound transcript ordinals ([#76](https://github.com/abruption/codex-unlock/issues/76)) ([938a65a](https://github.com/abruption/codex-unlock/commit/938a65a4b0306a999639f2a9b33fa5b1a3ce116f)), closes [#54](https://github.com/abruption/codex-unlock/issues/54) [#56](https://github.com/abruption/codex-unlock/issues/56)
* harden diagnostic command execution ([#74](https://github.com/abruption/codex-unlock/issues/74)) ([ce2105c](https://github.com/abruption/codex-unlock/commit/ce2105c9c9f6e990478a393f5f3cd0c34de83a75)), closes [#68](https://github.com/abruption/codex-unlock/issues/68) [#66](https://github.com/abruption/codex-unlock/issues/66)
* harden update cache boundary ([#72](https://github.com/abruption/codex-unlock/issues/72)) ([72d2b6e](https://github.com/abruption/codex-unlock/commit/72d2b6eb52d139ec952e42452e9c5828acb7d851)), closes [#57](https://github.com/abruption/codex-unlock/issues/57) [#62](https://github.com/abruption/codex-unlock/issues/62) [#70](https://github.com/abruption/codex-unlock/issues/70)
* key unlock leases by native lock identity ([#73](https://github.com/abruption/codex-unlock/issues/73)) ([9e97142](https://github.com/abruption/codex-unlock/commit/9e9714235e0c94fe6d0954a355e12f2b2c126ced))
* pin native runtime dependencies for consumer installs ([#71](https://github.com/abruption/codex-unlock/issues/71)) ([2c7e045](https://github.com/abruption/codex-unlock/commit/2c7e045bdfa30af2f2b723342f56f046c963d875)), closes [#69](https://github.com/abruption/codex-unlock/issues/69)
* validate CLI usage and Codex home before inspection ([#75](https://github.com/abruption/codex-unlock/issues/75)) ([81e26dd](https://github.com/abruption/codex-unlock/commit/81e26dd40c0f0fe44128312b4d86d2b24f8a86a2)), closes [#58](https://github.com/abruption/codex-unlock/issues/58) [#67](https://github.com/abruption/codex-unlock/issues/67)

## [0.4.0](https://github.com/abruption/codex-unlock/compare/v0.3.0...v0.4.0) (2026-09-28)


### Features

* publish type-only JSON v1 declarations ([#49](https://github.com/abruption/codex-unlock/issues/49)) ([c6091e7](https://github.com/abruption/codex-unlock/commit/c6091e7fad20864a7c34da2655a77b902f873891))

## [0.3.0](https://github.com/abruption/codex-unlock/compare/v0.2.0...v0.3.0) (2026-09-23)


### Features

* add cached update notices ([#40](https://github.com/abruption/codex-unlock/issues/40)) ([98d6258](https://github.com/abruption/codex-unlock/commit/98d625859f635f0c706d528f9cde2f09c0d853df))


### Bug Fixes

* harden update metadata boundary ([#38](https://github.com/abruption/codex-unlock/issues/38)) ([3170ebd](https://github.com/abruption/codex-unlock/commit/3170ebdb3783e1184f331a73f482ecafb56ce140))

## [0.2.0](https://github.com/abruption/codex-unlock/compare/v0.1.1...v0.2.0) (2026-09-22)


### Features

* define CLI JSON integration contract ([#31](https://github.com/abruption/codex-unlock/issues/31)) ([6ffa738](https://github.com/abruption/codex-unlock/commit/6ffa738fff6969834df6a3c4481fd3e608edd9c7))


### Bug Fixes

* serialize concurrent unlock attempts ([#35](https://github.com/abruption/codex-unlock/issues/35)) ([7a8e113](https://github.com/abruption/codex-unlock/commit/7a8e113e5c64ff7f6f58053ac07cde5d485e3b83))

## [0.1.1](https://github.com/abruption/codex-unlock/compare/v0.1.0...v0.1.1) (2026-09-21)


### Bug Fixes

* harden v0.1.1 lock recovery ([#21](https://github.com/abruption/codex-unlock/issues/21)) ([3e3d325](https://github.com/abruption/codex-unlock/commit/3e3d325f01deca3da740b51295119eee4d5e7e01))

## 0.1.0 (2026-09-15)


### Features

* add safe Codex session lock doctor ([f080d62](https://github.com/abruption/codex-unlock/commit/f080d6270f7430d1f82883639d31ba475f245055))


### Bug Fixes

* align installation with supported Node runtimes ([#5](https://github.com/abruption/codex-unlock/issues/5)) ([e779c2d](https://github.com/abruption/codex-unlock/commit/e779c2d7868b03b2c84c4cb6c1ff6472821ff466))


### Continuous Integration

* establish repository and release automation ([#3](https://github.com/abruption/codex-unlock/issues/3)) ([a4d9315](https://github.com/abruption/codex-unlock/commit/a4d931518be2632a7014901933e3f3f41fedb257))
