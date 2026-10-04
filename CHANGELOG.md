# Changelog

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
