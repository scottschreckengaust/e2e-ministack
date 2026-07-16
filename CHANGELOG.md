# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> This project has not yet cut a tagged release. Until the first version is
> tagged, all changes accumulate under **Unreleased**. The detailed history of
> changes to date lives in the git log and the merged pull requests; this file
> starts tracking notable changes forward from its introduction.

## [0.6.0](https://github.com/scottschreckengaust/e2e-ministack/compare/v0.5.1...v0.6.0) (2026-07-16)


### Features

* **security:** couple GitHub Code Scanning dismissal to .vex/ records ([#181](https://github.com/scottschreckengaust/e2e-ministack/issues/181)) ([#186](https://github.com/scottschreckengaust/e2e-ministack/issues/186)) ([313c65c](https://github.com/scottschreckengaust/e2e-ministack/commit/313c65cfa2bdff3addd19fdecb4eb5503a0f4d2a))
* **security:** prioritized VEX report sort + bounded recently-resolved ([#210](https://github.com/scottschreckengaust/e2e-ministack/issues/210)) ([#213](https://github.com/scottschreckengaust/e2e-ministack/issues/213)) ([99e23ac](https://github.com/scottschreckengaust/e2e-ministack/commit/99e23ac46c85cfc4a9ddb23601bf409883685e0a))
* **security:** schema-gate vex-to-sarif-suppressions output against OASIS SARIF 2.1.0 ([#187](https://github.com/scottschreckengaust/e2e-ministack/issues/187)) ([#198](https://github.com/scottschreckengaust/e2e-ministack/issues/198)) ([b057d40](https://github.com/scottschreckengaust/e2e-ministack/commit/b057d40152e07099a20a748e0fc8d8edcb00e2a1))
* **security:** VEX report CI job — reconcile .vex/ against Code Scanning alerts ([#189](https://github.com/scottschreckengaust/e2e-ministack/issues/189)) ([#204](https://github.com/scottschreckengaust/e2e-ministack/issues/204)) ([e924eb2](https://github.com/scottschreckengaust/e2e-ministack/commit/e924eb21d071d48f05d764325738be301af168c0))
* **security:** VEX report engine — .vex/-driven reconciliation table ([#189](https://github.com/scottschreckengaust/e2e-ministack/issues/189)) ([#203](https://github.com/scottschreckengaust/e2e-ministack/issues/203)) ([24b346f](https://github.com/scottschreckengaust/e2e-ministack/commit/24b346f0371d7870ffc0aaebe9bf25ff1fa9f894))
* **security:** VEX report format/UX — linked scanners, legend, count legibility ([#206](https://github.com/scottschreckengaust/e2e-ministack/issues/206)) ([#207](https://github.com/scottschreckengaust/e2e-ministack/issues/207)) ([7c360ba](https://github.com/scottschreckengaust/e2e-ministack/commit/7c360ba38364b55e2cfae1c39fe82a94e5937ee6))


### Bug Fixes

* **security:** repin the VEX-free suppression-view scan to the current image digest ([#210](https://github.com/scottschreckengaust/e2e-ministack/issues/210)) ([#211](https://github.com/scottschreckengaust/e2e-ministack/issues/211)) ([31b1bed](https://github.com/scottschreckengaust/e2e-ministack/commit/31b1bedc50a9d67feb300c39e01104b8834ebd5c))

## [0.5.1](https://github.com/scottschreckengaust/e2e-ministack/compare/v0.5.0...v0.5.1) (2026-07-13)


### Bug Fixes

* **sonar:** resolve gh to an absolute path, never via $PATH (S4036, [#170](https://github.com/scottschreckengaust/e2e-ministack/issues/170)) ([#178](https://github.com/scottschreckengaust/e2e-ministack/issues/178)) ([062c936](https://github.com/scottschreckengaust/e2e-ministack/commit/062c9363640c7b3ac65fe185357b60fc9d85e357))

## [0.5.0](https://github.com/scottschreckengaust/e2e-ministack/compare/v0.4.0...v0.5.0) (2026-07-10)


### Features

* **security:** add ClamAV + SonarQube scanners; exempt LGPL Sonar action in dependency-review ([#149](https://github.com/scottschreckengaust/e2e-ministack/issues/149), [#150](https://github.com/scottschreckengaust/e2e-ministack/issues/150), [#161](https://github.com/scottschreckengaust/e2e-ministack/issues/161)) ([#162](https://github.com/scottschreckengaust/e2e-ministack/issues/162)) ([afeab57](https://github.com/scottschreckengaust/e2e-ministack/commit/afeab570a0dfea2293e958145a02f0662cdc64ff))
* **test:** add @cdk/integ-runner snapshot gate for MiniStackStack ([#169](https://github.com/scottschreckengaust/e2e-ministack/issues/169)) ([60e04f7](https://github.com/scottschreckengaust/e2e-ministack/commit/60e04f7358e314ef490282bf30a32648f4b1948e))


### Bug Fixes

* **sonar:** use CDK construct instances to satisfy S1848 ([#170](https://github.com/scottschreckengaust/e2e-ministack/issues/170)) ([#172](https://github.com/scottschreckengaust/e2e-ministack/issues/172)) ([23fbe3b](https://github.com/scottschreckengaust/e2e-ministack/commit/23fbe3bbaf20b6779371f8a41a8c59020e93c4c6))

## [0.4.0](https://github.com/scottschreckengaust/e2e-ministack/compare/v0.3.0...v0.4.0) (2026-07-09)


### Features

* **ci:** auto-label PRs by changed paths (actions/labeler) ([#121](https://github.com/scottschreckengaust/e2e-ministack/issues/121)) ([20403d3](https://github.com/scottschreckengaust/e2e-ministack/commit/20403d348cca85e27317aca56e004b426e9d61ab)), closes [#116](https://github.com/scottschreckengaust/e2e-ministack/issues/116)
* **ci:** octocov sticky PR coverage comment + polyglot reporting contract docs ([#130](https://github.com/scottschreckengaust/e2e-ministack/issues/130)) ([9f39d82](https://github.com/scottschreckengaust/e2e-ministack/commit/9f39d827e3d0461ab91a49393767c4a2b06e2c8b)), closes [#125](https://github.com/scottschreckengaust/e2e-ministack/issues/125)
* **ci:** phase 3 — jazzer corpus-replay regression tier in the unit gate ([#122](https://github.com/scottschreckengaust/e2e-ministack/issues/122)) ([#132](https://github.com/scottschreckengaust/e2e-ministack/issues/132)) ([056d650](https://github.com/scottschreckengaust/e2e-ministack/commit/056d650c2e87a43055463df92bd9fe4b5c9b8c6b))
* **ci:** unit-tier coverage with 100% gate, Stryker JSON report, step summaries ([#128](https://github.com/scottschreckengaust/e2e-ministack/issues/128)) ([df4cc4b](https://github.com/scottschreckengaust/e2e-ministack/commit/df4cc4b50a80c1286a265d027926f3bd2b2bfcac)), closes [#124](https://github.com/scottschreckengaust/e2e-ministack/issues/124)
* **compat:** harness core — services/ layout, Contract/DeployAdapter, registries + unit schema-gate ([#141](https://github.com/scottschreckengaust/e2e-ministack/issues/141)) ([6a5bb36](https://github.com/scottschreckengaust/e2e-ministack/commit/6a5bb362009630435877dfef75b68fb17d568fca)), closes [#135](https://github.com/scottschreckengaust/e2e-ministack/issues/135)
* **compat:** Lambda vertical (CDK) — shared SDK+CLI oracles + iac/cdk adapter + describe.each ([#142](https://github.com/scottschreckengaust/e2e-ministack/issues/142)) ([19309c2](https://github.com/scottschreckengaust/e2e-ministack/commit/19309c2e6cb21fc24cc46a383cf89fa0143a5a98))
* **compat:** Lambda/CDK vertical self-provisions its own CompatLambdaStack ([#147](https://github.com/scottschreckengaust/e2e-ministack/issues/147)) ([c090043](https://github.com/scottschreckengaust/e2e-ministack/commit/c090043caf97cfbedc73cd2ec42bf8f0adab315e))
* **compat:** MiniStack-bump compatibility workflow — schedule + pin-change trigger, drift opens an issue ([#146](https://github.com/scottschreckengaust/e2e-ministack/issues/146)) ([e3859f0](https://github.com/scottschreckengaust/e2e-ministack/commit/e3859f0fe3f0f3d756f0ed29d882021ad55ef519)), closes [#138](https://github.com/scottschreckengaust/e2e-ministack/issues/138)
* **compat:** upstream MiniStack tracking — query-automated, comment/watch human-gated ([#145](https://github.com/scottschreckengaust/e2e-ministack/issues/145)) ([6cf947b](https://github.com/scottschreckengaust/e2e-ministack/commit/6cf947b96d3c9e7273745a99acfabd13aace59f1)), closes [#137](https://github.com/scottschreckengaust/e2e-ministack/issues/137)
* **mcp:** Cursor `.cursor/mcp.json` (GitHub MCP, Cursor env interpolation) ([#112](https://github.com/scottschreckengaust/e2e-ministack/issues/112)) ([#113](https://github.com/scottschreckengaust/e2e-ministack/issues/113)) ([eb89840](https://github.com/scottschreckengaust/e2e-ministack/commit/eb8984086096de4d9426289d6a228b0beb0c101d))
* **mcp:** repo-wide GitHub MCP server (remote HTTP PoC) + agent-agnostic worktree convention ([#72](https://github.com/scottschreckengaust/e2e-ministack/issues/72)) ([#88](https://github.com/scottschreckengaust/e2e-ministack/issues/88)) ([711654f](https://github.com/scottschreckengaust/e2e-ministack/commit/711654ff4539ba5b22f9a48f7126f9b3503246cc))
* **security:** add Trivy scanner to security.yml (report-only; FS + pinned image) ([#159](https://github.com/scottschreckengaust/e2e-ministack/issues/159)) ([68309a2](https://github.com/scottschreckengaust/e2e-ministack/commit/68309a26bdc1b6487d4c46b8013d23fd118a3821)), closes [#133](https://github.com/scottschreckengaust/e2e-ministack/issues/133)
* **security:** hard-fail MiniStack image scan via per-CVE OpenVEX records ([#160](https://github.com/scottschreckengaust/e2e-ministack/issues/160)) ([2fa86f6](https://github.com/scottschreckengaust/e2e-ministack/commit/2fa86f64884e9907a2c6c3308e21a3e61333e76d))
* **security:** license-UNKNOWN triage — PR-time detect + scheduled verdict poller ([#127](https://github.com/scottschreckengaust/e2e-ministack/issues/127) Leg B) ([#131](https://github.com/scottschreckengaust/e2e-ministack/issues/131)) ([9e81ee8](https://github.com/scottschreckengaust/e2e-ministack/commit/9e81ee87b231171bdd3838a59d16d877161fce97))


### Bug Fixes

* **security:** drop standing aiohttp license exemption — route UNKNOWNs to license-review issues ([#129](https://github.com/scottschreckengaust/e2e-ministack/issues/129)) ([52a6c82](https://github.com/scottschreckengaust/e2e-ministack/commit/52a6c82ace631a3c04133047223dfb96e527a8b1))
* **security:** force aiohttp 3.14.1 in IaC scanner pins (Dependabot alerts [#14](https://github.com/scottschreckengaust/e2e-ministack/issues/14)-[#24](https://github.com/scottschreckengaust/e2e-ministack/issues/24)) ([#123](https://github.com/scottschreckengaust/e2e-ministack/issues/123)) ([5e23f58](https://github.com/scottschreckengaust/e2e-ministack/commit/5e23f58f8a22737dc79aad38ae5445eb561e7767))

## [0.3.0](https://github.com/scottschreckengaust/e2e-ministack/compare/v0.2.0...v0.3.0) (2026-06-29)


### Features

* **governance:** add CODEOWNERS with maintainer catch-all ([#102](https://github.com/scottschreckengaust/e2e-ministack/issues/102)) ([#103](https://github.com/scottschreckengaust/e2e-ministack/issues/103)) ([a76e0cf](https://github.com/scottschreckengaust/e2e-ministack/commit/a76e0cf53df45fc8a6f4af66e3ca5af12fa9a0ac))
* **resolve-open-issues:** zero-dependency eval harness (baseline + before/after scorecard) ([#108](https://github.com/scottschreckengaust/e2e-ministack/issues/108)) ([28c8827](https://github.com/scottschreckengaust/e2e-ministack/commit/28c8827d99bf0ef546fa57e15fa7cbf7ab362de2))

## [0.2.0](https://github.com/scottschreckengaust/e2e-ministack/compare/v0.1.0...v0.2.0) (2026-06-26)


### Features

* **automation:** release + changelog automation via release-please ([#94](https://github.com/scottschreckengaust/e2e-ministack/issues/94)) ([da5d4b2](https://github.com/scottschreckengaust/e2e-ministack/commit/da5d4b21359ad79c03084e0775899e82904d19b4))


### Bug Fixes

* **lint:** exclude generated CHANGELOG.md from markdownlint + prettier ([#101](https://github.com/scottschreckengaust/e2e-ministack/issues/101)) ([27fe7f1](https://github.com/scottschreckengaust/e2e-ministack/commit/27fe7f12a34d15a0300c690531b94f383be6e8fd))
* **release:** release-please v5 (Node24) + tag/permission docs ([#98](https://github.com/scottschreckengaust/e2e-ministack/issues/98)) ([9166f11](https://github.com/scottschreckengaust/e2e-ministack/commit/9166f1104d65e7811888c3a5e46554c6e7bc3879))

## [Unreleased]

### Added

- This changelog, a Contributor Covenant Code of Conduct, and ongoing
  community-health and supply-chain documentation.

[Unreleased]: https://github.com/scottschreckengaust/e2e-ministack/commits/main
