# Changelog

## [0.6.0](https://github.com/FSM1/cipher-box/compare/cipherbox-fuse-v0.5.3...cipherbox-fuse-v0.6.0) (2026-06-15)


### Features

* desktop FUSE data-loss bugs and replay hardening ([#493](https://github.com/FSM1/cipher-box/issues/493)) ([79de97b](https://github.com/FSM1/cipher-box/commit/79de97bc5cfe5213cc2d6747305a914265b12430))
* **fuse:** durable write journal with crash-recovery replay ([#487](https://github.com/FSM1/cipher-box/issues/487)) ([dcd1bec](https://github.com/FSM1/cipher-box/commit/dcd1becb6f6dad1b8d44d70544b0a6b1248458dc))

## [0.5.3](https://github.com/FSM1/cipher-box/compare/cipherbox-fuse-v0.5.2...cipherbox-fuse-v0.5.3) (2026-05-26)


### Bug Fixes

* **desktop:** resolve folder rename permission errors and sync duplicates ([#466](https://github.com/FSM1/cipher-box/issues/466)) ([1f84eec](https://github.com/FSM1/cipher-box/commit/1f84eec428be6a81068381e1488b0598317d49ae))

## [0.5.2](https://github.com/FSM1/cipher-box/compare/cipherbox-fuse-v0.5.1...cipherbox-fuse-v0.5.2) (2026-04-14)


### Bug Fixes

* **desktop:** detect remote file edits and re-resolve IPNS in FUSE mount ([#454](https://github.com/FSM1/cipher-box/issues/454)) ([09e6830](https://github.com/FSM1/cipher-box/commit/09e6830b87de176b3613c700f78b2f1cd3b517f9))
* **desktop:** trigger metadata refresh from lookup/open, fix e2e sync test ([#456](https://github.com/FSM1/cipher-box/issues/456)) ([1e3ef75](https://github.com/FSM1/cipher-box/commit/1e3ef750f430f7d49ffe85d5d81cd80cb1467988))

## [0.5.1](https://github.com/FSM1/cipher-box/compare/cipherbox-fuse-v0.5.0...cipherbox-fuse-v0.5.1) (2026-04-06)


### Bug Fixes

* **api,desktop:** fix sequence number mismatch in cached IPNS resolves ([#449](https://github.com/FSM1/cipher-box/issues/449)) ([18b4e26](https://github.com/FSM1/cipher-box/commit/18b4e2600df804924461d967787408268c1f798c))
* **desktop:** align file upload IPNS sequence and verify file pointers ([#446](https://github.com/FSM1/cipher-box/issues/446)) ([741f226](https://github.com/FSM1/cipher-box/commit/741f22670f9c192a2d3168748241ad851bf32561))

## [0.5.0](https://github.com/FSM1/cipher-box/compare/cipherbox-fuse-v0.4.1...cipherbox-fuse-v0.5.0) (2026-03-31)


### Features

* desktop vault settings integration - phase 40 ([#424](https://github.com/FSM1/cipher-box/issues/424)) ([0d37d71](https://github.com/FSM1/cipher-box/commit/0d37d710bc1c57061433a992c020fc8951aba1ad))

## [0.4.1](https://github.com/FSM1/cipher-box/compare/cipherbox-fuse-v0.4.0...cipherbox-fuse-v0.4.1) (2026-03-30)


### Performance Improvements

* **fuse:** Phase 32 async FilePointer resolution ([#388](https://github.com/FSM1/cipher-box/issues/388)) ([8cddb05](https://github.com/FSM1/cipher-box/commit/8cddb05c31e2b010dc4afb9463d0d12f48722165))
* **WinFSP:** Phase 33 Windows Async FilePointer Resolution ([#389](https://github.com/FSM1/cipher-box/issues/389)) ([b2f6572](https://github.com/FSM1/cipher-box/commit/b2f6572212decf44c9bdedb92f8f48b37c69037c))

## [0.4.0](https://github.com/FSM1/cipher-box/compare/cipherbox-fuse-v0.3.0...cipherbox-fuse-v0.4.0) (2026-03-26)


### Features

* desktop auto-updater, TEE file enrollment, and CI build workflow ([#360](https://github.com/FSM1/cipher-box/issues/360)) ([2bf8f4b](https://github.com/FSM1/cipher-box/commit/2bf8f4b1ef4e37e14b2b24905d70ea4d620874af))
* **phase-24:** bug fixes & test infrastructure ([#361](https://github.com/FSM1/cipher-box/issues/361)) ([2f1f93b](https://github.com/FSM1/cipher-box/commit/2f1f93ba7e7a9411e3a73b31e91992c95efd7bfa))

## [0.3.0](https://github.com/FSM1/cipher-box/compare/cipherbox-fuse-v0.2.0...cipherbox-fuse-v0.3.0) (2026-03-25)

### Features

- phase 22 — performance baselines completion ([#355](https://github.com/FSM1/cipher-box/issues/355)) ([25bc1b3](https://github.com/FSM1/cipher-box/commit/25bc1b35fb69cb28c350a155b5b7b42104f4f5d0))

## [0.2.0](https://github.com/FSM1/cipher-box/compare/cipherbox-fuse-v0.1.0...cipherbox-fuse-v0.2.0) (2026-03-25)

### Features

- extract Rust SDK as five workspace crates ([#352](https://github.com/FSM1/cipher-box/issues/352)) ([34bce7b](https://github.com/FSM1/cipher-box/commit/34bce7bfd40170f0fb080f68f50a0e8cb37704cf))
