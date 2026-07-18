# Changelog

## [0.11.0](https://github.com/FSM1/cipher-box/compare/cipherbox-fuse-v0.10.1...cipherbox-fuse-v0.11.0) (2026-07-18)


### Features

* enforce share-invite authorization and IPNS data-integrity in the API ([#599](https://github.com/FSM1/cipher-box/issues/599)) ([703bc00](https://github.com/FSM1/cipher-box/commit/703bc0083d42547cd2c0e747d79be82a0c318e78))
* FUSE and WinFsp Rust integration with grant-root awareness and SDK-owned read chain ([#594](https://github.com/FSM1/cipher-box/issues/594)) ([4b96aa9](https://github.com/FSM1/cipher-box/commit/4b96aa950b19591331445d65dfa81b6bc25d90b2))
* rotation write-plane and re-mint durability with recipient-pubkey pinning ([#615](https://github.com/FSM1/cipher-box/issues/615)) ([27c4abe](https://github.com/FSM1/cipher-box/commit/27c4abec52ed7cdf0ce9d7147685b2bae97e16b5))


### Bug Fixes

* close rust and fuse scope-exit read-revocation bypasses ([#607](https://github.com/FSM1/cipher-box/issues/607)) ([2917c85](https://github.com/FSM1/cipher-box/commit/2917c853937ddc20e67a4149f9fc4d868f130c68))
* cross-language IPNS and node-codec verification parity ([#608](https://github.com/FSM1/cipher-box/issues/608)) ([77e52cb](https://github.com/FSM1/cipher-box/commit/77e52cb8dc65788f7df7cd1ffbe9cf7384ac3e21))
* **fuse:** resolve before per-file first-publish to avoid seq-1 equivocation ([#601](https://github.com/FSM1/cipher-box/issues/601)) ([e87befa](https://github.com/FSM1/cipher-box/commit/e87befa2df464e2df7a880447eb4f3c0508ff5cd))
* harden FUSE publish and TEE write paths against partial-failure states ([#610](https://github.com/FSM1/cipher-box/issues/610)) ([02efe51](https://github.com/FSM1/cipher-box/commit/02efe51bbc1930b02857b081b41404ae0ed9605c))
* harden rotation read-plane durability and deep crash-resume soundness ([#598](https://github.com/FSM1/cipher-box/issues/598)) ([d5486e5](https://github.com/FSM1/cipher-box/commit/d5486e586ab0d30113ca167819d6e053bb2ec3a3))

## [0.10.1](https://github.com/FSM1/cipher-box/compare/cipherbox-fuse-v0.10.0...cipherbox-fuse-v0.10.1) (2026-06-26)


### Bug Fixes

* **fuse:** revoke shares when items are deleted via the desktop mount ([#568](https://github.com/FSM1/cipher-box/issues/568)) ([82ad5d7](https://github.com/FSM1/cipher-box/commit/82ad5d77b6d3b524da62888142400c3a2cd62380))
* harden Phase 60 deferred safety patches in FUSE publish and desktop vault init ([#566](https://github.com/FSM1/cipher-box/issues/566)) ([0adcb04](https://github.com/FSM1/cipher-box/commit/0adcb0418198b3cc311da98551c9d0a4bef293c2))

## [0.10.0](https://github.com/FSM1/cipher-box/compare/cipherbox-fuse-v0.9.0...cipherbox-fuse-v0.10.0) (2026-06-25)


### Features

* strict fail-closed IPNS verification cutover across Rust, TS, and API ([#555](https://github.com/FSM1/cipher-box/issues/555)) ([03209e3](https://github.com/FSM1/cipher-box/commit/03209e3854e1309cde13c087a3f407568b17fcd7))


### Bug Fixes

* **fuse:** re-resolve remote file edits during local publish window ([#558](https://github.com/FSM1/cipher-box/issues/558)) ([d343c0f](https://github.com/FSM1/cipher-box/commit/d343c0f4e8a34aaac117fd397a92c233f7ab45f4))

## [0.9.0](https://github.com/FSM1/cipher-box/compare/cipherbox-fuse-v0.8.0...cipherbox-fuse-v0.9.0) (2026-06-23)


### Bug Fixes

* **fuse:** harden IPNS verify and publish paths and clear cleanup debt ([#553](https://github.com/FSM1/cipher-box/issues/553)) ([ff9b356](https://github.com/FSM1/cipher-box/commit/ff9b3566991b81d49c0357a38b856f51a4cd0845))

## [0.8.0](https://github.com/FSM1/cipher-box/compare/cipherbox-fuse-v0.7.0...cipherbox-fuse-v0.8.0) (2026-06-22)


### Bug Fixes

* FUSE and IPNS write-path durability hardening ([#543](https://github.com/FSM1/cipher-box/issues/543)) ([5d5daaa](https://github.com/FSM1/cipher-box/commit/5d5daaaf69aeb030ae9aa828ac4245525e0215fd))
* IPNS signed-record verify coverage chokepoint and non-CAS sequence gate ([#544](https://github.com/FSM1/cipher-box/issues/544)) ([cd173c9](https://github.com/FSM1/cipher-box/commit/cd173c9c20c50d29ea211f00efa84291d7a3178f))

## [0.7.0](https://github.com/FSM1/cipher-box/compare/cipherbox-fuse-v0.6.1...cipherbox-fuse-v0.7.0) (2026-06-21)


### Features

* desktop FUSE journal durability and at-rest safety ([#533](https://github.com/FSM1/cipher-box/issues/533)) ([b3511af](https://github.com/FSM1/cipher-box/commit/b3511afbd7011a0a5f151d47f2ec9bd1069262c1))

## [0.6.1](https://github.com/FSM1/cipher-box/compare/cipherbox-fuse-v0.6.0...cipherbox-fuse-v0.6.1) (2026-06-17)


### Bug Fixes

* re-encrypt file metadata on move and bin restore ([#507](https://github.com/FSM1/cipher-box/issues/507)) ([2c639de](https://github.com/FSM1/cipher-box/commit/2c639de8a4acec923fe5396f8fc5a6255c59978d))

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
