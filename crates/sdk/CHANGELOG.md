# Changelog

## [0.9.0](https://github.com/FSM1/cipher-box/compare/cipherbox-sdk-v0.8.0...cipherbox-sdk-v0.9.0) (2026-07-18)


### Features

* enforce share-invite authorization and IPNS data-integrity in the API ([#599](https://github.com/FSM1/cipher-box/issues/599)) ([703bc00](https://github.com/FSM1/cipher-box/commit/703bc0083d42547cd2c0e747d79be82a0c318e78))
* FUSE and WinFsp Rust integration with grant-root awareness and SDK-owned read chain ([#594](https://github.com/FSM1/cipher-box/issues/594)) ([4b96aa9](https://github.com/FSM1/cipher-box/commit/4b96aa950b19591331445d65dfa81b6bc25d90b2))
* rotation write-plane and re-mint durability with recipient-pubkey pinning ([#615](https://github.com/FSM1/cipher-box/issues/615)) ([27c4abe](https://github.com/FSM1/cipher-box/commit/27c4abec52ed7cdf0ce9d7147685b2bae97e16b5))


### Bug Fixes

* close rust and fuse scope-exit read-revocation bypasses ([#607](https://github.com/FSM1/cipher-box/issues/607)) ([2917c85](https://github.com/FSM1/cipher-box/commit/2917c853937ddc20e67a4149f9fc4d868f130c68))
* harden rotation read-plane durability and deep crash-resume soundness ([#598](https://github.com/FSM1/cipher-box/issues/598)) ([d5486e5](https://github.com/FSM1/cipher-box/commit/d5486e586ab0d30113ca167819d6e053bb2ec3a3))
* harden rotation soundness under concurrency and crash-resume ([#596](https://github.com/FSM1/cipher-box/issues/596)) ([faa781e](https://github.com/FSM1/cipher-box/commit/faa781e4164697b17cc7765624985dcb9a38f761))

## [0.8.0](https://github.com/FSM1/cipher-box/compare/cipherbox-sdk-v0.7.0...cipherbox-sdk-v0.8.0) (2026-06-25)


### Features

* strict fail-closed IPNS verification cutover across Rust, TS, and API ([#555](https://github.com/FSM1/cipher-box/issues/555)) ([03209e3](https://github.com/FSM1/cipher-box/commit/03209e3854e1309cde13c087a3f407568b17fcd7))

## [0.7.0](https://github.com/FSM1/cipher-box/compare/cipherbox-sdk-v0.6.0...cipherbox-sdk-v0.7.0) (2026-06-21)


### Features

* desktop FUSE journal durability and at-rest safety ([#533](https://github.com/FSM1/cipher-box/issues/533)) ([b3511af](https://github.com/FSM1/cipher-box/commit/b3511afbd7011a0a5f151d47f2ec9bd1069262c1))

## [0.6.0](https://github.com/FSM1/cipher-box/compare/cipherbox-sdk-v0.5.0...cipherbox-sdk-v0.6.0) (2026-06-15)


### Features

* **fuse:** durable write journal with crash-recovery replay ([#487](https://github.com/FSM1/cipher-box/issues/487)) ([dcd1bec](https://github.com/FSM1/cipher-box/commit/dcd1becb6f6dad1b8d44d70544b0a6b1248458dc))

## [0.5.0](https://github.com/FSM1/cipher-box/compare/cipherbox-sdk-v0.4.0...cipherbox-sdk-v0.5.0) (2026-03-31)


### Features

* desktop vault settings integration - phase 40 ([#424](https://github.com/FSM1/cipher-box/issues/424)) ([0d37d71](https://github.com/FSM1/cipher-box/commit/0d37d710bc1c57061433a992c020fc8951aba1ad))

## [0.4.0](https://github.com/FSM1/cipher-box/compare/cipherbox-sdk-v0.3.0...cipherbox-sdk-v0.4.0) (2026-03-26)


### Features

* **phase-24:** bug fixes & test infrastructure ([#361](https://github.com/FSM1/cipher-box/issues/361)) ([2f1f93b](https://github.com/FSM1/cipher-box/commit/2f1f93ba7e7a9411e3a73b31e91992c95efd7bfa))

## [0.3.0](https://github.com/FSM1/cipher-box/compare/cipherbox-sdk-v0.2.0...cipherbox-sdk-v0.3.0) (2026-03-25)

### Features

- phase 22 — performance baselines completion ([#355](https://github.com/FSM1/cipher-box/issues/355)) ([25bc1b3](https://github.com/FSM1/cipher-box/commit/25bc1b35fb69cb28c350a155b5b7b42104f4f5d0))

## [0.2.0](https://github.com/FSM1/cipher-box/compare/cipherbox-sdk-v0.1.0...cipherbox-sdk-v0.2.0) (2026-03-25)

### Features

- extract Rust SDK as five workspace crates ([#352](https://github.com/FSM1/cipher-box/issues/352)) ([34bce7b](https://github.com/FSM1/cipher-box/commit/34bce7bfd40170f0fb080f68f50a0e8cb37704cf))
