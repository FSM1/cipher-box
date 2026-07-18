# Changelog

## [0.47.0](https://github.com/FSM1/cipher-box/compare/cipherbox-desktop-v0.46.0...cipherbox-desktop-v0.47.0) (2026-07-18)


### Features

* FUSE and WinFsp Rust integration with grant-root awareness and SDK-owned read chain ([#594](https://github.com/FSM1/cipher-box/issues/594)) ([4b96aa9](https://github.com/FSM1/cipher-box/commit/4b96aa950b19591331445d65dfa81b6bc25d90b2))
* rotation write-plane and re-mint durability with recipient-pubkey pinning ([#615](https://github.com/FSM1/cipher-box/issues/615)) ([27c4abe](https://github.com/FSM1/cipher-box/commit/27c4abec52ed7cdf0ce9d7147685b2bae97e16b5))


### Bug Fixes

* harden FUSE publish and TEE write paths against partial-failure states ([#610](https://github.com/FSM1/cipher-box/issues/610)) ([02efe51](https://github.com/FSM1/cipher-box/commit/02efe51bbc1930b02857b081b41404ae0ed9605c))
* harden rotation read-plane durability and deep crash-resume soundness ([#598](https://github.com/FSM1/cipher-box/issues/598)) ([d5486e5](https://github.com/FSM1/cipher-box/commit/d5486e586ab0d30113ca167819d6e053bb2ec3a3))

## [0.46.0](https://github.com/FSM1/cipher-box/compare/cipherbox-desktop-v0.45.0...cipherbox-desktop-v0.46.0) (2026-06-26)


### Bug Fixes

* harden Phase 60 deferred safety patches in FUSE publish and desktop vault init ([#566](https://github.com/FSM1/cipher-box/issues/566)) ([0adcb04](https://github.com/FSM1/cipher-box/commit/0adcb0418198b3cc311da98551c9d0a4bef293c2))

## [0.45.0](https://github.com/FSM1/cipher-box/compare/cipherbox-desktop-v0.44.0...cipherbox-desktop-v0.45.0) (2026-06-25)


### Features

* strict fail-closed IPNS verification cutover across Rust, TS, and API ([#555](https://github.com/FSM1/cipher-box/issues/555)) ([03209e3](https://github.com/FSM1/cipher-box/commit/03209e3854e1309cde13c087a3f407568b17fcd7))

## [0.44.0](https://github.com/FSM1/cipher-box/compare/cipherbox-desktop-v0.43.0...cipherbox-desktop-v0.44.0) (2026-06-22)


### Bug Fixes

* FUSE and IPNS write-path durability hardening ([#543](https://github.com/FSM1/cipher-box/issues/543)) ([5d5daaa](https://github.com/FSM1/cipher-box/commit/5d5daaaf69aeb030ae9aa828ac4245525e0215fd))

## [0.43.0](https://github.com/FSM1/cipher-box/compare/cipherbox-desktop-v0.42.0...cipherbox-desktop-v0.43.0) (2026-06-21)


### Features

* desktop FUSE journal durability and at-rest safety ([#533](https://github.com/FSM1/cipher-box/issues/533)) ([b3511af](https://github.com/FSM1/cipher-box/commit/b3511afbd7011a0a5f151d47f2ec9bd1069262c1))

## [0.42.0](https://github.com/FSM1/cipher-box/compare/cipherbox-desktop-v0.41.0...cipherbox-desktop-v0.42.0) (2026-06-15)


### Features

* desktop FUSE data-loss bugs and replay hardening ([#493](https://github.com/FSM1/cipher-box/issues/493)) ([79de97b](https://github.com/FSM1/cipher-box/commit/79de97bc5cfe5213cc2d6747305a914265b12430))
* **fuse:** durable write journal with crash-recovery replay ([#487](https://github.com/FSM1/cipher-box/issues/487)) ([dcd1bec](https://github.com/FSM1/cipher-box/commit/dcd1becb6f6dad1b8d44d70544b0a6b1248458dc))

## [0.41.0](https://github.com/FSM1/cipher-box/compare/cipherbox-desktop-v0.40.0...cipherbox-desktop-v0.41.0) (2026-05-26)


### Bug Fixes

* **desktop:** resolve folder rename permission errors and sync duplicates ([#466](https://github.com/FSM1/cipher-box/issues/466)) ([1f84eec](https://github.com/FSM1/cipher-box/commit/1f84eec428be6a81068381e1488b0598317d49ae))

## [0.40.0](https://github.com/FSM1/cipher-box/compare/cipherbox-desktop-v0.39.0...cipherbox-desktop-v0.40.0) (2026-05-25)


### Bug Fixes

* **desktop:** use Web3Auth devnet network for production builds ([#462](https://github.com/FSM1/cipher-box/issues/462)) ([d502940](https://github.com/FSM1/cipher-box/commit/d502940c187b35df49ed305969071da0fd2749bd))

## [0.39.0](https://github.com/FSM1/cipher-box/compare/cipherbox-desktop-v0.38.0...cipherbox-desktop-v0.39.0) (2026-05-25)


### Bug Fixes

* **desktop:** use localhost callback server for Google OAuth in Tauri ([#459](https://github.com/FSM1/cipher-box/issues/459)) ([ebfa8a8](https://github.com/FSM1/cipher-box/commit/ebfa8a8af2dcec7bdde8b5eb78995f5d825ea8e1))

## [0.38.0](https://github.com/FSM1/cipher-box/compare/cipherbox-desktop-v0.37.0...cipherbox-desktop-v0.38.0) (2026-04-14)


### Bug Fixes

* **desktop:** trigger metadata refresh from lookup/open, fix e2e sync test ([#456](https://github.com/FSM1/cipher-box/issues/456)) ([1e3ef75](https://github.com/FSM1/cipher-box/commit/1e3ef750f430f7d49ffe85d5d81cd80cb1467988))

## [0.37.0](https://github.com/FSM1/cipher-box/compare/cipherbox-desktop-v0.36.0...cipherbox-desktop-v0.37.0) (2026-04-06)


### Bug Fixes

* **api,desktop:** fix sequence number mismatch in cached IPNS resolves ([#449](https://github.com/FSM1/cipher-box/issues/449)) ([18b4e26](https://github.com/FSM1/cipher-box/commit/18b4e2600df804924461d967787408268c1f798c))

## [0.36.0](https://github.com/FSM1/cipher-box/compare/cipherbox-desktop-v0.35.0...cipherbox-desktop-v0.36.0) (2026-04-01)


### Features

* desktop vault settings integration - phase 40 ([#424](https://github.com/FSM1/cipher-box/issues/424)) ([0d37d71](https://github.com/FSM1/cipher-box/commit/0d37d710bc1c57061433a992c020fc8951aba1ad))


### Bug Fixes

* **desktop:** use compile-time API URL fallback for release builds ([#425](https://github.com/FSM1/cipher-box/issues/425)) ([e5384c0](https://github.com/FSM1/cipher-box/commit/e5384c0afe7f0590edc8c9b7e754eebe8325f58f))
