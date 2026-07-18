# Changelog

## [0.37.0](https://github.com/FSM1/cipher-box/compare/cipherbox-api-client-v0.36.1...cipherbox-api-client-v0.37.0) (2026-07-18)


### Features

* enforce share-invite authorization and IPNS data-integrity in the API ([#599](https://github.com/FSM1/cipher-box/issues/599)) ([703bc00](https://github.com/FSM1/cipher-box/commit/703bc0083d42547cd2c0e747d79be82a0c318e78))
* FUSE and WinFsp Rust integration with grant-root awareness and SDK-owned read chain ([#594](https://github.com/FSM1/cipher-box/issues/594)) ([4b96aa9](https://github.com/FSM1/cipher-box/commit/4b96aa950b19591331445d65dfa81b6bc25d90b2))


### Bug Fixes

* close rust and fuse scope-exit read-revocation bypasses ([#607](https://github.com/FSM1/cipher-box/issues/607)) ([2917c85](https://github.com/FSM1/cipher-box/commit/2917c853937ddc20e67a4149f9fc4d868f130c68))
* cross-language IPNS and node-codec verification parity ([#608](https://github.com/FSM1/cipher-box/issues/608)) ([77e52cb](https://github.com/FSM1/cipher-box/commit/77e52cb8dc65788f7df7cd1ffbe9cf7384ac3e21))

## [0.36.1](https://github.com/FSM1/cipher-box/compare/cipherbox-api-client-v0.36.0...cipherbox-api-client-v0.36.1) (2026-06-26)


### Bug Fixes

* **fuse:** revoke shares when items are deleted via the desktop mount ([#568](https://github.com/FSM1/cipher-box/issues/568)) ([82ad5d7](https://github.com/FSM1/cipher-box/commit/82ad5d77b6d3b524da62888142400c3a2cd62380))

## [0.36.0](https://github.com/FSM1/cipher-box/compare/cipherbox-api-client-v0.35.0...cipherbox-api-client-v0.36.0) (2026-06-25)


### Features

* strict fail-closed IPNS verification cutover across Rust, TS, and API ([#555](https://github.com/FSM1/cipher-box/issues/555)) ([03209e3](https://github.com/FSM1/cipher-box/commit/03209e3854e1309cde13c087a3f407568b17fcd7))

## [0.4.0](https://github.com/FSM1/cipher-box/compare/cipherbox-api-client-v0.3.0...cipherbox-api-client-v0.4.0) (2026-03-26)


### Features

* **phase-24:** bug fixes & test infrastructure ([#361](https://github.com/FSM1/cipher-box/issues/361)) ([2f1f93b](https://github.com/FSM1/cipher-box/commit/2f1f93ba7e7a9411e3a73b31e91992c95efd7bfa))

## [0.3.0](https://github.com/FSM1/cipher-box/compare/cipherbox-api-client-v0.2.0...cipherbox-api-client-v0.3.0) (2026-03-25)

### Features

- phase 22 — performance baselines completion ([#355](https://github.com/FSM1/cipher-box/issues/355)) ([25bc1b3](https://github.com/FSM1/cipher-box/commit/25bc1b35fb69cb28c350a155b5b7b42104f4f5d0))

## [0.2.0](https://github.com/FSM1/cipher-box/compare/cipherbox-api-client-v0.1.0...cipherbox-api-client-v0.2.0) (2026-03-25)

### Features

- extract Rust SDK as five workspace crates ([#352](https://github.com/FSM1/cipher-box/issues/352)) ([34bce7b](https://github.com/FSM1/cipher-box/commit/34bce7bfd40170f0fb080f68f50a0e8cb37704cf))
