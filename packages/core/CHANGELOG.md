# Changelog

## [0.32.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/core-v0.31.1...@cipherbox/core-v0.32.0) (2026-07-18)


### Features

* integrate web client with node/v3 read and write runtime ([#588](https://github.com/FSM1/cipher-box/issues/588)) ([1fb8996](https://github.com/FSM1/cipher-box/commit/1fb8996a25947a0964b286ac44864f3e5e84e33c))
* rotation write-plane and re-mint durability with recipient-pubkey pinning ([#615](https://github.com/FSM1/cipher-box/issues/615)) ([27c4abe](https://github.com/FSM1/cipher-box/commit/27c4abec52ed7cdf0ce9d7147685b2bae97e16b5))
* SDK write-chain, write-revocation, bin re-link, and invite claim ([#583](https://github.com/FSM1/cipher-box/issues/583)) ([d81c1b4](https://github.com/FSM1/cipher-box/commit/d81c1b476805f7b6764e388604e3da657f7540f1))
* SDK-owned read chain and resolved folder listings ([#589](https://github.com/FSM1/cipher-box/issues/589)) ([6534c64](https://github.com/FSM1/cipher-box/commit/6534c642aacfd4755967ccbd622840610635b86c))
* unified Node codec and two-key vault v3 blob in core ([#578](https://github.com/FSM1/cipher-box/issues/578)) ([b2dba55](https://github.com/FSM1/cipher-box/commit/b2dba554a75cb975ab72d9e2777b7b2dde9a06bf))


### Bug Fixes

* complete web kind discrimination and revive deferred test suites ([#611](https://github.com/FSM1/cipher-box/issues/611)) ([fcf1596](https://github.com/FSM1/cipher-box/commit/fcf1596a736cd0d2bd75f0dd6f9ac13a224906fa))
* cross-language IPNS and node-codec verification parity ([#608](https://github.com/FSM1/cipher-box/issues/608)) ([77e52cb](https://github.com/FSM1/cipher-box/commit/77e52cb8dc65788f7df7cd1ffbe9cf7384ac3e21))
* harden SDK write-plane durability and correctness ([#602](https://github.com/FSM1/cipher-box/issues/602)) ([c21f896](https://github.com/FSM1/cipher-box/commit/c21f896b6839b5791ff0c8bd4c5985afef8c6a48))

## [0.31.1](https://github.com/FSM1/cipher-box/compare/@cipherbox/core-v0.31.0...@cipherbox/core-v0.31.1) (2026-06-26)


### Bug Fixes

* **bin:** unpin deleted content and revoke its shares ([#563](https://github.com/FSM1/cipher-box/issues/563)) ([1699522](https://github.com/FSM1/cipher-box/commit/16995221c79421d086aeee0b58fb7af3c7198fa9))

## [0.31.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/core-v0.30.0...@cipherbox/core-v0.31.0) (2026-06-17)


### Bug Fixes

* re-encrypt file metadata on move and bin restore ([#507](https://github.com/FSM1/cipher-box/issues/507)) ([2c639de](https://github.com/FSM1/cipher-box/commit/2c639de8a4acec923fe5396f8fc5a6255c59978d))

## [0.30.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/core-v0.29.0...@cipherbox/core-v0.30.0) (2026-03-31)


### Features

* **web:** user-configurable vault parameters ([#423](https://github.com/FSM1/cipher-box/issues/423)) ([fa7b443](https://github.com/FSM1/cipher-box/commit/fa7b44399f9c688783b995a2a716b6525eabeefe))

## [0.29.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/core-v0.28.0...@cipherbox/core-v0.29.0) (2026-03-26)


### Features

* **phase-24:** bug fixes & test infrastructure ([#361](https://github.com/FSM1/cipher-box/issues/361)) ([2f1f93b](https://github.com/FSM1/cipher-box/commit/2f1f93ba7e7a9411e3a73b31e91992c95efd7bfa))

## [0.28.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/core-v0.27.0...@cipherbox/core-v0.28.0) (2026-03-25)

### Features

- Phase 21 BYO-IPFS Node ([#346](https://github.com/FSM1/cipher-box/issues/346)) ([d2ef0c5](https://github.com/FSM1/cipher-box/commit/d2ef0c53bc9b614a47a63d019acc7b792b855ea0))
- phase 22 — performance baselines completion ([#355](https://github.com/FSM1/cipher-box/issues/355)) ([25bc1b3](https://github.com/FSM1/cipher-box/commit/25bc1b35fb69cb28c350a155b5b7b42104f4f5d0))

## [0.27.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/core-v0.26.0...@cipherbox/core-v0.27.0) (2026-03-25)

### Features

- extract Rust SDK as five workspace crates ([#352](https://github.com/FSM1/cipher-box/issues/352)) ([34bce7b](https://github.com/FSM1/cipher-box/commit/34bce7bfd40170f0fb080f68f50a0e8cb37704cf))

## [0.26.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/core-v0.25.0...@cipherbox/core-v0.26.0) (2026-03-24)

### Features

- vault blob v2 migration — zero-knowledge server ([#344](https://github.com/FSM1/cipher-box/issues/344)) ([6aa4114](https://github.com/FSM1/cipher-box/commit/6aa4114bd57a339d28c2e95be0d544e62aef11c2))

### Bug Fixes

- separate vault key blob from root folder IPNS name ([#349](https://github.com/FSM1/cipher-box/issues/349)) ([f04ba16](https://github.com/FSM1/cipher-box/commit/f04ba16ea099b16d13cc3c846e979ee461bd966d))

## [0.25.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/core-v0.24.2...@cipherbox/core-v0.25.0) (2026-03-21)

### Features

- extract core crypto SDK as shared packages ([#296](https://github.com/FSM1/cipher-box/issues/296)) ([2cdc3fb](https://github.com/FSM1/cipher-box/commit/2cdc3fb3675d9c092e8ec9e5493982cc67f21822))
