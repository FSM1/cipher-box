# Changelog

## [0.40.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-core-v0.39.0...@cipherbox/sdk-core-v0.40.0) (2026-07-18)


### Features

* atomic IPNS publish-gate, tombstone, and share schema cutover ([#584](https://github.com/FSM1/cipher-box/issues/584)) ([a036a84](https://github.com/FSM1/cipher-box/commit/a036a84d4477937ee4a59e2c70c0673c5142edc8))
* enforce share-invite authorization and IPNS data-integrity in the API ([#599](https://github.com/FSM1/cipher-box/issues/599)) ([703bc00](https://github.com/FSM1/cipher-box/commit/703bc0083d42547cd2c0e747d79be82a0c318e78))
* FUSE and WinFsp Rust integration with grant-root awareness and SDK-owned read chain ([#594](https://github.com/FSM1/cipher-box/issues/594)) ([4b96aa9](https://github.com/FSM1/cipher-box/commit/4b96aa950b19591331445d65dfa81b6bc25d90b2))
* integrate web client with node/v3 read and write runtime ([#588](https://github.com/FSM1/cipher-box/issues/588)) ([1fb8996](https://github.com/FSM1/cipher-box/commit/1fb8996a25947a0964b286ac44864f3e5e84e33c))
* read-chain navigation, grants, and rotation engine in sdk-core ([#579](https://github.com/FSM1/cipher-box/issues/579)) ([7216797](https://github.com/FSM1/cipher-box/commit/7216797ed2d0fe83a214335de45b611efd3ec679))
* rewrite TEE republish as a verify-in-enclave lease renewer ([#585](https://github.com/FSM1/cipher-box/issues/585)) ([ab209a9](https://github.com/FSM1/cipher-box/commit/ab209a9251752e1c317b9534c0c32fb465defd62))
* rotation soundness — content-key, inner-grant, concurrent-add, crash-safe resume ([#582](https://github.com/FSM1/cipher-box/issues/582)) ([4ad615a](https://github.com/FSM1/cipher-box/commit/4ad615aef3a9b89cf07ca6926def961fef34e2b8))
* rotation write-plane and re-mint durability with recipient-pubkey pinning ([#615](https://github.com/FSM1/cipher-box/issues/615)) ([27c4abe](https://github.com/FSM1/cipher-box/commit/27c4abec52ed7cdf0ce9d7147685b2bae97e16b5))
* SDK write-chain, write-revocation, bin re-link, and invite claim ([#583](https://github.com/FSM1/cipher-box/issues/583)) ([d81c1b4](https://github.com/FSM1/cipher-box/commit/d81c1b476805f7b6764e388604e3da657f7540f1))
* SDK-owned read chain and resolved folder listings ([#589](https://github.com/FSM1/cipher-box/issues/589)) ([6534c64](https://github.com/FSM1/cipher-box/commit/6534c642aacfd4755967ccbd622840610635b86c))
* unified Node codec and two-key vault v3 blob in core ([#578](https://github.com/FSM1/cipher-box/issues/578)) ([b2dba55](https://github.com/FSM1/cipher-box/commit/b2dba554a75cb975ab72d9e2777b7b2dde9a06bf))
* web rotation UX and durable anti-rollback client state ([#587](https://github.com/FSM1/cipher-box/issues/587)) ([1b4f68b](https://github.com/FSM1/cipher-box/commit/1b4f68b588f0bb51bec2267f6e742ccaa3b76426))


### Bug Fixes

* close rust and fuse scope-exit read-revocation bypasses ([#607](https://github.com/FSM1/cipher-box/issues/607)) ([2917c85](https://github.com/FSM1/cipher-box/commit/2917c853937ddc20e67a4149f9fc4d868f130c68))
* complete web kind discrimination and revive deferred test suites ([#611](https://github.com/FSM1/cipher-box/issues/611)) ([fcf1596](https://github.com/FSM1/cipher-box/commit/fcf1596a736cd0d2bd75f0dd6f9ac13a224906fa))
* cross-language IPNS and node-codec verification parity ([#608](https://github.com/FSM1/cipher-box/issues/608)) ([77e52cb](https://github.com/FSM1/cipher-box/commit/77e52cb8dc65788f7df7cd1ffbe9cf7384ac3e21))
* harden rotation read-plane durability and deep crash-resume soundness ([#598](https://github.com/FSM1/cipher-box/issues/598)) ([d5486e5](https://github.com/FSM1/cipher-box/commit/d5486e586ab0d30113ca167819d6e053bb2ec3a3))
* harden rotation soundness under concurrency and crash-resume ([#596](https://github.com/FSM1/cipher-box/issues/596)) ([faa781e](https://github.com/FSM1/cipher-box/commit/faa781e4164697b17cc7765624985dcb9a38f761))
* harden SDK write-plane durability and correctness ([#602](https://github.com/FSM1/cipher-box/issues/602)) ([c21f896](https://github.com/FSM1/cipher-box/commit/c21f896b6839b5791ff0c8bd4c5985afef8c6a48))
* shared-folder write and navigation correctness on web ([#603](https://github.com/FSM1/cipher-box/issues/603)) ([bd8c1e0](https://github.com/FSM1/cipher-box/commit/bd8c1e0be4001b6542a2ba9e3f3788a20ff12466))

## [0.39.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-core-v0.38.0...@cipherbox/sdk-core-v0.39.0) (2026-06-25)


### Features

* strict fail-closed IPNS verification cutover across Rust, TS, and API ([#555](https://github.com/FSM1/cipher-box/issues/555)) ([03209e3](https://github.com/FSM1/cipher-box/commit/03209e3854e1309cde13c087a3f407568b17fcd7))

## [0.38.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-core-v0.37.1...@cipherbox/sdk-core-v0.38.0) (2026-06-22)


### Bug Fixes

* FUSE and IPNS write-path durability hardening ([#543](https://github.com/FSM1/cipher-box/issues/543)) ([5d5daaa](https://github.com/FSM1/cipher-box/commit/5d5daaaf69aeb030ae9aa828ac4245525e0215fd))
* IPNS signed-record verify coverage chokepoint and non-CAS sequence gate ([#544](https://github.com/FSM1/cipher-box/issues/544)) ([cd173c9](https://github.com/FSM1/cipher-box/commit/cd173c9c20c50d29ea211f00efa84291d7a3178f))

## [0.37.1](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-core-v0.37.0...@cipherbox/sdk-core-v0.37.1) (2026-06-17)


### Bug Fixes

* re-encrypt file metadata on move and bin restore ([#507](https://github.com/FSM1/cipher-box/issues/507)) ([2c639de](https://github.com/FSM1/cipher-box/commit/2c639de8a4acec923fe5396f8fc5a6255c59978d))

## [0.37.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-core-v0.36.2...@cipherbox/sdk-core-v0.37.0) (2026-06-15)


### Features

* **sdk-core:** handle IPNS write conflicts via 409 merge and file CAS publish ([#488](https://github.com/FSM1/cipher-box/issues/488)) ([1abceb4](https://github.com/FSM1/cipher-box/commit/1abceb4b88a6245509db44794e56f687695d2b30))


### Bug Fixes

* **test:** align edit-filepointer helper with updateFileMetadata internal-publish contract ([#495](https://github.com/FSM1/cipher-box/issues/495)) ([0c2422c](https://github.com/FSM1/cipher-box/commit/0c2422c8c0deda7d13317eaef22c11332a5ff091))

## [0.36.2](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-core-v0.36.1...@cipherbox/sdk-core-v0.36.2) (2026-06-10)


### Bug Fixes

* bind pinning provider fetch fallback to globalThis for browser compatibility ([#477](https://github.com/FSM1/cipher-box/issues/477)) ([39dd78e](https://github.com/FSM1/cipher-box/commit/39dd78ec578e5bf991d8102db66e895b7a835e5e))

## [0.36.1](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-core-v0.36.0...@cipherbox/sdk-core-v0.36.1) (2026-05-26)


### Bug Fixes

* **desktop:** resolve folder rename permission errors and sync duplicates ([#466](https://github.com/FSM1/cipher-box/issues/466)) ([1f84eec](https://github.com/FSM1/cipher-box/commit/1f84eec428be6a81068381e1488b0598317d49ae))

## [0.36.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-core-v0.35.0...@cipherbox/sdk-core-v0.36.0) (2026-04-14)


### Bug Fixes

* **desktop:** detect remote file edits and re-resolve IPNS in FUSE mount ([#454](https://github.com/FSM1/cipher-box/issues/454)) ([09e6830](https://github.com/FSM1/cipher-box/commit/09e6830b87de176b3613c700f78b2f1cd3b517f9))

## [0.35.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-core-v0.34.0...@cipherbox/sdk-core-v0.35.0) (2026-04-06)


### Features

* IPNS signature storage and verification ([#448](https://github.com/FSM1/cipher-box/issues/448)) ([9b80833](https://github.com/FSM1/cipher-box/commit/9b80833ffd7d2dbe0c4cef5b24825b611cd97879))


### Bug Fixes

* **desktop:** align file upload IPNS sequence and verify file pointers ([#446](https://github.com/FSM1/cipher-box/issues/446)) ([741f226](https://github.com/FSM1/cipher-box/commit/741f22670f9c192a2d3168748241ad851bf32561))

## [0.34.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-core-v0.33.0...@cipherbox/sdk-core-v0.34.0) (2026-03-31)


### Features

* **web:** user-configurable vault parameters ([#423](https://github.com/FSM1/cipher-box/issues/423)) ([fa7b443](https://github.com/FSM1/cipher-box/commit/fa7b44399f9c688783b995a2a716b6525eabeefe))

## [0.33.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-core-v0.32.0...@cipherbox/sdk-core-v0.33.0) (2026-03-30)


### Features

* parallel batch upload pipeline with Web Worker encryption ([#416](https://github.com/FSM1/cipher-box/issues/416)) ([ee918ac](https://github.com/FSM1/cipher-box/commit/ee918accc1bd82339eca87d973c13ab2e0556f37))

## [0.32.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-core-v0.31.0...@cipherbox/sdk-core-v0.32.0) (2026-03-30)


### Features

* **sdk:** select AES-CTR encryption for streaming media uploads ([#399](https://github.com/FSM1/cipher-box/issues/399)) ([a595e4b](https://github.com/FSM1/cipher-box/commit/a595e4b53eb5c33fd68e50eb97cee1b647f595fc))
* **tee-worker:** migrate TEE worker to Phala Cloud CVM ([#395](https://github.com/FSM1/cipher-box/issues/395)) ([a08414f](https://github.com/FSM1/cipher-box/commit/a08414fe7674b80d80b64c8dc671f5dca8143fba))

## [0.31.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-core-v0.30.0...@cipherbox/sdk-core-v0.31.0) (2026-03-27)


### Features

* **phase-27:** writable shares ([#372](https://github.com/FSM1/cipher-box/issues/372)) ([65721b4](https://github.com/FSM1/cipher-box/commit/65721b47f7791d908efb78323b27ee8487e9d3a5))

## [0.30.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-core-v0.29.0...@cipherbox/sdk-core-v0.30.0) (2026-03-26)


### Features

* **phase-24:** bug fixes & test infrastructure ([#361](https://github.com/FSM1/cipher-box/issues/361)) ([2f1f93b](https://github.com/FSM1/cipher-box/commit/2f1f93ba7e7a9411e3a73b31e91992c95efd7bfa))
* **phase-26:** observability alerting & UX timeout tuning ([#366](https://github.com/FSM1/cipher-box/issues/366)) ([0bd7001](https://github.com/FSM1/cipher-box/commit/0bd70019c277f1f3544643a7763808bae0a720c5))
* **sdk-core:** extract vault key blob publish/load into SDK ([#368](https://github.com/FSM1/cipher-box/issues/368)) ([6d66be6](https://github.com/FSM1/cipher-box/commit/6d66be6843e6d5685c4bf740eea150e855fc2df0))

## [0.29.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-core-v0.28.0...@cipherbox/sdk-core-v0.29.0) (2026-03-25)

### Features

- Phase 21 BYO-IPFS Node ([#346](https://github.com/FSM1/cipher-box/issues/346)) ([d2ef0c5](https://github.com/FSM1/cipher-box/commit/d2ef0c53bc9b614a47a63d019acc7b792b855ea0))
- phase 22 — performance baselines completion ([#355](https://github.com/FSM1/cipher-box/issues/355)) ([25bc1b3](https://github.com/FSM1/cipher-box/commit/25bc1b35fb69cb28c350a155b5b7b42104f4f5d0))

## [0.28.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-core-v0.27.0...@cipherbox/sdk-core-v0.28.0) (2026-03-25)

### Features

- extract Rust SDK as five workspace crates ([#352](https://github.com/FSM1/cipher-box/issues/352)) ([34bce7b](https://github.com/FSM1/cipher-box/commit/34bce7bfd40170f0fb080f68f50a0e8cb37704cf))

## [0.27.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-core-v0.26.0...@cipherbox/sdk-core-v0.27.0) (2026-03-24)

### Features

- vault blob v2 migration — zero-knowledge server ([#344](https://github.com/FSM1/cipher-box/issues/344)) ([6aa4114](https://github.com/FSM1/cipher-box/commit/6aa4114bd57a339d28c2e95be0d544e62aef11c2))

### Bug Fixes

- separate vault key blob from root folder IPNS name ([#349](https://github.com/FSM1/cipher-box/issues/349)) ([f04ba16](https://github.com/FSM1/cipher-box/commit/f04ba16ea099b16d13cc3c846e979ee461bd966d))

## [0.26.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-core-v0.25.0...@cipherbox/sdk-core-v0.26.0) (2026-03-22)

### Features

- **test:** add SDK-driven E2E and load test suites ([#318](https://github.com/FSM1/cipher-box/issues/318)) ([02ef044](https://github.com/FSM1/cipher-box/commit/02ef044ac1266064983c1122f6acefc601ec9865))

## [0.25.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-core-v0.24.2...@cipherbox/sdk-core-v0.25.0) (2026-03-21)

### Features

- extract core crypto SDK as shared packages ([#296](https://github.com/FSM1/cipher-box/issues/296)) ([2cdc3fb](https://github.com/FSM1/cipher-box/commit/2cdc3fb3675d9c092e8ec9e5493982cc67f21822))
