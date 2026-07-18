# Changelog

## [0.38.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.37.2...@cipherbox/sdk-v0.38.0) (2026-07-18)


### Features

* enforce share-invite authorization and IPNS data-integrity in the API ([#599](https://github.com/FSM1/cipher-box/issues/599)) ([703bc00](https://github.com/FSM1/cipher-box/commit/703bc0083d42547cd2c0e747d79be82a0c318e78))
* integrate web client with node/v3 read and write runtime ([#588](https://github.com/FSM1/cipher-box/issues/588)) ([1fb8996](https://github.com/FSM1/cipher-box/commit/1fb8996a25947a0964b286ac44864f3e5e84e33c))
* read-chain navigation, grants, and rotation engine in sdk-core ([#579](https://github.com/FSM1/cipher-box/issues/579)) ([7216797](https://github.com/FSM1/cipher-box/commit/7216797ed2d0fe83a214335de45b611efd3ec679))
* recovery tool v3, vault-load guards, web UX and CI boundary guards ([#613](https://github.com/FSM1/cipher-box/issues/613)) ([cba7857](https://github.com/FSM1/cipher-box/commit/cba7857187d8aa6f92b02a0d4d88269f71f770ec))
* rotation soundness — content-key, inner-grant, concurrent-add, crash-safe resume ([#582](https://github.com/FSM1/cipher-box/issues/582)) ([4ad615a](https://github.com/FSM1/cipher-box/commit/4ad615aef3a9b89cf07ca6926def961fef34e2b8))
* rotation write-plane and re-mint durability with recipient-pubkey pinning ([#615](https://github.com/FSM1/cipher-box/issues/615)) ([27c4abe](https://github.com/FSM1/cipher-box/commit/27c4abec52ed7cdf0ce9d7147685b2bae97e16b5))
* SDK write-chain, write-revocation, bin re-link, and invite claim ([#583](https://github.com/FSM1/cipher-box/issues/583)) ([d81c1b4](https://github.com/FSM1/cipher-box/commit/d81c1b476805f7b6764e388604e3da657f7540f1))
* SDK-owned read chain and resolved folder listings ([#589](https://github.com/FSM1/cipher-box/issues/589)) ([6534c64](https://github.com/FSM1/cipher-box/commit/6534c642aacfd4755967ccbd622840610635b86c))
* unified Node codec and two-key vault v3 blob in core ([#578](https://github.com/FSM1/cipher-box/issues/578)) ([b2dba55](https://github.com/FSM1/cipher-box/commit/b2dba554a75cb975ab72d9e2777b7b2dde9a06bf))
* web rotation UX and durable anti-rollback client state ([#587](https://github.com/FSM1/cipher-box/issues/587)) ([1b4f68b](https://github.com/FSM1/cipher-box/commit/1b4f68b588f0bb51bec2267f6e742ccaa3b76426))


### Bug Fixes

* close rust and fuse scope-exit read-revocation bypasses ([#607](https://github.com/FSM1/cipher-box/issues/607)) ([2917c85](https://github.com/FSM1/cipher-box/commit/2917c853937ddc20e67a4149f9fc4d868f130c68))
* complete web kind discrimination and revive deferred test suites ([#611](https://github.com/FSM1/cipher-box/issues/611)) ([fcf1596](https://github.com/FSM1/cipher-box/commit/fcf1596a736cd0d2bd75f0dd6f9ac13a224906fa))
* harden rotation read-plane durability and deep crash-resume soundness ([#598](https://github.com/FSM1/cipher-box/issues/598)) ([d5486e5](https://github.com/FSM1/cipher-box/commit/d5486e586ab0d30113ca167819d6e053bb2ec3a3))
* harden rotation soundness under concurrency and crash-resume ([#596](https://github.com/FSM1/cipher-box/issues/596)) ([faa781e](https://github.com/FSM1/cipher-box/commit/faa781e4164697b17cc7765624985dcb9a38f761))
* harden SDK write-plane durability and correctness ([#602](https://github.com/FSM1/cipher-box/issues/602)) ([c21f896](https://github.com/FSM1/cipher-box/commit/c21f896b6839b5791ff0c8bd4c5985afef8c6a48))
* shared-folder write and navigation correctness on web ([#603](https://github.com/FSM1/cipher-box/issues/603)) ([bd8c1e0](https://github.com/FSM1/cipher-box/commit/bd8c1e0be4001b6542a2ba9e3f3788a20ff12466))

## [0.37.2](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.37.1...@cipherbox/sdk-v0.37.2) (2026-06-26)


### Bug Fixes

* **bin:** unpin deleted content and revoke its shares ([#563](https://github.com/FSM1/cipher-box/issues/563)) ([1699522](https://github.com/FSM1/cipher-box/commit/16995221c79421d086aeee0b58fb7af3c7198fa9))

## [0.37.1](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.37.0...@cipherbox/sdk-v0.37.1) (2026-06-21)


### Bug Fixes

* IPFS/IPNS data-integrity fixes for unpin and folder unenroll ([#527](https://github.com/FSM1/cipher-box/issues/527)) ([b7acb57](https://github.com/FSM1/cipher-box/commit/b7acb570ced77f43f35eecd65a7f9f15fdd29afc))

## [0.37.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.36.0...@cipherbox/sdk-v0.37.0) (2026-06-18)


### Features

* **web:** shared-folder intra-share move and useFolderNavigation consolidation ([#509](https://github.com/FSM1/cipher-box/issues/509)) ([c36ac6d](https://github.com/FSM1/cipher-box/commit/c36ac6d7792947a734a539a23de6b42d5c1fdd98))

## [0.36.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.35.0...@cipherbox/sdk-v0.36.0) (2026-06-17)

### Bug Fixes

- re-encrypt file metadata on move and bin restore ([#507](https://github.com/FSM1/cipher-box/issues/507)) ([2c639de](https://github.com/FSM1/cipher-box/commit/2c639de8a4acec923fe5396f8fc5a6255c59978d))

## [0.35.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.34.0...@cipherbox/sdk-v0.35.0) (2026-06-16)

### Features

- consolidate SDK shared-folder ownership and encrypt share itemName at rest ([#500](https://github.com/FSM1/cipher-box/issues/500)) ([383e856](https://github.com/FSM1/cipher-box/commit/383e856cbfba6a23b60cc116e0b5163c92e6be97))
- **sdk:** self-bootstrap folder tree from root IPNS key ([#498](https://github.com/FSM1/cipher-box/issues/498)) ([2657740](https://github.com/FSM1/cipher-box/commit/2657740f144203a095f43e8692794fcd71c9e283))

## [0.34.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.33.0...@cipherbox/sdk-v0.34.0) (2026-06-15)

### Features

- **sdk-core:** handle IPNS write conflicts via 409 merge and file CAS publish ([#488](https://github.com/FSM1/cipher-box/issues/488)) ([1abceb4](https://github.com/FSM1/cipher-box/commit/1abceb4b88a6245509db44794e56f687695d2b30))

### Bug Fixes

- **web:** reconcile SDK folderTree sequence to stop deleted-file resurrection ([#489](https://github.com/FSM1/cipher-box/issues/489)) ([e7ea982](https://github.com/FSM1/cipher-box/commit/e7ea98235b25cdfabb6b6341d34dc79f93d58517))

## [0.33.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.32.0...@cipherbox/sdk-v0.33.0) (2026-03-30)

### Features

- parallel batch upload pipeline with Web Worker encryption ([#416](https://github.com/FSM1/cipher-box/issues/416)) ([ee918ac](https://github.com/FSM1/cipher-box/commit/ee918accc1bd82339eca87d973c13ab2e0556f37))

## [0.32.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.31.0...@cipherbox/sdk-v0.32.0) (2026-03-30)

### Features

- Phase 28 Code Hygiene & Logging ([#382](https://github.com/FSM1/cipher-box/issues/382)) ([9827f49](https://github.com/FSM1/cipher-box/commit/9827f49df59a8730ef0b4ea7bf74caa59b36b055))
- Phase 29 Infrastructure Hardening ([#383](https://github.com/FSM1/cipher-box/issues/383)) ([a209337](https://github.com/FSM1/cipher-box/commit/a2093370c4bd7203a18ba028c7506387b192cd32))
- **sdk:** select AES-CTR encryption for streaming media uploads ([#399](https://github.com/FSM1/cipher-box/issues/399)) ([a595e4b](https://github.com/FSM1/cipher-box/commit/a595e4b53eb5c33fd68e50eb97cee1b647f595fc))

## [0.31.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.30.0...@cipherbox/sdk-v0.31.0) (2026-03-27)

### Features

- **phase-27:** writable shares ([#372](https://github.com/FSM1/cipher-box/issues/372)) ([65721b4](https://github.com/FSM1/cipher-box/commit/65721b47f7791d908efb78323b27ee8487e9d3a5))

## [0.30.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.29.0...@cipherbox/sdk-v0.30.0) (2026-03-26)

### Features

- **phase-24:** bug fixes & test infrastructure ([#361](https://github.com/FSM1/cipher-box/issues/361)) ([2f1f93b](https://github.com/FSM1/cipher-box/commit/2f1f93ba7e7a9411e3a73b31e91992c95efd7bfa))

## [0.29.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.28.0...@cipherbox/sdk-v0.29.0) (2026-03-25)

### Features

- Phase 21 BYO-IPFS Node ([#346](https://github.com/FSM1/cipher-box/issues/346)) ([d2ef0c5](https://github.com/FSM1/cipher-box/commit/d2ef0c53bc9b614a47a63d019acc7b792b855ea0))
- phase 22 — performance baselines completion ([#355](https://github.com/FSM1/cipher-box/issues/355)) ([25bc1b3](https://github.com/FSM1/cipher-box/commit/25bc1b35fb69cb28c350a155b5b7b42104f4f5d0))

## [0.28.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.27.0...@cipherbox/sdk-v0.28.0) (2026-03-25)

### Features

- extract Rust SDK as five workspace crates ([#352](https://github.com/FSM1/cipher-box/issues/352)) ([34bce7b](https://github.com/FSM1/cipher-box/commit/34bce7bfd40170f0fb080f68f50a0e8cb37704cf))

## [0.27.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.26.1...@cipherbox/sdk-v0.27.0) (2026-03-24)

### Features

- vault blob v2 migration — zero-knowledge server ([#344](https://github.com/FSM1/cipher-box/issues/344)) ([6aa4114](https://github.com/FSM1/cipher-box/commit/6aa4114bd57a339d28c2e95be0d544e62aef11c2))

## [0.26.1](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.26.0...@cipherbox/sdk-v0.26.1) (2026-03-24)

### Performance Improvements

- optimize IPFS upload with concurrent pins and pebbleds datastore ([#342](https://github.com/FSM1/cipher-box/issues/342)) ([8f8f03f](https://github.com/FSM1/cipher-box/commit/8f8f03fa64c5aba91e8dc72c5b8dc67fd0b629d5))

## [0.26.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.25.0...@cipherbox/sdk-v0.26.0) (2026-03-22)

### Features

- **test:** add SDK-driven E2E and load test suites ([#318](https://github.com/FSM1/cipher-box/issues/318)) ([02ef044](https://github.com/FSM1/cipher-box/commit/02ef044ac1266064983c1122f6acefc601ec9865))

## [0.25.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.24.2...@cipherbox/sdk-v0.25.0) (2026-03-21)

### Features

- extract core crypto SDK as shared packages ([#296](https://github.com/FSM1/cipher-box/issues/296)) ([2cdc3fb](https://github.com/FSM1/cipher-box/commit/2cdc3fb3675d9c092e8ec9e5493982cc67f21822))
