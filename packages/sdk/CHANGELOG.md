# Changelog

## [0.35.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.34.0...@cipherbox/sdk-v0.35.0) (2026-06-16)


### Features

* consolidate SDK shared-folder ownership and encrypt share itemName at rest ([#500](https://github.com/FSM1/cipher-box/issues/500)) ([383e856](https://github.com/FSM1/cipher-box/commit/383e856cbfba6a23b60cc116e0b5163c92e6be97))
* **sdk:** self-bootstrap folder tree from root IPNS key ([#498](https://github.com/FSM1/cipher-box/issues/498)) ([2657740](https://github.com/FSM1/cipher-box/commit/2657740f144203a095f43e8692794fcd71c9e283))

## [0.34.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.33.0...@cipherbox/sdk-v0.34.0) (2026-06-15)


### Features

* **sdk-core:** handle IPNS write conflicts via 409 merge and file CAS publish ([#488](https://github.com/FSM1/cipher-box/issues/488)) ([1abceb4](https://github.com/FSM1/cipher-box/commit/1abceb4b88a6245509db44794e56f687695d2b30))


### Bug Fixes

* **web:** reconcile SDK folderTree sequence to stop deleted-file resurrection ([#489](https://github.com/FSM1/cipher-box/issues/489)) ([e7ea982](https://github.com/FSM1/cipher-box/commit/e7ea98235b25cdfabb6b6341d34dc79f93d58517))

## [0.33.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.32.0...@cipherbox/sdk-v0.33.0) (2026-03-30)


### Features

* parallel batch upload pipeline with Web Worker encryption ([#416](https://github.com/FSM1/cipher-box/issues/416)) ([ee918ac](https://github.com/FSM1/cipher-box/commit/ee918accc1bd82339eca87d973c13ab2e0556f37))

## [0.32.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.31.0...@cipherbox/sdk-v0.32.0) (2026-03-30)


### Features

* Phase 28 Code Hygiene & Logging ([#382](https://github.com/FSM1/cipher-box/issues/382)) ([9827f49](https://github.com/FSM1/cipher-box/commit/9827f49df59a8730ef0b4ea7bf74caa59b36b055))
* Phase 29 Infrastructure Hardening ([#383](https://github.com/FSM1/cipher-box/issues/383)) ([a209337](https://github.com/FSM1/cipher-box/commit/a2093370c4bd7203a18ba028c7506387b192cd32))
* **sdk:** select AES-CTR encryption for streaming media uploads ([#399](https://github.com/FSM1/cipher-box/issues/399)) ([a595e4b](https://github.com/FSM1/cipher-box/commit/a595e4b53eb5c33fd68e50eb97cee1b647f595fc))

## [0.31.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.30.0...@cipherbox/sdk-v0.31.0) (2026-03-27)


### Features

* **phase-27:** writable shares ([#372](https://github.com/FSM1/cipher-box/issues/372)) ([65721b4](https://github.com/FSM1/cipher-box/commit/65721b47f7791d908efb78323b27ee8487e9d3a5))

## [0.30.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/sdk-v0.29.0...@cipherbox/sdk-v0.30.0) (2026-03-26)


### Features

* **phase-24:** bug fixes & test infrastructure ([#361](https://github.com/FSM1/cipher-box/issues/361)) ([2f1f93b](https://github.com/FSM1/cipher-box/commit/2f1f93ba7e7a9411e3a73b31e91992c95efd7bfa))

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
