# Changelog

## [0.45.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-client-v0.44.0...@cipherbox/api-client-v0.45.0) (2026-07-18)


### Features

* atomic IPNS publish-gate, tombstone, and share schema cutover ([#584](https://github.com/FSM1/cipher-box/issues/584)) ([a036a84](https://github.com/FSM1/cipher-box/commit/a036a84d4477937ee4a59e2c70c0673c5142edc8))
* enforce share-invite authorization and IPNS data-integrity in the API ([#599](https://github.com/FSM1/cipher-box/issues/599)) ([703bc00](https://github.com/FSM1/cipher-box/commit/703bc0083d42547cd2c0e747d79be82a0c318e78))
* integrate web client with node/v3 read and write runtime ([#588](https://github.com/FSM1/cipher-box/issues/588)) ([1fb8996](https://github.com/FSM1/cipher-box/commit/1fb8996a25947a0964b286ac44864f3e5e84e33c))
* web rotation UX and durable anti-rollback client state ([#587](https://github.com/FSM1/cipher-box/issues/587)) ([1b4f68b](https://github.com/FSM1/cipher-box/commit/1b4f68b588f0bb51bec2267f6e742ccaa3b76426))


### Bug Fixes

* harden SDK write-plane durability and correctness ([#602](https://github.com/FSM1/cipher-box/issues/602)) ([c21f896](https://github.com/FSM1/cipher-box/commit/c21f896b6839b5791ff0c8bd4c5985afef8c6a48))

## [0.44.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-client-v0.43.0...@cipherbox/api-client-v0.44.0) (2026-06-26)


### Bug Fixes

* **bin:** unpin deleted content and revoke its shares ([#563](https://github.com/FSM1/cipher-box/issues/563)) ([1699522](https://github.com/FSM1/cipher-box/commit/16995221c79421d086aeee0b58fb7af3c7198fa9))

## [0.43.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-client-v0.42.0...@cipherbox/api-client-v0.43.0) (2026-06-22)


### Features

* **api:** API CID and provider hardening with unpin module dedup ([#541](https://github.com/FSM1/cipher-box/issues/541)) ([106ee88](https://github.com/FSM1/cipher-box/commit/106ee8816339385c46f4352402c8a1acecb366bb))

## [0.42.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-client-v0.41.0...@cipherbox/api-client-v0.42.0) (2026-06-21)


### Bug Fixes

* IPFS/IPNS data-integrity fixes for unpin and folder unenroll ([#527](https://github.com/FSM1/cipher-box/issues/527)) ([b7acb57](https://github.com/FSM1/cipher-box/commit/b7acb570ced77f43f35eecd65a7f9f15fdd29afc))

## [0.41.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-client-v0.40.0...@cipherbox/api-client-v0.41.0) (2026-06-18)


### Features

* **web:** shared-folder intra-share move and useFolderNavigation consolidation ([#509](https://github.com/FSM1/cipher-box/issues/509)) ([c36ac6d](https://github.com/FSM1/cipher-box/commit/c36ac6d7792947a734a539a23de6b42d5c1fdd98))

## [0.40.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-client-v0.39.0...@cipherbox/api-client-v0.40.0) (2026-06-17)


### Features

* **api:** share item-name backfill endpoint ([#505](https://github.com/FSM1/cipher-box/issues/505)) ([63638b5](https://github.com/FSM1/cipher-box/commit/63638b55983f00e91b5c8b4e8f6cf4372ad8b320))

## [0.39.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-client-v0.38.0...@cipherbox/api-client-v0.39.0) (2026-06-16)


### Features

* consolidate SDK shared-folder ownership and encrypt share itemName at rest ([#500](https://github.com/FSM1/cipher-box/issues/500)) ([383e856](https://github.com/FSM1/cipher-box/commit/383e856cbfba6a23b60cc116e0b5163c92e6be97))

## [0.38.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-client-v0.37.0...@cipherbox/api-client-v0.38.0) (2026-04-14)


### Bug Fixes

* **desktop:** detect remote file edits and re-resolve IPNS in FUSE mount ([#454](https://github.com/FSM1/cipher-box/issues/454)) ([09e6830](https://github.com/FSM1/cipher-box/commit/09e6830b87de176b3613c700f78b2f1cd3b517f9))

## [0.37.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-client-v0.36.0...@cipherbox/api-client-v0.37.0) (2026-04-06)


### Features

* IPNS signature storage and verification ([#448](https://github.com/FSM1/cipher-box/issues/448)) ([9b80833](https://github.com/FSM1/cipher-box/commit/9b80833ffd7d2dbe0c4cef5b24825b611cd97879))

## [0.36.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-client-v0.35.0...@cipherbox/api-client-v0.36.0) (2026-04-01)


### Features

* **api:** expose API version on /health endpoint ([#429](https://github.com/FSM1/cipher-box/issues/429)) ([6abf87e](https://github.com/FSM1/cipher-box/commit/6abf87e68fea82bbddaf51f29c07f2091e402e7d))

## [0.33.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-client-v0.32.0...@cipherbox/api-client-v0.33.0) (2026-03-31)


### Features

* **web:** user-configurable vault parameters ([#423](https://github.com/FSM1/cipher-box/issues/423)) ([fa7b443](https://github.com/FSM1/cipher-box/commit/fa7b44399f9c688783b995a2a716b6525eabeefe))

## [0.32.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-client-v0.31.0...@cipherbox/api-client-v0.32.0) (2026-03-30)


### Features

* Phase 29 Infrastructure Hardening ([#383](https://github.com/FSM1/cipher-box/issues/383)) ([a209337](https://github.com/FSM1/cipher-box/commit/a2093370c4bd7203a18ba028c7506387b192cd32))
* Phase 30 Web App Observability ([#386](https://github.com/FSM1/cipher-box/issues/386)) ([c82fbe7](https://github.com/FSM1/cipher-box/commit/c82fbe7c6d37c744b372a665aea69b72046418f5))


### Bug Fixes

* **api:** add BYO status endpoint, fix load test failures, fix test type errors ([#400](https://github.com/FSM1/cipher-box/issues/400)) ([0517397](https://github.com/FSM1/cipher-box/commit/0517397a6735cc6e626ae9f6e5e05725a50075d5))

## [0.31.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-client-v0.30.0...@cipherbox/api-client-v0.31.0) (2026-03-27)


### Features

* **phase-27:** writable shares ([#372](https://github.com/FSM1/cipher-box/issues/372)) ([65721b4](https://github.com/FSM1/cipher-box/commit/65721b47f7791d908efb78323b27ee8487e9d3a5))

## [0.30.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-client-v0.29.0...@cipherbox/api-client-v0.30.0) (2026-03-26)


### Features

* **phase-24:** bug fixes & test infrastructure ([#361](https://github.com/FSM1/cipher-box/issues/361)) ([2f1f93b](https://github.com/FSM1/cipher-box/commit/2f1f93ba7e7a9411e3a73b31e91992c95efd7bfa))

## [0.29.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-client-v0.28.0...@cipherbox/api-client-v0.29.0) (2026-03-25)

### Features

- Phase 21 BYO-IPFS Node ([#346](https://github.com/FSM1/cipher-box/issues/346)) ([d2ef0c5](https://github.com/FSM1/cipher-box/commit/d2ef0c53bc9b614a47a63d019acc7b792b855ea0))
- phase 22 — performance baselines completion ([#355](https://github.com/FSM1/cipher-box/issues/355)) ([25bc1b3](https://github.com/FSM1/cipher-box/commit/25bc1b35fb69cb28c350a155b5b7b42104f4f5d0))

## [0.28.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-client-v0.27.0...@cipherbox/api-client-v0.28.0) (2026-03-25)

### Features

- extract Rust SDK as five workspace crates ([#352](https://github.com/FSM1/cipher-box/issues/352)) ([34bce7b](https://github.com/FSM1/cipher-box/commit/34bce7bfd40170f0fb080f68f50a0e8cb37704cf))

## [0.27.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-client-v0.26.0...@cipherbox/api-client-v0.27.0) (2026-03-24)

### Features

- vault blob v2 migration — zero-knowledge server ([#344](https://github.com/FSM1/cipher-box/issues/344)) ([6aa4114](https://github.com/FSM1/cipher-box/commit/6aa4114bd57a339d28c2e95be0d544e62aef11c2))

## [0.26.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-client-v0.25.0...@cipherbox/api-client-v0.26.0) (2026-03-22)

### Features

- **test:** add SDK-driven E2E and load test suites ([#318](https://github.com/FSM1/cipher-box/issues/318)) ([02ef044](https://github.com/FSM1/cipher-box/commit/02ef044ac1266064983c1122f6acefc601ec9865))

## [0.25.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-client-v0.24.2...@cipherbox/api-client-v0.25.0) (2026-03-21)

### Features

- **05:** Folder System - IPNS metadata, folder hierarchy, and operations ([#39](https://github.com/FSM1/cipher-box/issues/39)) ([8793004](https://github.com/FSM1/cipher-box/commit/8793004985c02dd2495a5b7dedb6570b8883eaaa))
- **12.3.1:** Pre-wipe identity cleanup ([#127](https://github.com/FSM1/cipher-box/issues/127)) ([6806153](https://github.com/FSM1/cipher-box/commit/6806153251e0b86b2da2901d75cb73e20b3c94f3))
- **12.4:** MFA + Cross-Device Approval ([#128](https://github.com/FSM1/cipher-box/issues/128)) ([e9de010](https://github.com/FSM1/cipher-box/commit/e9de010759e22b36efd3ea1bb1604105c34fded1))
- **12.6:** per-file IPNS metadata split ([#133](https://github.com/FSM1/cipher-box/issues/133)) ([dee300a](https://github.com/FSM1/cipher-box/commit/dee300aa3fb68f54225fa6d573e915423fbe5a8c))
- **12:** Core Kit Identity Provider Foundation ([#123](https://github.com/FSM1/cipher-box/issues/123)) ([a07cb26](https://github.com/FSM1/cipher-box/commit/a07cb266a3b92b0e3b4b2544c1f85e6e33c55df4))
- **14:** user-to-user encrypted sharing ([#183](https://github.com/FSM1/cipher-box/issues/183)) ([84a232d](https://github.com/FSM1/cipher-box/commit/84a232db4faf6fbfb3a354cdf847e75583073851))
- add client-side IPNS signature validation ([#88](https://github.com/FSM1/cipher-box/issues/88)) ([8d18b65](https://github.com/FSM1/cipher-box/commit/8d18b6586068f5206d15c472c160656e4f41459e))
- atomic file upload with server-side quota tracking ([#56](https://github.com/FSM1/cipher-box/issues/56)) ([34c0eca](https://github.com/FSM1/cipher-box/commit/34c0eca34f89dd5bc4f5fc64b48e6adc7d5a5aa3))
- extract core crypto SDK as shared packages ([#296](https://github.com/FSM1/cipher-box/issues/296)) ([2cdc3fb](https://github.com/FSM1/cipher-box/commit/2cdc3fb3675d9c092e8ec9e5493982cc67f21822))
- IPNS resolution improvement with Someguy sidecar and latency metrics ([#284](https://github.com/FSM1/cipher-box/issues/284)) ([c1c96de](https://github.com/FSM1/cipher-box/commit/c1c96de3048471a88b30be42669a532f41d56eb3))
- phase 10 data portability ([#95](https://github.com/FSM1/cipher-box/issues/95)) ([787d881](https://github.com/FSM1/cipher-box/commit/787d88166f0d5158577cea2b7e52c35cdacae97d))
- phase 15 link sharing ([#190](https://github.com/FSM1/cipher-box/issues/190)) ([76258cf](https://github.com/FSM1/cipher-box/commit/76258cf3ae063ef068aa7a52aa16582b321b8f12))
- Phase 16 — conflict detection via optimistic concurrency ([#253](https://github.com/FSM1/cipher-box/issues/253)) ([f864e50](https://github.com/FSM1/cipher-box/commit/f864e500aab39aaeea88f6a68f449a0c057005ea))
- Phase 17 — Recycle Bin ([#262](https://github.com/FSM1/cipher-box/issues/262)) ([c0af622](https://github.com/FSM1/cipher-box/commit/c0af6225a7bf8b49ae4ab04804eed6b6484fd3bf))
- Phase 9 — Tauri desktop client with FUSE mount ([#63](https://github.com/FSM1/cipher-box/issues/63)) ([07884ee](https://github.com/FSM1/cipher-box/commit/07884ee1c08ebdb246e4fd7a8ffa342b51ab7a74))
- SIWE wallet login + unified identity (Phase 12.3) ([#126](https://github.com/FSM1/cipher-box/issues/126)) ([40e704b](https://github.com/FSM1/cipher-box/commit/40e704bb807bb0bde21a8715647809441297d096))
- TEE integration for automatic IPNS republishing ([#61](https://github.com/FSM1/cipher-box/issues/61)) ([8f54c59](https://github.com/FSM1/cipher-box/commit/8f54c59b69b3dbaf914d0ba6ae0a3cbdfdc74bc2))
- **web:** GDPR account deletion with IPFS unpin ([#202](https://github.com/FSM1/cipher-box/issues/202)) ([b981d41](https://github.com/FSM1/cipher-box/commit/b981d4127f20c5b240572b6cf43642a00bf8825d))

### Bug Fixes

- **api,web:** MFA REQUIRED_SHARE auth flow + E2E test coverage ([#213](https://github.com/FSM1/cipher-box/issues/213)) ([133a541](https://github.com/FSM1/cipher-box/commit/133a541b792a11a32eeae620a806e39a4d1c39a5))
- **auth:** google OAuth brave fallback, wallet SIWE, sync & UX fixes ([#137](https://github.com/FSM1/cipher-box/issues/137)) ([6e3bbde](https://github.com/FSM1/cipher-box/commit/6e3bbde322d91ae100445a8f94a366eb7841dfe4))
- **security:** harden auth and sharing subsystems ([#267](https://github.com/FSM1/cipher-box/issues/267)) ([4f53611](https://github.com/FSM1/cipher-box/commit/4f536118efa67d48c6d59cc9b40e05121e076dd8))
