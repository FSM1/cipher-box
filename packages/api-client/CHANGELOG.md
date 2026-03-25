# Changelog

## [0.28.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-client-v0.27.0...@cipherbox/api-client-v0.28.0) (2026-03-25)


### Features

* extract Rust SDK as five workspace crates ([#352](https://github.com/FSM1/cipher-box/issues/352)) ([34bce7b](https://github.com/FSM1/cipher-box/commit/34bce7bfd40170f0fb080f68f50a0e8cb37704cf))

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
