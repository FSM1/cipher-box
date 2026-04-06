# Changelog

## [0.31.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/crypto-v0.30.0...@cipherbox/crypto-v0.31.0) (2026-04-06)


### Features

* IPNS signature storage and verification ([#448](https://github.com/FSM1/cipher-box/issues/448)) ([9b80833](https://github.com/FSM1/cipher-box/commit/9b80833ffd7d2dbe0c4cef5b24825b611cd97879))

## [0.30.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/crypto-v0.29.0...@cipherbox/crypto-v0.30.0) (2026-03-31)


### Features

* **web:** user-configurable vault parameters ([#423](https://github.com/FSM1/cipher-box/issues/423)) ([fa7b443](https://github.com/FSM1/cipher-box/commit/fa7b44399f9c688783b995a2a716b6525eabeefe))

## [0.29.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/crypto-v0.28.0...@cipherbox/crypto-v0.29.0) (2026-03-26)


### Features

* **phase-24:** bug fixes & test infrastructure ([#361](https://github.com/FSM1/cipher-box/issues/361)) ([2f1f93b](https://github.com/FSM1/cipher-box/commit/2f1f93ba7e7a9411e3a73b31e91992c95efd7bfa))

## [0.28.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/crypto-v0.27.0...@cipherbox/crypto-v0.28.0) (2026-03-25)

### Features

- Phase 21 BYO-IPFS Node ([#346](https://github.com/FSM1/cipher-box/issues/346)) ([d2ef0c5](https://github.com/FSM1/cipher-box/commit/d2ef0c53bc9b614a47a63d019acc7b792b855ea0))
- phase 22 — performance baselines completion ([#355](https://github.com/FSM1/cipher-box/issues/355)) ([25bc1b3](https://github.com/FSM1/cipher-box/commit/25bc1b35fb69cb28c350a155b5b7b42104f4f5d0))

## [0.27.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/crypto-v0.26.1...@cipherbox/crypto-v0.27.0) (2026-03-25)

### Features

- extract Rust SDK as five workspace crates ([#352](https://github.com/FSM1/cipher-box/issues/352)) ([34bce7b](https://github.com/FSM1/cipher-box/commit/34bce7bfd40170f0fb080f68f50a0e8cb37704cf))

## [0.26.1](https://github.com/FSM1/cipher-box/compare/@cipherbox/crypto-v0.26.0...@cipherbox/crypto-v0.26.1) (2026-03-24)

### Bug Fixes

- separate vault key blob from root folder IPNS name ([#349](https://github.com/FSM1/cipher-box/issues/349)) ([f04ba16](https://github.com/FSM1/cipher-box/commit/f04ba16ea099b16d13cc3c846e979ee461bd966d))

## [0.26.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/crypto-v0.25.1...@cipherbox/crypto-v0.26.0) (2026-03-23)

### Features

- **05:** Folder System - IPNS metadata, folder hierarchy, and operations ([#39](https://github.com/FSM1/cipher-box/issues/39)) ([8793004](https://github.com/FSM1/cipher-box/commit/8793004985c02dd2495a5b7dedb6570b8883eaaa))
- **12.1:** AES-CTR streaming encryption for media files ([#135](https://github.com/FSM1/cipher-box/issues/135)) ([433ae35](https://github.com/FSM1/cipher-box/commit/433ae3550959e7dd75085f5b392091098d4a8a58))
- **12.2:** Encrypted Device Registry ([#125](https://github.com/FSM1/cipher-box/issues/125)) ([f3e354e](https://github.com/FSM1/cipher-box/commit/f3e354ea14e1341b159438848f10072828ee38d3))
- **12.3.1:** Pre-wipe identity cleanup ([#127](https://github.com/FSM1/cipher-box/issues/127)) ([6806153](https://github.com/FSM1/cipher-box/commit/6806153251e0b86b2da2901d75cb73e20b3c94f3))
- **12.6:** per-file IPNS metadata split ([#133](https://github.com/FSM1/cipher-box/issues/133)) ([dee300a](https://github.com/FSM1/cipher-box/commit/dee300aa3fb68f54225fa6d573e915423fbe5a8c))
- **14:** user-to-user encrypted sharing ([#183](https://github.com/FSM1/cipher-box/issues/183)) ([84a232d](https://github.com/FSM1/cipher-box/commit/84a232db4faf6fbfb3a354cdf847e75583073851))
- add external file drag-and-drop from Finder/Explorer ([#78](https://github.com/FSM1/cipher-box/issues/78)) ([a776885](https://github.com/FSM1/cipher-box/commit/a77688557edc3e555d2c9402cd16133d63a8711a))
- extract core crypto SDK as shared packages ([#296](https://github.com/FSM1/cipher-box/issues/296)) ([2cdc3fb](https://github.com/FSM1/cipher-box/commit/2cdc3fb3675d9c092e8ec9e5493982cc67f21822))
- Phase 13 — File Versioning ([#161](https://github.com/FSM1/cipher-box/issues/161)) ([60a2dc7](https://github.com/FSM1/cipher-box/commit/60a2dc7ec12780c4c9f5e57d5116f440dd55e2d1))
- Phase 17 — Recycle Bin ([#262](https://github.com/FSM1/cipher-box/issues/262)) ([c0af622](https://github.com/FSM1/cipher-box/commit/c0af6225a7bf8b49ae4ab04804eed6b6484fd3bf))
- Phase 9.1 — Environment, DevOps & Staging Deployment ([#64](https://github.com/FSM1/cipher-box/issues/64)) ([73b5aac](https://github.com/FSM1/cipher-box/commit/73b5aacc33040b9aeed13b9dbce440021a899285))
- remove v1 folder metadata, make v2 FilePointer canonical ([#150](https://github.com/FSM1/cipher-box/issues/150)) ([30d982c](https://github.com/FSM1/cipher-box/commit/30d982ce6da0c128205ce08e0806b7db03fc65e4))
- switch file IPNS keys from deterministic HKDF to random ([#181](https://github.com/FSM1/cipher-box/issues/181)) ([7f01f98](https://github.com/FSM1/cipher-box/commit/7f01f9823e4f0f1bef180f5da7a927c97592c6e9))

### Bug Fixes

- **17.1:** close bin integration gaps - CID unpinning + Windows bin ([#268](https://github.com/FSM1/cipher-box/issues/268)) ([15a7ece](https://github.com/FSM1/cipher-box/commit/15a7ece0892fad0b9bb7447a8487d548449e4dd4))
- **api,crypto:** address 6 security review findings ([#172](https://github.com/FSM1/cipher-box/issues/172)) ([d222bd0](https://github.com/FSM1/cipher-box/commit/d222bd0b323d582575d0ec6e0639bf96893d8d5b))
- **api,crypto:** address 6 security review findings (H-01, H-06, H-07, M-01, M-04, M-06) ([d222bd0](https://github.com/FSM1/cipher-box/commit/d222bd0b323d582575d0ec6e0639bf96893d8d5b))
- **crypto:** correct DeviceEntry publicKey validator from 130 to 64 hex chars ([f5be3cb](https://github.com/FSM1/cipher-box/commit/f5be3cb54889626ef36073d99d263f567679bef3))
- **crypto:** correct DeviceEntry publicKey validator length ([#178](https://github.com/FSM1/cipher-box/issues/178)) ([f5be3cb](https://github.com/FSM1/cipher-box/commit/f5be3cb54889626ef36073d99d263f567679bef3))
