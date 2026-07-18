# Changelog

## [0.45.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-v0.44.1...@cipherbox/api-v0.45.0) (2026-07-18)


### Features

* atomic IPNS publish-gate, tombstone, and share schema cutover ([#584](https://github.com/FSM1/cipher-box/issues/584)) ([a036a84](https://github.com/FSM1/cipher-box/commit/a036a84d4477937ee4a59e2c70c0673c5142edc8))
* enforce share-invite authorization and IPNS data-integrity in the API ([#599](https://github.com/FSM1/cipher-box/issues/599)) ([703bc00](https://github.com/FSM1/cipher-box/commit/703bc0083d42547cd2c0e747d79be82a0c318e78))
* integrate web client with node/v3 read and write runtime ([#588](https://github.com/FSM1/cipher-box/issues/588)) ([1fb8996](https://github.com/FSM1/cipher-box/commit/1fb8996a25947a0964b286ac44864f3e5e84e33c))
* rewrite TEE republish as a verify-in-enclave lease renewer ([#585](https://github.com/FSM1/cipher-box/issues/585)) ([ab209a9](https://github.com/FSM1/cipher-box/commit/ab209a9251752e1c317b9534c0c32fb465defd62))
* web rotation UX and durable anti-rollback client state ([#587](https://github.com/FSM1/cipher-box/issues/587)) ([1b4f68b](https://github.com/FSM1/cipher-box/commit/1b4f68b588f0bb51bec2267f6e742ccaa3b76426))


### Bug Fixes

* close rust and fuse scope-exit read-revocation bypasses ([#607](https://github.com/FSM1/cipher-box/issues/607)) ([2917c85](https://github.com/FSM1/cipher-box/commit/2917c853937ddc20e67a4149f9fc4d868f130c68))
* harden FUSE publish and TEE write paths against partial-failure states ([#610](https://github.com/FSM1/cipher-box/issues/610)) ([02efe51](https://github.com/FSM1/cipher-box/commit/02efe51bbc1930b02857b081b41404ae0ed9605c))

## [0.44.1](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-v0.44.0...@cipherbox/api-v0.44.1) (2026-06-26)


### Bug Fixes

* **bin:** unpin deleted content and revoke its shares ([#563](https://github.com/FSM1/cipher-box/issues/563)) ([1699522](https://github.com/FSM1/cipher-box/commit/16995221c79421d086aeee0b58fb7af3c7198fa9))

## [0.44.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-v0.43.0...@cipherbox/api-v0.44.0) (2026-06-25)


### Features

* strict fail-closed IPNS verification cutover across Rust, TS, and API ([#555](https://github.com/FSM1/cipher-box/issues/555)) ([03209e3](https://github.com/FSM1/cipher-box/commit/03209e3854e1309cde13c087a3f407568b17fcd7))

## [0.43.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-v0.42.0...@cipherbox/api-v0.43.0) (2026-06-22)


### Features

* **api:** API CID and provider hardening with unpin module dedup ([#541](https://github.com/FSM1/cipher-box/issues/541)) ([106ee88](https://github.com/FSM1/cipher-box/commit/106ee8816339385c46f4352402c8a1acecb366bb))


### Bug Fixes

* IPNS signed-record verify coverage chokepoint and non-CAS sequence gate ([#544](https://github.com/FSM1/cipher-box/issues/544)) ([cd173c9](https://github.com/FSM1/cipher-box/commit/cd173c9c20c50d29ea211f00efa84291d7a3178f))

## [0.42.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-v0.41.0...@cipherbox/api-v0.42.0) (2026-06-21)


### Bug Fixes

* IPFS/IPNS data-integrity fixes for unpin and folder unenroll ([#527](https://github.com/FSM1/cipher-box/issues/527)) ([b7acb57](https://github.com/FSM1/cipher-box/commit/b7acb570ced77f43f35eecd65a7f9f15fdd29afc))

## [0.41.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-v0.40.0...@cipherbox/api-v0.41.0) (2026-06-18)


### Features

* **web:** shared-folder intra-share move and useFolderNavigation consolidation ([#509](https://github.com/FSM1/cipher-box/issues/509)) ([c36ac6d](https://github.com/FSM1/cipher-box/commit/c36ac6d7792947a734a539a23de6b42d5c1fdd98))

## [0.40.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-v0.39.0...@cipherbox/api-v0.40.0) (2026-06-17)


### Features

* **api:** share item-name backfill endpoint ([#505](https://github.com/FSM1/cipher-box/issues/505)) ([63638b5](https://github.com/FSM1/cipher-box/commit/63638b55983f00e91b5c8b4e8f6cf4372ad8b320))

## [0.39.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-v0.38.0...@cipherbox/api-v0.39.0) (2026-06-16)


### Features

* consolidate SDK shared-folder ownership and encrypt share itemName at rest ([#500](https://github.com/FSM1/cipher-box/issues/500)) ([383e856](https://github.com/FSM1/cipher-box/commit/383e856cbfba6a23b60cc116e0b5163c92e6be97))

## [0.38.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-v0.37.1...@cipherbox/api-v0.38.0) (2026-06-15)


### Features

* **api:** guard unpin with ownership check and reference-counted quota decrement ([#485](https://github.com/FSM1/cipher-box/issues/485)) ([158addc](https://github.com/FSM1/cipher-box/commit/158addccac4f182b2bd7221f1ee80cdece393928))
* **fuse:** durable write journal with crash-recovery replay ([#487](https://github.com/FSM1/cipher-box/issues/487)) ([dcd1bec](https://github.com/FSM1/cipher-box/commit/dcd1becb6f6dad1b8d44d70544b0a6b1248458dc))


### Bug Fixes

* resolve UAT audit findings in BYO pinning and migration flows ([#479](https://github.com/FSM1/cipher-box/issues/479)) ([9f3136a](https://github.com/FSM1/cipher-box/commit/9f3136a9440bb16e31c8073f90c0fee827074da1))

## [0.37.1](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-v0.37.0...@cipherbox/api-v0.37.1) (2026-04-06)


### Bug Fixes

* **api:** include @cipherbox/crypto in API Docker build ([#450](https://github.com/FSM1/cipher-box/issues/450)) ([3a7f886](https://github.com/FSM1/cipher-box/commit/3a7f8863e2be2bc62f615c871077e34d25365d53))

## [0.37.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-v0.36.1...@cipherbox/api-v0.37.0) (2026-04-06)


### Features

* IPNS signature storage and verification ([#448](https://github.com/FSM1/cipher-box/issues/448)) ([9b80833](https://github.com/FSM1/cipher-box/commit/9b80833ffd7d2dbe0c4cef5b24825b611cd97879))


### Bug Fixes

* **api,desktop:** fix sequence number mismatch in cached IPNS resolves ([#449](https://github.com/FSM1/cipher-box/issues/449)) ([18b4e26](https://github.com/FSM1/cipher-box/commit/18b4e2600df804924461d967787408268c1f798c))

## [0.36.1](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-v0.36.0...@cipherbox/api-v0.36.1) (2026-04-02)


### Bug Fixes

* **api:** use Google sub for linked account resolution ([#445](https://github.com/FSM1/cipher-box/issues/445)) ([3908f65](https://github.com/FSM1/cipher-box/commit/3908f65751e7fd064360855decc9030de75e7c8c))

## [0.36.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/api-v0.35.0...@cipherbox/api-v0.36.0) (2026-04-01)


### Features

* **api:** expose API version on /health endpoint ([#429](https://github.com/FSM1/cipher-box/issues/429)) ([6abf87e](https://github.com/FSM1/cipher-box/commit/6abf87e68fea82bbddaf51f29c07f2091e402e7d))
