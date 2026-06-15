# Changelog

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
