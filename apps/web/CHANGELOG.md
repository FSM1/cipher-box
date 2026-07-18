# Changelog

## [0.49.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/web-v0.48.0...@cipherbox/web-v0.49.0) (2026-07-18)


### Features

* atomic IPNS publish-gate, tombstone, and share schema cutover ([#584](https://github.com/FSM1/cipher-box/issues/584)) ([a036a84](https://github.com/FSM1/cipher-box/commit/a036a84d4477937ee4a59e2c70c0673c5142edc8))
* enforce share-invite authorization and IPNS data-integrity in the API ([#599](https://github.com/FSM1/cipher-box/issues/599)) ([703bc00](https://github.com/FSM1/cipher-box/commit/703bc0083d42547cd2c0e747d79be82a0c318e78))
* integrate web client with node/v3 read and write runtime ([#588](https://github.com/FSM1/cipher-box/issues/588)) ([1fb8996](https://github.com/FSM1/cipher-box/commit/1fb8996a25947a0964b286ac44864f3e5e84e33c))
* recovery tool v3, vault-load guards, web UX and CI boundary guards ([#613](https://github.com/FSM1/cipher-box/issues/613)) ([cba7857](https://github.com/FSM1/cipher-box/commit/cba7857187d8aa6f92b02a0d4d88269f71f770ec))
* rotation write-plane and re-mint durability with recipient-pubkey pinning ([#615](https://github.com/FSM1/cipher-box/issues/615)) ([27c4abe](https://github.com/FSM1/cipher-box/commit/27c4abec52ed7cdf0ce9d7147685b2bae97e16b5))
* SDK write-chain, write-revocation, bin re-link, and invite claim ([#583](https://github.com/FSM1/cipher-box/issues/583)) ([d81c1b4](https://github.com/FSM1/cipher-box/commit/d81c1b476805f7b6764e388604e3da657f7540f1))
* SDK-owned read chain and resolved folder listings ([#589](https://github.com/FSM1/cipher-box/issues/589)) ([6534c64](https://github.com/FSM1/cipher-box/commit/6534c642aacfd4755967ccbd622840610635b86c))
* unified Node codec and two-key vault v3 blob in core ([#578](https://github.com/FSM1/cipher-box/issues/578)) ([b2dba55](https://github.com/FSM1/cipher-box/commit/b2dba554a75cb975ab72d9e2777b7b2dde9a06bf))
* web rotation UX and durable anti-rollback client state ([#587](https://github.com/FSM1/cipher-box/issues/587)) ([1b4f68b](https://github.com/FSM1/cipher-box/commit/1b4f68b588f0bb51bec2267f6e742ccaa3b76426))


### Bug Fixes

* complete web kind discrimination and revive deferred test suites ([#611](https://github.com/FSM1/cipher-box/issues/611)) ([fcf1596](https://github.com/FSM1/cipher-box/commit/fcf1596a736cd0d2bd75f0dd6f9ac13a224906fa))
* harden rotation read-plane durability and deep crash-resume soundness ([#598](https://github.com/FSM1/cipher-box/issues/598)) ([d5486e5](https://github.com/FSM1/cipher-box/commit/d5486e586ab0d30113ca167819d6e053bb2ec3a3))
* harden rotation soundness under concurrency and crash-resume ([#596](https://github.com/FSM1/cipher-box/issues/596)) ([faa781e](https://github.com/FSM1/cipher-box/commit/faa781e4164697b17cc7765624985dcb9a38f761))
* harden SDK write-plane durability and correctness ([#602](https://github.com/FSM1/cipher-box/issues/602)) ([c21f896](https://github.com/FSM1/cipher-box/commit/c21f896b6839b5791ff0c8bd4c5985afef8c6a48))
* shared-folder write and navigation correctness on web ([#603](https://github.com/FSM1/cipher-box/issues/603)) ([bd8c1e0](https://github.com/FSM1/cipher-box/commit/bd8c1e0be4001b6542a2ba9e3f3788a20ff12466))

## [0.48.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/web-v0.47.0...@cipherbox/web-v0.48.0) (2026-06-26)


### Bug Fixes

* **web:** embed sequence 1 on first BYO storage-config IPNS publish ([#571](https://github.com/FSM1/cipher-box/issues/571)) ([91c96eb](https://github.com/FSM1/cipher-box/commit/91c96eb50839292c47bff4eceaf9a0b681c8b5ac))

## [0.47.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/web-v0.46.0...@cipherbox/web-v0.47.0) (2026-06-25)


### Features

* strict fail-closed IPNS verification cutover across Rust, TS, and API ([#555](https://github.com/FSM1/cipher-box/issues/555)) ([03209e3](https://github.com/FSM1/cipher-box/commit/03209e3854e1309cde13c087a3f407568b17fcd7))

## [0.46.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/web-v0.45.0...@cipherbox/web-v0.46.0) (2026-06-22)


### Bug Fixes

* FUSE and IPNS write-path durability hardening ([#543](https://github.com/FSM1/cipher-box/issues/543)) ([5d5daaa](https://github.com/FSM1/cipher-box/commit/5d5daaaf69aeb030ae9aa828ac4245525e0215fd))
* IPNS signed-record verify coverage chokepoint and non-CAS sequence gate ([#544](https://github.com/FSM1/cipher-box/issues/544)) ([cd173c9](https://github.com/FSM1/cipher-box/commit/cd173c9c20c50d29ea211f00efa84291d7a3178f))

## [0.45.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/web-v0.44.0...@cipherbox/web-v0.45.0) (2026-06-18)


### Features

* **web:** shared-folder intra-share move and useFolderNavigation consolidation ([#509](https://github.com/FSM1/cipher-box/issues/509)) ([c36ac6d](https://github.com/FSM1/cipher-box/commit/c36ac6d7792947a734a539a23de6b42d5c1fdd98))

## [0.44.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/web-v0.43.0...@cipherbox/web-v0.44.0) (2026-06-17)


### Features

* **api:** share item-name backfill endpoint ([#505](https://github.com/FSM1/cipher-box/issues/505)) ([63638b5](https://github.com/FSM1/cipher-box/commit/63638b55983f00e91b5c8b4e8f6cf4372ad8b320))

## [0.43.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/web-v0.42.0...@cipherbox/web-v0.43.0) (2026-06-16)


### Features

* consolidate SDK shared-folder ownership and encrypt share itemName at rest ([#500](https://github.com/FSM1/cipher-box/issues/500)) ([383e856](https://github.com/FSM1/cipher-box/commit/383e856cbfba6a23b60cc116e0b5163c92e6be97))
* **sdk:** self-bootstrap folder tree from root IPNS key ([#498](https://github.com/FSM1/cipher-box/issues/498)) ([2657740](https://github.com/FSM1/cipher-box/commit/2657740f144203a095f43e8692794fcd71c9e283))

## [0.42.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/web-v0.41.0...@cipherbox/web-v0.42.0) (2026-06-15)


### Features

* **api:** guard unpin with ownership check and reference-counted quota decrement ([#485](https://github.com/FSM1/cipher-box/issues/485)) ([158addc](https://github.com/FSM1/cipher-box/commit/158addccac4f182b2bd7221f1ee80cdece393928))
* **sdk-core:** handle IPNS write conflicts via 409 merge and file CAS publish ([#488](https://github.com/FSM1/cipher-box/issues/488)) ([1abceb4](https://github.com/FSM1/cipher-box/commit/1abceb4b88a6245509db44794e56f687695d2b30))


### Bug Fixes

* resolve UAT audit findings in BYO pinning and migration flows ([#479](https://github.com/FSM1/cipher-box/issues/479)) ([9f3136a](https://github.com/FSM1/cipher-box/commit/9f3136a9440bb16e31c8073f90c0fee827074da1))
* **web:** reconcile SDK folderTree sequence to stop deleted-file resurrection ([#489](https://github.com/FSM1/cipher-box/issues/489)) ([e7ea982](https://github.com/FSM1/cipher-box/commit/e7ea98235b25cdfabb6b6341d34dc79f93d58517))
* **web:** register folder in SDK folderTree before file edit and version writes ([#496](https://github.com/FSM1/cipher-box/issues/496)) ([b24e78e](https://github.com/FSM1/cipher-box/commit/b24e78e90fd000026e030dbb0c090b8fb7182667))

## [0.41.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/web-v0.40.0...@cipherbox/web-v0.41.0) (2026-05-26)


### Bug Fixes

* **web:** resolve bin view column header layout conflict ([#471](https://github.com/FSM1/cipher-box/issues/471)) ([eb52e10](https://github.com/FSM1/cipher-box/commit/eb52e10da744313aa70da56e88427cc3c86570f1))

## [0.40.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/web-v0.39.0...@cipherbox/web-v0.40.0) (2026-04-14)


### Bug Fixes

* **desktop:** detect remote file edits and re-resolve IPNS in FUSE mount ([#454](https://github.com/FSM1/cipher-box/issues/454)) ([09e6830](https://github.com/FSM1/cipher-box/commit/09e6830b87de176b3613c700f78b2f1cd3b517f9))

## [0.39.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/web-v0.38.0...@cipherbox/web-v0.39.0) (2026-04-06)


### Features

* IPNS signature storage and verification ([#448](https://github.com/FSM1/cipher-box/issues/448)) ([9b80833](https://github.com/FSM1/cipher-box/commit/9b80833ffd7d2dbe0c4cef5b24825b611cd97879))


### Bug Fixes

* **api,desktop:** fix sequence number mismatch in cached IPNS resolves ([#449](https://github.com/FSM1/cipher-box/issues/449)) ([18b4e26](https://github.com/FSM1/cipher-box/commit/18b4e2600df804924461d967787408268c1f798c))

## [0.38.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/web-v0.37.0...@cipherbox/web-v0.38.0) (2026-04-02)


### Bug Fixes

* **web:** improve file browser empty state handling during uploads ([#443](https://github.com/FSM1/cipher-box/issues/443)) ([03fe1e4](https://github.com/FSM1/cipher-box/commit/03fe1e47a86af13eb0bca84373ecd5f7ac1715bd))

## [0.37.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/web-v0.36.0...@cipherbox/web-v0.37.0) (2026-04-01)


### Bug Fixes

* **web:** replace emoji sidebar icons with consistent inline SVGs ([#436](https://github.com/FSM1/cipher-box/issues/436)) ([c7f72b6](https://github.com/FSM1/cipher-box/commit/c7f72b6131d0b840841697c0328cec6603dd5e00))

## [0.36.0](https://github.com/FSM1/cipher-box/compare/@cipherbox/web-v0.35.0...@cipherbox/web-v0.36.0) (2026-04-01)


### Features

* **web:** user-configurable vault parameters ([#423](https://github.com/FSM1/cipher-box/issues/423)) ([fa7b443](https://github.com/FSM1/cipher-box/commit/fa7b44399f9c688783b995a2a716b6525eabeefe))


### Bug Fixes

* **web:** replace encrypting pulse with shimmer to prevent progress flash ([#420](https://github.com/FSM1/cipher-box/issues/420)) ([0300eac](https://github.com/FSM1/cipher-box/commit/0300eace7425c8a1a77763351f0e93f6eef1a86f))
