# Changelog

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
