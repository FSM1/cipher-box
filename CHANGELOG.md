# Changelog

## [0.46.0](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.45.2...cipher-box-v0.46.0) (2026-07-18)


### Features

* add AAD-bound AES-256-GCM node-seal primitive with cross-language KAT ([#576](https://github.com/FSM1/cipher-box/issues/576)) ([65237ac](https://github.com/FSM1/cipher-box/commit/65237ac18b2ae2534304d57e0d08dec52a263d04))
* atomic IPNS publish-gate, tombstone, and share schema cutover ([#584](https://github.com/FSM1/cipher-box/issues/584)) ([a036a84](https://github.com/FSM1/cipher-box/commit/a036a84d4477937ee4a59e2c70c0673c5142edc8))
* enforce share-invite authorization and IPNS data-integrity in the API ([#599](https://github.com/FSM1/cipher-box/issues/599)) ([703bc00](https://github.com/FSM1/cipher-box/commit/703bc0083d42547cd2c0e747d79be82a0c318e78))
* FUSE and WinFsp Rust integration with grant-root awareness and SDK-owned read chain ([#594](https://github.com/FSM1/cipher-box/issues/594)) ([4b96aa9](https://github.com/FSM1/cipher-box/commit/4b96aa950b19591331445d65dfa81b6bc25d90b2))
* integrate web client with node/v3 read and write runtime ([#588](https://github.com/FSM1/cipher-box/issues/588)) ([1fb8996](https://github.com/FSM1/cipher-box/commit/1fb8996a25947a0964b286ac44864f3e5e84e33c))
* read-chain navigation, grants, and rotation engine in sdk-core ([#579](https://github.com/FSM1/cipher-box/issues/579)) ([7216797](https://github.com/FSM1/cipher-box/commit/7216797ed2d0fe83a214335de45b611efd3ec679))
* recovery tool v3, vault-load guards, web UX and CI boundary guards ([#613](https://github.com/FSM1/cipher-box/issues/613)) ([cba7857](https://github.com/FSM1/cipher-box/commit/cba7857187d8aa6f92b02a0d4d88269f71f770ec))
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
* **fuse:** resolve before per-file first-publish to avoid seq-1 equivocation ([#601](https://github.com/FSM1/cipher-box/issues/601)) ([e87befa](https://github.com/FSM1/cipher-box/commit/e87befa2df464e2df7a880447eb4f3c0508ff5cd))
* harden FUSE publish and TEE write paths against partial-failure states ([#610](https://github.com/FSM1/cipher-box/issues/610)) ([02efe51](https://github.com/FSM1/cipher-box/commit/02efe51bbc1930b02857b081b41404ae0ed9605c))
* harden rotation read-plane durability and deep crash-resume soundness ([#598](https://github.com/FSM1/cipher-box/issues/598)) ([d5486e5](https://github.com/FSM1/cipher-box/commit/d5486e586ab0d30113ca167819d6e053bb2ec3a3))
* harden rotation soundness under concurrency and crash-resume ([#596](https://github.com/FSM1/cipher-box/issues/596)) ([faa781e](https://github.com/FSM1/cipher-box/commit/faa781e4164697b17cc7765624985dcb9a38f761))
* harden SDK write-plane durability and correctness ([#602](https://github.com/FSM1/cipher-box/issues/602)) ([c21f896](https://github.com/FSM1/cipher-box/commit/c21f896b6839b5791ff0c8bd4c5985afef8c6a48))
* shared-folder write and navigation correctness on web ([#603](https://github.com/FSM1/cipher-box/issues/603)) ([bd8c1e0](https://github.com/FSM1/cipher-box/commit/bd8c1e0be4001b6542a2ba9e3f3788a20ff12466))

## [0.45.2](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.45.1...cipher-box-v0.45.2) (2026-06-26)


### Bug Fixes

* **web:** embed sequence 1 on first BYO storage-config IPNS publish ([#571](https://github.com/FSM1/cipher-box/issues/571)) ([91c96eb](https://github.com/FSM1/cipher-box/commit/91c96eb50839292c47bff4eceaf9a0b681c8b5ac))

## [0.45.1](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.45.0...cipher-box-v0.45.1) (2026-06-26)


### Bug Fixes

* **bin:** unpin deleted content and revoke its shares ([#563](https://github.com/FSM1/cipher-box/issues/563)) ([1699522](https://github.com/FSM1/cipher-box/commit/16995221c79421d086aeee0b58fb7af3c7198fa9))
* **fuse:** revoke shares when items are deleted via the desktop mount ([#568](https://github.com/FSM1/cipher-box/issues/568)) ([82ad5d7](https://github.com/FSM1/cipher-box/commit/82ad5d77b6d3b524da62888142400c3a2cd62380))
* harden Phase 60 deferred safety patches in FUSE publish and desktop vault init ([#566](https://github.com/FSM1/cipher-box/issues/566)) ([0adcb04](https://github.com/FSM1/cipher-box/commit/0adcb0418198b3cc311da98551c9d0a4bef293c2))

## [0.45.0](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.44.1...cipher-box-v0.45.0) (2026-06-25)


### Features

* strict fail-closed IPNS verification cutover across Rust, TS, and API ([#555](https://github.com/FSM1/cipher-box/issues/555)) ([03209e3](https://github.com/FSM1/cipher-box/commit/03209e3854e1309cde13c087a3f407568b17fcd7))


### Bug Fixes

* **fuse:** re-resolve remote file edits during local publish window ([#558](https://github.com/FSM1/cipher-box/issues/558)) ([d343c0f](https://github.com/FSM1/cipher-box/commit/d343c0f4e8a34aaac117fd397a92c233f7ab45f4))

## [0.44.1](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.44.0...cipher-box-v0.44.1) (2026-06-23)


### Bug Fixes

* **fuse:** harden IPNS verify and publish paths and clear cleanup debt ([#553](https://github.com/FSM1/cipher-box/issues/553)) ([ff9b356](https://github.com/FSM1/cipher-box/commit/ff9b3566991b81d49c0357a38b856f51a4cd0845))

## [0.44.0](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.43.0...cipher-box-v0.44.0) (2026-06-22)


### Features

* **api:** API CID and provider hardening with unpin module dedup ([#541](https://github.com/FSM1/cipher-box/issues/541)) ([106ee88](https://github.com/FSM1/cipher-box/commit/106ee8816339385c46f4352402c8a1acecb366bb))


### Bug Fixes

* FUSE and IPNS write-path durability hardening ([#543](https://github.com/FSM1/cipher-box/issues/543)) ([5d5daaa](https://github.com/FSM1/cipher-box/commit/5d5daaaf69aeb030ae9aa828ac4245525e0215fd))
* IPNS signed-record verify coverage chokepoint and non-CAS sequence gate ([#544](https://github.com/FSM1/cipher-box/issues/544)) ([cd173c9](https://github.com/FSM1/cipher-box/commit/cd173c9c20c50d29ea211f00efa84291d7a3178f))

## [0.43.0](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.42.0...cipher-box-v0.43.0) (2026-06-21)


### Features

* desktop FUSE journal durability and at-rest safety ([#533](https://github.com/FSM1/cipher-box/issues/533)) ([b3511af](https://github.com/FSM1/cipher-box/commit/b3511afbd7011a0a5f151d47f2ec9bd1069262c1))


### Bug Fixes

* **e2e:** make desktop e2e helper dirs workspace packages ([#536](https://github.com/FSM1/cipher-box/issues/536)) ([ac71fef](https://github.com/FSM1/cipher-box/commit/ac71fef0068a7da1393994a4c73e0b84956d8b13))
* IPFS/IPNS data-integrity fixes for unpin and folder unenroll ([#527](https://github.com/FSM1/cipher-box/issues/527)) ([b7acb57](https://github.com/FSM1/cipher-box/commit/b7acb570ced77f43f35eecd65a7f9f15fdd29afc))

## [0.42.0](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.41.1...cipher-box-v0.42.0) (2026-06-18)


### Features

* **web:** shared-folder intra-share move and useFolderNavigation consolidation ([#509](https://github.com/FSM1/cipher-box/issues/509)) ([c36ac6d](https://github.com/FSM1/cipher-box/commit/c36ac6d7792947a734a539a23de6b42d5c1fdd98))

## [0.41.1](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.41.0...cipher-box-v0.41.1) (2026-06-17)


### Bug Fixes

* re-encrypt file metadata on move and bin restore ([#507](https://github.com/FSM1/cipher-box/issues/507)) ([2c639de](https://github.com/FSM1/cipher-box/commit/2c639de8a4acec923fe5396f8fc5a6255c59978d))

## [0.41.0](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.40.0...cipher-box-v0.41.0) (2026-06-17)


### Features

* **api:** share item-name backfill endpoint ([#505](https://github.com/FSM1/cipher-box/issues/505)) ([63638b5](https://github.com/FSM1/cipher-box/commit/63638b55983f00e91b5c8b4e8f6cf4372ad8b320))

## [0.40.0](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.39.0...cipher-box-v0.40.0) (2026-06-16)


### Features

* consolidate SDK shared-folder ownership and encrypt share itemName at rest ([#500](https://github.com/FSM1/cipher-box/issues/500)) ([383e856](https://github.com/FSM1/cipher-box/commit/383e856cbfba6a23b60cc116e0b5163c92e6be97))
* **sdk:** self-bootstrap folder tree from root IPNS key ([#498](https://github.com/FSM1/cipher-box/issues/498)) ([2657740](https://github.com/FSM1/cipher-box/commit/2657740f144203a095f43e8692794fcd71c9e283))

## [0.39.0](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.38.6...cipher-box-v0.39.0) (2026-06-15)


### Features

* **api:** guard unpin with ownership check and reference-counted quota decrement ([#485](https://github.com/FSM1/cipher-box/issues/485)) ([158addc](https://github.com/FSM1/cipher-box/commit/158addccac4f182b2bd7221f1ee80cdece393928))
* desktop FUSE data-loss bugs and replay hardening ([#493](https://github.com/FSM1/cipher-box/issues/493)) ([79de97b](https://github.com/FSM1/cipher-box/commit/79de97bc5cfe5213cc2d6747305a914265b12430))
* **fuse:** durable write journal with crash-recovery replay ([#487](https://github.com/FSM1/cipher-box/issues/487)) ([dcd1bec](https://github.com/FSM1/cipher-box/commit/dcd1becb6f6dad1b8d44d70544b0a6b1248458dc))
* **sdk-core:** handle IPNS write conflicts via 409 merge and file CAS publish ([#488](https://github.com/FSM1/cipher-box/issues/488)) ([1abceb4](https://github.com/FSM1/cipher-box/commit/1abceb4b88a6245509db44794e56f687695d2b30))


### Bug Fixes

* resolve UAT audit findings in BYO pinning and migration flows ([#479](https://github.com/FSM1/cipher-box/issues/479)) ([9f3136a](https://github.com/FSM1/cipher-box/commit/9f3136a9440bb16e31c8073f90c0fee827074da1))
* **test:** align edit-filepointer helper with updateFileMetadata internal-publish contract ([#495](https://github.com/FSM1/cipher-box/issues/495)) ([0c2422c](https://github.com/FSM1/cipher-box/commit/0c2422c8c0deda7d13317eaef22c11332a5ff091))
* **web:** reconcile SDK folderTree sequence to stop deleted-file resurrection ([#489](https://github.com/FSM1/cipher-box/issues/489)) ([e7ea982](https://github.com/FSM1/cipher-box/commit/e7ea98235b25cdfabb6b6341d34dc79f93d58517))
* **web:** register folder in SDK folderTree before file edit and version writes ([#496](https://github.com/FSM1/cipher-box/issues/496)) ([b24e78e](https://github.com/FSM1/cipher-box/commit/b24e78e90fd000026e030dbb0c090b8fb7182667))

## [0.38.6](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.38.5...cipher-box-v0.38.6) (2026-06-10)


### Bug Fixes

* bind pinning provider fetch fallback to globalThis for browser compatibility ([#477](https://github.com/FSM1/cipher-box/issues/477)) ([39dd78e](https://github.com/FSM1/cipher-box/commit/39dd78ec578e5bf991d8102db66e895b7a835e5e))

## [0.38.5](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.38.4...cipher-box-v0.38.5) (2026-05-26)


### Bug Fixes

* **web:** resolve bin view column header layout conflict ([#471](https://github.com/FSM1/cipher-box/issues/471)) ([eb52e10](https://github.com/FSM1/cipher-box/commit/eb52e10da744313aa70da56e88427cc3c86570f1))

## [0.38.4](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.38.3...cipher-box-v0.38.4) (2026-05-26)


### Bug Fixes

* **desktop:** resolve folder rename permission errors and sync duplicates ([#466](https://github.com/FSM1/cipher-box/issues/466)) ([1f84eec](https://github.com/FSM1/cipher-box/commit/1f84eec428be6a81068381e1488b0598317d49ae))
* **test:** increase folder rename sync timeout and make optional ([#470](https://github.com/FSM1/cipher-box/issues/470)) ([f5acfcb](https://github.com/FSM1/cipher-box/commit/f5acfcb67570491cf7b8caafc120f1f697be6986))
* **test:** wait for FUSE metadata publish before SDK folder rename ([#469](https://github.com/FSM1/cipher-box/issues/469)) ([bc65c03](https://github.com/FSM1/cipher-box/commit/bc65c03316a0983a1fd0d0406f55abeab40dd8f2))

## [0.38.3](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.38.2...cipher-box-v0.38.3) (2026-05-26)


### Bug Fixes

* **ci:** target staging environment for desktop release builds ([#464](https://github.com/FSM1/cipher-box/issues/464)) ([cb5458d](https://github.com/FSM1/cipher-box/commit/cb5458d6e1446b731b55b3823ce7cedece79d50b))

## [0.38.2](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.38.1...cipher-box-v0.38.2) (2026-05-25)


### Bug Fixes

* **desktop:** use Web3Auth devnet network for production builds ([#462](https://github.com/FSM1/cipher-box/issues/462)) ([d502940](https://github.com/FSM1/cipher-box/commit/d502940c187b35df49ed305969071da0fd2749bd))

## [0.38.1](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.38.0...cipher-box-v0.38.1) (2026-05-25)


### Bug Fixes

* **desktop:** use localhost callback server for Google OAuth in Tauri ([#459](https://github.com/FSM1/cipher-box/issues/459)) ([ebfa8a8](https://github.com/FSM1/cipher-box/commit/ebfa8a8af2dcec7bdde8b5eb78995f5d825ea8e1))

## [0.38.0](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.37.1...cipher-box-v0.38.0) (2026-04-14)


### Features

* add static landing page for cipherbox.cc with IPFS deployment ([#452](https://github.com/FSM1/cipher-box/issues/452)) ([705b9df](https://github.com/FSM1/cipher-box/commit/705b9df8f2e8fb1db849853c658adf27e3bf58c4))


### Bug Fixes

* **desktop:** detect remote file edits and re-resolve IPNS in FUSE mount ([#454](https://github.com/FSM1/cipher-box/issues/454)) ([09e6830](https://github.com/FSM1/cipher-box/commit/09e6830b87de176b3613c700f78b2f1cd3b517f9))
* **desktop:** trigger metadata refresh from lookup/open, fix e2e sync test ([#456](https://github.com/FSM1/cipher-box/issues/456)) ([1e3ef75](https://github.com/FSM1/cipher-box/commit/1e3ef750f430f7d49ffe85d5d81cd80cb1467988))

## [0.37.1](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.37.0...cipher-box-v0.37.1) (2026-04-06)


### Bug Fixes

* **api:** include @cipherbox/crypto in API Docker build ([#450](https://github.com/FSM1/cipher-box/issues/450)) ([3a7f886](https://github.com/FSM1/cipher-box/commit/3a7f8863e2be2bc62f615c871077e34d25365d53))

## [0.37.0](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.36.1...cipher-box-v0.37.0) (2026-04-06)


### Features

* IPNS signature storage and verification ([#448](https://github.com/FSM1/cipher-box/issues/448)) ([9b80833](https://github.com/FSM1/cipher-box/commit/9b80833ffd7d2dbe0c4cef5b24825b611cd97879))


### Bug Fixes

* **api,desktop:** fix sequence number mismatch in cached IPNS resolves ([#449](https://github.com/FSM1/cipher-box/issues/449)) ([18b4e26](https://github.com/FSM1/cipher-box/commit/18b4e2600df804924461d967787408268c1f798c))
* **desktop:** align file upload IPNS sequence and verify file pointers ([#446](https://github.com/FSM1/cipher-box/issues/446)) ([741f226](https://github.com/FSM1/cipher-box/commit/741f22670f9c192a2d3168748241ad851bf32561))

## [0.36.1](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.36.0...cipher-box-v0.36.1) (2026-04-02)


### Bug Fixes

* **api:** use Google sub for linked account resolution ([#445](https://github.com/FSM1/cipher-box/issues/445)) ([3908f65](https://github.com/FSM1/cipher-box/commit/3908f65751e7fd064360855decc9030de75e7c8c))
* **web:** improve file browser empty state handling during uploads ([#443](https://github.com/FSM1/cipher-box/issues/443)) ([03fe1e4](https://github.com/FSM1/cipher-box/commit/03fe1e47a86af13eb0bca84373ecd5f7ac1715bd))

## [0.36.0](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.35.0...cipher-box-v0.36.0) (2026-04-01)


### Features

* **api:** expose API version on /health endpoint ([#429](https://github.com/FSM1/cipher-box/issues/429)) ([6abf87e](https://github.com/FSM1/cipher-box/commit/6abf87e68fea82bbddaf51f29c07f2091e402e7d))


### Bug Fixes

* **ci:** correct openapi.json extra-files path for release-please ([#432](https://github.com/FSM1/cipher-box/issues/432)) ([88a12a0](https://github.com/FSM1/cipher-box/commit/88a12a005305e362534b27940d671a53fc66c4db))
* **ci:** exclude openapi.json version from spec verification ([#434](https://github.com/FSM1/cipher-box/issues/434)) ([4471b1b](https://github.com/FSM1/cipher-box/commit/4471b1bc8c2145d5fb32639c57791b184e049bdb))
* **ci:** ignore OpenAPI version comment in generated TS file diff ([#438](https://github.com/FSM1/cipher-box/issues/438)) ([c19c501](https://github.com/FSM1/cipher-box/commit/c19c5017c2b2a60fe156c2d003afc6d092a81a2e))
* **ci:** move release-as injection from post-merge to PR branch ([#431](https://github.com/FSM1/cipher-box/issues/431)) ([e8c4ef3](https://github.com/FSM1/cipher-box/commit/e8c4ef351e88166e85c576403127ca624f110695))
* **ci:** remove openapi.json from release-please extra-files ([4471b1b](https://github.com/FSM1/cipher-box/commit/4471b1bc8c2145d5fb32639c57791b184e049bdb))
* **web:** replace emoji sidebar icons with consistent inline SVGs ([#436](https://github.com/FSM1/cipher-box/issues/436)) ([c7f72b6](https://github.com/FSM1/cipher-box/commit/c7f72b6131d0b840841697c0328cec6603dd5e00))

## [0.35.0](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.34.0...cipher-box-v0.35.0) (2026-03-31)


### Features

* desktop vault settings integration - phase 40 ([#424](https://github.com/FSM1/cipher-box/issues/424)) ([0d37d71](https://github.com/FSM1/cipher-box/commit/0d37d710bc1c57061433a992c020fc8951aba1ad))
* **web:** user-configurable vault parameters ([#423](https://github.com/FSM1/cipher-box/issues/423)) ([fa7b443](https://github.com/FSM1/cipher-box/commit/fa7b44399f9c688783b995a2a716b6525eabeefe))


### Bug Fixes

* **desktop:** use compile-time API URL fallback for release builds ([#425](https://github.com/FSM1/cipher-box/issues/425)) ([e5384c0](https://github.com/FSM1/cipher-box/commit/e5384c0afe7f0590edc8c9b7e754eebe8325f58f))
* **web:** replace encrypting pulse with shimmer to prevent progress flash ([#420](https://github.com/FSM1/cipher-box/issues/420)) ([0300eac](https://github.com/FSM1/cipher-box/commit/0300eace7425c8a1a77763351f0e93f6eef1a86f))

## [0.34.0](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.33.0...cipher-box-v0.34.0) (2026-03-30)


### Features

* parallel batch upload pipeline with Web Worker encryption ([#416](https://github.com/FSM1/cipher-box/issues/416)) ([ee918ac](https://github.com/FSM1/cipher-box/commit/ee918accc1bd82339eca87d973c13ab2e0556f37))

## [0.33.0](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.32.1...cipher-box-v0.33.0) (2026-03-30)


### Features

* **web:** Inline upload progress ([#410](https://github.com/FSM1/cipher-box/issues/410)) ([81c9f71](https://github.com/FSM1/cipher-box/commit/81c9f717bb39ccd43feef4738f0c011a6d8d2ed2))


### Bug Fixes

* **tee:** remove bash default syntax from compose image reference ([#412](https://github.com/FSM1/cipher-box/issues/412)) ([d206e19](https://github.com/FSM1/cipher-box/commit/d206e1932057b71357fa157e0156571a8019f8c2))
* **web:** reverse upload dedup to prevent real file rows disappearing ([#414](https://github.com/FSM1/cipher-box/issues/414)) ([e2321f8](https://github.com/FSM1/cipher-box/commit/e2321f849a188a114767c4704ebaf79cb3514e8e))
* **web:** trigger sync after upload, fix E2E duplicate row failures ([#413](https://github.com/FSM1/cipher-box/issues/413)) ([e2932af](https://github.com/FSM1/cipher-box/commit/e2932af90dc7009e82360752d574ee8173997f6a))

## [0.32.1](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.32.0...cipher-box-v0.32.1) (2026-03-30)


### Bug Fixes

* **ci:** check E2E jobs within ci-e2e.yml orchestrator runs ([#409](https://github.com/FSM1/cipher-box/issues/409)) ([949b18e](https://github.com/FSM1/cipher-box/commit/949b18e9685898bb24744c4e42ca8ea45e099586))
* **ci:** force all E2E suites on workflow_dispatch and re-trigger release gate ([bb87d17](https://github.com/FSM1/cipher-box/commit/bb87d17848a8ff388346a74ab313bcd5cd3b7681))
* **ci:** skip E2E gates when web/desktop unchanged ([#407](https://github.com/FSM1/cipher-box/issues/407)) ([28d1390](https://github.com/FSM1/cipher-box/commit/28d1390d31515720f273d2f3e75337a8c9e01d27))
* **ci:** use --cvm-id flag for Phala Cloud CVM redeployment ([#405](https://github.com/FSM1/cipher-box/issues/405)) ([10bf6fa](https://github.com/FSM1/cipher-box/commit/10bf6faf4ea725f2ee5e28debee5b70eef478274))

## [0.32.0](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.31.1...cipher-box-v0.32.0) (2026-03-30)


### Features

* Phase 28 Code Hygiene & Logging ([#382](https://github.com/FSM1/cipher-box/issues/382)) ([9827f49](https://github.com/FSM1/cipher-box/commit/9827f49df59a8730ef0b4ea7bf74caa59b36b055))
* Phase 29 Infrastructure Hardening ([#383](https://github.com/FSM1/cipher-box/issues/383)) ([a209337](https://github.com/FSM1/cipher-box/commit/a2093370c4bd7203a18ba028c7506387b192cd32))
* Phase 30 Web App Observability ([#386](https://github.com/FSM1/cipher-box/issues/386)) ([c82fbe7](https://github.com/FSM1/cipher-box/commit/c82fbe7c6d37c744b372a665aea69b72046418f5))
* **sdk:** select AES-CTR encryption for streaming media uploads ([#399](https://github.com/FSM1/cipher-box/issues/399)) ([a595e4b](https://github.com/FSM1/cipher-box/commit/a595e4b53eb5c33fd68e50eb97cee1b647f595fc))
* **tee-worker:** migrate TEE worker to Phala Cloud CVM ([#395](https://github.com/FSM1/cipher-box/issues/395)) ([a08414f](https://github.com/FSM1/cipher-box/commit/a08414fe7674b80d80b64c8dc671f5dca8143fba))


### Bug Fixes

* **api:** add BYO status endpoint, fix load test failures, fix test type errors ([#400](https://github.com/FSM1/cipher-box/issues/400)) ([0517397](https://github.com/FSM1/cipher-box/commit/0517397a6735cc6e626ae9f6e5e05725a50075d5))
* **ci:** release gate skips past runs where desktop tests didn't execute ([#401](https://github.com/FSM1/cipher-box/issues/401)) ([afa288f](https://github.com/FSM1/cipher-box/commit/afa288faa453d92c449ff31b2cd8839aa862dd8a))
* resolve E2E test failures and narrow CI cargo gate ([#398](https://github.com/FSM1/cipher-box/issues/398)) ([6e12701](https://github.com/FSM1/cipher-box/commit/6e12701e695e3a95b5ad191c2916646c3b4a9396))


### Performance Improvements

* **fuse:** Phase 32 async FilePointer resolution ([#388](https://github.com/FSM1/cipher-box/issues/388)) ([8cddb05](https://github.com/FSM1/cipher-box/commit/8cddb05c31e2b010dc4afb9463d0d12f48722165))
* **WinFSP:** Phase 33 Windows Async FilePointer Resolution ([#389](https://github.com/FSM1/cipher-box/issues/389)) ([b2f6572](https://github.com/FSM1/cipher-box/commit/b2f6572212decf44c9bdedb92f8f48b37c69037c))

## [0.31.1](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.31.0...cipher-box-v0.31.1) (2026-03-27)


### Bug Fixes

* **ci:** use tauri-action@v0 in desktop build workflow ([#377](https://github.com/FSM1/cipher-box/issues/377)) ([dfff93d](https://github.com/FSM1/cipher-box/commit/dfff93d9b0f2d25b31ae539379f35edb8d20b77c))

## [0.31.0](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.30.1...cipher-box-v0.31.0) (2026-03-27)


### Features

* **phase-27:** writable shares ([#372](https://github.com/FSM1/cipher-box/issues/372)) ([65721b4](https://github.com/FSM1/cipher-box/commit/65721b47f7791d908efb78323b27ee8487e9d3a5))


### Bug Fixes

* **e2e:** wait for React state before Ctrl+S in writable shares test ([#375](https://github.com/FSM1/cipher-box/issues/375)) ([98ba7d4](https://github.com/FSM1/cipher-box/commit/98ba7d4d034b8a55afce0093b1910f4e845b56ff))
* **shares:** allow write-share recipients to add subfolder keys ([#374](https://github.com/FSM1/cipher-box/issues/374)) ([eafde2c](https://github.com/FSM1/cipher-box/commit/eafde2c88f82b3a2c5d4de81e8f2037847ab66d9))
* **shares:** fix file IPNS key lookup for standalone file shares ([#376](https://github.com/FSM1/cipher-box/issues/376)) ([0135d18](https://github.com/FSM1/cipher-box/commit/0135d186f6f878baab6ab7fda5bd0acae9fbf597))

## [0.30.1](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.30.0...cipher-box-v0.30.1) (2026-03-26)


### Bug Fixes

* **ci:** wire Tauri signing keys into staging desktop builds ([#370](https://github.com/FSM1/cipher-box/issues/370)) ([ed62930](https://github.com/FSM1/cipher-box/commit/ed62930824b78e242b215563ed5e051624177482))

## [0.30.0](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.29.1...cipher-box-v0.30.0) (2026-03-26)


### Features

* desktop auto-updater, TEE file enrollment, and CI build workflow ([#360](https://github.com/FSM1/cipher-box/issues/360)) ([2bf8f4b](https://github.com/FSM1/cipher-box/commit/2bf8f4b1ef4e37e14b2b24905d70ea4d620874af))
* **phase-24:** bug fixes & test infrastructure ([#361](https://github.com/FSM1/cipher-box/issues/361)) ([2f1f93b](https://github.com/FSM1/cipher-box/commit/2f1f93ba7e7a9411e3a73b31e91992c95efd7bfa))
* **phase-26:** observability alerting & UX timeout tuning ([#366](https://github.com/FSM1/cipher-box/issues/366)) ([0bd7001](https://github.com/FSM1/cipher-box/commit/0bd70019c277f1f3544643a7763808bae0a720c5))
* **sdk-core:** extract vault key blob publish/load into SDK ([#368](https://github.com/FSM1/cipher-box/issues/368)) ([6d66be6](https://github.com/FSM1/cipher-box/commit/6d66be6843e6d5685c4bf740eea150e855fc2df0))


### Bug Fixes

* **ci:** add SDK_E2E_SECRET and Kubo CORS config for recovery E2E test ([d4f20e3](https://github.com/FSM1/cipher-box/commit/d4f20e3ffcf0574ce7aef14b006be751c5d5dfa7))
* **ci:** recovery E2E test auth and Kubo CORS ([#363](https://github.com/FSM1/cipher-box/issues/363)) ([d4f20e3](https://github.com/FSM1/cipher-box/commit/d4f20e3ffcf0574ce7aef14b006be751c5d5dfa7))
* **e2e:** fix IPNS record parsing and resolution order in recovery tool ([#369](https://github.com/FSM1/cipher-box/issues/369)) ([392ccc9](https://github.com/FSM1/cipher-box/commit/392ccc9404d6ce1b0764ec6ef99af5b3be41d89d))
* **e2e:** use CipherBox API for IPNS resolution in recovery test ([#364](https://github.com/FSM1/cipher-box/issues/364)) ([266656e](https://github.com/FSM1/cipher-box/commit/266656e1e7bab7a61ad8961c5be96a828cd22da5))
* **e2e:** use mock-ipns-routing for recovery IPNS resolution ([#365](https://github.com/FSM1/cipher-box/issues/365)) ([da46ee3](https://github.com/FSM1/cipher-box/commit/da46ee312c2346c7686d11208bc871816da6a0f4))

## [0.29.1](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.29.0...cipher-box-v0.29.1) (2026-03-25)

### Bug Fixes

- **ci:** exclude test files from TEE worker Docker build ([#358](https://github.com/FSM1/cipher-box/issues/358)) ([3535716](https://github.com/FSM1/cipher-box/commit/353571678609049fb39a254c1829217c564a134e))

## [0.29.0](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.28.0...cipher-box-v0.29.0) (2026-03-25)

### Features

- Phase 21 BYO-IPFS Node ([#346](https://github.com/FSM1/cipher-box/issues/346)) ([d2ef0c5](https://github.com/FSM1/cipher-box/commit/d2ef0c53bc9b614a47a63d019acc7b792b855ea0))
- phase 22 — performance baselines completion ([#355](https://github.com/FSM1/cipher-box/issues/355)) ([25bc1b3](https://github.com/FSM1/cipher-box/commit/25bc1b35fb69cb28c350a155b5b7b42104f4f5d0))

## [0.28.0](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.27.0...cipher-box-v0.28.0) (2026-03-25)

### Features

- extract Rust SDK as five workspace crates ([#352](https://github.com/FSM1/cipher-box/issues/352)) ([34bce7b](https://github.com/FSM1/cipher-box/commit/34bce7bfd40170f0fb080f68f50a0e8cb37704cf))

### Bug Fixes

- **test:** match actual bin publish log message in Windows E2E ([#354](https://github.com/FSM1/cipher-box/issues/354)) ([6881294](https://github.com/FSM1/cipher-box/commit/6881294c6a71b2e0a04f4d23ac4a773f33a29891))

## [0.27.0](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.26.6...cipher-box-v0.27.0) (2026-03-24)

### Features

- vault blob v2 migration — zero-knowledge server ([#344](https://github.com/FSM1/cipher-box/issues/344)) ([6aa4114](https://github.com/FSM1/cipher-box/commit/6aa4114bd57a339d28c2e95be0d544e62aef11c2))

### Bug Fixes

- deduplicate session restore race conditions on page reload ([#350](https://github.com/FSM1/cipher-box/issues/350)) ([1a873de](https://github.com/FSM1/cipher-box/commit/1a873de894a8784d8f7ec0a5f433a418f619df58))
- prevent duplicate folder_ipns row on vault init ([#351](https://github.com/FSM1/cipher-box/issues/351)) ([a955f86](https://github.com/FSM1/cipher-box/commit/a955f86f1fea94d7f3302defe1ec3647f51d60db))
- separate vault key blob from root folder IPNS name ([#349](https://github.com/FSM1/cipher-box/issues/349)) ([f04ba16](https://github.com/FSM1/cipher-box/commit/f04ba16ea099b16d13cc3c846e979ee461bd966d))

## [0.26.6](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.26.5...cipher-box-v0.26.6) (2026-03-24)

### Bug Fixes

- **ci:** fix load test workflow for staging runs ([#337](https://github.com/FSM1/cipher-box/issues/337)) ([c13c060](https://github.com/FSM1/cipher-box/commit/c13c060001bc574ea346a407ef77efd1de39e3c6))

### Performance Improvements

- optimize IPFS upload with concurrent pins and pebbleds datastore ([#342](https://github.com/FSM1/cipher-box/issues/342)) ([8f8f03f](https://github.com/FSM1/cipher-box/commit/8f8f03fa64c5aba91e8dc72c5b8dc67fd0b629d5))

## [0.26.5](https://github.com/FSM1/cipher-box/compare/cipher-box-v0.26.4...cipher-box-v0.26.5) (2026-03-23)

### Bug Fixes

- **ci:** use include-component-in-tag for root release-please package ([#333](https://github.com/FSM1/cipher-box/issues/333)) ([cb749fb](https://github.com/FSM1/cipher-box/commit/cb749fbcae0154c2da85746e4471907494c6e523))

## [0.26.4](https://github.com/FSM1/cipher-box/compare/v0.26.3...v0.26.4) (2026-03-23)

### Bug Fixes

- **ci:** set explicit empty component for root release-please package ([#330](https://github.com/FSM1/cipher-box/issues/330)) ([4fb0ace](https://github.com/FSM1/cipher-box/commit/4fb0acede557880869d0b796bf44d35a148c36ca))

## [0.26.3](https://github.com/FSM1/cipher-box/compare/v0.26.2...v0.26.3) (2026-03-23)

### Bug Fixes

- **docker:** use raw byte count for SOMEGUY_LIBP2P_MAX_MEMORY ([#328](https://github.com/FSM1/cipher-box/issues/328)) ([89c11c0](https://github.com/FSM1/cipher-box/commit/89c11c0454a99ecc9a8dfc0ceff65e707e01655f))

## [0.26.2](https://github.com/FSM1/cipher-box/compare/v0.26.1...v0.26.2) (2026-03-23)

### Bug Fixes

- **ci:** change staging tag format to avoid release-please collision ([#326](https://github.com/FSM1/cipher-box/issues/326)) ([293019b](https://github.com/FSM1/cipher-box/commit/293019b8cac00e8770b90c18a8881d0410c6df55))

## [0.26.1](https://github.com/FSM1/cipher-box/compare/v0.26.0...v0.26.1) (2026-03-23)

### Bug Fixes

- **docker:** restore someguy sidecar with corrected IPNS config ([#325](https://github.com/FSM1/cipher-box/issues/325)) ([0e9cb1e](https://github.com/FSM1/cipher-box/commit/0e9cb1e0e1315720bc0685d60b441d8fdf0ce4b5))

### Build System

- **ci,docker:** add release-please changelog-sections and remove broken someguy sidecar ([#322](https://github.com/FSM1/cipher-box/issues/322)) ([e806cb9](https://github.com/FSM1/cipher-box/commit/e806cb9b198c5db3c31a5498b1c2b3ccb75d49fd))
- **docker:** upgrade Kubo from v0.34.0 to v0.40.0 ([#321](https://github.com/FSM1/cipher-box/issues/321)) ([c2590eb](https://github.com/FSM1/cipher-box/commit/c2590eb59f12e951f2f1b106c666f20b9359508d))

## [0.26.0](https://github.com/FSM1/cipher-box/compare/v0.25.2...v0.26.0) (2026-03-22)

### Features

- **test:** add SDK-driven E2E and load test suites ([#318](https://github.com/FSM1/cipher-box/issues/318)) ([02ef044](https://github.com/FSM1/cipher-box/commit/02ef044ac1266064983c1122f6acefc601ec9865))

### Bug Fixes

- **ci:** set release-please title pattern to 'chore: release v${version}' ([9cdea31](https://github.com/FSM1/cipher-box/commit/9cdea31da5e6cd7f2f26ac0311aeebf6b980a080))
- **ci:** set release-please title pattern to use version instead of component ([#317](https://github.com/FSM1/cipher-box/issues/317)) ([9cdea31](https://github.com/FSM1/cipher-box/commit/9cdea31da5e6cd7f2f26ac0311aeebf6b980a080))

## [0.25.2](https://github.com/FSM1/cipher-box/compare/v0.25.1...v0.25.2) (2026-03-22)

### Bug Fixes

- **api:** make delegated routing publish fire-and-forget ([#308](https://github.com/FSM1/cipher-box/issues/308)) ([e49973a](https://github.com/FSM1/cipher-box/commit/e49973a9666162b93567ea7f60b16678d4398c25))
- **ci:** add bootstrap-sha to skip old unparseable release PRs ([#311](https://github.com/FSM1/cipher-box/issues/311)) ([23fecee](https://github.com/FSM1/cipher-box/commit/23feceed4ac2005f7f1d3b092c1532bb8f442774))
- **ci:** remove custom title pattern, use release-please default ([#312](https://github.com/FSM1/cipher-box/issues/312)) ([b865863](https://github.com/FSM1/cipher-box/commit/b865863d3808e6d7036733249a9365e79bd38caa))
- **ci:** remove packages/crypto from release-please extra-files ([#316](https://github.com/FSM1/cipher-box/issues/316)) ([8f42601](https://github.com/FSM1/cipher-box/commit/8f42601576391ad02a3d50b627456b301ccdf792))
- **ci:** scope API client drift check to generated paths only ([#310](https://github.com/FSM1/cipher-box/issues/310)) ([f78a87d](https://github.com/FSM1/cipher-box/commit/f78a87d3449533c971e43598946e064fd41dbf18))

## [0.25.1](https://github.com/FSM1/cipher-box/compare/v0.25.0...v0.25.1) (2026-03-21)

### Bug Fixes

- **ci:** remove stale workspace package from API Dockerfile ([#305](https://github.com/FSM1/cipher-box/issues/305)) ([1634028](https://github.com/FSM1/cipher-box/commit/1634028a36fbc44cfc080b450e1ac4bf62a9a678))

## [0.25.0](https://github.com/FSM1/cipher-box/compare/v0.24.2...v0.25.0) (2026-03-21)

### Features

- extract core crypto SDK as shared packages ([#296](https://github.com/FSM1/cipher-box/issues/296)) ([2cdc3fb](https://github.com/FSM1/cipher-box/commit/2cdc3fb3675d9c092e8ec9e5493982cc67f21822))
- IPNS resolution improvement with Someguy sidecar and latency metrics ([#284](https://github.com/FSM1/cipher-box/issues/284)) ([c1c96de](https://github.com/FSM1/cipher-box/commit/c1c96de3048471a88b30be42669a532f41d56eb3))

### Bug Fixes

- **ci:** build new shared packages before web/desktop in all workflows ([95a511e](https://github.com/FSM1/cipher-box/commit/95a511eadb0216c89b68a9b5441fd374afc76d42))
- **ci:** build shared packages before web/desktop in all workflows ([#299](https://github.com/FSM1/cipher-box/issues/299)) ([95a511e](https://github.com/FSM1/cipher-box/commit/95a511eadb0216c89b68a9b5441fd374afc76d42))
- **docker:** use bytes for someguy LIBP2P_MAX_MEMORY flag ([#290](https://github.com/FSM1/cipher-box/issues/290)) ([51c22c7](https://github.com/FSM1/cipher-box/commit/51c22c783142306efa13f247da4a58224685aab2))
- **e2e:** eliminate all Zustand store access from E2E tests ([#304](https://github.com/FSM1/cipher-box/issues/304)) ([43d7848](https://github.com/FSM1/cipher-box/commit/43d784839458fbed06bd19935cdbfd4c30dce8b5))
- **web:** remove isLoaded check from ensureFolderRegistered guard ([#301](https://github.com/FSM1/cipher-box/issues/301)) ([e6fe6ee](https://github.com/FSM1/cipher-box/commit/e6fe6eeab96ce42e2bdcada5d85c0e0f2720bd22))
- **web:** use static import for vault store in \_\_E2E helpers ([#303](https://github.com/FSM1/cipher-box/issues/303)) ([a09b502](https://github.com/FSM1/cipher-box/commit/a09b5024823ca93b5fdd34b013f3a477499f8b1f))

## [0.24.2](https://github.com/FSM1/cipher-box/compare/v0.24.1...v0.24.2) (2026-03-07)

### Bug Fixes

- strip trailing slash from GRAFANA_URL ([#285](https://github.com/FSM1/cipher-box/issues/285)) ([09ced7d](https://github.com/FSM1/cipher-box/commit/09ced7dd6a948f2ef3a56758cf2924ca0bf3807f))
- strip trailing slash from GRAFANA_URL to prevent 301 redirect ([09ced7d](https://github.com/FSM1/cipher-box/commit/09ced7dd6a948f2ef3a56758cf2924ca0bf3807f))

## [0.24.1](https://github.com/FSM1/cipher-box/compare/v0.24.0...v0.24.1) (2026-03-07)

### Bug Fixes

- auto-provision Grafana dashboard on staging deploy ([#282](https://github.com/FSM1/cipher-box/issues/282)) ([904663b](https://github.com/FSM1/cipher-box/commit/904663b399f6822408b053adef52e42736fa3d5f))

## [0.24.0](https://github.com/FSM1/cipher-box/compare/v0.23.1...v0.24.0) (2026-03-07)

### Features

- add performance instrumentation for IPFS/IPNS and TEE operations ([#281](https://github.com/FSM1/cipher-box/issues/281)) ([509188d](https://github.com/FSM1/cipher-box/commit/509188dcee2b63c0c12eee61887ba928c3523818))

### Bug Fixes

- remove project-level statusLine config ([#276](https://github.com/FSM1/cipher-box/issues/276)) ([a6878a4](https://github.com/FSM1/cipher-box/commit/a6878a47e21e273645fac46c50c52d96692a1fad))

## [0.23.1](https://github.com/FSM1/cipher-box/compare/v0.23.0...v0.23.1) (2026-03-05)

### Bug Fixes

- **17.1:** close bin integration gaps - CID unpinning + Windows bin ([#268](https://github.com/FSM1/cipher-box/issues/268)) ([15a7ece](https://github.com/FSM1/cipher-box/commit/15a7ece0892fad0b9bb7447a8487d548449e4dd4))
- **ci:** use query param instead of -f flag in codecov-base gh api call ([f1cadfa](https://github.com/FSM1/cipher-box/commit/f1cadfaff4c25ca130d78bb8efc0cb3674711de5))
- **desktop:** fix Windows FUSE overwrite race and bin E2E test ([#271](https://github.com/FSM1/cipher-box/issues/271)) ([42bbdd7](https://github.com/FSM1/cipher-box/commit/42bbdd74075bd2d8854b4e6af77354f6a9dd2982))
- **e2e:** clear file input before setInputFiles to fix TC08 ([#270](https://github.com/FSM1/cipher-box/issues/270)) ([ec34d0a](https://github.com/FSM1/cipher-box/commit/ec34d0ad8343174aa95d4be0e355505515fd8419))
- **e2e:** clear file input before setInputFiles to fix TC08 re-upload ([ec34d0a](https://github.com/FSM1/cipher-box/commit/ec34d0ad8343174aa95d4be0e355505515fd8419))
- **security:** harden auth and sharing subsystems ([#267](https://github.com/FSM1/cipher-box/issues/267)) ([4f53611](https://github.com/FSM1/cipher-box/commit/4f536118efa67d48c6d59cc9b40e05121e076dd8))
- **web:** clear share and quota stores on logout ([#265](https://github.com/FSM1/cipher-box/issues/265)) ([11dada9](https://github.com/FSM1/cipher-box/commit/11dada95bef89b7f91ea61a2e6e9b6e74db0d040))

## [0.23.0](https://github.com/FSM1/cipher-box/compare/v0.22.0...v0.23.0) (2026-03-04)

### Features

- Phase 17 — Recycle Bin ([#262](https://github.com/FSM1/cipher-box/issues/262)) ([c0af622](https://github.com/FSM1/cipher-box/commit/c0af6225a7bf8b49ae4ab04804eed6b6484fd3bf))

## [0.22.0](https://github.com/FSM1/cipher-box/compare/v0.21.9...v0.22.0) (2026-03-03)

### Features

- Phase 16 — conflict detection via optimistic concurrency ([#253](https://github.com/FSM1/cipher-box/issues/253)) ([f864e50](https://github.com/FSM1/cipher-box/commit/f864e500aab39aaeea88f6a68f449a0c057005ea))

### Bug Fixes

- **api:** start new IPNS entries at seq 1 to match client expectation ([#255](https://github.com/FSM1/cipher-box/issues/255)) ([493111d](https://github.com/FSM1/cipher-box/commit/493111d64aedcc15e2039e80937da3d9910f7961))
- **ci:** include run ID in release gate success message ([#260](https://github.com/FSM1/cipher-box/issues/260)) ([f929643](https://github.com/FSM1/cipher-box/commit/f9296435f4c0f1964c53ec4d8159cf4c0214394b))
- **ci:** prevent bash -e from killing release gate on skipped desktop tests ([#259](https://github.com/FSM1/cipher-box/issues/259)) ([13d805f](https://github.com/FSM1/cipher-box/commit/13d805fb5187663523d82f4412b45ca62272de49))
- **ci:** prevent bash -e from killing script on run_executed_tests ([13d805f](https://github.com/FSM1/cipher-box/commit/13d805fb5187663523d82f4412b45ca62272de49))
- **ci:** verify desktop E2E jobs actually ran in release gate ([#258](https://github.com/FSM1/cipher-box/issues/258)) ([5b641ca](https://github.com/FSM1/cipher-box/commit/5b641caa5746b41ceabf8e358a1a216626796cad))
- **web:** update sequence numbers after single-item folder mutations ([#256](https://github.com/FSM1/cipher-box/issues/256)) ([e7e8f5f](https://github.com/FSM1/cipher-box/commit/e7e8f5fb7b1612db6892c9e046fdece89ad011bb))

## [0.21.9](https://github.com/FSM1/cipher-box/compare/v0.21.8...v0.21.9) (2026-03-03)

### Bug Fixes

- **ci:** poll for E2E completion in release gate ([#252](https://github.com/FSM1/cipher-box/issues/252)) ([308619f](https://github.com/FSM1/cipher-box/commit/308619fbda788603fa47bf7052728cb1fa40d7c5))
- **e2e:** use Edit instead of Preview for text files in sharing tests ([#250](https://github.com/FSM1/cipher-box/issues/250)) ([ef90514](https://github.com/FSM1/cipher-box/commit/ef9051473d2dc816988148fe389d15ba7f87bc74))

## [0.21.8](https://github.com/FSM1/cipher-box/compare/v0.21.7...v0.21.8) (2026-03-02)

### Bug Fixes

- **ci:** use explicit SHA for paths-filter ref in desktop E2E ([#244](https://github.com/FSM1/cipher-box/issues/244)) ([24570e8](https://github.com/FSM1/cipher-box/commit/24570e8b5f5d90dd44ee2fa7df9901fd3499cac9))

## [0.21.7](https://github.com/FSM1/cipher-box/compare/v0.21.6...v0.21.7) (2026-03-02)

### Bug Fixes

- **ci:** resolve parent SHA for paths-filter base in desktop E2E ([e5afc27](https://github.com/FSM1/cipher-box/commit/e5afc279b81af5afd6204fd2cd741b814b08ff03))
- **ci:** resolve parent SHA for paths-filter in desktop E2E ([#242](https://github.com/FSM1/cipher-box/issues/242)) ([e5afc27](https://github.com/FSM1/cipher-box/commit/e5afc279b81af5afd6204fd2cd741b814b08ff03))

## [0.21.6](https://github.com/FSM1/cipher-box/compare/v0.21.5...v0.21.6) (2026-03-02)

### Bug Fixes

- **ci:** fix desktop E2E warnings and gate staging on E2E results ([#240](https://github.com/FSM1/cipher-box/issues/240)) ([fec66f7](https://github.com/FSM1/cipher-box/commit/fec66f747428b1a4a9a129aaadb7c51d19514cec))

## [0.21.5](https://github.com/FSM1/cipher-box/compare/v0.21.4...v0.21.5) (2026-03-02)

### Bug Fixes

- **ci:** pre-create GitHub release to avoid desktop build race ([#238](https://github.com/FSM1/cipher-box/issues/238)) ([37e46ec](https://github.com/FSM1/cipher-box/commit/37e46ec07f93855060962a1b987532515a059f25))
- **ci:** pre-create GitHub release to avoid race between desktop builds ([37e46ec](https://github.com/FSM1/cipher-box/commit/37e46ec07f93855060962a1b987532515a059f25))

## [0.21.4](https://github.com/FSM1/cipher-box/compare/v0.21.3...v0.21.4) (2026-03-02)

### Bug Fixes

- **ci:** use backslash paths for msiexec in WinFsp install ([#236](https://github.com/FSM1/cipher-box/issues/236)) ([2d3ec01](https://github.com/FSM1/cipher-box/commit/2d3ec0166d44a6d3823f81caa612fe1cb714cb4f))

## [0.21.3](https://github.com/FSM1/cipher-box/compare/v0.21.2...v0.21.3) (2026-03-01)

### Bug Fixes

- **ci:** write WinFsp registry key for winfsp-sys build script ([#234](https://github.com/FSM1/cipher-box/issues/234)) ([db84431](https://github.com/FSM1/cipher-box/commit/db84431691f55fbeda3e3fbba21bd714231b73a6))

## [0.21.2](https://github.com/FSM1/cipher-box/compare/v0.21.1...v0.21.2) (2026-03-01)

### Bug Fixes

- **ci:** fix Windows desktop staging build and add Linux desktop build ([#232](https://github.com/FSM1/cipher-box/issues/232)) ([62d8319](https://github.com/FSM1/cipher-box/commit/62d8319079dbca3289c0bf401ea241e1b84eee2a))

## [0.21.1](https://github.com/FSM1/cipher-box/compare/v0.21.0...v0.21.1) (2026-03-01)

### Bug Fixes

- **ci:** fix desktop E2E failures on macOS and Linux ([#228](https://github.com/FSM1/cipher-box/issues/228)) ([dbc4e3d](https://github.com/FSM1/cipher-box/commit/dbc4e3d4459268b03f293dc90f2abb29c6382ae6))
- **ci:** fix desktop E2E on all three platforms ([#230](https://github.com/FSM1/cipher-box/issues/230)) ([232e7e8](https://github.com/FSM1/cipher-box/commit/232e7e8fecc90f9ddb808d77801a5c1791113609))
- desktop E2E tests pass on all platforms ([#231](https://github.com/FSM1/cipher-box/issues/231)) ([30bbaa4](https://github.com/FSM1/cipher-box/commit/30bbaa4f39af4edaa26fd2200d8faea496ee17e4))

## [0.21.0](https://github.com/FSM1/cipher-box/compare/v0.20.0...v0.21.0) (2026-03-01)

### Features

- cross-platform desktop E2E testing - phase 11.4 ([#223](https://github.com/FSM1/cipher-box/issues/223)) ([c8329c6](https://github.com/FSM1/cipher-box/commit/c8329c65dc0a94eb50e22764d8a524f9e5ba3790))

### Bug Fixes

- **ci:** consolidate desktop E2E pipeline and add Rust tests ([#227](https://github.com/FSM1/cipher-box/issues/227)) ([52159dc](https://github.com/FSM1/cipher-box/commit/52159dc3ea229cb54f4ddbbcd48fb477c5bbd857))
- **ci:** symlink FUSE-T pkgconfig as fuse.pc for macOS builds ([#225](https://github.com/FSM1/cipher-box/issues/225)) ([f2cfb0f](https://github.com/FSM1/cipher-box/commit/f2cfb0f5d61d5a8ffcb7f6c246c0861607563a90))
- **ci:** use bash shell for find-run step in e2e-desktop ([#226](https://github.com/FSM1/cipher-box/issues/226)) ([a6e1c4c](https://github.com/FSM1/cipher-box/commit/a6e1c4c1b3088bfb3be4e484ed567bf1ae0cc9d9))
- **ci:** use bash shell for find-run step in e2e-desktop workflow ([a6e1c4c](https://github.com/FSM1/cipher-box/commit/a6e1c4c1b3088bfb3be4e484ed567bf1ae0cc9d9))

## [0.20.0](https://github.com/FSM1/cipher-box/compare/v0.19.5...v0.20.0) (2026-02-28)

### Features

- Linux desktop app with FUSE mount ([#220](https://github.com/FSM1/cipher-box/issues/220)) ([0f7cf95](https://github.com/FSM1/cipher-box/commit/0f7cf95d1ac5b672d4fb592bb78cdf723ff10f70))

## [0.19.5](https://github.com/FSM1/cipher-box/compare/v0.19.4...v0.19.5) (2026-02-27)

### Bug Fixes

- **api:** disable synchronize:true in all environments ([#216](https://github.com/FSM1/cipher-box/issues/216)) ([4b4a3b3](https://github.com/FSM1/cipher-box/commit/4b4a3b315e7f3588f3c815e4aed0faf7bd098010))

## [0.19.4](https://github.com/FSM1/cipher-box/compare/v0.19.3...v0.19.4) (2026-02-27)

### Bug Fixes

- **api,web:** MFA REQUIRED_SHARE auth flow + E2E test coverage ([#213](https://github.com/FSM1/cipher-box/issues/213)) ([133a541](https://github.com/FSM1/cipher-box/commit/133a541b792a11a32eeae620a806e39a4d1c39a5))

## [0.19.3](https://github.com/FSM1/cipher-box/compare/v0.19.2...v0.19.3) (2026-02-26)

### Bug Fixes

- **web:** MFA auth flow + Security tab display bugs ([#210](https://github.com/FSM1/cipher-box/issues/210)) ([9fd64d1](https://github.com/FSM1/cipher-box/commit/9fd64d14ef183699f59e21f32dfe3a8fef37dfbf))

## [0.19.2](https://github.com/FSM1/cipher-box/compare/v0.19.1...v0.19.2) (2026-02-26)

### Bug Fixes

- **api:** derive SIWE allowed domains from CORS origins ([#207](https://github.com/FSM1/cipher-box/issues/207)) ([4723063](https://github.com/FSM1/cipher-box/commit/4723063ecbfc15b66b031f4e1dd72b6e1fabcf00))

## [0.19.1](https://github.com/FSM1/cipher-box/compare/v0.19.0...v0.19.1) (2026-02-26)

### Bug Fixes

- **web:** MFA status detection false positive + auth architecture docs ([#205](https://github.com/FSM1/cipher-box/issues/205)) ([a395b82](https://github.com/FSM1/cipher-box/commit/a395b82dd5b6a9cdbc5d8a974d70d05c6e053ee7))

## [0.19.0](https://github.com/FSM1/cipher-box/compare/v0.18.0...v0.19.0) (2026-02-26)

### Features

- **web:** GDPR account deletion with IPFS unpin ([#202](https://github.com/FSM1/cipher-box/issues/202)) ([b981d41](https://github.com/FSM1/cipher-box/commit/b981d4127f20c5b240572b6cf43642a00bf8825d))

### Bug Fixes

- **ipns:** prefer DB cache over stale network IPNS records ([#203](https://github.com/FSM1/cipher-box/issues/203)) ([8d3c989](https://github.com/FSM1/cipher-box/commit/8d3c9898c6cd7267965a1894f0287a0b800f128d))

## [0.18.0](https://github.com/FSM1/cipher-box/compare/v0.17.0...v0.18.0) (2026-02-24)

### Features

- phase 15.1 client-side encrypted search ([#198](https://github.com/FSM1/cipher-box/issues/198)) ([3236f4a](https://github.com/FSM1/cipher-box/commit/3236f4af5599cd58ed290a418ae6266406e0b8b1))

### Bug Fixes

- **15.1:** prevent logout race in search index init ([#200](https://github.com/FSM1/cipher-box/issues/200)) ([11abcfa](https://github.com/FSM1/cipher-box/commit/11abcfa9b53861c25c3af0e4d575c066882848b2))

## [0.17.0](https://github.com/FSM1/cipher-box/compare/v0.16.0...v0.17.0) (2026-02-24)

### Features

- **ci:** add Windows desktop build to staging deployment ([d5b1c0a](https://github.com/FSM1/cipher-box/commit/d5b1c0a4b8c9a504365ea808180cc2aece74657b))

### Bug Fixes

- **ci:** add Windows desktop build to staging deployment ([#196](https://github.com/FSM1/cipher-box/issues/196)) ([d5b1c0a](https://github.com/FSM1/cipher-box/commit/d5b1c0a4b8c9a504365ea808180cc2aece74657b))

## [0.16.0](https://github.com/FSM1/cipher-box/compare/v0.15.1...v0.16.0) (2026-02-24)

### Features

- Phase 11 — Windows Desktop with WinFsp virtual filesystem ([#189](https://github.com/FSM1/cipher-box/issues/189)) ([7254721](https://github.com/FSM1/cipher-box/commit/72547215c4b0806f3e07ec8822803e0f2e1f6b0b))
- phase 15 link sharing ([#190](https://github.com/FSM1/cipher-box/issues/190)) ([76258cf](https://github.com/FSM1/cipher-box/commit/76258cf3ae063ef068aa7a52aa16582b321b8f12))

### Bug Fixes

- **ci:** prevent parenthesized text in commit subjects breaking Release Please ([#192](https://github.com/FSM1/cipher-box/issues/192)) ([1942b80](https://github.com/FSM1/cipher-box/commit/1942b800d669a4b905b7855fdde26406179675ea))

## [0.15.1](https://github.com/FSM1/cipher-box/compare/v0.15.0...v0.15.1) (2026-02-22)

### Bug Fixes

- **api:** add missing migration to create shares tables ([#186](https://github.com/FSM1/cipher-box/issues/186)) ([26c9d9c](https://github.com/FSM1/cipher-box/commit/26c9d9c8dfb91dca65ace15212fc78a30da5e788))

## [0.15.0](https://github.com/FSM1/cipher-box/compare/v0.14.0...v0.15.0) (2026-02-22)

### Features

- **14:** user-to-user encrypted sharing ([#183](https://github.com/FSM1/cipher-box/issues/183)) ([84a232d](https://github.com/FSM1/cipher-box/commit/84a232db4faf6fbfb3a354cdf847e75583073851))

## [0.14.0](https://github.com/FSM1/cipher-box/compare/v0.13.4...v0.14.0) (2026-02-21)

### Features

- switch file IPNS keys from deterministic HKDF to random ([#181](https://github.com/FSM1/cipher-box/issues/181)) ([7f01f98](https://github.com/FSM1/cipher-box/commit/7f01f9823e4f0f1bef180f5da7a927c97592c6e9))

## [0.13.4](https://github.com/FSM1/cipher-box/compare/v0.13.3...v0.13.4) (2026-02-21)

### Bug Fixes

- **crypto:** correct DeviceEntry publicKey validator from 130 to 64 hex chars ([f5be3cb](https://github.com/FSM1/cipher-box/commit/f5be3cb54889626ef36073d99d263f567679bef3))
- **crypto:** correct DeviceEntry publicKey validator length ([#178](https://github.com/FSM1/cipher-box/issues/178)) ([f5be3cb](https://github.com/FSM1/cipher-box/commit/f5be3cb54889626ef36073d99d263f567679bef3))

## [0.13.3](https://github.com/FSM1/cipher-box/compare/v0.13.2...v0.13.3) (2026-02-21)

### Bug Fixes

- **api,crypto:** address 6 security review findings ([#172](https://github.com/FSM1/cipher-box/issues/172)) ([d222bd0](https://github.com/FSM1/cipher-box/commit/d222bd0b323d582575d0ec6e0639bf96893d8d5b))
- **api,crypto:** address 6 security review findings (H-01, H-06, H-07, M-01, M-04, M-06) ([d222bd0](https://github.com/FSM1/cipher-box/commit/d222bd0b323d582575d0ec6e0639bf96893d8d5b))
- **desktop:** allow FUSE rename on SMB backend ([#174](https://github.com/FSM1/cipher-box/issues/174)) ([049ac7b](https://github.com/FSM1/cipher-box/commit/049ac7baede7ff1e6bce56f50653afb9c90dda83))

## [0.13.2](https://github.com/FSM1/cipher-box/compare/v0.13.1...v0.13.2) (2026-02-20)

### Bug Fixes

- **desktop:** wrap get_dev_key invoke in try/catch for release builds ([#167](https://github.com/FSM1/cipher-box/issues/167)) ([1699b5e](https://github.com/FSM1/cipher-box/commit/1699b5e73e60cb2a1c84dc61c86141def27c82d7))

## [0.13.1](https://github.com/FSM1/cipher-box/compare/v0.13.0...v0.13.1) (2026-02-19)

### Bug Fixes

- **web:** Implement lazy file size resolution from per-file IPNS metadata ([#163](https://github.com/FSM1/cipher-box/issues/163)) ([6197064](https://github.com/FSM1/cipher-box/commit/61970646d45f49af67167f811da2d2be4543223e))
- **web:** navigate back to parent on subfolder load failure ([#166](https://github.com/FSM1/cipher-box/issues/166)) ([ec24fab](https://github.com/FSM1/cipher-box/commit/ec24fab24ba6bc9138b4ecbcbe436b274e80d7be))

## [0.13.0](https://github.com/FSM1/cipher-box/compare/v0.12.2...v0.13.0) (2026-02-19)

### Features

- Phase 13 — File Versioning ([#161](https://github.com/FSM1/cipher-box/issues/161)) ([60a2dc7](https://github.com/FSM1/cipher-box/commit/60a2dc7ec12780c4c9f5e57d5116f440dd55e2d1))

## [0.12.2](https://github.com/FSM1/cipher-box/compare/v0.12.1...v0.12.2) (2026-02-19)

### Bug Fixes

- **ci:** install FUSE-T instead of macFUSE for desktop build ([#159](https://github.com/FSM1/cipher-box/issues/159)) ([d151a07](https://github.com/FSM1/cipher-box/commit/d151a07a51c6535e016f842fcd5f089621715c75))

## [0.12.1](https://github.com/FSM1/cipher-box/compare/v0.12.0...v0.12.1) (2026-02-19)

### Bug Fixes

- **ci:** grant contents:write to staging deploy for release upload ([#157](https://github.com/FSM1/cipher-box/issues/157)) ([0312006](https://github.com/FSM1/cipher-box/commit/0312006f84e32427cc68488dbeafe84e45c6ce64))

## [0.12.0](https://github.com/FSM1/cipher-box/compare/v0.11.1...v0.12.0) (2026-02-19)

### Features

- add desktop binary build to staging deploy ([#155](https://github.com/FSM1/cipher-box/issues/155)) ([2cee04e](https://github.com/FSM1/cipher-box/commit/2cee04e668a46b98d0d7d47b27386592aa5121a8))

### Bug Fixes

- **web:** improve mobile layout for file browser, toolbar, and footer ([#154](https://github.com/FSM1/cipher-box/issues/154)) ([f1fa934](https://github.com/FSM1/cipher-box/commit/f1fa934bd5227e18251461f84ee7dab035a461f0))

## [0.11.1](https://github.com/FSM1/cipher-box/compare/v0.11.0...v0.11.1) (2026-02-19)

### Bug Fixes

- **api:** save IPNS record to DB before delegated routing publish ([#151](https://github.com/FSM1/cipher-box/issues/151)) ([28edbc2](https://github.com/FSM1/cipher-box/commit/28edbc2dfc72d868148309dd66a80c0fd4a42530))
- **desktop:** session restore on cold start and Google OAuth storage fix ([#153](https://github.com/FSM1/cipher-box/issues/153)) ([967bcc0](https://github.com/FSM1/cipher-box/commit/967bcc0c569c871759e08752efb9657fc10bb941))

## [0.11.0](https://github.com/FSM1/cipher-box/compare/v0.10.2...v0.11.0) (2026-02-19)

### Features

- **desktop:** macOS desktop catch-up and hybrid metadata fix ([#148](https://github.com/FSM1/cipher-box/issues/148)) ([ccad747](https://github.com/FSM1/cipher-box/commit/ccad7472c768de4e9019d6b86c8ac084ed2ca3d4))
- remove v1 folder metadata, make v2 FilePointer canonical ([#150](https://github.com/FSM1/cipher-box/issues/150)) ([30d982c](https://github.com/FSM1/cipher-box/commit/30d982ce6da0c128205ce08e0806b7db03fc65e4))

## [0.10.2](https://github.com/FSM1/cipher-box/compare/v0.10.1...v0.10.2) (2026-02-18)

### Bug Fixes

- **ci:** enable test-login on staging API ([#146](https://github.com/FSM1/cipher-box/issues/146)) ([63b0a69](https://github.com/FSM1/cipher-box/commit/63b0a69fa31ebc545a29c0b9e67611c323ae2425))
- **web:** guard against undefined ipnsName in text editor and details dialog ([#145](https://github.com/FSM1/cipher-box/issues/145)) ([8105af9](https://github.com/FSM1/cipher-box/commit/8105af9b4c4666558d8e501228dee9d733b47536))

## [0.10.1](https://github.com/FSM1/cipher-box/compare/v0.10.0...v0.10.1) (2026-02-18)

### Bug Fixes

- **web:** align MFA enrollment banner with Pencil design ([#143](https://github.com/FSM1/cipher-box/issues/143)) ([24d5cd1](https://github.com/FSM1/cipher-box/commit/24d5cd1f705b12f5722f419abc74b936415215e6))

## [0.10.0](https://github.com/FSM1/cipher-box/compare/v0.9.2...v0.10.0) (2026-02-18)

### Features

- **api:** Add Prometheus metrics and Grafana dashboard for staging monitoring ([#141](https://github.com/FSM1/cipher-box/issues/141)) ([835d6c3](https://github.com/FSM1/cipher-box/commit/835d6c3b22182e73b3fe5828b9f3895249ef8f2a))

## [0.9.2](https://github.com/FSM1/cipher-box/compare/v0.9.1...v0.9.2) (2026-02-18)

### Bug Fixes

- **web:** Display file encryption metadata in details dialog ([#139](https://github.com/FSM1/cipher-box/issues/139)) ([a06fb22](https://github.com/FSM1/cipher-box/commit/a06fb226481d781caf0cf5fef089085d35c72d9c))

## [0.9.1](https://github.com/FSM1/cipher-box/compare/v0.9.0...v0.9.1) (2026-02-17)

### Bug Fixes

- **auth:** google OAuth brave fallback, wallet SIWE, sync & UX fixes ([#137](https://github.com/FSM1/cipher-box/issues/137)) ([6e3bbde](https://github.com/FSM1/cipher-box/commit/6e3bbde322d91ae100445a8f94a366eb7841dfe4))

## [0.9.0](https://github.com/FSM1/cipher-box/compare/v0.8.0...v0.9.0) (2026-02-17)

### Features

- **12.1:** AES-CTR streaming encryption for media files ([#135](https://github.com/FSM1/cipher-box/issues/135)) ([433ae35](https://github.com/FSM1/cipher-box/commit/433ae3550959e7dd75085f5b392091098d4a8a58))
- **12.2:** Encrypted Device Registry ([#125](https://github.com/FSM1/cipher-box/issues/125)) ([f3e354e](https://github.com/FSM1/cipher-box/commit/f3e354ea14e1341b159438848f10072828ee38d3))
- **12.3.1:** Pre-wipe identity cleanup ([#127](https://github.com/FSM1/cipher-box/issues/127)) ([6806153](https://github.com/FSM1/cipher-box/commit/6806153251e0b86b2da2901d75cb73e20b3c94f3))
- **12.4:** MFA + Cross-Device Approval ([#128](https://github.com/FSM1/cipher-box/issues/128)) ([e9de010](https://github.com/FSM1/cipher-box/commit/e9de010759e22b36efd3ea1bb1604105c34fded1))
- **12.5:** MFA polishing, UAT & E2E testing ([#131](https://github.com/FSM1/cipher-box/issues/131)) ([7bd4067](https://github.com/FSM1/cipher-box/commit/7bd4067b892ff708c39924d511887ece85ddd737))
- **12.6:** per-file IPNS metadata split ([#133](https://github.com/FSM1/cipher-box/issues/133)) ([dee300a](https://github.com/FSM1/cipher-box/commit/dee300aa3fb68f54225fa6d573e915423fbe5a8c))
- **12:** Core Kit Identity Provider Foundation ([#123](https://github.com/FSM1/cipher-box/issues/123)) ([a07cb26](https://github.com/FSM1/cipher-box/commit/a07cb266a3b92b0e3b4b2544c1f85e6e33c55df4))
- **design:** add /design:sync skill for detecting UI drift ([#122](https://github.com/FSM1/cipher-box/issues/122)) ([c75b127](https://github.com/FSM1/cipher-box/commit/c75b127eb8add60befc303260eca20de78f6d3e1))
- SIWE wallet login + unified identity (Phase 12.3) ([#126](https://github.com/FSM1/cipher-box/issues/126)) ([40e704b](https://github.com/FSM1/cipher-box/commit/40e704bb807bb0bde21a8715647809441297d096))
- **web:** move multi-select action bar to bottom of file list ([#117](https://github.com/FSM1/cipher-box/issues/117)) ([a888781](https://github.com/FSM1/cipher-box/commit/a8887810c5df5a21f86cbc68651d4849feda5069))

### Bug Fixes

- **auth:** resolve tab crash, JWKS persistence, and CoreKit auth UAT ([#130](https://github.com/FSM1/cipher-box/issues/130)) ([33a4667](https://github.com/FSM1/cipher-box/commit/33a466742690efe2d82e66ff6ad24b16971b118b))
- multi-select action bar button visibility ([#120](https://github.com/FSM1/cipher-box/issues/120)) ([d0d41ed](https://github.com/FSM1/cipher-box/commit/d0d41edea98ce9c9bad27de256fbb499b67fa75f))

## [0.8.0](https://github.com/FSM1/cipher-box/compare/v0.7.4...v0.8.0) (2026-02-12)

### Features

- Add multi-selection and batch operations to file browser ([#114](https://github.com/FSM1/cipher-box/issues/114)) ([c2fef51](https://github.com/FSM1/cipher-box/commit/c2fef510e8256107f1e9f5105f885d6930c71bd9))

### Bug Fixes

- **docker:** add database name to postgres healthcheck ([#116](https://github.com/FSM1/cipher-box/issues/116)) ([3f58d46](https://github.com/FSM1/cipher-box/commit/3f58d46255a17463540645c6e1c0cbeda98e846d))

## [0.7.4](https://github.com/FSM1/cipher-box/compare/v0.7.3...v0.7.4) (2026-02-11)

### Bug Fixes

- **web:** improve modal-close focus styling per PR review ([b1f5141](https://github.com/FSM1/cipher-box/commit/b1f5141190495550b6ea91121b3f49786537cd23))
- **web:** replace double-outline focus style with thicker border ([#111](https://github.com/FSM1/cipher-box/issues/111)) ([b1f5141](https://github.com/FSM1/cipher-box/commit/b1f5141190495550b6ea91121b3f49786537cd23))

## [0.7.3](https://github.com/FSM1/cipher-box/compare/v0.7.2...v0.7.3) (2026-02-11)

### Bug Fixes

- **web:** restore login footer with API status indicator ([#107](https://github.com/FSM1/cipher-box/issues/107)) ([3eaeb89](https://github.com/FSM1/cipher-box/commit/3eaeb8912f34de3d256837ec334d10780dd312c1))

## [0.7.2](https://github.com/FSM1/cipher-box/compare/v0.7.1...v0.7.2) (2026-02-11)

### Bug Fixes

- **web:** matrix rain effect visibility improvements ([#104](https://github.com/FSM1/cipher-box/issues/104)) ([e4ba8fb](https://github.com/FSM1/cipher-box/commit/e4ba8fb729fbed7ae72fac38b3d3c8fc80aa5f95))

## [0.7.1](https://github.com/FSM1/cipher-box/compare/v0.7.0...v0.7.1) (2026-02-11)

### Bug Fixes

- **web:** correct GitHub URL in app footer ([#102](https://github.com/FSM1/cipher-box/issues/102)) ([6531077](https://github.com/FSM1/cipher-box/commit/653107707f69d1f28e372662ce98bbef8a36c888))

## [0.7.0](https://github.com/FSM1/cipher-box/compare/v0.6.0...v0.7.0) (2026-02-11)

### Features

- add PDF, audio, and video file preview ([#100](https://github.com/FSM1/cipher-box/issues/100)) ([91da9b2](https://github.com/FSM1/cipher-box/commit/91da9b211ab7cd17d5bb6b397579e60414c520bc))
- add vault export, recovery tool, and export format documentation (Phase 10) ([#98](https://github.com/FSM1/cipher-box/issues/98)) ([9e7fe8e](https://github.com/FSM1/cipher-box/commit/9e7fe8e05b5c6a20eba443917ec65259c943b9b3))

## [0.6.0](https://github.com/FSM1/cipher-box/compare/v0.5.0...v0.6.0) (2026-02-11)

### Features

- phase 10 data portability ([#95](https://github.com/FSM1/cipher-box/issues/95)) ([787d881](https://github.com/FSM1/cipher-box/commit/787d88166f0d5158577cea2b7e52c35cdacae97d))

## [0.5.0](https://github.com/FSM1/cipher-box/compare/v0.4.0...v0.5.0) (2026-02-11)

### Features

- add image file preview to web UI file browser ([#94](https://github.com/FSM1/cipher-box/issues/94)) ([405142b](https://github.com/FSM1/cipher-box/commit/405142baa2508a703abd7cd6261ad7be1e6b8156))

### Bug Fixes

- em dash rendering in StagingBanner component ([#92](https://github.com/FSM1/cipher-box/issues/92)) ([6bd93ee](https://github.com/FSM1/cipher-box/commit/6bd93ee32966de452f35bd821c053b091dd2bf83))

## [0.4.0](https://github.com/FSM1/cipher-box/compare/v0.3.0...v0.4.0) (2026-02-11)

### Features

- add client-side IPNS signature validation ([#88](https://github.com/FSM1/cipher-box/issues/88)) ([8d18b65](https://github.com/FSM1/cipher-box/commit/8d18b6586068f5206d15c472c160656e4f41459e))
- add in-browser text file editor modal ([#87](https://github.com/FSM1/cipher-box/issues/87)) ([04bfc8c](https://github.com/FSM1/cipher-box/commit/04bfc8c1705e43b99ffa0389511ad597fe435571))
- add matrix background effect to logged-in app shell ([#91](https://github.com/FSM1/cipher-box/issues/91)) ([175f26e](https://github.com/FSM1/cipher-box/commit/175f26e6325c2d4655f2346b79e7182e63bb72bf))
- replace upload modal with collapsible bottom-right popup widget ([#90](https://github.com/FSM1/cipher-box/issues/90)) ([e43af30](https://github.com/FSM1/cipher-box/commit/e43af303a1cd6d1107060a04e3a7f42a762f81a6))

### Bug Fixes

- **ci:** chain tag-staging to deploy-staging via workflow_call ([#85](https://github.com/FSM1/cipher-box/issues/85)) ([1c41f6d](https://github.com/FSM1/cipher-box/commit/1c41f6ddf82f22992e6f03c7a2b70a04278980bc))
- file browser scrolling and layout overflow issues ([#89](https://github.com/FSM1/cipher-box/issues/89)) ([8d3f190](https://github.com/FSM1/cipher-box/commit/8d3f190853b03d094b633b79d3bf544895adcf4d))

## [0.3.0](https://github.com/FSM1/cipher-box/compare/v0.2.0...v0.3.0) (2026-02-10)

### Features

- add external file drag-and-drop from Finder/Explorer ([#78](https://github.com/FSM1/cipher-box/issues/78)) ([a776885](https://github.com/FSM1/cipher-box/commit/a77688557edc3e555d2c9402cd16133d63a8711a))
- add file/folder details modal with CID and encryption metadata ([#82](https://github.com/FSM1/cipher-box/issues/82)) ([96dca2d](https://github.com/FSM1/cipher-box/commit/96dca2d59c394df603aba33cbdbd00859d6790ed))

## [0.2.0](https://github.com/FSM1/cipher-box/compare/v0.1.2...v0.2.0) (2026-02-10)

### Features

- add staging environment warning banner ([#73](https://github.com/FSM1/cipher-box/issues/73)) ([e8b6079](https://github.com/FSM1/cipher-box/commit/e8b6079c731718f16a37f0896d29bcdf70ac9e5e))

### Bug Fixes

- fetch storage quota from backend on mount ([#76](https://github.com/FSM1/cipher-box/issues/76)) ([713292e](https://github.com/FSM1/cipher-box/commit/713292ef694ea89b481207da986b1e85dec8e62f))

## [0.1.2](https://github.com/FSM1/cipher-box/compare/v0.1.1...v0.1.2) (2026-02-09)

### Bug Fixes

- **ci:** restart Caddy after web deploy to fix stale bind mount ([#68](https://github.com/FSM1/cipher-box/issues/68)) ([9b85dd3](https://github.com/FSM1/cipher-box/commit/9b85dd3d902ad482e5e9fad72ddb1befd5878094))
- subfolder navigation after reload with E2E coverage ([#70](https://github.com/FSM1/cipher-box/issues/70)) ([836d53e](https://github.com/FSM1/cipher-box/commit/836d53ed9c5033d5e43c3cd40c94f70a48855e4a))

## [0.1.1](https://github.com/FSM1/cipher-box/compare/v0.1.0...v0.1.1) (2026-02-09)

### Bug Fixes

- show loading state during vault sync and fix stale closure bug ([#65](https://github.com/FSM1/cipher-box/issues/65)) ([b5e30e2](https://github.com/FSM1/cipher-box/commit/b5e30e2e6a613d0fe4a996c26ea364a36d1db726))
