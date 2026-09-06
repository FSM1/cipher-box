# Changelog

## [2.0.0](https://github.com/FSM1/cipher-box/compare/v1.0.0...v2.0.0) (2026-09-06)


### Features

* accept a delivered share and render the scope it grants ([#1586](https://github.com/FSM1/cipher-box/issues/1586)) ([ca95659](https://github.com/FSM1/cipher-box/commit/ca95659e1656c43eed400df6535e23bd37b52c63))
* add AAD-bound AES-256-GCM node-seal primitive with cross-language KAT ([#576](https://github.com/FSM1/cipher-box/issues/576)) ([65237ac](https://github.com/FSM1/cipher-box/commit/65237ac18b2ae2534304d57e0d08dec52a263d04))
* add the ephemeral-key invite blob and ledger expiry ([#1024](https://github.com/FSM1/cipher-box/issues/1024)) ([ac11236](https://github.com/FSM1/cipher-box/commit/ac11236402737c1c38af4de3a0daf5fecb7810ef))
* add the libfuse3 host adapter over the vendored fuser crate ([#1419](https://github.com/FSM1/cipher-box/issues/1419)) ([238e769](https://github.com/FSM1/cipher-box/commit/238e769fc48093dbf7822210ffc97c004ed21f5b))
* add the vault browser selection model and bound the session check ([#1122](https://github.com/FSM1/cipher-box/issues/1122)) ([99a88ed](https://github.com/FSM1/cipher-box/commit/99a88ed1bb7b18f92ac6dbb7c167c10d614984df))
* add the web introspection hook and the e2e smoke gate ([#1078](https://github.com/FSM1/cipher-box/issues/1078)) ([3d087d6](https://github.com/FSM1/cipher-box/commit/3d087d6736875c8c1aed6c79e35af5488307a139))
* add the web share dialog and contact-code import over the grant commands ([#1401](https://github.com/FSM1/cipher-box/issues/1401)) ([0ecc851](https://github.com/FSM1/cipher-box/commit/0ecc85192c2c3459783bc2039aa93731e78f8935))
* add the WinFsp host adapter ([#1550](https://github.com/FSM1/cipher-box/issues/1550)) ([72902ad](https://github.com/FSM1/cipher-box/commit/72902ad39351d01e44a7269bd38cdbe5c4431414))
* **api:** add a scheduled dormant-mailbox sweep ([#777](https://github.com/FSM1/cipher-box/issues/777)) ([4ea0a55](https://github.com/FSM1/cipher-box/commit/4ea0a557f1ccd9b9081aca676e7b317eb93b67af))
* **api:** add the hosted upload path with quota gate and registry traversal ([#695](https://github.com/FSM1/cipher-box/issues/695)) ([a822050](https://github.com/FSM1/cipher-box/commit/a8220501db12e92b665fcad0ff0f4f1af15d2c12))
* **api:** add the in-process republisher record cache and recovery ([#694](https://github.com/FSM1/cipher-box/issues/694)) ([30ac772](https://github.com/FSM1/cipher-box/commit/30ac77273d304f0c6b7f2dd87a0fc58f36ebfd9a))
* **api:** API CID and provider hardening with unpin module dedup ([#541](https://github.com/FSM1/cipher-box/issues/541)) ([106ee88](https://github.com/FSM1/cipher-box/commit/106ee8816339385c46f4352402c8a1acecb366bb))
* **api:** build identity auth, refresh rotation, and the ops baseline ([#661](https://github.com/FSM1/cipher-box/issues/661)) ([114e577](https://github.com/FSM1/cipher-box/commit/114e577e479f39b092312212dfabe9d66adaf962))
* **api:** build the mailbox with post, poll, ack, caps, and rate limits ([#668](https://github.com/FSM1/cipher-box/issues/668)) ([dbdf74d](https://github.com/FSM1/cipher-box/commit/dbdf74df2914e7a07d6e12581ced2d9093215609))
* **api:** implement the account hard-delete cascade ([#707](https://github.com/FSM1/cipher-box/issues/707)) ([6c900e9](https://github.com/FSM1/cipher-box/commit/6c900e9c2162414b108b4feb386d223423dc5028))
* approve a new device against a comparison value both screens derive ([#1606](https://github.com/FSM1/cipher-box/issues/1606)) ([6d1598a](https://github.com/FSM1/cipher-box/commit/6d1598a81415a7e1cdcb92b50e48db1b98b0720a))
* atomic IPNS publish-gate, tombstone, and share schema cutover ([#584](https://github.com/FSM1/cipher-box/issues/584)) ([a036a84](https://github.com/FSM1/cipher-box/commit/a036a84d4477937ee4a59e2c70c0673c5142edc8))
* author the cross-scope re-seal and cut the scope a move leaves ([#1679](https://github.com/FSM1/cipher-box/issues/1679)) ([1adc629](https://github.com/FSM1/cipher-box/commit/1adc6292be2d419fbc408b804e04b7f2459a0f2d))
* bind an auth challenge to the operation it authorises ([#1546](https://github.com/FSM1/cipher-box/issues/1546)) ([7e4a533](https://github.com/FSM1/cipher-box/commit/7e4a5331bd1a67a06800c82379d527257c44af7f))
* bind the recipient key and a cut epoch into the grant-set commitment ([#1604](https://github.com/FSM1/cipher-box/issues/1604)) ([aab5ba7](https://github.com/FSM1/cipher-box/commit/aab5ba701a842133361937aeab599cf68187938c))
* bound and verify preserved dead letters, gate the real keyring seam ([#1450](https://github.com/FSM1/cipher-box/issues/1450)) ([71c6e7e](https://github.com/FSM1/cipher-box/commit/71c6e7e28801fd069182d7312f15e5a1c955befb))
* bound readSealed in bytes and refuse an over-long envelope before the walk ([#1496](https://github.com/FSM1/cipher-box/issues/1496)) ([daf2276](https://github.com/FSM1/cipher-box/commit/daf22761680446ac59a78cf7778d5f024476d1c4))
* bound the facade command boundary, redact host-facing projections, and prefer an exact lookup ([#1613](https://github.com/FSM1/cipher-box/issues/1613)) ([470a427](https://github.com/FSM1/cipher-box/commit/470a4271cea32f7f2017473f1c7cabca39b1aaae))
* bound the grant section in bytes and let a carried field declare itself uncuttable ([#1454](https://github.com/FSM1/cipher-box/issues/1454)) ([be3bc3c](https://github.com/FSM1/cipher-box/commit/be3bc3c4552c96155b01ab300eca64c4b99a53a7)), closes [#1355](https://github.com/FSM1/cipher-box/issues/1355) [#1356](https://github.com/FSM1/cipher-box/issues/1356)
* bound the live stream tickets and surface a recoverable stream refusal ([#1146](https://github.com/FSM1/cipher-box/issues/1146)) ([4ee9cbf](https://github.com/FSM1/cipher-box/commit/4ee9cbfe36390e1f4c8413d6a3c12f125678ac15))
* bound the write body and bind the ascent public half into its signature ([#1368](https://github.com/FSM1/cipher-box/issues/1368)) ([3c2a735](https://github.com/FSM1/cipher-box/commit/3c2a73593a66a9897ea56a8091d18d30828370d8))
* branch a delete on the bin retention setting and cap the staged block on the publish leg ([#1618](https://github.com/FSM1/cipher-box/issues/1618)) ([bba5fca](https://github.com/FSM1/cipher-box/commit/bba5fca41b55f53d5abf029ceed327d024a47760))
* browser seam implementations and packages/client browser suite ([#670](https://github.com/FSM1/cipher-box/issues/670)) ([8e07b0e](https://github.com/FSM1/cipher-box/commit/8e07b0e01f9a6261ddc994a39585360c8244e209))
* build and serve the engine wasm artifact for apps/web ([#889](https://github.com/FSM1/cipher-box/issues/889)) ([4355562](https://github.com/FSM1/cipher-box/commit/43555629e21ce6aba73f9ce5e419b6c028124d17))
* build the crates/fuse operation core and host-adapter trait ([#885](https://github.com/FSM1/cipher-box/issues/885)) ([6a1f422](https://github.com/FSM1/cipher-box/commit/6a1f42204cbcb6131ae41c20e78fe26bf3ddac94))
* build the device-approval rendezvous on the API ([#1312](https://github.com/FSM1/cipher-box/issues/1312)) ([c0bbf8f](https://github.com/FSM1/cipher-box/commit/c0bbf8f9698a5068f76408adcb9dc0d696cf7a6a)), closes [#1317](https://github.com/FSM1/cipher-box/issues/1317)
* cancel an upload and collect orphaned staged blocks ([#950](https://github.com/FSM1/cipher-box/issues/950)) ([7a17c9f](https://github.com/FSM1/cipher-box/commit/7a17c9f4d553c49839838b61667dfba4db174078))
* carry a payload-bearing outcome out of the facade command surface ([#1151](https://github.com/FSM1/cipher-box/issues/1151)) ([f4d9ca5](https://github.com/FSM1/cipher-box/commit/f4d9ca5364cd2afc69e99ce5350db2b02506ee8a))
* CipherBox issues the identity token, and wallet login is a first login ([#1273](https://github.com/FSM1/cipher-box/issues/1273)) ([69a8a72](https://github.com/FSM1/cipher-box/commit/69a8a72523ea272fbb0596d04454b702ffffcf5f))
* classify recoverable engine refusals and bind the vault browser notice chrome ([#1100](https://github.com/FSM1/cipher-box/issues/1100)) ([67de38d](https://github.com/FSM1/cipher-box/commit/67de38df11f1ea0fb13907096f39e077dd8ca494))
* **client:** add tab leadership, broadcast transport, and failover ([#733](https://github.com/FSM1/cipher-box/issues/733)) ([921ba1f](https://github.com/FSM1/cipher-box/commit/921ba1f3ba1841f41c80927a010988cef6890d87))
* collapse the re-point channels to two and re-point the vault anchor ([#1542](https://github.com/FSM1/cipher-box/issues/1542)) ([797f716](https://github.com/FSM1/cipher-box/commit/797f7165c68fb59b93017b6780de210c84b0736a))
* consume the scope-exit rotation triggers ([#1103](https://github.com/FSM1/cipher-box/issues/1103)) ([9bbd1f4](https://github.com/FSM1/cipher-box/commit/9bbd1f41e9ee0b281292ef109b06c6c066cf86d0))
* convert invite claims into personal grants ([#1119](https://github.com/FSM1/cipher-box/issues/1119)) ([868f1e6](https://github.com/FSM1/cipher-box/commit/868f1e656acc110353482943e59f3a41cc5225fc))
* **core:** add content-seal primitive and content-DAG CID compute/verify ([#696](https://github.com/FSM1/cipher-box/issues/696)) ([46ed609](https://github.com/FSM1/cipher-box/commit/46ed609b425ae2f4bc6d80f4d70aa2f587876a61))
* **core:** add the settings-name KDF edge and regenerate the catalog KATs ([#874](https://github.com/FSM1/cipher-box/issues/874)) ([e9ca922](https://github.com/FSM1/cipher-box/commit/e9ca922e85311baf6ec2aec5073041708ba7634d)), closes [#861](https://github.com/FSM1/cipher-box/issues/861)
* **core:** crypto suite and frozen KDF edge catalog ([#664](https://github.com/FSM1/cipher-box/issues/664)) ([381f062](https://github.com/FSM1/cipher-box/commit/381f062a7f606d7aa8bd4cb89544426f99a5255c))
* **core:** land the det-CBOR codec, error surface, and KAT manifest spine ([#659](https://github.com/FSM1/cipher-box/issues/659)) ([63bbf30](https://github.com/FSM1/cipher-box/commit/63bbf309792f3b3a31d52777a356e6ea379bb0b5))
* **core:** owner write blob for cold-start write-seed recovery ([#792](https://github.com/FSM1/cipher-box/issues/792)) ([09ecaae](https://github.com/FSM1/cipher-box/commit/09ecaaedb264e5ec6a053b71b3d168f26de985a6))
* **core:** seal owner-local state under one kind-separated structure ([#1215](https://github.com/FSM1/cipher-box/issues/1215)) ([5301716](https://github.com/FSM1/cipher-box/commit/53017163c006788eff92752350e0deed10f9f886)), closes [#1232](https://github.com/FSM1/cipher-box/issues/1232)
* decide the Core Kit storage scope and gate its key set ([#1174](https://github.com/FSM1/cipher-box/issues/1174)) ([390a579](https://github.com/FSM1/cipher-box/commit/390a579b5536fdc98017ad774e7bf2960f21caa7))
* derive the genesis scope seeds so a first-run mint is idempotent ([#1274](https://github.com/FSM1/cipher-box/issues/1274)) ([a7cf06f](https://github.com/FSM1/cipher-box/commit/a7cf06f8d51593978c9042401d8ae3880f143e18))
* derive the owner writer pseudonym from a dedicated KDF edge ([#1211](https://github.com/FSM1/cipher-box/issues/1211)) ([21b78a1](https://github.com/FSM1/cipher-box/commit/21b78a13fa3128ace3ca06d8a234274828e98cfc))
* derive web auth state from the engine and let an engine-less leader yield ([#1342](https://github.com/FSM1/cipher-box/issues/1342)) ([e6ca68c](https://github.com/FSM1/cipher-box/commit/e6ca68c8bc2bf713b59b20eb26104e2b558fc5b1))
* desktop FUSE journal durability and at-rest safety ([#533](https://github.com/FSM1/cipher-box/issues/533)) ([b3511af](https://github.com/FSM1/cipher-box/commit/b3511afbd7011a0a5f151d47f2ec9bd1069262c1))
* **desktop:** give the shell a frontend that can log in ([#1277](https://github.com/FSM1/cipher-box/issues/1277)) ([ec78f47](https://github.com/FSM1/cipher-box/commit/ec78f47914c169aebcd671fc42112b2c1ff9270e))
* **desktop:** implement the desktop seam set against the conformance kits ([#666](https://github.com/FSM1/cipher-box/issues/666)) ([981e3fc](https://github.com/FSM1/cipher-box/commit/981e3fcf5d4bd03dbbd8a6167146caf5a0c8b706))
* **desktop:** link the engine so a signed-in shell reaches a vault ([#1279](https://github.com/FSM1/cipher-box/issues/1279)) ([c27c00b](https://github.com/FSM1/cipher-box/commit/c27c00b9e0b01b9b08d84b71a94b5ad0e0ecfca8))
* **desktop:** scaffold the Tauri shell and version surface ([#660](https://github.com/FSM1/cipher-box/issues/660)) ([95a8738](https://github.com/FSM1/cipher-box/commit/95a873814838782aeba0481118ce049963491f0f))
* **desktop:** sign in with the recovery phrase and keep names out of the fuser logs ([#1577](https://github.com/FSM1/cipher-box/issues/1577)) ([c7f4dd3](https://github.com/FSM1/cipher-box/commit/c7f4dd348ec80fdb8ab77acfa4e53a252261838c))
* edit the bin retention and neutralise a name a dialog reads ([#1634](https://github.com/FSM1/cipher-box/issues/1634)) ([1fec7d3](https://github.com/FSM1/cipher-box/commit/1fec7d3dc9b475d6fd34e66b3dccd42792ce9b02))
* enforce share-invite authorization and IPNS data-integrity in the API ([#599](https://github.com/FSM1/cipher-box/issues/599)) ([703bc00](https://github.com/FSM1/cipher-box/commit/703bc0083d42547cd2c0e747d79be82a0c318e78))
* **engine:** add a combined move intent op so a kernel rename is one entry ([#897](https://github.com/FSM1/cipher-box/issues/897)) ([069f214](https://github.com/FSM1/cipher-box/commit/069f2147b80a0e6542bbb5ce4538858732e1837e))
* **engine:** add cross-key atomic floor commit to the FloorStore seam ([#690](https://github.com/FSM1/cipher-box/issues/690)) ([d2f49bd](https://github.com/FSM1/cipher-box/commit/d2f49bd038f15917f3b348584972ccbee356be62))
* **engine:** add eager-set descendant-scope enumeration walk ([#744](https://github.com/FSM1/cipher-box/issues/744)) ([23bd468](https://github.com/FSM1/cipher-box/commit/23bd4684d47ccfba02e14fad2bb87524d6c37dc3))
* **engine:** add grant-section record layout and direct-child-scope index ([#741](https://github.com/FSM1/cipher-box/issues/741)) ([45e5ab8](https://github.com/FSM1/cipher-box/commit/45e5ab8a151f59a5c4e1b6d14019b0937faf8c73))
* **engine:** add grants ledger contact import and mailbox logic ([#735](https://github.com/FSM1/cipher-box/issues/735)) ([6cb7d1b](https://github.com/FSM1/cipher-box/commit/6cb7d1b244f197fe4fe599b8e8ec8b63ead4986d))
* **engine:** add owner-side read-grant creation ([#769](https://github.com/FSM1/cipher-box/issues/769)) ([0de14db](https://github.com/FSM1/cipher-box/commit/0de14dba3cc0c100ef86edb8e034ac221c9ce754))
* **engine:** add rotateScope read-plane root cut and scope-root re-seal helper ([#747](https://github.com/FSM1/cipher-box/issues/747)) ([c3659d6](https://github.com/FSM1/cipher-box/commit/c3659d665bb88fbe5bb0e9885abc1ce9c797a1c8))
* **engine:** add the content plane with chunk framing and verified reads ([#700](https://github.com/FSM1/cipher-box/issues/700)) ([92cb3a2](https://github.com/FSM1/cipher-box/commit/92cb3a223ed3e7c01ccfa6e3938841048b7f735c))
* **engine:** add the lazy-wave sweep epoch-lag convergence pass ([#753](https://github.com/FSM1/cipher-box/issues/753)) ([91a9f46](https://github.com/FSM1/cipher-box/commit/91a9f46d5a611ffb1fa961ca696360143d9dcfd7))
* **engine:** add the owner-only write-plane rotation primitive ([#760](https://github.com/FSM1/cipher-box/issues/760)) ([2e4a0f3](https://github.com/FSM1/cipher-box/commit/2e4a0f382ddb9ed79a34bd69efccb570427c2190))
* **engine:** add the owner-revocation eager cascade ([#755](https://github.com/FSM1/cipher-box/issues/755)) ([4f3d25e](https://github.com/FSM1/cipher-box/commit/4f3d25e80749bfcf4ca1c229385a4ab887bc4254))
* **engine:** adoption gate and floor law with sim harness ([#682](https://github.com/FSM1/cipher-box/issues/682)) ([d2c630b](https://github.com/FSM1/cipher-box/commit/d2c630b16ea0be6f56f82dd68ad4c96b2c3ea65d))
* **engine:** bind resolved scope-root records to the enumerated scope_id ([#779](https://github.com/FSM1/cipher-box/issues/779)) ([184bfc6](https://github.com/FSM1/cipher-box/commit/184bfc6d6a83e04d8062a6a08032d41dab1dc519))
* **engine:** build the gated resolve and publish pipeline and liveness jobs ([#692](https://github.com/FSM1/cipher-box/issues/692)) ([05f9fd5](https://github.com/FSM1/cipher-box/commit/05f9fd513e2f6bd1d04b2e4981abf0b672145487))
* **engine:** cap resolved-record envelope size at the fetch boundary ([#783](https://github.com/FSM1/cipher-box/issues/783)) ([0d79778](https://github.com/FSM1/cipher-box/commit/0d79778bfaafd2a376e75bb7651263736ac69a71))
* **engine:** classify drain failures into dead-letter, blocked, and abandonment ([#898](https://github.com/FSM1/cipher-box/issues/898)) ([3a3f124](https://github.com/FSM1/cipher-box/commit/3a3f1247f3d99c26ceddfe4b0921cae59b1d4cd7))
* **engine:** close the rotation trigger table and bind every cut to its scope ([#1318](https://github.com/FSM1/cipher-box/issues/1318)) ([06918b1](https://github.com/FSM1/cipher-box/commit/06918b1e7e5c31b42de53f1d9a8a3bd3e1378f7a))
* **engine:** compose the cold-start live-session data path ([#762](https://github.com/FSM1/cipher-box/issues/762)) ([9b17111](https://github.com/FSM1/cipher-box/commit/9b17111847957c57c65544b82566bd469e954076))
* **engine:** cut a write scope at grant time and publish a downgrade before its wave ([#1547](https://github.com/FSM1/cipher-box/issues/1547)) ([1df781d](https://github.com/FSM1/cipher-box/commit/1df781d516c5ece884ffc0a00df800b97812394d))
* **engine:** derive the cold-start session identity at start ([#758](https://github.com/FSM1/cipher-box/issues/758)) ([f642fc6](https://github.com/FSM1/cipher-box/commit/f642fc6003682b780f6e52a0010c02707d3ca2d2))
* **engine:** freeze the content format and land the engine-side KAT ([#877](https://github.com/FSM1/cipher-box/issues/877)) ([452cd6a](https://github.com/FSM1/cipher-box/commit/452cd6a45afc5d56e9c0618ed27c7d95c492fcfe))
* **engine:** give CreateInviteLink a production mint path ([#1321](https://github.com/FSM1/cipher-box/issues/1321)) ([b7ac92f](https://github.com/FSM1/cipher-box/commit/b7ac92fe5cd4fddf883c83a368a772cd1c3b4de5))
* **engine:** give the vault settings write plane a facade caller and a renewal slot ([#1298](https://github.com/FSM1/cipher-box/issues/1298)) ([abc9a8d](https://github.com/FSM1/cipher-box/commit/abc9a8d30bfc6ca5f79df36c3bbac1f04695cc6b))
* **engine:** implement the sync core with op queue, rebase, and pointers ([#706](https://github.com/FSM1/cipher-box/issues/706)) ([36cc216](https://github.com/FSM1/cipher-box/commit/36cc216f77ed1d37ad0c2a24a200df375fd6db68))
* **engine:** make an invite claim single-use so a redelivery cannot resurrect a cut grant ([#1314](https://github.com/FSM1/cipher-box/issues/1314)) ([f77eb85](https://github.com/FSM1/cipher-box/commit/f77eb85606c1f12c00858f732354286a85c426f4))
* **engine:** prefer last-known-good vault settings over defaults on a degraded load ([#934](https://github.com/FSM1/cipher-box/issues/934)) ([b07a11d](https://github.com/FSM1/cipher-box/commit/b07a11da9a25d8720dd55f58c3587657715d6a54))
* **engine:** publish a folder create end to end ([#886](https://github.com/FSM1/cipher-box/issues/886)) ([3c713b9](https://github.com/FSM1/cipher-box/commit/3c713b94364a462dcd5e13ec8f5498a0ed89141d))
* **engine:** publish a move from one shared folder into another ([#1765](https://github.com/FSM1/cipher-box/issues/1765)) ([d64132d](https://github.com/FSM1/cipher-box/commit/d64132d9698066b5105f485f4666638a123b2c23))
* **engine:** publish and load the owner-sealed bin index record ([#1582](https://github.com/FSM1/cipher-box/issues/1582)) ([6905989](https://github.com/FSM1/cipher-box/commit/69059893e89d6723cf92829d0c8b74fab0c6bacb))
* **engine:** publish and resolve the vault settings record ([#903](https://github.com/FSM1/cipher-box/issues/903)) ([7759cb6](https://github.com/FSM1/cipher-box/commit/7759cb6e176c3282ebc2f01ef08c4d0b571074b7))
* **engine:** publish the remaining four op kinds under the reference-ordering law ([#892](https://github.com/FSM1/cipher-box/issues/892)) ([223b33c](https://github.com/FSM1/cipher-box/commit/223b33cf1b29f8b04eb32c107d7dc19855aed14b))
* **engine:** re-seal a granted folder's interior into the scope the grant mints ([#1619](https://github.com/FSM1/cipher-box/issues/1619)) ([fe5b42e](https://github.com/FSM1/cipher-box/commit/fe5b42e4aae120a27a3f8c28b3d2d8296da8aea3))
* **engine:** reclaim descendant content under a reachability proof and cascade the doomed drop ([#1570](https://github.com/FSM1/cipher-box/issues/1570)) ([cf6ca85](https://github.com/FSM1/cipher-box/commit/cf6ca85eeca3bed8570d32928945b7306de727da))
* **engine:** restore, purge, and expire bin entries ([#1623](https://github.com/FSM1/cipher-box/issues/1623)) ([8a83907](https://github.com/FSM1/cipher-box/commit/8a8390796c99d73e77b5d8af65c5d15196490a89))
* **engine:** scaffold seams, fakes, conformance kits, and the facade ([#662](https://github.com/FSM1/cipher-box/issues/662)) ([b5d6645](https://github.com/FSM1/cipher-box/commit/b5d6645dfaaba8248cf6ad6189bdbda33a182b9e))
* **engine:** serve a staged content version and re-decide placement while a session runs ([#1585](https://github.com/FSM1/cipher-box/issues/1585)) ([cdd51bf](https://github.com/FSM1/cipher-box/commit/cdd51bfed05a9413a83e7ca54d7b0689fd425127))
* **engine:** surface cold-start undecodable dead-letters ([#773](https://github.com/FSM1/cipher-box/issues/773)) ([8a50699](https://github.com/FSM1/cipher-box/commit/8a506997044d59e30cbe6cfc848d371421df6037))
* **engine:** wire the facade cold-start pipeline and live resolve-tick driver ([#789](https://github.com/FSM1/cipher-box/issues/789)) ([5856c5b](https://github.com/FSM1/cipher-box/commit/5856c5bd9754a566ccb99f17f4f3f436bee03608))
* **engine:** wire the liveness re-PUT scheduler into facade cold-start ([#739](https://github.com/FSM1/cipher-box/issues/739)) ([7bf8d05](https://github.com/FSM1/cipher-box/commit/7bf8d05836cbbd1a83933bafe592d8da3fc31382))
* **engine:** wire the rotation and grant facade command arms ([#1346](https://github.com/FSM1/cipher-box/issues/1346)) ([bac0d0c](https://github.com/FSM1/cipher-box/commit/bac0d0c74b059a85eb8e14abbec1bea400f43b40))
* enrol the settings record on a read and re-arm the genesis bin index ([#1676](https://github.com/FSM1/cipher-box/issues/1676)) ([982ed4a](https://github.com/FSM1/cipher-box/commit/982ed4a9a3d55ce77823316ef230386dd07fb65a))
* erase every durable seam and this device's auth state on forget ([#1477](https://github.com/FSM1/cipher-box/issues/1477)) ([423376f](https://github.com/FSM1/cipher-box/commit/423376f17f84b2d4c08b3ea3ac3d4a1ee3c371c6))
* expose the bin through the worker protocol ([#1630](https://github.com/FSM1/cipher-box/issues/1630)) ([f1cf88f](https://github.com/FSM1/cipher-box/commit/f1cf88fe4c4adecab538a3924a0213ca011df321))
* extract the login orchestration into a host-agnostic package ([#1276](https://github.com/FSM1/cipher-box/issues/1276)) ([102c25f](https://github.com/FSM1/cipher-box/commit/102c25ff672de64669eaff9d2b8e1e41d1bb97cb))
* FUSE and WinFsp Rust integration with grant-root awareness and SDK-owned read chain ([#594](https://github.com/FSM1/cipher-box/issues/594)) ([4b96aa9](https://github.com/FSM1/cipher-box/commit/4b96aa950b19591331445d65dfa81b6bc25d90b2))
* gate both accelerator read legs behind a Caddy forward_auth front and emit the missing ops metrics ([#1461](https://github.com/FSM1/cipher-box/issues/1461)) ([3773671](https://github.com/FSM1/cipher-box/commit/377367174c89db22da00febe93192a16774cae36))
* give an owner the invite-link surface and serve the app a CSP ([#1448](https://github.com/FSM1/cipher-box/issues/1448)) ([35ad21a](https://github.com/FSM1/cipher-box/commit/35ad21ac60fa2c12ad5b56fe19dfdeec5f426266))
* give the drain a two-ended scope with per-node plane resolution ([#1672](https://github.com/FSM1/cipher-box/issues/1672)) ([75d24a3](https://github.com/FSM1/cipher-box/commit/75d24a3536faf1a9f02f9e2d32ed7884d1b44257))
* give the mailbox the engine's own bearer and retire the Mailbox host seam ([#1501](https://github.com/FSM1/cipher-box/issues/1501)) ([20c7587](https://github.com/FSM1/cipher-box/commit/20c7587c3d6af28ac06e4a8558d8061da98e73c7))
* grant section, write-body, and structure signatures in core ([#675](https://github.com/FSM1/cipher-box/issues/675)) ([3ca7c44](https://github.com/FSM1/cipher-box/commit/3ca7c445519639ddfc84b950dcb7daaf36a7ddb8))
* hand out one opaque invite fragment and wire the claim path across the client ([#1435](https://github.com/FSM1/cipher-box/issues/1435)) ([aae4447](https://github.com/FSM1/cipher-box/commit/aae44471d1812c802cf0282b61c389e37a0865a9))
* hand-written engine API client, token lifecycle, and contract suite ([#671](https://github.com/FSM1/cipher-box/issues/671)) ([a3bfd18](https://github.com/FSM1/cipher-box/commit/a3bfd18703d5f096de8e9a1841b9ac0c715ac06f))
* harvest the v1 login UI and rewire it to the facade ([#911](https://github.com/FSM1/cipher-box/issues/911)) ([a20d53e](https://github.com/FSM1/cipher-box/commit/a20d53ec82a1f7829ad55819524f7eab8653293e))
* harvest the v1 vault browser read path over the snapshot adapter ([#971](https://github.com/FSM1/cipher-box/issues/971)) ([6ab2a3c](https://github.com/FSM1/cipher-box/commit/6ab2a3c2a9347e3ba9dd594c2dd20179d5f9579f))
* hold the read epoch each walked interior scope root sits at ([#1660](https://github.com/FSM1/cipher-box/issues/1660)) ([de9bdd4](https://github.com/FSM1/cipher-box/commit/de9bdd4b765db10d56e213f1273bb5877fa7204d))
* implement ManualRefresh as a forced nocache pass and retire the dead refresh-hint seam ([#1212](https://github.com/FSM1/cipher-box/issues/1212)) ([c390fe4](https://github.com/FSM1/cipher-box/commit/c390fe499d6e39323e1ddab60e5d796ef7094dac))
* implement the concrete cascade re-seal resolver over the real seams ([#1053](https://github.com/FSM1/cipher-box/issues/1053)) ([040a7ed](https://github.com/FSM1/cipher-box/commit/040a7ed4c624f3ce02a87cec0e1c1eaa268edf3c))
* implement the concrete rotation resolvers and publishers ([#1027](https://github.com/FSM1/cipher-box/issues/1027)) ([f995043](https://github.com/FSM1/cipher-box/commit/f99504333e8c47b658f7d5456786ab483d9daa51))
* implement the concrete WriteSubtreeResolver over the real seams ([#1116](https://github.com/FSM1/cipher-box/issues/1116)) ([879090c](https://github.com/FSM1/cipher-box/commit/879090c1d95af5ecccea6d1a64a19ab1b3c99f07))
* implement the fuse content write path over sealed spill files ([#1156](https://github.com/FSM1/cipher-box/issues/1156)) ([6d38a10](https://github.com/FSM1/cipher-box/commit/6d38a10780d2b689300ff04500e7c4759de7afd0))
* implement the fuse ranged read path and the plaintext chunk cache ([#1118](https://github.com/FSM1/cipher-box/issues/1118)) ([77ad6a7](https://github.com/FSM1/cipher-box/commit/77ad6a71ee988c55edc25d5436274f2d3cdedbf2))
* implement the write wave publisher over the real net seams ([#1101](https://github.com/FSM1/cipher-box/issues/1101)) ([28a2269](https://github.com/FSM1/cipher-box/commit/28a226998ead77f368bebf3d4734d6ccf87d2b59))
* integrate web client with node/v3 read and write runtime ([#588](https://github.com/FSM1/cipher-box/issues/588)) ([1fb8996](https://github.com/FSM1/cipher-box/commit/1fb8996a25947a0964b286ac44864f3e5e84e33c))
* IPNS records, name codec, and pointer payloads in core ([#676](https://github.com/FSM1/cipher-box/issues/676)) ([d36e682](https://github.com/FSM1/cipher-box/commit/d36e6827b5e97ede8c2d0e764d477ca3991fe227))
* kind-uniform envelope, AAD, and seal/unseal in core ([#673](https://github.com/FSM1/cipher-box/issues/673)) ([0ebbe5a](https://github.com/FSM1/cipher-box/commit/0ebbe5a59b3d4c5cd6a9f79bea4b07ed1fb9ddb9))
* land the grantee arm of the rotation net ([#1329](https://github.com/FSM1/cipher-box/issues/1329)) ([023e010](https://github.com/FSM1/cipher-box/commit/023e010a8798276e9f84ed8fa83a8e7d3fba6ce1))
* land the production received-shares store over the staging seam ([#1185](https://github.com/FSM1/cipher-box/issues/1185)) ([2d54ddc](https://github.com/FSM1/cipher-box/commit/2d54ddc7fb41832de77c46c2981e89665a2cd8b4))
* land the useSyncExternalStore snapshot adapter and Core Kit login handoff ([#899](https://github.com/FSM1/cipher-box/issues/899)) ([082662c](https://github.com/FSM1/cipher-box/commit/082662c6ab90c8376d5aaed022d9e99730e52b09))
* make core's child refs wipe their own plaintext and freeze identity-preimage separation as a KAT ([#1520](https://github.com/FSM1/cipher-box/issues/1520)) ([dc4f66d](https://github.com/FSM1/cipher-box/commit/dc4f66dcf7c98bd5e49e285de9994d21e52c722a))
* make the desktop mount a wake source and drive the tray from the engine ([#1500](https://github.com/FSM1/cipher-box/issues/1500)) ([8fb519f](https://github.com/FSM1/cipher-box/commit/8fb519ff2823792a629474ecd208358290c6c4c0))
* make the recovery phrase a working login path ([#1288](https://github.com/FSM1/cipher-box/issues/1288)) ([72c35d3](https://github.com/FSM1/cipher-box/commit/72c35d3d41e9344237aa48a50088450dd6c7335f))
* mint a read-scoped accelerator token instead of presenting the session JWT ([#1449](https://github.com/FSM1/cipher-box/issues/1449)) ([c070485](https://github.com/FSM1/cipher-box/commit/c0704857ef40f822dbadc192761e57a0141d211d))
* mint an invite link its own scope and give it a lifecycle ([#1411](https://github.com/FSM1/cipher-box/issues/1411)) ([fb823a8](https://github.com/FSM1/cipher-box/commit/fb823a826fce1985670d373373c3d9e80cdde04d))
* mint the bin index KDF edges and freeze its det-CBOR grammar ([#1560](https://github.com/FSM1/cipher-box/issues/1560)) ([91798ad](https://github.com/FSM1/cipher-box/commit/91798ad213174af0f38edd28ddecad98d4793138))
* mount and unmount the vault across the desktop session lifecycle ([1c9d05e](https://github.com/FSM1/cipher-box/commit/1c9d05e49988164b3e2d5fd4cdac269e7182ba16)), closes [#1377](https://github.com/FSM1/cipher-box/issues/1377)
* mount macOS on FUSE-T's SMB backend and give WinFsp its status table ([#1429](https://github.com/FSM1/cipher-box/issues/1429)) ([146fbb7](https://github.com/FSM1/cipher-box/commit/146fbb7f18220b1b7098bb350cada8122229d02d))
* move the SIWE challenge below the facade ([#943](https://github.com/FSM1/cipher-box/issues/943)) ([76c9e52](https://github.com/FSM1/cipher-box/commit/76c9e52f1fba795d52b482a266914d50fcf00df3))
* open the settings route, gate the share offer, and end a session in every tab ([#1502](https://github.com/FSM1/cipher-box/issues/1502)) ([3f860bf](https://github.com/FSM1/cipher-box/commit/3f860bf652eec130eb8bcaa627e36a92ce1ce28d))
* persist imported contacts and collapse the received-shares store to one key ([#1196](https://github.com/FSM1/cipher-box/issues/1196)) ([2a820e8](https://github.com/FSM1/cipher-box/commit/2a820e84593de33eb3522f21e7401acf67668a0e))
* pin and name registry with register-first and quota in the api ([#677](https://github.com/FSM1/cipher-box/issues/677)) ([d81527b](https://github.com/FSM1/cipher-box/commit/d81527b82b3a68b4584ed14860ac1d545d4748cf))
* port the details panel, add a text editor, and stream file reads ([#1105](https://github.com/FSM1/cipher-box/issues/1105)) ([a798ebf](https://github.com/FSM1/cipher-box/commit/a798ebf4e43bc83e637d0b80ee21500395e33580))
* profile every pipeline stage and give the migration window its slot ([#1406](https://github.com/FSM1/cipher-box/issues/1406)) ([7221d5c](https://github.com/FSM1/cipher-box/commit/7221d5cb1e60d2f839ebf812e6e186e72f52584f))
* project a facade snapshot and download read surface for the web client ([#811](https://github.com/FSM1/cipher-box/issues/811)) ([b91633b](https://github.com/FSM1/cipher-box/commit/b91633b351ace7b0e95b193447e2765141d44d83))
* provision a first-run vault so a fresh account can publish ([#1219](https://github.com/FSM1/cipher-box/issues/1219)) ([fbc8131](https://github.com/FSM1/cipher-box/commit/fbc813141af4a53e63cb73e4c79ff10920dfbc01))
* prune a local delete's detached subtree, seal per-owner staging bookkeeping, and normalize the strict comparator to NFC ([#1521](https://github.com/FSM1/cipher-box/issues/1521)) ([e007419](https://github.com/FSM1/cipher-box/commit/e007419808a6d7c92d9c57d31e4d264e5ba5b8e5))
* prune old versions and reclaim their bytes off a durable retire ledger ([#1158](https://github.com/FSM1/cipher-box/issues/1158)) ([17528aa](https://github.com/FSM1/cipher-box/commit/17528aabc15fed6120d173dc6a892f39077f8b6a))
* put grant-ledger recipient keys under owner authority ([#1344](https://github.com/FSM1/cipher-box/issues/1344)) ([4b4c998](https://github.com/FSM1/cipher-box/commit/4b4c998071d51fc7fbb3b4be2a8c7de5e2d7f4c6))
* put the desktop Core Kit store in keyring custody and revoke a logout at the API ([#1527](https://github.com/FSM1/cipher-box/issues/1527)) ([1f94678](https://github.com/FSM1/cipher-box/commit/1f94678ded15cbced2581bbc7ccf21463e6f3166))
* read vault settings back with quota chrome and manage account login methods ([#1536](https://github.com/FSM1/cipher-box/issues/1536)) ([9d0af2c](https://github.com/FSM1/cipher-box/commit/9d0af2c397b8da4ca7bf7ff0845fa3afdcb3b167))
* read-chain navigation, grants, and rotation engine in sdk-core ([#579](https://github.com/FSM1/cipher-box/issues/579)) ([7216797](https://github.com/FSM1/cipher-box/commit/7216797ed2d0fe83a214335de45b611efd3ec679))
* rebuild the sweep as an interior-node lazy wave over the real seams ([#1200](https://github.com/FSM1/cipher-box/issues/1200)) ([fcfa4b4](https://github.com/FSM1/cipher-box/commit/fcfa4b4778cdcfa3aab7acd580154ecb350294a6))
* recovery tool v3, vault-load guards, web UX and CI boundary guards ([#613](https://github.com/FSM1/cipher-box/issues/613)) ([cba7857](https://github.com/FSM1/cipher-box/commit/cba7857187d8aa6f92b02a0d4d88269f71f770ec))
* report the received-share list to a host and fix the vault-pointer cold start ([#1445](https://github.com/FSM1/cipher-box/issues/1445)) ([3d3ac0f](https://github.com/FSM1/cipher-box/commit/3d3ac0fc1a6668a8fd7ef702934f42cda24943c5))
* report upload progress on the op that drives it ([#925](https://github.com/FSM1/cipher-box/issues/925)) ([fa73c60](https://github.com/FSM1/cipher-box/commit/fa73c60f0a0feee2a0d06fcfa33e2894162c3e76))
* resolve the focus window's folders below the scope root ([#945](https://github.com/FSM1/cipher-box/issues/945)) ([a830c17](https://github.com/FSM1/cipher-box/commit/a830c17adf49323356648ff312c10bbc0e92da1a))
* rewrite TEE republish as a verify-in-enclave lease renewer ([#585](https://github.com/FSM1/cipher-box/issues/585)) ([ab209a9](https://github.com/FSM1/cipher-box/commit/ab209a9251752e1c317b9534c0c32fb465defd62))
* rewrite the staging dashboard for v2 and bind the front to this Cloudflare zone ([#1526](https://github.com/FSM1/cipher-box/issues/1526)) ([b906203](https://github.com/FSM1/cipher-box/commit/b906203dbbcc95fa5caf46b48d901a5e7c7cdfed))
* rotation soundness — content-key, inner-grant, concurrent-add, crash-safe resume ([#582](https://github.com/FSM1/cipher-box/issues/582)) ([4ad615a](https://github.com/FSM1/cipher-box/commit/4ad615aef3a9b89cf07ca6926def961fef34e2b8))
* rotation write-plane and re-mint durability with recipient-pubkey pinning ([#615](https://github.com/FSM1/cipher-box/issues/615)) ([27c4abe](https://github.com/FSM1/cipher-box/commit/27c4abec52ed7cdf0ce9d7147685b2bae97e16b5))
* run the FUSE-op TTL check and measure the desktop staging budget ([#1409](https://github.com/FSM1/cipher-box/issues/1409)) ([1a0a8ec](https://github.com/FSM1/cipher-box/commit/1a0a8ecffeed881ebf9c23259d12c409ed54231e))
* run the polled pointer consult, complete the grant, and expose the sharing read ([#1424](https://github.com/FSM1/cipher-box/issues/1424)) ([243c6ce](https://github.com/FSM1/cipher-box/commit/243c6ce74d6e194949988c63acd9da6281eaf3c1))
* scaffold the apps/web toolchain and the single EngineProvider ([#883](https://github.com/FSM1/cipher-box/issues/883)) ([8f1ac04](https://github.com/FSM1/cipher-box/commit/8f1ac04ebb5500643f1d77d1d821dc04fef52790))
* schedule the sweep, aggregate its buckets, and hold the granted-root pairing ([#1341](https://github.com/FSM1/cipher-box/issues/1341)) ([6e2b614](https://github.com/FSM1/cipher-box/commit/6e2b614738d5bc53e5ee506b534b74c2bdf767f4))
* SDK write-chain, write-revocation, bin re-link, and invite claim ([#583](https://github.com/FSM1/cipher-box/issues/583)) ([d81c1b4](https://github.com/FSM1/cipher-box/commit/d81c1b476805f7b6764e388604e3da657f7540f1))
* SDK-owned read chain and resolved folder listings ([#589](https://github.com/FSM1/cipher-box/issues/589)) ([6534c64](https://github.com/FSM1/cipher-box/commit/6534c642aacfd4755967ccbd622840610635b86c))
* seal the owner's contact book and land the invite-record store ([#1234](https://github.com/FSM1/cipher-box/issues/1234)) ([cf2bc77](https://github.com/FSM1/cipher-box/commit/cf2bc7719460404edd8e6e7b24bdefa5b56e68c4))
* serve COOP everywhere, generate the deployed policy, record an invite's scope ([#1489](https://github.com/FSM1/cipher-box/issues/1489)) ([091bae4](https://github.com/FSM1/cipher-box/commit/091bae40a9c859d4857bad963a8b9220997bdd1e))
* settle the BYO endpoint transport and address-range policy ([#932](https://github.com/FSM1/cipher-box/issues/932)) ([4f4f37a](https://github.com/FSM1/cipher-box/commit/4f4f37a70069f2f01ea58eece5a7617ee7021e97))
* share the React auth surfaces between the web app and the shell ([#1764](https://github.com/FSM1/cipher-box/issues/1764)) ([9f9abac](https://github.com/FSM1/cipher-box/commit/9f9abaccfbeb424df68fd152ac368b2ced667da2))
* signal a skipped republisher walk and cover the load scenarios ([#1283](https://github.com/FSM1/cipher-box/issues/1283)) ([818d513](https://github.com/FSM1/cipher-box/commit/818d5132a812ab9fbbee370cec38c87b71f4b7d5))
* source the read-accelerator bearer from the session and pin two guards ([#1243](https://github.com/FSM1/cipher-box/issues/1243)) ([892ca99](https://github.com/FSM1/cipher-box/commit/892ca99813b3930f81e168bf0878b17f5c44e711))
* strict fail-closed IPNS verification cutover across Rust, TS, and API ([#555](https://github.com/FSM1/cipher-box/issues/555)) ([03209e3](https://github.com/FSM1/cipher-box/commit/03209e3854e1309cde13c087a3f407568b17fcd7))
* surface fuse refusal paths and carry the over-budget cause ([#1287](https://github.com/FSM1/cipher-box/issues/1287)) ([b5b9d97](https://github.com/FSM1/cipher-box/commit/b5b9d97559c4b616b06c460040d71c978a7aa4ec))
* surface the held queue heads and follow a settings change the engine adopts ([#1749](https://github.com/FSM1/cipher-box/issues/1749)) ([1d577c3](https://github.com/FSM1/cipher-box/commit/1d577c32faea055408e3b530b59f8bde8831d390))
* unified Node codec and two-key vault v3 blob in core ([#578](https://github.com/FSM1/cipher-box/issues/578)) ([b2dba55](https://github.com/FSM1/cipher-box/commit/b2dba554a75cb975ab72d9e2777b7b2dde9a06bf))
* unlink a soft-deleted node from a folder in another scope ([#1747](https://github.com/FSM1/cipher-box/issues/1747)) ([6ff891e](https://github.com/FSM1/cipher-box/commit/6ff891eb22017d58996a78e8457537cedd31c5ca))
* **wasm:** bind the engine facade surface and gate the browser-shaped WASM KATs ([#663](https://github.com/FSM1/cipher-box/issues/663)) ([fbc9811](https://github.com/FSM1/cipher-box/commit/fbc981163f2a5007005f381bad2e1f535c2d99bf))
* web rotation UX and durable anti-rollback client state ([#587](https://github.com/FSM1/cipher-box/issues/587)) ([1b4f68b](https://github.com/FSM1/cipher-box/commit/1b4f68b588f0bb51bec2267f6e742ccaa3b76426))
* **web:** add the /bin route over the engine bin commands ([#1632](https://github.com/FSM1/cipher-box/issues/1632)) ([a8af820](https://github.com/FSM1/cipher-box/commit/a8af8207d008dd5d7043e63ff5e9955a6c9879d6))
* **web:** add the shared route and render the engine's revocation classification ([#1559](https://github.com/FSM1/cipher-box/issues/1559)) ([71ef728](https://github.com/FSM1/cipher-box/commit/71ef728f746b6f6e7db3c4dca0d824eeaee5b47f))
* **web:** ask the engine for the vault root instead of seeding an anchor ([#927](https://github.com/FSM1/cipher-box/issues/927)) ([afb3887](https://github.com/FSM1/cipher-box/commit/afb388752e20e6776710c23dd2851cfaa3a3a807))
* **web:** give each device a WebCrypto signing identity key ([#1569](https://github.com/FSM1/cipher-box/issues/1569)) ([0cb06f4](https://github.com/FSM1/cipher-box/commit/0cb06f4d3781ad3634e507b6b24fe23b4a4092c9))
* **web:** host the engine worker and land the local facade transport ([#728](https://github.com/FSM1/cipher-box/issues/728)) ([ddedceb](https://github.com/FSM1/cipher-box/commit/ddedcebda86abd724e61906fcec2f070bdf75a8c))
* **web:** land the Service Worker byte pipe and app-shell precache ([#951](https://github.com/FSM1/cipher-box/issues/951)) ([565a2d6](https://github.com/FSM1/cipher-box/commit/565a2d6b15f726db98315dfc4132142cefad1e19))
* **web:** mint invite links and claim one at /invite ([#1442](https://github.com/FSM1/cipher-box/issues/1442)) ([d4b7d7b](https://github.com/FSM1/cipher-box/commit/d4b7d7beffc37f416f414c58485be6cb0270702e))
* **web:** name the origin folder on a bin row and the outcome a delete actuates ([#1674](https://github.com/FSM1/cipher-box/issues/1674)) ([fefd3b9](https://github.com/FSM1/cipher-box/commit/fefd3b92fba2f905154dfcf3416b3d046d58524b))
* wire folder mutations and file preview to the facade ([#1081](https://github.com/FSM1/cipher-box/issues/1081)) ([dca953f](https://github.com/FSM1/cipher-box/commit/dca953f71cad0df39375e05e14a23a65a083cc1d))
* wire the pin-provider layer across all three modes ([#1072](https://github.com/FSM1/cipher-box/issues/1072)) ([e373a89](https://github.com/FSM1/cipher-box/commit/e373a89550dff15c5bc8f903059ad0a34577274b))
* wire web file upload through the facade write handles ([#1071](https://github.com/FSM1/cipher-box/issues/1071)) ([c76eb60](https://github.com/FSM1/cipher-box/commit/c76eb602cc193384e0807f7ecf29c48ddd140cc2))
* write file content end to end ([#907](https://github.com/FSM1/cipher-box/issues/907)) ([2d11836](https://github.com/FSM1/cipher-box/commit/2d11836b95bc4aa80f94ab5e01b97fceae9a2968))


### Bug Fixes

* address grant delivery to the recipient identity key ([#961](https://github.com/FSM1/cipher-box/issues/961)) ([20d03b8](https://github.com/FSM1/cipher-box/commit/20d03b873a9762db7170443538d8eff8a0b5ff38))
* admit the joiner in a node name and neutralise a peer's deceptive name ([#1768](https://github.com/FSM1/cipher-box/issues/1768)) ([4bf1d23](https://github.com/FSM1/cipher-box/commit/4bf1d2324930b1f34f1f5d8730883eafd395973e))
* anchor a grant at the scope that holds it and bound what a bearer link can take ([#1596](https://github.com/FSM1/cipher-box/issues/1596)) ([2526cd2](https://github.com/FSM1/cipher-box/commit/2526cd2a6cb549089b7c272f1443ca4b0c8262d9))
* **api:** discriminate the two upload 413s and report the gated quota sum ([#848](https://github.com/FSM1/cipher-box/issues/848)) ([b4e4c79](https://github.com/FSM1/cipher-box/commit/b4e4c791e932712b0c1d0158dc1cdadf2971ab48)), closes [#842](https://github.com/FSM1/cipher-box/issues/842) [#843](https://github.com/FSM1/cipher-box/issues/843)
* **api:** harden advisory locks with lock_timeout and add the real-Postgres integration gate ([#688](https://github.com/FSM1/cipher-box/issues/688)) ([1ccd177](https://github.com/FSM1/cipher-box/commit/1ccd17734fd7f0b9984918fb04d458a10ce2d5c2))
* **api:** map user-row lock timeouts to 503 and parameterize the lock_timeout set ([#693](https://github.com/FSM1/cipher-box/issues/693)) ([701a1a8](https://github.com/FSM1/cipher-box/commit/701a1a8e8a2c087f5890de06d215b04f541863a3))
* **api:** pin uploaded blocks under their caller-computed content address ([#912](https://github.com/FSM1/cipher-box/issues/912)) ([d2a047d](https://github.com/FSM1/cipher-box/commit/d2a047df30e9fa75d16fa0b548e5cad4b6ec8d10))
* **api:** refcount the registry per referencing record ([#1578](https://github.com/FSM1/cipher-box/issues/1578)) ([d0a09f7](https://github.com/FSM1/cipher-box/commit/d0a09f72ade58d7a242604ae23e6d8a2466f79fd))
* **api:** reject BYO hosted ingress and stop holding the pool across the pin ([#716](https://github.com/FSM1/cipher-box/issues/716)) ([1e20485](https://github.com/FSM1/cipher-box/commit/1e2048581cf256f6e44b648bedd4a1629060c60a))
* **api:** report retire unpin count from PinStore.unpin result ([#737](https://github.com/FSM1/cipher-box/issues/737)) ([654db89](https://github.com/FSM1/cipher-box/commit/654db89eadfbb7c8a33312f2539ca7ddf090eb19)), closes [#729](https://github.com/FSM1/cipher-box/issues/729)
* **api:** serialize mailbox pending-cap enforcement per recipient ([#683](https://github.com/FSM1/cipher-box/issues/683)) ([5f76e04](https://github.com/FSM1/cipher-box/commit/5f76e0488c5fa3e6e4ddce7fc942024d4c6b79ed))
* **api:** serialize retire unpin against upload and cap record-transport body ([#723](https://github.com/FSM1/cipher-box/issues/723)) ([c8597a6](https://github.com/FSM1/cipher-box/commit/c8597a62a1704394ab4d1c7db352a66d4129e320))
* **api:** stream-bound record-transport body to cap heap ([#738](https://github.com/FSM1/cipher-box/issues/738)) ([f4edc17](https://github.com/FSM1/cipher-box/commit/f4edc171c16e1a669628f38daaa3c5681fb92ea8)), closes [#722](https://github.com/FSM1/cipher-box/issues/722)
* apply the graft cross-plane rule to the focus folder leg ([#1640](https://github.com/FSM1/cipher-box/issues/1640)) ([874917d](https://github.com/FSM1/cipher-box/commit/874917df1b8929e52ff65d7316e99ee67e7bdb9d))
* authenticate every scope-root structure at the record read epoch ([#1049](https://github.com/FSM1/cipher-box/issues/1049)) ([380d996](https://github.com/FSM1/cipher-box/commit/380d996915ee81a70c3c8af1d914f9d49b71860d))
* barrier desktop store unlink ordering where directories cannot be fsynced ([#952](https://github.com/FSM1/cipher-box/issues/952)) ([f023cbf](https://github.com/FSM1/cipher-box/commit/f023cbf5ba410e80310edd90f9f268f867f2361a))
* bind the write wave re-seal to the authorized commitment and re-read the write-epoch floor ([#1177](https://github.com/FSM1/cipher-box/issues/1177)) ([978d4de](https://github.com/FSM1/cipher-box/commit/978d4de40ecf3e428b5db68cf23839613e3d3562))
* **bin:** unpin deleted content and revoke its shares ([#563](https://github.com/FSM1/cipher-box/issues/563)) ([1699522](https://github.com/FSM1/cipher-box/commit/16995221c79421d086aeee0b58fb7af3c7198fa9))
* bound the child-scope index and see a trimmed-region wipe leak ([#1299](https://github.com/FSM1/cipher-box/issues/1299)) ([823243c](https://github.com/FSM1/cipher-box/commit/823243cc38904105e8ac166c2fb9ffc63ab819e4))
* bound the grant-set commitment's entries at 1024 ([#1098](https://github.com/FSM1/cipher-box/issues/1098)) ([9fe4066](https://github.com/FSM1/cipher-box/commit/9fe4066011e95a93ff17a2b716cd52ce8dd76ce6))
* bound the read a mounted e2e wait makes and free a wedged mount ([#1751](https://github.com/FSM1/cipher-box/issues/1751)) ([fc9bfdf](https://github.com/FSM1/cipher-box/commit/fc9bfdf79c9a0409de39355f64cd554520b2d4d3))
* bound vault settings freshness and op-drain correctness ([#1046](https://github.com/FSM1/cipher-box/issues/1046)) ([131d201](https://github.com/FSM1/cipher-box/commit/131d201db34b1767698ef512d7e2e8818c7b65b8))
* bring the browser mailbox seam onto the served API routes ([#955](https://github.com/FSM1/cipher-box/issues/955)) ([e1376cb](https://github.com/FSM1/cipher-box/commit/e1376cb1217343562cefa1252224a5b4554e8042))
* carry a moved record's whole content set and scope the doomed journal ([#1762](https://github.com/FSM1/cipher-box/issues/1762)) ([d86e6be](https://github.com/FSM1/cipher-box/commit/d86e6be25ca9c29e738b3f55a780ef0bf9c7e7ab))
* carry command outcomes to TypeScript and namespace floors per account ([#1311](https://github.com/FSM1/cipher-box/issues/1311)) ([1d11578](https://github.com/FSM1/cipher-box/commit/1d1157803e1fe9e97fb02290d41c6c30c636a155))
* carry follower read results over a private port, not the origin bus ([#982](https://github.com/FSM1/cipher-box/issues/982)) ([a8e4672](https://github.com/FSM1/cipher-box/commit/a8e4672725651cb12d8ff2b4e553e1242e2457b7))
* cascade the move-replace vacate and fold case fully ([#1540](https://github.com/FSM1/cipher-box/issues/1540)) ([9ba0047](https://github.com/FSM1/cipher-box/commit/9ba0047a64159092456574d7feee6b05d5a67d83))
* charge the grafted claim record and fold its contest incrementally ([#1754](https://github.com/FSM1/cipher-box/issues/1754)) ([186f30d](https://github.com/FSM1/cipher-box/commit/186f30df265e3d86ed75c1ef920b56803d737df5))
* chunk the registration to the registry per-entry content-CID cap ([#946](https://github.com/FSM1/cipher-box/issues/946)) ([4162154](https://github.com/FSM1/cipher-box/commit/4162154d388c92dcc9bb5720bbfc680ffe392416))
* **ci:** pin the staging host key on every deploy SSH connection ([#1114](https://github.com/FSM1/cipher-box/issues/1114)) ([0e5a1d6](https://github.com/FSM1/cipher-box/commit/0e5a1d69aad98b3f3bdcc49808562a2bd6726300))
* close four rotation-plane paths that outlast a revocation ([#1532](https://github.com/FSM1/cipher-box/issues/1532)) ([291671a](https://github.com/FSM1/cipher-box/commit/291671a5e07f02d44d12339ebd34a5b428a54646))
* close rust and fuse scope-exit read-revocation bypasses ([#607](https://github.com/FSM1/cipher-box/issues/607)) ([2917c85](https://github.com/FSM1/cipher-box/commit/2917c853937ddc20e67a4149f9fc4d868f130c68))
* complete web kind discrimination and revive deferred test suites ([#611](https://github.com/FSM1/cipher-box/issues/611)) ([fcf1596](https://github.com/FSM1/cipher-box/commit/fcf1596a736cd0d2bd75f0dd6f9ac13a224906fa))
* converge a cold start and drain a write a cut left behind ([#1641](https://github.com/FSM1/cipher-box/issues/1641)) ([6d49607](https://github.com/FSM1/cipher-box/commit/6d49607f724a3e0cb5c9404a802677f36996b9e4))
* **core:** authenticate the op record sender with HPKE auth mode ([#891](https://github.com/FSM1/cipher-box/issues/891)) ([efcff79](https://github.com/FSM1/cipher-box/commit/efcff7944d932ba4f91f8aec37cd1b70d69df179))
* **core:** authenticate the op record's sender with HPKE auth mode ([efcff79](https://github.com/FSM1/cipher-box/commit/efcff7944d932ba4f91f8aec37cd1b70d69df179)), closes [#879](https://github.com/FSM1/cipher-box/issues/879)
* **core:** bind mailbox recipient into the sender signature preimage ([#731](https://github.com/FSM1/cipher-box/issues/731)) ([f9017a8](https://github.com/FSM1/cipher-box/commit/f9017a856fd686dd0762b67d83be0d8c7751f1d4))
* **core:** enforce single-byte content codec in release on the trusted compute_cid path ([#698](https://github.com/FSM1/cipher-box/issues/698)) ([3ffdf0a](https://github.com/FSM1/cipher-box/commit/3ffdf0accfe40f8c0ab9ed1a8d42f981fdde9244))
* **core:** harden crypto input validation and unify secret zeroization ([#726](https://github.com/FSM1/cipher-box/issues/726)) ([3274feb](https://github.com/FSM1/cipher-box/commit/3274feb2ba9a9979f512f9d1510f80ea946f7997))
* **core:** size the encode buffer up front so secret writes never realloc ([#689](https://github.com/FSM1/cipher-box/issues/689)) ([67253f8](https://github.com/FSM1/cipher-box/commit/67253f86a03ed974ba5bd08889b1bf8b130429bb))
* **core:** size the encode_map_partial buffer up front ([#901](https://github.com/FSM1/cipher-box/issues/901)) ([a384519](https://github.com/FSM1/cipher-box/commit/a384519732e870c30355a8bb0e26e033776f18bc))
* **core:** wipe secret-bearing unknown fields and replaced map values ([#935](https://github.com/FSM1/cipher-box/issues/935)) ([35af7a1](https://github.com/FSM1/cipher-box/commit/35af7a1736f124a2277cbfde5c6ee2208f5bf1b7))
* **core:** zeroize content-key copies on the sealed-body encode path ([#680](https://github.com/FSM1/cipher-box/issues/680)) ([8367549](https://github.com/FSM1/cipher-box/commit/83675491f782eecd7e6e4c6f3489c4159767ff34)), closes [#672](https://github.com/FSM1/cipher-box/issues/672)
* correct the engine mailbox client routes and gate them live ([#835](https://github.com/FSM1/cipher-box/issues/835)) ([d99d146](https://github.com/FSM1/cipher-box/commit/d99d14697fd0522ff4d088dab27e54d53e970f04)), closes [#827](https://github.com/FSM1/cipher-box/issues/827)
* cross-check the minted ascent link and classify rotation authoring refusals ([#1070](https://github.com/FSM1/cipher-box/issues/1070)) ([04d84c9](https://github.com/FSM1/cipher-box/commit/04d84c9df4ab5094d88bea21f8cee7b7d955a7ae))
* cross-language IPNS and node-codec verification parity ([#608](https://github.com/FSM1/cipher-box/issues/608)) ([77e52cb](https://github.com/FSM1/cipher-box/commit/77e52cb8dc65788f7df7cd1ffbe9cf7384ac3e21))
* cut a scope by its own revocation floor, refuse an un-resealable root, bound the re-seal budget ([#1594](https://github.com/FSM1/cipher-box/issues/1594)) ([6ab203d](https://github.com/FSM1/cipher-box/commit/6ab203ddd23e78d6897240c1813f96701f1c10f8))
* decide a dead letter against its own leaves and bound the preserved set outside the write path ([#1509](https://github.com/FSM1/cipher-box/issues/1509)) ([be0a524](https://github.com/FSM1/cipher-box/commit/be0a5241ab154f9be774b56f052b20240378f51e))
* defer the child adopter's sequence floor raise until the record is durable ([#1759](https://github.com/FSM1/cipher-box/issues/1759)) ([02ffe41](https://github.com/FSM1/cipher-box/commit/02ffe41971dfb16017c195d6f976cadf1b6ed5af))
* **desktop:** land the WinFsp mount on the Windows desktop e2e leg ([#1719](https://github.com/FSM1/cipher-box/issues/1719)) ([aded42c](https://github.com/FSM1/cipher-box/commit/aded42ce54fbeb6ef72ece463a3ad14b5d64a788))
* **desktop:** mount over a mount point that holds only platform junk files ([#1791](https://github.com/FSM1/cipher-box/issues/1791)) ([5ead979](https://github.com/FSM1/cipher-box/commit/5ead979c7895a6c428471782e5041291e0e88e51))
* **e2e:** make desktop e2e helper dirs workspace packages ([#536](https://github.com/FSM1/cipher-box/issues/536)) ([ac71fef](https://github.com/FSM1/cipher-box/commit/ac71fef0068a7da1393994a4c73e0b84956d8b13))
* end an idle media body on a signal and re-broker on a worker restart ([#1117](https://github.com/FSM1/cipher-box/issues/1117)) ([2819cb8](https://github.com/FSM1/cipher-box/commit/2819cb83137916bf8f9f55163cc7956cac191d58))
* **engine:** anchor the vault-pointer walk and file granted floors under their sharer ([#1597](https://github.com/FSM1/cipher-box/issues/1597)) ([a0c0f98](https://github.com/FSM1/cipher-box/commit/a0c0f981a9361be9410d3235ede54b5026fd46a5))
* **engine:** apply the graft cross-plane rule to the folder leg ([874917d](https://github.com/FSM1/cipher-box/commit/874917df1b8929e52ff65d7316e99ee67e7bdb9d))
* **engine:** bind received shares and their epoch floors to the sharer that granted them ([#1568](https://github.com/FSM1/cipher-box/issues/1568)) ([77ed81f](https://github.com/FSM1/cipher-box/commit/77ed81f28297c780eaa35e633088038d0301d444))
* **engine:** bind the owner-gate commitment to the rotated scope in rotate_scope_write ([#780](https://github.com/FSM1/cipher-box/issues/780)) ([6e4ebfb](https://github.com/FSM1/cipher-box/commit/6e4ebfb63a24783dd103ea1dfa6a416afdef1164))
* **engine:** charge or hold the drain halts no retry can shed ([#1320](https://github.com/FSM1/cipher-box/issues/1320)) ([0c77ce0](https://github.com/FSM1/cipher-box/commit/0c77ce073064e76afbc095d9fe1e37be7bf60c23))
* **engine:** close three fail-open seams on the rotation write path ([#1307](https://github.com/FSM1/cipher-box/issues/1307)) ([f1021ae](https://github.com/FSM1/cipher-box/commit/f1021aed1651b1bcc4ac838ebd0dd66eca04e534))
* **engine:** give a node id two grafted scopes name to neither ([#1653](https://github.com/FSM1/cipher-box/issues/1653)) ([9afec70](https://github.com/FSM1/cipher-box/commit/9afec704fd6f9613a3c50ef3285340dfdc212871))
* **engine:** raise the cut-epoch floor from a verified commitment ([0b6cb68](https://github.com/FSM1/cipher-box/commit/0b6cb689a2b528df82e23985d6268512ca42616b))
* **engine:** raise the cut-epoch floor from a verified commitment so a cut recipient refuses a replayed pre-cut set ([#1737](https://github.com/FSM1/cipher-box/issues/1737)) ([0b6cb68](https://github.com/FSM1/cipher-box/commit/0b6cb689a2b528df82e23985d6268512ca42616b))
* **engine:** re-key reparented descendants to the grantee seed at grant creation ([#782](https://github.com/FSM1/cipher-box/issues/782)) ([2c509d7](https://github.com/FSM1/cipher-box/commit/2c509d72cebd37ff530cc25a35ec38b0abc5c415))
* **engine:** re-mint grant tags on the write name wave and bind a re-sealed blob to its derived tag ([#1141](https://github.com/FSM1/cipher-box/issues/1141)) ([d11bfce](https://github.com/FSM1/cipher-box/commit/d11bfce11c4440019c3f02cfc083624003c77fa1))
* **engine:** refuse a relocation that crosses a scope boundary ([ed2c12c](https://github.com/FSM1/cipher-box/commit/ed2c12c6b6916fe382b1584b39f360748d15703d))
* **engine:** resume a stalled grant's interior move against the root it promoted ([506bf0c](https://github.com/FSM1/cipher-box/commit/506bf0c61a6b261dda1116e72126148b69f848b5))
* **engine:** retire the head block a publish orphaned before the transport ([#944](https://github.com/FSM1/cipher-box/issues/944)) ([e9086c3](https://github.com/FSM1/cipher-box/commit/e9086c358eb02043f9976d819f1f0f5b281aaf96))
* **engine:** scope the content-wipe watchdog and guard the genesis sequence floor ([#1284](https://github.com/FSM1/cipher-box/issues/1284)) ([8df8f6e](https://github.com/FSM1/cipher-box/commit/8df8f6e03a7a0705c13d4a674f9ded10d9a1d1db))
* **engine:** settle a refused upload and isolate an unreadable sweep node ([#1217](https://github.com/FSM1/cipher-box/issues/1217)) ([3d99f14](https://github.com/FSM1/cipher-box/commit/3d99f140ee2e24102e4e4d163a51db23ee5bc66a))
* **engine:** unlink every link at a soft delete and give the bin plane exits ([#1658](https://github.com/FSM1/cipher-box/issues/1658)) ([f745b70](https://github.com/FSM1/cipher-box/commit/f745b705236def53a31ffb4a6ee18231437cec1b))
* **engine:** use versioned compare-and-remove for dest-add compensation ([#781](https://github.com/FSM1/cipher-box/issues/781)) ([3f7aad6](https://github.com/FSM1/cipher-box/commit/3f7aad646d1a1a56877239ca22595ae0f4739da2))
* fail closed on short OPFS staging reads and writes and request persistent storage ([#834](https://github.com/FSM1/cipher-box/issues/834)) ([82daa4c](https://github.com/FSM1/cipher-box/commit/82daa4cdf325fd43645e645d6758e7c92578d55f))
* fail closed on the transferred upload chunk and on an unknown worker command ([#1145](https://github.com/FSM1/cipher-box/issues/1145)) ([076c589](https://github.com/FSM1/cipher-box/commit/076c5893c9e0fdf6a9fbe5cc1149541d02067281))
* forward the API and content-gateway config to the browser engine ([#1035](https://github.com/FSM1/cipher-box/issues/1035)) ([5516bd8](https://github.com/FSM1/cipher-box/commit/5516bd8e197d4a532e530d73974d883c2674b823))
* FUSE and IPNS write-path durability hardening ([#543](https://github.com/FSM1/cipher-box/issues/543)) ([5d5daaa](https://github.com/FSM1/cipher-box/commit/5d5daaaf69aeb030ae9aa828ac4245525e0215fd))
* **fuse:** harden IPNS verify and publish paths and clear cleanup debt ([#553](https://github.com/FSM1/cipher-box/issues/553)) ([ff9b356](https://github.com/FSM1/cipher-box/commit/ff9b3566991b81d49c0357a38b856f51a4cd0845))
* **fuse:** re-resolve remote file edits during local publish window ([#558](https://github.com/FSM1/cipher-box/issues/558)) ([d343c0f](https://github.com/FSM1/cipher-box/commit/d343c0f4e8a34aaac117fd397a92c233f7ab45f4))
* **fuse:** resolve before per-file first-publish to avoid seq-1 equivocation ([#601](https://github.com/FSM1/cipher-box/issues/601)) ([e87befa](https://github.com/FSM1/cipher-box/commit/e87befa2df464e2df7a880447eb4f3c0508ff5cd))
* **fuse:** revoke shares when items are deleted via the desktop mount ([#568](https://github.com/FSM1/cipher-box/issues/568)) ([82ad5d7](https://github.com/FSM1/cipher-box/commit/82ad5d77b6d3b524da62888142400c3a2cd62380))
* give a relocation with no source parent a true verdict ([#1651](https://github.com/FSM1/cipher-box/issues/1651)) ([203021b](https://github.com/FSM1/cipher-box/commit/203021b9118bbb38d4722cb747351e4b3e565a64))
* give the retired node its own key space and bound the bookkeeping reads ([#1771](https://github.com/FSM1/cipher-box/issues/1771)) ([3cfa663](https://github.com/FSM1/cipher-box/commit/3cfa663c37da678f09bca2d42003feacedf0a47f))
* harden FUSE publish and TEE write paths against partial-failure states ([#610](https://github.com/FSM1/cipher-box/issues/610)) ([02efe51](https://github.com/FSM1/cipher-box/commit/02efe51bbc1930b02857b081b41404ae0ed9605c))
* harden Phase 60 deferred safety patches in FUSE publish and desktop vault init ([#566](https://github.com/FSM1/cipher-box/issues/566)) ([0adcb04](https://github.com/FSM1/cipher-box/commit/0adcb0418198b3cc311da98551c9d0a4bef293c2))
* harden rotation read-plane durability and deep crash-resume soundness ([#598](https://github.com/FSM1/cipher-box/issues/598)) ([d5486e5](https://github.com/FSM1/cipher-box/commit/d5486e586ab0d30113ca167819d6e053bb2ec3a3))
* harden rotation soundness under concurrency and crash-resume ([#596](https://github.com/FSM1/cipher-box/issues/596)) ([faa781e](https://github.com/FSM1/cipher-box/commit/faa781e4164697b17cc7765624985dcb9a38f761))
* harden SDK write-plane durability and correctness ([#602](https://github.com/FSM1/cipher-box/issues/602)) ([c21f896](https://github.com/FSM1/cipher-box/commit/c21f896b6839b5791ff0c8bd4c5985afef8c6a48))
* harden the desktop floor store read-modify-write and intent length prefix ([#968](https://github.com/FSM1/cipher-box/issues/968)) ([cf3d20c](https://github.com/FSM1/cipher-box/commit/cf3d20cf372b2f1b4fcbe22c43f96d72a633d2cb))
* harden the epoch floor gates on cold seed and on revival ([#1157](https://github.com/FSM1/cipher-box/issues/1157)) ([df3343d](https://github.com/FSM1/cipher-box/commit/df3343db17d3c01b0990ac7e7875c3d9d9fea205))
* hold a grafted shared scope to the identity that granted it and pace the mailbox pull ([#1629](https://github.com/FSM1/cipher-box/issues/1629)) ([acdbd2c](https://github.com/FSM1/cipher-box/commit/acdbd2cdd85e26c86f336b49c0b994eabc75d542))
* hold a received share's verdict to the cut-epoch floor the gate reads ([#1698](https://github.com/FSM1/cipher-box/issues/1698)) ([da2e048](https://github.com/FSM1/cipher-box/commit/da2e048b2c38bc3bdf60d4cf4736860593eb8959))
* hold a replayed quarantine until a poll converges and scope the owed-retire to its record ([#1588](https://github.com/FSM1/cipher-box/issues/1588)) ([ac61451](https://github.com/FSM1/cipher-box/commit/ac614516c6abf7990eecfb6316b289fa9a268259))
* hold a scope-exit cut across a restart and prune a claim by what its scope names ([#1755](https://github.com/FSM1/cipher-box/issues/1755)) ([420d310](https://github.com/FSM1/cipher-box/commit/420d310267cccd2a3e9e420a09d4031ea7b796d5))
* hold a stream slot across the open and evict revoked scope seeds ([#1061](https://github.com/FSM1/cipher-box/issues/1061)) ([9308f3f](https://github.com/FSM1/cipher-box/commit/9308f3f557c8eb9838364a05a3555bb6a43023bf))
* hold every client to one node-name law and render a duplicate name apart ([#1671](https://github.com/FSM1/cipher-box/issues/1671)) ([7e053b2](https://github.com/FSM1/cipher-box/commit/7e053b2a9dbfb491e4ea3f55029721f5b1e6ba98))
* hold every grafted body to the claim record and the sharer label to the name law ([#1680](https://github.com/FSM1/cipher-box/issues/1680)) ([db9bc3b](https://github.com/FSM1/cipher-box/commit/db9bc3b7b8d83e3a60d28755c4e83520982c534a))
* hold the bin index enrolment to the record its load observed ([#1742](https://github.com/FSM1/cipher-box/issues/1742)) ([32d428c](https://github.com/FSM1/cipher-box/commit/32d428c77b99445a888c22426be0f13caaf240c3))
* hold the interior re-seal's read-epoch bar to the signature and split the grant's partial-commit failures ([#1756](https://github.com/FSM1/cipher-box/issues/1756)) ([5acb86d](https://github.com/FSM1/cipher-box/commit/5acb86dc1aecd38991071ce4e9c9d1107969d6c0))
* hold the web API base URL to a transport scheme policy ([#1763](https://github.com/FSM1/cipher-box/issues/1763)) ([9140df7](https://github.com/FSM1/cipher-box/commit/9140df77db647a9bce79bdded7585d77cc9da7b1))
* IPFS/IPNS data-integrity fixes for unpin and folder unenroll ([#527](https://github.com/FSM1/cipher-box/issues/527)) ([b7acb57](https://github.com/FSM1/cipher-box/commit/b7acb570ced77f43f35eecd65a7f9f15fdd29afc))
* IPNS signed-record verify coverage chokepoint and non-CAS sequence gate ([#544](https://github.com/FSM1/cipher-box/issues/544)) ([cd173c9](https://github.com/FSM1/cipher-box/commit/cd173c9c20c50d29ea211f00efa84291d7a3178f))
* journal a prune debt before the publish and re-derive what is live at retire time ([#1289](https://github.com/FSM1/cipher-box/issues/1289)) ([fae7a59](https://github.com/FSM1/cipher-box/commit/fae7a59fdacab747c93eaee01131982aee016333))
* journal what a delete owes at unlink-ack and prune what an observed one detaches ([#1511](https://github.com/FSM1/cipher-box/issues/1511)) ([b30e2a9](https://github.com/FSM1/cipher-box/commit/b30e2a937f1a80066449bc31b8550ca968fc0c8c))
* keep the desktop shell in the menu bar after sign-in and show the WinFsp notice on Windows only ([#1795](https://github.com/FSM1/cipher-box/issues/1795)) ([22e70c3](https://github.com/FSM1/cipher-box/commit/22e70c365463208af378eac876f7c5d7b2fc901d))
* key the app-shell cache off a content-derived build id ([#979](https://github.com/FSM1/cipher-box/issues/979)) ([bf8bc74](https://github.com/FSM1/cipher-box/commit/bf8bc74cbb320acc2294936334d338dc08c9f4c1))
* key the engine's floors by identity and land the logout half of forget ([#1517](https://github.com/FSM1/cipher-box/issues/1517)) ([d0949c8](https://github.com/FSM1/cipher-box/commit/d0949c84ec95a579d32cc9363af2aa169f1923a3))
* key the held set by plane and renew the scope pointer ([eee8ce6](https://github.com/FSM1/cipher-box/commit/eee8ce604134b53744bd01e40ef2b4e6cf7de6fa))
* label the durable sequence-floor key so the store names no record ([#1760](https://github.com/FSM1/cipher-box/issues/1760)) ([8f908e6](https://github.com/FSM1/cipher-box/commit/8f908e6b9132f985e98db09fcc35de4414842535))
* link the FUSE-T rpath into the macOS binaries that load it ([#1515](https://github.com/FSM1/cipher-box/issues/1515)) ([586201c](https://github.com/FSM1/cipher-box/commit/586201c96b48acfe837d9e5741cc4cb0dc0dd6f2))
* make put_staged_bytes failure-atomic and hold every host to it ([#1194](https://github.com/FSM1/cipher-box/issues/1194)) ([550192b](https://github.com/FSM1/cipher-box/commit/550192b9bcd30e1cae0d4688b6c207f6d416f5a8))
* make refresh rotation atomic and sweep expired accelerator tokens ([#1505](https://github.com/FSM1/cipher-box/issues/1505)) ([dc0819b](https://github.com/FSM1/cipher-box/commit/dc0819bc3350eb29b5b01d1957f9e440daf07dbc))
* make the encode-path recursion depth bound release-active ([#839](https://github.com/FSM1/cipher-box/issues/839)) ([f937f9e](https://github.com/FSM1/cipher-box/commit/f937f9ee952dca9faed7cfafd625e72c82bbe752))
* make the rotation gated read idempotent at the sequence floor ([#1104](https://github.com/FSM1/cipher-box/issues/1104)) ([dfb12b9](https://github.com/FSM1/cipher-box/commit/dfb12b99182ba6d32d98f5770396d3b2cfc9a0c0))
* make the staging-store kit mandatory and align the record ceiling with the block limit ([#1310](https://github.com/FSM1/cipher-box/issues/1310)) ([c5447dd](https://github.com/FSM1/cipher-box/commit/c5447ddb90b2ede7a76030d2f4eacff22ccd890c))
* make the write-epoch floor guard atomic with the publish it protects ([#1363](https://github.com/FSM1/cipher-box/issues/1363)) ([d0015af](https://github.com/FSM1/cipher-box/commit/d0015afd47f90d42c74f981c660aad1175e327d4))
* mark a leaf uploaded before releasing its staged bytes ([#941](https://github.com/FSM1/cipher-box/issues/941)) ([4567c33](https://github.com/FSM1/cipher-box/commit/4567c33ad2dd0dac5ece26510c503755d71ca1d3))
* mark an op published at its record ack and mirror the gate stage 2 on the produce side ([#1058](https://github.com/FSM1/cipher-box/issues/1058)) ([c85ca11](https://github.com/FSM1/cipher-box/commit/c85ca11883111156ab5d4f3dbdfda9c1b54a0117))
* merge the root re-projection and project the version count ([#875](https://github.com/FSM1/cipher-box/issues/875)) ([fa45f3b](https://github.com/FSM1/cipher-box/commit/fa45f3b2e3e66cf69335fb4691117598378250ae)), closes [#863](https://github.com/FSM1/cipher-box/issues/863) [#854](https://github.com/FSM1/cipher-box/issues/854)
* mint the write-plane history link and recover a resumed wave from published state ([#1190](https://github.com/FSM1/cipher-box/issues/1190)) ([5d6e71b](https://github.com/FSM1/cipher-box/commit/5d6e71b535f83cba9bd035ae2d30a1d3864cff16))
* mount over a mount point that holds only platform junk files ([5ead979](https://github.com/FSM1/cipher-box/commit/5ead979c7895a6c428471782e5041291e0e88e51))
* move every adoption floor raise behind the durability it pays for ([#1750](https://github.com/FSM1/cipher-box/issues/1750)) ([5c7b83a](https://github.com/FSM1/cipher-box/commit/5c7b83ab46d31fc67eb33f9f17a9207b6148ee06))
* move follower commands and uploads onto the private port and reclaim dead followers ([#1039](https://github.com/FSM1/cipher-box/issues/1039)) ([e935078](https://github.com/FSM1/cipher-box/commit/e935078a1f5e8f850a38b7996692d029ed96d6cb))
* move the engine event stream off the origin-wide channel and watch follower presence locks ([#1082](https://github.com/FSM1/cipher-box/issues/1082)) ([21b124d](https://github.com/FSM1/cipher-box/commit/21b124db7f0371b02e7b645424a72b1735e33833))
* name a rewritten grant row from the owner commitment and finish a stalled write share ([#1777](https://github.com/FSM1/cipher-box/issues/1777)) ([a09cecd](https://github.com/FSM1/cipher-box/commit/a09cecd039647138c47d228d29e0b755e97bd25a))
* name the download outcome and seal the Core Kit store at rest ([#1242](https://github.com/FSM1/cipher-box/issues/1242)) ([b2499d9](https://github.com/FSM1/cipher-box/commit/b2499d917dc0ce27ff61106288b71d57330a245f))
* name the refusal a drain reports and keep the bytes a spent budget charged ([#1343](https://github.com/FSM1/cipher-box/issues/1343)) ([eb04d00](https://github.com/FSM1/cipher-box/commit/eb04d001be4be462347c6d616d64057cc6802c2f))
* narrow the facade background loops and surface their trust violations ([#1042](https://github.com/FSM1/cipher-box/issues/1042)) ([18dec88](https://github.com/FSM1/cipher-box/commit/18dec88af1338f6e16f75070c3d80d06dc6469e2))
* narrow the settings first-run carve-out to a device with no mark of a record ([#1149](https://github.com/FSM1/cipher-box/issues/1149)) ([8c69c17](https://github.com/FSM1/cipher-box/commit/8c69c17c72a900083049efee3ca9d0656a410e8c))
* open the row menu on the right of the row and move the action button to the last column ([#1784](https://github.com/FSM1/cipher-box/issues/1784)) ([93513da](https://github.com/FSM1/cipher-box/commit/93513da2378687a5afffe7dd5a34eca50d647d2d))
* order an invite mint and a share pointer after the write-scope cut ([#1602](https://github.com/FSM1/cipher-box/issues/1602)) ([b416a94](https://github.com/FSM1/cipher-box/commit/b416a94672000f15c3e626aaa14578eb29fe0591))
* pair staged content versions with reads and close two disclosure gaps ([#1360](https://github.com/FSM1/cipher-box/issues/1360)) ([6a2a974](https://github.com/FSM1/cipher-box/commit/6a2a974f52eea8e67b0c9af91b3b2cb8952b892d))
* pin one engine stream per media ticket and surface the stream ceiling as recoverable ([#1065](https://github.com/FSM1/cipher-box/issues/1065)) ([4820773](https://github.com/FSM1/cipher-box/commit/4820773ad936e2b93c8c500852cac7288b95cc9e))
* pin the content version for the life of a ranged read stream ([#980](https://github.com/FSM1/cipher-box/issues/980)) ([47271ad](https://github.com/FSM1/cipher-box/commit/47271ad027d580ddcfdb4bdbe5fcc84e7c9f7c5b))
* pin the grant section's signer at the adoption gate's stage 3 ([#1120](https://github.com/FSM1/cipher-box/issues/1120)) ([d2a75db](https://github.com/FSM1/cipher-box/commit/d2a75db8f62b6f31c63e18aadaa5d57be6fdffde))
* pin the login challenge shape and give the bearer header one home ([#1099](https://github.com/FSM1/cipher-box/issues/1099)) ([ba60593](https://github.com/FSM1/cipher-box/commit/ba60593fd2e4d9051deabc3bc5797ad690097e28))
* prove an owner action against the held root name and hand out this member's contact code ([#1564](https://github.com/FSM1/cipher-box/issues/1564)) ([d94251a](https://github.com/FSM1/cipher-box/commit/d94251a8c8e809e2e7e53c6449fb8ba0e00d6197))
* prove the boundary, anchor the resume, and authenticate the threaded ancestor seed ([#1410](https://github.com/FSM1/cipher-box/issues/1410)) ([9739813](https://github.com/FSM1/cipher-box/commit/9739813b84e5db80645434c67eea9bd12658792f))
* publish one scope root per invite conversion pass ([#1774](https://github.com/FSM1/cipher-box/issues/1774)) ([1468c8a](https://github.com/FSM1/cipher-box/commit/1468c8a83863d71ff0640a4da8112b95272c83f7))
* put a listed folder's unprojected file rows on the focus file leg ([#1773](https://github.com/FSM1/cipher-box/issues/1773)) ([f00caa3](https://github.com/FSM1/cipher-box/commit/f00caa38c191a1d465efc6d52a1fc85c9ade1fa3))
* queue the file children the tick's folder leg lists so a remote add paints its size ([#1802](https://github.com/FSM1/cipher-box/issues/1802)) ([f272115](https://github.com/FSM1/cipher-box/commit/f2721150d6cf3f59843948c18663ac334ecd3cbc))
* reach the engine from the mount root and run the mounted suite on macOS and Linux ([#1600](https://github.com/FSM1/cipher-box/issues/1600)) ([f91f196](https://github.com/FSM1/cipher-box/commit/f91f196ab5a2927e95958c0a3b2df36595619a64))
* reach the owner's own nested scope root on both planes ([#1642](https://github.com/FSM1/cipher-box/issues/1642)) ([6aa2e73](https://github.com/FSM1/cipher-box/commit/6aa2e732ad69d0304bb37d14ae0fa85b4b451b5c))
* read a mount write back and stop a Linux invalidation from blocking its own request ([#1607](https://github.com/FSM1/cipher-box/issues/1607)) ([b721f93](https://github.com/FSM1/cipher-box/commit/b721f9328021eaee58c1449e387be0727f3291a4))
* reclaim what a delete detaches and repaint a file another device republished ([#1478](https://github.com/FSM1/cipher-box/issues/1478)) ([dc2a224](https://github.com/FSM1/cipher-box/commit/dc2a2249056aaaf7ddaeed04161c909ed7d1003b))
* reconcile the grant plan's child index with the convergence pass and re-assert the proof in the mint's walk ([#1745](https://github.com/FSM1/cipher-box/issues/1745)) ([40e4440](https://github.com/FSM1/cipher-box/commit/40e44407f4c0cf14096d51a549390cc293106b56))
* recover a promoted scope root's write plane on a non-minting device ([#1646](https://github.com/FSM1/cipher-box/issues/1646)) ([1dfa022](https://github.com/FSM1/cipher-box/commit/1dfa022014afed0f7d96cb935dfc683e85deea10))
* redact the grantee fields of a rendered grant ledger row ([#1753](https://github.com/FSM1/cipher-box/issues/1753)) ([f360d09](https://github.com/FSM1/cipher-box/commit/f360d09fd3d204c71a62ad2b5515a8076e1967bc))
* refuse a content write that would supersede a version it never saw ([#1123](https://github.com/FSM1/cipher-box/issues/1123)) ([2ec86e5](https://github.com/FSM1/cipher-box/commit/2ec86e565decdb9f5185e8460de44ee0f094b967))
* refuse a cross-scope move that carries a scope root at the command ([#1761](https://github.com/FSM1/cipher-box/issues/1761)) ([da58a9b](https://github.com/FSM1/cipher-box/commit/da58a9b82bac420f0a5ed541a94367112bc46d3f))
* refuse a relocation that crosses a scope boundary ([#1649](https://github.com/FSM1/cipher-box/issues/1649)) ([ed2c12c](https://github.com/FSM1/cipher-box/commit/ed2c12c6b6916fe382b1584b39f360748d15703d))
* refuse a second account the origin's engine and reclaim the stores it leaves ([#1333](https://github.com/FSM1/cipher-box/issues/1333)) ([b1b1b05](https://github.com/FSM1/cipher-box/commit/b1b1b05ba4d0a268c12f1203a5f1702539d2531f))
* refuse the write-plane values a re-seal and a pointer publish cannot carry ([#1748](https://github.com/FSM1/cipher-box/issues/1748)) ([124d96b](https://github.com/FSM1/cipher-box/commit/124d96bf9a63ef5290fe2d8fc53c54a572180adc))
* reject non-prime-order X25519 keys and refuse a self-grant ([#1286](https://github.com/FSM1/cipher-box/issues/1286)) ([9e2a28c](https://github.com/FSM1/cipher-box/commit/9e2a28c1b1c6704133986a4970558c07cff105c5))
* render the PDF preview in an unsandboxed frame so Chromium shows it ([#1782](https://github.com/FSM1/cipher-box/issues/1782)) ([85a2477](https://github.com/FSM1/cipher-box/commit/85a24771dd5a5ee7f091c10103c32399bcb104b1))
* renew every owned scope pointer and name a cut's revoked recipient by the committed tag ([#1563](https://github.com/FSM1/cipher-box/issues/1563)) ([144c2af](https://github.com/FSM1/cipher-box/commit/144c2af2176680706549b5269f51b1320dbb9a9d))
* report a seal failure above the local read-epoch floor as availability, not abuse ([#1793](https://github.com/FSM1/cipher-box/issues/1793)) ([2c4d63a](https://github.com/FSM1/cipher-box/commit/2c4d63a59ca2b2bec354bb2904e20538a761d267))
* resolve the mount's focused sub-folders on a device that started from cached state ([#1786](https://github.com/FSM1/cipher-box/issues/1786)) ([d6cc958](https://github.com/FSM1/cipher-box/commit/d6cc958bd35f695e5e33840c78dd9b2a0b87dff3))
* resume a stalled grant's interior move against the root it promoted ([#1624](https://github.com/FSM1/cipher-box/issues/1624)) ([506bf0c](https://github.com/FSM1/cipher-box/commit/506bf0c61a6b261dda1116e72126148b69f848b5))
* retire every uploaded content block on abandonment ([#923](https://github.com/FSM1/cipher-box/issues/923)) ([fefcfbe](https://github.com/FSM1/cipher-box/commit/fefcfbe41e6d7a89f843689d06d334be6f03d54d))
* retry a failed first-run mint in-session and stop an assumed placement latching BYO ([#1338](https://github.com/FSM1/cipher-box/issues/1338)) ([ef95dc8](https://github.com/FSM1/cipher-box/commit/ef95dc81098fb4b9ab827eb7b779aa580a548cc3))
* rotate a scope root over the last gate-passing copy when the record fills the reservation ([#1769](https://github.com/FSM1/cipher-box/issues/1769)) ([3b3ed0e](https://github.com/FSM1/cipher-box/commit/3b3ed0eeef5a1e710338d0ea810519cd0e3df55e))
* run the focus file leg on navigation so a listed folder paints its sizes at once ([#1785](https://github.com/FSM1/cipher-box/issues/1785)) ([b34ac09](https://github.com/FSM1/cipher-box/commit/b34ac09283343157256c581cacc361441911417d))
* save a file through the Service Worker instead of past it ([#1282](https://github.com/FSM1/cipher-box/issues/1282)) ([7d3f93f](https://github.com/FSM1/cipher-box/commit/7d3f93fb19ec505dab9cbd9f5305ba653de89bb3))
* seal the write-plane history link to the owner and bound it ([#1285](https://github.com/FSM1/cipher-box/issues/1285)) ([f3e4f7f](https://github.com/FSM1/cipher-box/commit/f3e4f7fd129ee3a1a3d1cf87e822cf53da684aa2))
* self-heal a corrupt Core Kit store instead of wedging the app ([#1183](https://github.com/FSM1/cipher-box/issues/1183)) ([f249e17](https://github.com/FSM1/cipher-box/commit/f249e17c2ffc15374b33effce3862eead031a3d4))
* serve fuse base blocks from the chunk cache and un-vacuum the epoch-lag test ([#1300](https://github.com/FSM1/cipher-box/issues/1300)) ([5719f03](https://github.com/FSM1/cipher-box/commit/5719f03a436e28728c335545e03db40ad4ec6b78)), closes [#1168](https://github.com/FSM1/cipher-box/issues/1168) [#1218](https://github.com/FSM1/cipher-box/issues/1218)
* settle a leaderless follower and frame the media head from the pinned version ([#1533](https://github.com/FSM1/cipher-box/issues/1533)) ([0bc52a5](https://github.com/FSM1/cipher-box/commit/0bc52a5f1b68c1a6400cc91484c01fdc590f6a98))
* settle four engine rotation and durable-key defects ([#1614](https://github.com/FSM1/cipher-box/issues/1614)) ([3356419](https://github.com/FSM1/cipher-box/commit/335641928d58a4f4d69f3ac65646da0355d3cdb3))
* shared-folder write and navigation correctness on web ([#603](https://github.com/FSM1/cipher-box/issues/603)) ([bd8c1e0](https://github.com/FSM1/cipher-box/commit/bd8c1e0be4001b6542a2ba9e3f3788a20ff12466))
* state the capped fetch bound honestly and cover the first-chunk overshoot ([#977](https://github.com/FSM1/cipher-box/issues/977)) ([4ab8ecd](https://github.com/FSM1/cipher-box/commit/4ab8ecd71eb8a537f2935a44d86fbe2ccded54cc))
* subtract the retained versions before a prune retires a doomed root ([#1173](https://github.com/FSM1/cipher-box/issues/1173)) ([983ed67](https://github.com/FSM1/cipher-box/commit/983ed67a8cb08582542a9fc45f624d7c8d8caaa5))
* tell a trust rejection from an availability failure on the boundary walk ([#1743](https://github.com/FSM1/cipher-box/issues/1743)) ([6f02279](https://github.com/FSM1/cipher-box/commit/6f02279d38aeee22a1f8fc9d00c1019f6b46685a))
* time a mount's entry cache apart from its attribute one and give readdir a coherent cursor ([#1518](https://github.com/FSM1/cipher-box/issues/1518)) ([7918ff3](https://github.com/FSM1/cipher-box/commit/7918ff398b2186e2ede7052b8672f55f815ea6b0))
* typecheck the browser suite and harden the client seams ([#1023](https://github.com/FSM1/cipher-box/issues/1023)) ([71a25dd](https://github.com/FSM1/cipher-box/commit/71a25ddf1ddd3c15844283991736d3d530119321))
* unfreeze an unpreservable dead letter, refuse a restored replay, and say why a reclaim stalled ([#1524](https://github.com/FSM1/cipher-box/issues/1524)) ([aa58d78](https://github.com/FSM1/cipher-box/commit/aa58d78536d93462a8c519338166e5920d9d2440))
* validate worker request fields and wipe a refused upload chunk ([#1241](https://github.com/FSM1/cipher-box/issues/1241)) ([4237a79](https://github.com/FSM1/cipher-box/commit/4237a7960815a69b94a6f2ed879d9ea04acdec3a))
* verify the approver answer before a factor is adopted and split the enrollment flag ([#1746](https://github.com/FSM1/cipher-box/issues/1746)) ([4faa9b1](https://github.com/FSM1/cipher-box/commit/4faa9b111ef5e71bbef8a20e19c319f4877ab0fd))
* **web:** add CSP and nosniff to the staging web vhost ([#969](https://github.com/FSM1/cipher-box/issues/969)) ([9d72c7c](https://github.com/FSM1/cipher-box/commit/9d72c7cb81b15f24a051212f36dfaeef2b4b6256)), closes [#888](https://github.com/FSM1/cipher-box/issues/888)
* **web:** embed sequence 1 on first BYO storage-config IPNS publish ([#571](https://github.com/FSM1/cipher-box/issues/571)) ([91c96eb](https://github.com/FSM1/cipher-box/commit/91c96eb50839292c47bff4eceaf9a0b681c8b5ac))
* **web:** key the app-shell cache off a content-derived build id ([bf8bc74](https://github.com/FSM1/cipher-box/commit/bf8bc74cbb320acc2294936334d338dc08c9f4c1)), closes [#974](https://github.com/FSM1/cipher-box/issues/974)
* wipe decoded op plaintext and carry the BYO bearer as scrubbable bytes ([#1319](https://github.com/FSM1/cipher-box/issues/1319)) ([73ff314](https://github.com/FSM1/cipher-box/commit/73ff3141c9e3212c5331a36e14eeb914c907bd29))
* wipe the decoder in-flight tree and the seal layer preserved unknowns ([#957](https://github.com/FSM1/cipher-box/issues/957)) ([5c59235](https://github.com/FSM1/cipher-box/commit/5c592359b783ddaa99743cff0b9de1e84ec45a37))


### Performance Improvements

* memoize the durable queue scan so a render is not one HPKE open per queued op ([#919](https://github.com/FSM1/cipher-box/issues/919)) ([436685a](https://github.com/FSM1/cipher-box/commit/436685afde98c7ad85a06c013e5c8ec4015e152e))
* memoize the engine render behind the two generations it answers for ([#1772](https://github.com/FSM1/cipher-box/issues/1772)) ([28126dc](https://github.com/FSM1/cipher-box/commit/28126dc4e632a2ef1076c7c9599431f7b9feaf5c))

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
