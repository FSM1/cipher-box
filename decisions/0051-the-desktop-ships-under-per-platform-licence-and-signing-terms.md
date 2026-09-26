# ADR 0051 — The desktop ships under per-platform licence and signing terms

- **Status:** Accepted on 2026-09-26 — retroactive; the rule shipped in FSM1/cipher-box#736,
  FSM1/cipher-box#1550 and FSM1/cipher-box#1860, and the blueprint carries it; the `blueprint/*.md` and
  `CONTEXT.md` rewording in FSM1/cipher-box follows
- **Date:** 2026-09-26
- **Relates to:**
  [#32](https://github.com/FSM1/cipher-box-next/issues/32) (the macOS driver research: FUSE-T
  for v2.0, macFUSE rejected partly on its licence, and "FUSE-T commercial license terms for
  bundling" on the verify list), [#46](https://github.com/FSM1/cipher-box-next/issues/46) (the
  desktop blueprint thread, which handed the FUSE-T licence edge to the testing strategy),
  [#47](https://github.com/FSM1/cipher-box-next/issues/47) (the hardware verification gates, gate
  4), [#48](https://github.com/FSM1/cipher-box-next/issues/48) (the deploy blueprint thread:
  `desktop-release.yml` and the minisign updater signature),
  [ADR 0018](./0018-the-pr-gate-is-grouped-by-area-with-an-adapter-leg-per-desktop-platform.md)
  (the `Desktop` area and its per-platform legs, where the D3 and D4 proof runs), the
  `blueprint/desktop.md` "Backends", "Tauri shell" and "Open edges" sections, the
  `blueprint/deploy.md` "Desktop release artifacts" section, and the `blueprint/testing.md`
  "Hardware verification gates" section
- **Implemented by:** FSM1/cipher-box#736 (the FUSE-T licence verdict, D1),
  FSM1/cipher-box#1515 (the `@rpath` link to the member-installed FUSE-T, D1),
  FSM1/cipher-box#1550 (the WinFsp host adapter, the attribution footer and
  `docs/ATTRIBUTION.md`, D2) and FSM1/cipher-box#1860 (the hardened runtime, the entitlement and
  the optional Apple signing, D3 to D5). The decision sources are FSM1/cipher-box#1376 (D2,
  2026-08-26) and FSM1/cipher-box#1516 (D4, 2026-09-05).

## Context

CipherBox is MIT. The desktop app projects the vault through a different mount technology on
each platform, and each technology arrives with its own licence. The macOS build also meets a
platform rule that the other two builds do not meet: Gatekeeper and the hardened runtime.

**macOS: FUSE-T.** The #32 research chose FUSE-T 1.2.7 with the SMB backend and put its licence
on the verify list. FSM1/cipher-box#736 ran the five hardware gates on 2026-07-22 and recorded
gate 4 in `tools/hw-gates/RESULTS.md`. The FUSE-T licence is free for non-commercial use. For
"commercial use or/and bundling with commercial software" the vendor must get a commercial
licence from the author, with no published price. The author states that the licence targets
the case of a vendor that repackages the binaries inside its own app bundle. The library that
CipherBox links, `libfuse-t.dylib`, is LGPL-2.1. The SMB server is the author's own code under
AGPL or a commercial licence. The PR body rated gate 4 "CONDITIONAL", not "PASS".

**Windows: WinFsp through winfsp-rs.** WinFsp is GPLv3 with a FLOSS exception. The only Rust
bindings, `winfsp` and `winfsp-sys` from `SnowflakePowered/winfsp-rs`, are GPL-3.0 with no
linking exception. The 2026-08-25 recon on FSM1/cipher-box#1376 gave the owner three
options: relicense the desktop binary as GPL-3.0, write and maintain a permissive WinFsp FFI in a
new crate that permits `unsafe`, or ask the winfsp-rs author for an exception. A comment of
2026-08-25 then recorded "ship under the WinFsp FLOSS exception", with two conditions: show the
WinFsp notice and project address in the UI and the documentation, and ship no proprietary
software beside it. That route gives "no GPL obligation on CipherBox" only if CipherBox does not
link winfsp-rs, because the exception covers WinFsp and not the binding. On 2026-08-26 the owner
answered an AskUserQuestion: keep to the v1 approach, build on winfsp-rs 0.12, and accept the
GPLv3 combined work. The WinFsp commercial licence stays the alternative. The FLOSS-exception
route of the day before did not ship.

**macOS: signing.** FSM1/cipher-box#1516 found on 2026-08-26 that the bundle had no
`bundle.macOS` block: no Developer ID identity, no hardened runtime, no notarization. The
bundle was ad hoc signed. The hardened runtime turns on library validation, which refuses a
library that Apple or the app's own team did not sign. `libfuse-t.dylib` carries a third-party
Developer ID, so under the hardened runtime the mount does not start. On 2026-09-05 the owner
decided that the Apple Developer Program enrolment is not planned for v2.0.0, and that the code
half can land at any time and degrade to ad hoc signing until the secrets exist.
FSM1/cipher-box#1860 landed that code half on 2026-09-16.

The rules live today in `blueprint/desktop.md` "Backends" (the "Windows licensing" paragraph),
"Tauri shell" (the licence footer) and "Open edges" ("FUSE-T license terms"), and in
`blueprint/deploy.md` "Desktop release artifacts".

## Decision

**D1 — The macOS build does not bundle FUSE-T; the member installs it.** Bundling FUSE-T in
`CipherBox.app` requires a commercial licence negotiated with the FUSE-T author, and that
negotiation must close before v2.0 ships with a bundled FUSE-T. Until then the free interim path
is a FUSE-T that the member installs from the official package or Homebrew. The shell links
`libfuse-t.dylib` dynamically through `@rpath`, with the rpath at the FUSE-T install directory,
and carries no copy of it (`apps/desktop/src-tauri/build.rs:23`-`38`, from
FSM1/cipher-box#1515). The rule landed with FSM1/cipher-box#736; this ADR records it.

**D2 — The Windows build is a GPLv3 combined work through winfsp-rs, and it shows the WinFsp
notice.** The Windows host adapter is built on winfsp-rs, so the Windows build is a combined
work with WinFsp and winfsp-rs and is distributed under GPLv3. The WinFsp commercial licence is
the alternative for a distribution that cannot be made under GPLv3. Two conditions are part of
the backend:

- The notice "WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos" and the
  address <https://github.com/winfsp/winfsp> show in the desktop UI on every screen
  (`apps/desktop/src/frontDoor.tsx:301`) and are stated in `docs/ATTRIBUTION.md`.
- No proprietary software is bundled beside WinFsp.

The GPLv3 position was decided on 2026-08-26 in FSM1/cipher-box#1376. It replaces the
FLOSS-exception route of 2026-08-25, which held only for a CipherBox that does not link
winfsp-rs. The two conditions come from the 2026-08-25 decision. The 2026-08-26 decision does not
repeat them and does not revoke them, and FSM1/cipher-box#1550 shipped both. The rest of the
repository stays MIT. The footer shows the WinFsp notice on a build that names no platform, and
withholds it only from a build known to ship no WinFsp
(`apps/desktop/src/frontDoor.tsx:319`-`348`).

**D3 — The macOS bundle runs the hardened runtime and disables library validation.** The
`bundle.macOS` block of `apps/desktop/src-tauri/tauri.conf.json` (lines 28 to 32) sets
`hardenedRuntime: true` and names `Entitlements.plist`. That file carries one entitlement,
`com.apple.security.cs.disable-library-validation`. Without it, library validation refuses the
third-party `libfuse-t.dylib` and the mount does not start. The accepted cost: any library on
the rpath can load into the process without a signature check. The rest of the hardened runtime
stays on. The rule landed with FSM1/cipher-box#1860; this ADR records it and its trade-off.

**D4 — Developer ID signing and notarization are optional, and the fallback is ad hoc
signing.** A repository without Apple credentials still produces a macOS bundle, and that
bundle is ad hoc signed and not notarized. `signingIdentity` is `null` in
`tauri.conf.json:29`, so the bundler reads the identity from `APPLE_SIGNING_IDENTITY`. The
Apple Developer Program enrolment is not planned for v2.0.0. The v2.0.0 macOS install note must
tell a member to use System Settings > Privacy & Security > Open Anyway on the first launch.
Decided on 2026-09-05 in FSM1/cipher-box#1516.

**D5 — Signing runs only when every `APPLE_*` secret exists.** The macOS job of
`.github/workflows/desktop-release.yml` (lines 81 to 101) exports six variables to the build:
`APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`,
`APPLE_PASSWORD` and `APPLE_TEAM_ID`. It exports all six or none. An empty secret stops the
export with a notice, and the bundle stays ad hoc signed. The job writes each value to
`GITHUB_ENV` behind a random heredoc delimiter. The rule landed with FSM1/cipher-box#1860; this
ADR records it.

## Rationale

- **D1 keeps the free path open without a licence the project does not hold.** The author's
  terms bind a vendor that repackages FUSE-T. A member who installs FUSE-T takes it under the
  author's own terms, and CipherBox distributes nothing of it. The code treats FUSE-T as the
  member's own install: the macOS footer names it as a courtesy, not as a licence notice
  (`apps/desktop/src/frontDoor.tsx:316`, "FUSE-T is the member's own install, and asks for no
  notice"), and the FUSE-T section of `docs/ATTRIBUTION.md` says that FUSE-T "is installed by
  the user's machine rather than bundled".
- **D2 costs the Windows build its MIT terms and nothing else.** MIT code can join a GPLv3
  combined work, so the rest of the repository keeps its licence. The binding is maintained
  upstream and was the v1 approach, so CipherBox writes and maintains no WinFsp FFI of its own.
  The notice condition is a UI fact, and the footer test proves it on every screen.
- **D2 withholds a notice only where the build is known not to owe it.** A build that names no
  platform carries every notice. One notice too many is cosmetic. One notice too few breaks a
  licence condition.
- **D3 adds no reader of the plaintext that the mount did not already have.** The FUSE-T
  install that the member runs is already in the plaintext path: its SMB server serves every
  mounted read and write to the kernel. An actor who can replace a file of that install sees the
  plaintext with or without library validation. The entitlement removes one check on the
  library, and the rest of the hardened runtime stays on.
- **D4 lets the code half ship before the credentials.** The owner decides when to enrol. The
  bundle block and the release step do not change on that day; only the secrets arrive.
- **D5 makes a half-configured signing impossible.** An absent secret expands to an empty
  string, and the bundler reads an empty string as an identity and passes it to `codesign`. A
  partial set would fail the release or produce a signed bundle that is not notarized.
  All-or-nothing gives exactly two outcomes: ad hoc, or signed and notarized.

## Alternatives rejected

**(a) Ship the Windows build under the WinFsp FLOSS exception (the 2026-08-25 decision).** The
exception covers WinFsp, not winfsp-rs. It holds only with a permissive WinFsp FFI that
CipherBox writes and maintains in a new crate that permits `unsafe`. On 2026-08-26 the owner
kept the v1 binding and accepted the GPLv3 combined work instead.

**(b) Ask the winfsp-rs author for a permissive licence or a linking exception.** The
2026-08-25 recon listed it. It puts the Windows mount behind an answer the project does not
control, and the owner did not choose it.

**(c) Bundle FUSE-T in the app now.** It needs the commercial licence first, and the author
publishes no price. The member-installed path is free and meets the author's stated intent.

**(d) macFUSE instead of FUSE-T.** #32 rejected it: kernel extension install friction on Apple
Silicon, a paid licence for commercial bundling, and a `fuser` ABI divergence.

**(e) Keep the macOS bundle without the hardened runtime.** This was the state before
FSM1/cipher-box#1860. Notarization requires the hardened runtime, so this closes the Developer
ID path permanently.

**(f) Hardened runtime with library validation on.** Library validation refuses
`libfuse-t.dylib`, and the mount does not start.

**(g) Enrol in the Apple Developer Program before v2.0.0.** The owner decided on 2026-09-05 that
the enrolment is not planned for v2.0.0.

## Consequences

1. **The blueprint already carries D1, D2, D3 and D5, and the first half of D4.**
   `blueprint/desktop.md` "Backends" carries D2 in its "Windows licensing" paragraph, "Tauri
   shell" names the licence footer that D2 requires, and "Open edges" carries D1 under "FUSE-T
   license terms". `blueprint/deploy.md` "Desktop release artifacts" carries D3, D5, and the
   optional signing with the ad hoc fallback of D4. `blueprint/testing.md` "Hardware
   verification gates" item 4 names the FUSE-T licence check behind D1.
2. **`CONTEXT.md` carries no term for these rules, and none is needed.** They are distribution
   terms, not domain language.
3. **This ADR amends no earlier ADR.**
4. **Two blueprint sentences contradict the record, and the editorial pass corrects them.**
   - `blueprint/testing.md` "Hardware verification gates" (line 293). Old: "All five passed:".
     New: "Gates 1, 2, 3 and 5 passed, and gate 4 is CONDITIONAL: bundling FUSE-T needs a
     negotiated commercial licence, and a member-installed FUSE-T is the free interim path
     (ADR 0051)." The rest of the sentence, about gate 5 on macOS 27, stays. The source is the
     gate 4 verdict "CONDITIONAL" in FSM1/cipher-box#736 and `tools/hw-gates/RESULTS.md`.
   - `blueprint/desktop.md` "Backends" table, Windows column of the "Backend" row (line 124).
     Old: "**WinFsp** (MSI bundled)". New: "**WinFsp** (member-installed; the installer bundles
     and downloads no WinFsp)". The source is the code: `tauri.conf.json` names no Windows
     resource, the Windows leg of `desktop-release.yml` installs WinFsp only on the build runner
     through `.github/actions/setup-winfsp`, and `apps/desktop/src-tauri/build.rs` delay-loads the
     WinFsp DLL from the member's own install.
5. **`blueprint/deploy.md` section "Desktop release artifacts" gains the rest of D4**, in the
   owner's words of 2026-09-05 on FSM1/cipher-box#1516: "The Apple Developer Program enrolment
   is not planned for v2.0.0. The macOS install note for v2.0.0 must tell a member to use System
   Settings > Privacy & Security > Open Anyway on first launch."
6. **`blueprint/desktop.md` section "Backends" gains the citation (ADR 0051)** on the "Windows
   licensing" paragraph.
7. **`blueprint/desktop.md` section "Open edges" gains the citation (ADR 0051)** on the "FUSE-T
   license terms" item.
8. **`blueprint/deploy.md` section "Desktop release artifacts" gains the citation (ADR 0051)**
   on the paragraph about the hardened runtime and optional Developer ID signing.
9. **No wire format, no KDF edge, no op queue record, and no updater rule changes.** The
   minisign updater signature of #48 is independent of the Apple signature.

## Residuals

**E1 — The FUSE-T negotiation is open, and the blueprint disagrees with the gate record.** No
commercial licence exists, so v2.0 ships with the member-installed FUSE-T. The author's open
questions stay open: the price, whether an automatic download of the official package counts as
redistribution, and the notices for the closed SMB server. `blueprint/testing.md` "Hardware
verification gates" says "All five passed". FSM1/cipher-box#736 rated gate 4 "CONDITIONAL".
The body of FSM1/cipher-box#736 itself says "All five gates now pass" and also rates gate 4
"CONDITIONAL". This ADR records the conditional verdict of D1, and consequence 4 corrects the
`blueprint/testing.md` sentence.

**E2 — The GPLv3 distribution duties go past the two named conditions.** GPLv3 sections 4 and 6
ask that a binary distribution carries the licence text and gives access to the Corresponding
Source. The source is the public repository at the release tag. No file in the repository holds
the GPLv3 text, `tauri.conf.json` sets no `licenseFile`, so the Windows installer shows no
licence, and neither the installer nor the footer points to the CipherBox source. The blueprint
names only the notice and the no-proprietary-bundle conditions, and this ADR records those. The
missing text and source pointer are a compliance gap in the Windows distribution, filed as
FSM1/cipher-box#2015.

**E3 — The Backends table and the code disagree on the WinFsp installer.** The Windows column of
the `blueprint/desktop.md` "Backends" table reads "**WinFsp** (MSI bundled)". The Windows
installer bundles no WinFsp MSI: `apps/desktop/src-tauri/tauri.conf.json` names no Windows
resource, and the Windows leg of `desktop-release.yml` only provisions WinFsp on the runner
through `.github/actions/setup-winfsp`. `apps/desktop/src-tauri/build.rs` delay-loads the WinFsp
DLL so that the shell starts on a device where WinFsp is installed outside `PATH`. D2 holds in
both cases. This ADR records what the code does, and consequence 4 corrects the row.

**E4 — D3 lets an actor who can write the rpath directory load code into the process.** The
process holds the vault keys. The rationale bounds this by the FUSE-T install, which is already
in the plaintext path. The bound holds only while the rpath names the FUSE-T install directory
alone. A later rpath entry that a less-privileged actor can write widens the exposure, and no
test checks the rpath set against that condition.

**E5 — Without the enrolment, every macOS member meets a Gatekeeper refusal on the first
launch.** Consequence 5 puts the install note of D4 into the blueprint, but the note itself
does not exist yet. `docs/DEPLOYMENT.md` is v1 legacy and still
says "right-click > Open". FSM1/cipher-box#1516 stays open until the credentials exist.

**E6 — The FSKit successor needs the enrolment that D4 defers.** FSM1/cipher-box#736 records
that a shipping FSKit module signs its app extension with the team certificate. The successor
timeline in `blueprint/desktop.md` therefore depends on the Apple Developer Program enrolment.

**E7 — Windows has no Authenticode signature, and no rule covers one.** Windows SmartScreen
warns on the first launch of the installer. Only the minisign updater signature protects the
Windows update path.

**E8 — The Linux build's licence terms are outside this ADR.** The footer and
`docs/ATTRIBUTION.md` carry the MIT notice of the vendored `fuser` on the macOS and Linux
builds. No blueprint row records that as a rule.

## Gate

- **D1:** the `Desktop Build` job of `.github/workflows/ci-desktop.yml` (the `Desktop` area),
  macOS leg, step "FUSE-T rpath reaches the shell binary": the binary links
  `@rpath/libfuse-t.dylib`, and its `LC_RPATH` names the FUSE-T install directory that
  `pkg-config --variable=libdir fuse-t` reports. `apps/desktop/src/frontDoor.test.tsx`: "shows
  the fuser notice and names FUSE-T on macOS while %s". No test asserts that `CipherBox.app`
  holds no copy of FUSE-T. That is a finding.
- **D2:** `apps/desktop/src/frontDoor.test.tsx`, block "the attribution footer": "shows the
  WinFsp notice on a Windows build while %s" (every screen), "carries every notice when the build
  named no platform", and the macOS and Linux cases that assert no WinFsp text.
  `apps/desktop/src/csp.test.ts`: "names the mount backend each host build ships" and "refuses a
  platform token the footer has no arm for". Both files run in the `Desktop frontend typecheck +
tests` job. No test proves that no proprietary software ships beside WinFsp, and no test
  checks the notice in `docs/ATTRIBUTION.md`. Review enforces both. That is a finding.
- **D3:** the `Desktop Build` macOS leg, step "Tauri bundle with no Apple credentials", builds
  the bundle with the `bundle.macOS` block in force. It asserts only the executable and
  `Signature=adhoc`. No test asserts the hardened runtime flag or the entitlement in the
  signature, and no mounted test runs the bundle, so nothing proves that `libfuse-t.dylib` loads
  under the hardened runtime. That is a finding.
- **D4:** the same step proves the fallback: a bundle built with no Apple credentials is ad hoc
  signed. No test runs the Developer ID path, because no job holds the credentials.
- **D5:** no test. The export step runs only in `desktop-release.yml` on a `v*` tag, and no PR
  job runs it with a partial secret set. That is a finding.

The blueprint and glossary are maintained in the `FSM1/cipher-box` repository. The `blueprint/`
copies in this repository are the as-charted archive and are not edited by this ADR.
