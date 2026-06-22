# Desktop E2E recycle-bin: stronger bin-published assertion (API round-trip)

Source: Phase 56 ship — diagnosing the Windows desktop E2E failure.

## Done in Phase 56

The phase-56 bin first-publish regression was caught only by the Windows desktop
E2E because the `.sh` (macOS/Linux) recycle-bin test lacked the "Verify bin entry
published" step that the `.ps1` (Windows) had. Phase 56 added the matching Test 5
to `tests/desktop-e2e/scripts/test-recycle-bin.sh` (grep `/tmp/cipherbox-desktop.log`
for `Bin entry published`), so all three platforms now exercise the bin publish.

## Residual follow-up

The bin-published check is a log-grep proxy. A stronger assertion would verify the
bin IPNS record actually resolves via the API (round-trip), not just that the log
line appeared. Also consider factoring the shared assertion list so the `.sh` and
`.ps1` recycle-bin scripts can't drift again.

Destination: a desktop-E2E test-hardening pass (or fold into Phase 58 if it touches
the desktop E2E suite).
