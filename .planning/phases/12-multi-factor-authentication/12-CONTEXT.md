# Phase 12: Multi-Factor Authentication - Context

**Gathered:** 2026-02-12
**Status:** Ready for planning

## Phase Boundary

Users can strengthen account security with additional authentication factors and recovery options, using Web3Auth's `mfaSettings` configuration. This phase covers MFA enrollment, device share factor, backup recovery phrase, and settings page integration. Cross-platform desktop MFA is a separate phase (11). Sharing and link generation are separate phases (14-15).

## Implementation Decisions

### Enrollment flow

- Claude's discretion on wizard vs single-page setup (pick best approach based on Web3Auth SDK patterns)
- Proactive nudge: show a banner/notification suggesting MFA after first login, with dismiss option
- **Mandatory first-time setup**: user must complete MFA enrollment before first vault access — no skip
- If enrollment fails partway (browser closed, error), start fresh on next login — no partial resume

### Recovery phrase UX

- Claude's discretion on presentation format (word grid, sequential reveal, etc.)
- Checkbox confirmation: "I have saved my recovery phrase in a safe place" — no quiz
- Re-access to recovery phrase after setup: depends on Web3Auth SDK capabilities (researcher to investigate)
- **Prominent warning**: bold message explaining vault is permanently inaccessible if phrase is lost and device is unavailable
- Allow recovery phrase regeneration from settings (invalidates old phrase)

### Settings page layout

- MFA section added to existing settings page
- Claude's discretion on status card vs toggle vs other layout (user may want to see mockups during implementation)
- Claude's discretion on whether MFA is a section within settings or a dedicated sub-page
- **Show current auth method** (Google, email, etc.) alongside MFA status so user sees full auth picture

### Factor types

- Support **all factor types that Web3Auth mfaSettings provides** out of the box (not just device share + recovery)
- Device share and recovery phrase are the minimum required (from success criteria)

### Login with MFA active

- Login UX for MFA second-factor depends heavily on Web3Auth SDK integration path
- Researcher should investigate current SDK customization capabilities
- Reference: ChainSafe Files (`github.com/chainsafe/ui-monorepo`) used SDK-based Web3Auth integration with significant customization — verify if this approach is still viable

### Recovery flow

- Claude's discretion on recovery entry point (login page link vs automatic detection)
- Must work when user has lost their device share

### CRITICAL: Key identity after MFA

- **Research required**: Does enabling MFA via Web3Auth `mfaSettings` change the derived private key?
- If key changes: must decide between mandatory-MFA-for-all (single key path) vs optional-MFA with vault re-encryption
- This decision blocks the architecture of the entire phase — researcher must answer definitively
- Success Criterion 4 requires publicKey to remain identical after MFA enrollment

### Test automation

- **Research required**: How does the E2E test account (`test_account_4718@example.com`) authenticate with MFA?
- If MFA is mandatory, automation needs a path (hardcoded recovery phrase, pre-enrolled device share, or SDK bypass for test environments)
- Researcher should investigate Web3Auth test/devnet MFA behavior

### Claude's Discretion

- Enrollment flow structure (wizard vs single-page)
- Recovery phrase presentation format
- Settings page layout for MFA section
- Recovery flow entry point
- Loading/error states during enrollment
- Exact factor enrollment order

## Specific Ideas

- Reference: ChainSafe Files (`chainsafe/ui-monorepo`) — user previously built Web3Auth MFA integration there with SDK-based approach that allowed significant customization. Verify if this integration pattern is still supported.
- User expects MFA setup to be a hard requirement — security-first stance
- The relationship between MFA enrollment and derived key identity is the single most important technical question for this phase

## Deferred Ideas

None — discussion stayed within phase scope

---

_Phase: 12-multi-factor-authentication_
_Context gathered: 2026-02-12_
