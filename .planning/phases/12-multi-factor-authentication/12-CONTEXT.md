# Phase 12: Multi-Factor Authentication - Context

**Gathered:** 2026-02-12
**Updated:** 2026-02-12 (architectural pivot: PnP Modal SDK → Core Kit for full MFA control)
**Status:** Ready for re-research and replanning

## Phase Boundary

Users can strengthen account security with additional authentication factors and recovery options. This phase replaces the PnP Modal SDK auth layer with Web3Auth Core Kit (or MPC Core Kit) to gain full control over MFA enrollment, cross-device share transfer, and recovery flows. It also adds SIWE (Sign-In with Ethereum) for wallet login unification. Cross-platform desktop MFA is a separate phase (11). Sharing and link generation are separate phases (14-15).

## Architectural Pivot (2026-02-12)

### Why not PnP Modal SDK + mfaSettings?

The initial research (12-RESEARCH.md) found that the PnP Modal SDK approach (`mfaSettings` + React hooks) gives up too much control:

- **No cross-device approval flow**: The old tKey/Core Kit had `requestDeviceShare()` / `approveDevice()` for approving a new device from an existing one. The PnP SDK hides this behind `manageMFA()` in Web3Auth's opaque modal iframe.
- **No custom enrollment UX**: SDK handles all MFA UI in its modal — can't customize enrollment steps, recovery phrase presentation, or factor management.
- **Device shares are ephemeral**: Browser localStorage is fragile. Without cross-device transfer, losing browser data means falling back to recovery phrase every time.
- **No programmatic share management**: Can't build custom device sync or approval flows.
- **External wallet MFA gap**: PnP SDK's MFA (Shamir splits) only applies to MPC-derived keys, not external wallet logins. Wallet users would bypass MFA entirely.

### New direction: Core Kit + SIWE

Replace PnP Modal SDK entirely with lower-level Core Kit for:

1. **Full MFA control**: Custom enrollment UI, programmatic share management, cross-device approval
2. **Custom login UI**: Build CipherBox-branded login screens instead of Web3Auth's modal
3. **SIWE for wallets**: Wallet signs SIWE message → CipherBox API verifies → issues JWT → submitted to Web3Auth as custom verifier (sub = wallet address). This gives wallet users a Web3Auth-managed MPC key that CAN be protected by MFA.
4. **Unified auth model**: Every user (social + wallet) gets a Web3Auth-managed key with full MFA support

### Scope expansion

This turns Phase 12 from "configure SDK settings" into "replace auth layer + add MFA." Accepted tradeoff: bigger phase, but correct architecture for a zero-knowledge product.

## Implementation Decisions

### Enrollment flow

- Claude's discretion on wizard vs single-page setup (pick best approach based on Core Kit patterns)
- Proactive nudge: show a banner/notification suggesting MFA after first login, with dismiss option
- **Mandatory first-time setup**: user must complete MFA enrollment before first vault access — no skip
- If enrollment fails partway (browser closed, error), start fresh on next login — no partial resume

### Recovery phrase UX

- Claude's discretion on presentation format (word grid, sequential reveal, etc.)
- Checkbox confirmation: "I have saved my recovery phrase in a safe place" — no quiz
- Re-access to recovery phrase after setup: depends on Core Kit SDK capabilities (researcher to investigate)
- **Prominent warning**: bold message explaining vault is permanently inaccessible if phrase is lost and device is unavailable
- Allow recovery phrase regeneration from settings (invalidates old phrase)

### Settings page layout

- MFA section added to existing settings page
- Claude's discretion on status card vs toggle vs other layout (user may want to see mockups during implementation)
- Claude's discretion on whether MFA is a section within settings or a dedicated sub-page
- **Show current auth method** (Google, email, etc.) alongside MFA status so user sees full auth picture

### Factor types

- Support all factor types that Core Kit provides
- Device share and recovery phrase are the minimum required (from success criteria)
- **Cross-device approval**: Users should be able to approve a new device from an existing authenticated device

### Login with MFA active

- Custom second-factor UI built by CipherBox (not Web3Auth modal)
- User should see which factors are available and choose one
- Reference: ChainSafe Files (`github.com/chainsafe/ui-monorepo`) used SDK-based Web3Auth integration with significant customization — user has domain expertise here

### SIWE for wallet login

- Wallet user signs SIWE message with MetaMask/WalletConnect
- CipherBox API verifies SIWE signature, issues a token
- Token submitted to Web3Auth via custom verifier (sub = wallet address)
- Web3Auth derives MPC key for this identity — wallet user now has MFA-protectable key
- Eliminates the ADR-001 signature-derived key bifurcation

### Recovery flow

- Claude's discretion on recovery entry point (login page link vs automatic detection)
- Must work when user has lost their device share
- Cross-device approval should be the PRIMARY recovery path (not just recovery phrase)

### CRITICAL: Key identity after MFA

- Previous research confirmed: Shamir Secret Sharing splits the existing key, reconstructed key is identical
- This should still hold with Core Kit — verify during research
- Success Criterion 4 requires publicKey to remain identical after MFA enrollment

### Test automation

- **Research required**: How does E2E testing work with Core Kit MFA?
- If MFA is mandatory, automation needs a path
- Researcher should investigate Core Kit test/devnet MFA behavior

### Claude's Discretion

- Enrollment flow structure (wizard vs single-page)
- Recovery phrase presentation format
- Settings page layout for MFA section
- Recovery flow entry point
- Loading/error states during enrollment
- Exact factor enrollment order
- Login UI design (replacing Web3Auth modal)

## Specific Ideas

- Reference: ChainSafe Files (`chainsafe/ui-monorepo`) — user previously built Web3Auth MFA integration with SDK-based approach allowing significant customization including cross-device approval
- User expects MFA setup to be a hard requirement — security-first stance
- SIWE unifies wallet + social login into one key management model
- Cross-device approval is a key differentiator vs the simpler PnP approach

## Deferred Ideas

None — discussion stayed within phase scope

---

_Phase: 12-multi-factor-authentication_
_Context gathered: 2026-02-12_
_Updated: 2026-02-12 (Core Kit pivot)_
