# Phase 10: Data Portability - Context

**Gathered:** 2026-02-11
**Status:** Ready for planning

## Phase Boundary

Users can export their vault as a JSON file for independent recovery. The export contains encrypted root keys and the root IPNS name — enough to traverse the IPNS-based folder hierarchy and decrypt all files using the user's private key, without any CipherBox infrastructure. A standalone recovery page (independent of CipherBox) performs the actual recovery.

## Implementation Decisions

### Export content scope

- **Minimal export**: root IPNS name, encrypted root folder key, encrypted root IPNS private key
- **No subfolder keys** — recovery traverses IPNS to discover subfolder hierarchy and keys
- **No CID list** — CIDs are discovered via IPNS traversal, not pre-listed in export
- **No plaintext metadata** — folder names and structure only visible after decryption (maximum privacy)
- **No public key** — recovery tool derives public key from provided private key
- **No gateway info** — IPFS is content-addressed, any gateway works
- **Include version identifier** — `version: "1.0"` and format identifier for future compatibility
- **Derivation info**: Claude's discretion on whether to include auth method hints

### Recovery tool form

- **Standalone static HTML page** — single file, no build step, fully independent of CipherBox infrastructure
- Can be saved locally, hosted on IPFS, or served from GitHub Pages
- **Key input**: both paste (hex/base64) and file upload supported
- **File delivery**: zip download with full folder structure preserved
- **Guided walkthrough UI** — step-by-step: upload export, enter key, click recover, with explanations at each step

### Export UX & safety

- **Web app only** for v1 — no desktop export (users can use web app)
- **Confirmation dialog** before export — security warning explaining the export contains sensitive encrypted keys, advising secure storage (external drive, password manager)
- **No re-authentication** required — user is already authenticated
- **Progress indicator**: Claude's discretion (likely a spinner during API call)

### Documentation depth

- **Two locations**: user-friendly explanation in recovery page + detailed technical spec in repo
- **Full technical reference** — every field, crypto algorithm (AES-256-GCM params, ECIES curve, HKDF salt), IPNS resolution steps, folder traversal logic. Sufficient for reimplementation in any language
- **Test vectors included** — sample vault export + sample private key + expected decrypted output
- **Architecture context** — brief section explaining zero-knowledge model and why vault export proves data sovereignty

### Claude's Discretion

- Whether to include auth method derivation hints in export
- Progress indicator implementation (spinner vs instant)
- Exact confirmation dialog copy
- Recovery page visual design and layout
- Technical spec markdown structure

## Specific Ideas

- Recovery page must be a single static HTML file — no dependencies on CipherBox servers or npm packages at runtime
- Export format per API spec: `GET /user/export-vault` endpoint
- Recovery flow per DATA_FLOWS.md section 5.2: load export, provide private key, decrypt root keys, traverse IPNS, download and decrypt all files
- Zip download preserves folder hierarchy as directory structure

## Deferred Ideas

None — discussion stayed within phase scope

---

_Phase: 10-data-portability_
_Context gathered: 2026-02-11_
