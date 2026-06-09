---
phase: { N }
slug: { phase-slug }
status: draft
threats_open: 0
asvs_level: 1
created: { date }
---

# Phase {N} — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

---

## Trust Boundaries

| Boundary   | Description   | Data Crossing             |
| ---------- | ------------- | ------------------------- |
| {boundary} | {description} | {data type / sensitivity} |

---

## Threat Register

| Threat ID | Category          | Component   | Disposition                    | Mitigation             | Status |
| --------- | ----------------- | ----------- | ------------------------------ | ---------------------- | ------ |
| T-{N}-01  | {STRIDE category} | {component} | {mitigate / accept / transfer} | {control or reference} | open   |

_Status: open · closed_
_Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)_

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
| ------- | ---------- | --------- | ----------- | ---- |

_Accepted risks do not resurface in future audit runs._

_If none: "No accepted risks."_

---

## Security Audit Trail

| Audit Date   | Threats Total | Closed | Open | Run By         |
| ------------ | ------------- | ------ | ---- | -------------- |
| {YYYY-MM-DD} | {N}           | {N}    | {N}  | {name / agent} |

---

## Sign-Off

- [ ] All threats have a disposition (mitigate / accept / transfer)
- [ ] Accepted risks documented in Accepted Risks Log
- [ ] `threats_open: 0` confirmed
- [ ] `status: verified` set in frontmatter

**Approval:** {pending / verified YYYY-MM-DD}
