# Session Context

**Session ID:** 0bf632ac-cddf-4e84-8cdb-a7c76df4420f

**Commit Message:** <objective>

Review produced code through the lens of a cryptography and

## Prompt



---

<objective>

Review produced code through the lens of a cryptography and security testing expert. This command evaluates cryptographic implementations, validates security assumptions, and generates comprehensive test cases and edge cases.

**This command is NOT overwritten by GSD updates.**

**Use when:**
- After implementing cryptographic features
- Before merging security-critical code
- When you want test case ideas for crypto operations
- To validate security assumptions in the design

**Creates:**
- `.planning/security/REVIEW-[timestamp].md` — Security review report
- Test case suggestions (inline or as file)

</objective>

<execution_context>

## Project Security Rules

Reference the project's CLAUDE.md security rules:
- Never store privateKey in localStorage/sessionStorage
- Never log sensitive keys
- Never send unencrypted keys to server
- Always use ECIES for key wrapping
- Always use AES-256-GCM for content encryption
- Server NEVER has access to plaintext or unencrypted keys
- Always encrypt ipnsPrivateKey with TEE public key before sending
- TEE decrypts IPNS keys in hardware only, signs, and immediately discards

## Cryptographic Standards

| Algorithm | Use Case | Notes |
|-----------|----------|-------|
| AES-256-GCM | Content encryption | Authenticated encryption required |
| ECIES | Key wrapping | For asymmetric key transport |
| Web Crypto API | Browser crypto | No polyfills or JS implementations |
| Uint8Array | Binary data | Never strings for crypto data |

</execution_context>

<process>

## Phase 1: Scope Definition

Use AskUserQuestion:
- header: "Review Scope"
- question: "What should I review?"
- multiSelect: false
- options:
  - "Specific files" — I'll provide file paths or patterns
  - "Recent changes" — Review uncommitted or recent commits
  - "Phase code" — Review code from a specific GSD phase
  - "Full crypto audit" — Comprehensive review of all crypto-related code

**If "Specific files":** Ask for file paths/patterns
**If "Recent changes":** Run `git diff` and `git diff --cached` to identify changed files
**If "Phase code":** Ask which phase, then read the phase's PLAN.md to identify relevant files
**If "Full crypto audit":** Search for crypto-related patterns across codebase

## Phase 2: Code Discovery

Based on scope, identify files to review:

```bash
# Find crypto-related files
grep -r -l "encrypt\|decrypt\|crypto\|Crypto\|cipher\|AES\|ECIES\|privateKey\|publicKey" --include="*.ts" --include="*.js" . | grep -v node_modules | grep -v ".test."
```

Also search for:
- Key management code
- Authentication/authorization
- Data serialization of sensitive data
- API endpoints handling secrets
- Storage operations for keys

## Phase 3: Security Analysis

For each file/section, analyze through these lenses:

### 3.1 Cryptographic Correctness

- [ ] Correct algorithm usage (AES-256-GCM, not AES-CBC without MAC)
- [ ] Proper IV/nonce generation (crypto.getRandomValues, never predictable)
- [ ] IV/nonce never reused with same key
- [ ] Authenticated encryption used (GCM, not just encryption)
- [ ] Key sizes appropriate (256-bit for AES, appropriate curves for EC)
- [ ] No deprecated algorithms (MD5, SHA1 for security, DES, RC4)

### 3.2 Key Management

- [ ] Keys derived using proper KDF (not just hashing)
- [ ] Keys never logged or exposed in errors
- [ ] Keys cleared from memory after use
- [ ] Key hierarchy follows spec (rootFolderKey → folderKey → fileKey)
- [ ] Key wrapping uses ECIES as specified
- [ ] No hardcoded keys or secrets

### 3.3 Trust Boundaries

- [ ] Client-side encryption before any server transmission
- [ ] Server never receives plaintext keys
- [ ] TEE boundaries respected (encrypted IPNS keys only)
- [ ] No trust assumptions on server for key material

### 3.4 Implementation Safety

- [ ] Using Web Crypto API (not crypto-js or similar)
- [ ] Uint8Array for all binary data
- [ ] Constant-time comparison for authentication tokens
- [ ] No sensitive data in error messages
- [ ] No sensitive data in logs
- [ ] Proper error handling (no silent failures in crypto)

### 3.5 Data Flow Security

- [ ] Sensitive data encrypted at rest
- [ ] Sensitive data encrypted in transit
- [ ] No sensitive data in URLs or query params
- [ ] No sensitive data in localStorage/sessionStorage (except encrypted)
- [ ] Metadata leakage minimized

## Phase 4: Generate Test Cases

For each crypto operation found, generate test cases:

### Positive Test Cases
- Normal operation with valid inputs
- Boundary conditions (empty data, max size data)
- Different key types/sizes

### Negative Test Cases
- Invalid key format
- Corrupted ciphertext
- Wrong key for decryption
- Tampered authenticated data (GCM tag modification)
- Truncated ciphertext

### Edge Cases
- Empty plaintext encryption
- Very large data encryption (chunking behavior)
- Unicode/binary data handling
- Concurrent encryption operations
- Key rotation scenarios
- Re-encryption with new keys

### Attack Scenarios
- Replay attacks (nonce reuse detection)
- Padding oracle (if applicable)
- Timing attacks (constant-time operations)
- Key confusion attacks
- Downgrade attacks

## Phase 5: Generate Report

Create `.planning/security/` directory if needed:

```bash
mkdir -p .planning/security
```

Write review report to `.planning/security/REVIEW-[timestamp].md`:

```markdown
# Security Review Report

**Date:** [timestamp]
**Scope:** [what was reviewed]
**Reviewer:** Claude (security:review command)

## Executive Summary

[2-3 sentences on overall security posture]

**Risk Level:** [LOW/MEDIUM/HIGH/CRITICAL]

## Files Reviewed

| File | Crypto Operations | Risk Level |
|------|-------------------|------------|
| [file] | [operations] | [level] |

## Findings

### Critical Issues

[Issues that must be fixed before deployment]

### High Priority

[Issues that should be fixed soon]

### Medium Priority

[Issues that represent technical debt]

### Low Priority / Recommendations

[Nice-to-haves and best practices]

## Detailed Analysis

### [File/Component Name]

**What it does:**
[Brief description]

**Crypto operations:**
- [operation 1]
- [operation 2]

**Issues found:**

1. **[Issue Title]**
   - **Severity:** [CRITICAL/HIGH/MEDIUM/LOW]
   - **Location:** [file:line]
   - **Description:** [what's wrong]
   - **Impact:** [what could happen]
   - **Recommendation:** [how to fix]
   - **Reference:** [standard/best practice]

**Positive observations:**
- [what's done well]

---

[Continue for each file/component]

## Test Cases

### [Feature/Component]

#### Unit Tests

```typescript
describe('[component] security', () => {
  // Positive cases
  it('should [expected behavior]', () => {
    // Test suggestion
  });

  // Negative cases
  it('should reject [invalid input]', () => {
    // Test suggestion
  });

  // Edge cases
  it('should handle [edge case]', () => {
    // Test suggestion
  });
});
```

#### Integration Tests

- [ ] [Test scenario 1]
- [ ] [Test scenario 2]

#### Attack Scenarios to Test

- [ ] [Attack scenario 1] — [how to test]
- [ ] [Attack scenario 2] — [how to test]

## Compliance Checklist

Based on project security rules:

- [ ] No privateKey in localStorage/sessionStorage
- [ ] No sensitive keys logged
- [ ] No unencrypted keys sent to server
- [ ] ECIES used for key wrapping
- [ ] AES-256-GCM used for content encryption
- [ ] Server has zero knowledge of plaintext
- [ ] IPNS keys encrypted with TEE public key

## Recommendations Summary

| Priority | Recommendation | Effort |
|----------|----------------|--------|
| [P0/P1/P2] | [recommendation] | [LOW/MEDIUM/HIGH] |

## Next Steps

1. [Immediate action]
2. [Short-term action]
3. [Long-term consideration]

---
*Generated by security:review command*
*This review is automated guidance, not a substitute for professional security audit*
```

## Phase 6: Present Results

Display summary inline:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 SECURITY REVIEW COMPLETE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**Scope:** [what was reviewed]
**Risk Level:** [overall risk]

## Summary

| Severity | Count |
|----------|-------|
| Critical | [n] |
| High | [n] |
| Medium | [n] |
| Low | [n] |

## Top Issues

1. [Most critical issue]
2. [Second issue]
3. [Third issue]

## Test Cases Generated

[n] test case suggestions across [m] categories

**Full report:** `.planning/security/REVIEW-[timestamp].md`

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Use AskUserQuestion:
- header: "Next"
- question: "What would you like to do?"
- options:
  - "View full report" — Display the complete review
  - "Generate test file" — Create a test file with suggested cases
  - "Fix critical issues" — Start addressing critical findings
  - "Done" — End review

</process>

<vulnerability_patterns>

## Common Crypto Vulnerabilities to Check

### Nonce/IV Reuse
```typescript
// BAD: Reusing IV
const iv = new Uint8Array(12); // zeros!
// GOOD: Random IV each time
const iv = crypto.getRandomValues(new Uint8Array(12));
```

### Missing Authentication
```typescript
// BAD: AES-CBC without MAC
// GOOD: AES-GCM (authenticated)
```

### Weak Key Derivation
```typescript
// BAD: Simple hash
const key = await crypto.subtle.digest('SHA-256', password);
// GOOD: PBKDF2/Argon2 with iterations
```

### Timing Attacks
```typescript
// BAD: Early return on mismatch
if (a[i] !== b[i]) return false;
// GOOD: Constant-time comparison
```

### Key in Logs/Errors
```typescript
// BAD
console.log('Key:', key);
throw new Error(`Failed with key ${key}`);
// GOOD
console.log('Key operation failed');
throw new Error('Decryption failed');
```

### Predictable Randomness
```typescript
// BAD
Math.random()
// GOOD
crypto.getRandomValues()
```

</vulnerability_patterns>

<success_criteria>

- [ ] Scope defined and files identified
- [ ] All crypto operations catalogued
- [ ] Each operation checked against security criteria
- [ ] Issues categorized by severity
- [ ] Test cases generated for each crypto operation
- [ ] Report written to `.planning/security/`
- [ ] Summary presented to user
- [ ] Next steps offered

**Quality indicators:**
- Findings are specific (file:line, not vague)
- Test cases are implementable (actual code suggestions)
- Recommendations include HOW to fix, not just WHAT's wrong
- False positives acknowledged where uncertain

</success_criteria>


ARGUMENTS: of all the changes in pr 123

## Summary

All fixes applied and tests pass. Here's a summary of everything fixed:

**Changes made (8 files, 38 insertions, 15 deletions):**

| Fix | File | What changed |
|-----|------|-------------|
| **C-01** | `.gitignore` | Changed `.env` to `**/.env` (recursive match) |
| **C-01** | `apps/api/.env`, `tests/e2e/.env`, `cipherbox-test.txt` | Untracked from git (`git rm --cached`) |
| **C-02** | `google-oauth.service.ts` | Added production guard: throws if `GOOGLE_CLIENT_ID` unset in production, warns in dev/staging |
| **C-02** | `.env.example` | Added `GOOGLE_CLIENT_ID` and `IDENTITY_JWT_PRIVATE_KEY` entries |
| **H-01** | `auth.service.ts` | Replaced `!==` with `crypto.timingSafeEqual()` for secret comparison |
| **H-02** | `auth.service.ts` | Added `NODE_ENV === 'production'` rejection as defense-in-depth |
| **H-03** | `auth.controller.ts` | Added `@UseGuards(ThrottlerGuard)` and `@Throttle` (5 req/15min) to test-login |
| **M-01** | `hooks.ts` | Removed 5 `console.log` calls leaking public keys and migration events |
| **M-01** | `useAuth.ts` | Removed `console.log` of public key on login |
| **M-02** | `email-otp.service.ts` | Narrowed OTP logging to `development` only (was `!== 'production'`, which included staging) |

**Still needed (manual action required):**
1. **Rotate secrets immediately:** JWT_SECRET, Pinata JWT/API key (they're in git history permanently)
2. **Consider** running `gitleaks` or BFG Repo Cleaner on git history
3. **Commit** these changes (shall I commit them?)

## Key Actions

- - **Bash**: Get PR #123 details
- - **Bash**: Get PR #123 diff
- - **Bash**: List all changed files in PR #123
- - **Task**: Review backend identity/auth security
- - **Task**: Review frontend auth/migration security
- - **Task**: Review E2E tests and env security
- - **TaskOutput**: 
- - **TaskOutput**: 
- - **TaskOutput**: 
- - **TaskOutput**: 
