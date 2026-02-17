# Testing Patterns

**Analysis Date:** 2026-01-20

## Test Framework

**Runner:**
- Not configured - no test framework installed

**Assertion Library:**
- Not configured

**Run Commands:**
```bash
# No test commands available
# package.json does not include test scripts
```

## Current State

**Status:** No automated testing infrastructure exists in this codebase.

The project is in preliminary R&D/POC phase. The only "testing" is:
1. Manual execution of the POC harness (`npm start`)
2. Runtime verification within the POC code itself

## POC Verification Pattern

The POC (`00-Preliminary-R&D/poc/src/index.ts`) uses inline verification:

```typescript
// Verification is built into the workflow
const downloadAndVerifyFile = async (
    ctx: HarnessContext,
    folder: FolderState,
    expectedName: string,
    expectedContent: Uint8Array,
    expectedMetadataCid?: string
): Promise<void> => {
    // ... fetch and decrypt file ...

    if (bytesToHex(plaintext) !== bytesToHex(expectedContent)) {
        throw new Error(`File content mismatch for ${expectedName}`);
    }
};

// Called after each operation
await downloadAndVerifyFile(ctx, docsFolder, fileName, fileContent, docsAfterUpload.cid);
console.log("File verified after upload");
```

---

## Recommended Testing Setup (for future implementation)

### Philosophy

CipherBox shall employ a **Test Pyramid** approach with comprehensive coverage at all layers. Backend and TEE development **must** follow **Test-Driven Development (TDD)**, while frontend relies on **End-to-End automation** for validation.

**Core Principles:**
- TDD is mandatory for all backend and TEE code - write tests first, then implementation
- Test Pyramid structure: more unit tests, fewer E2E tests for fast feedback loops
- All tests must run in CI/CD pipeline - no manual testing gates
- Cryptographic operations require exhaustive testing with 100% coverage
- Frontend coverage achieved through automated E2E browser tests (no TDD required)

### Test Pyramid Structure

**Target Ratios:**
- Unit Tests: 70% of test suite
- Integration Tests: 20% of test suite
- E2E Tests: 10% of test suite

**Layer Definitions:**

| Layer | Scope | Speed | Dependencies |
|-------|-------|-------|--------------|
| Unit | Single function/class | < 5ms | All mocked |
| Integration | Service composition, DB | 50-500ms | Real database, mocked externals |
| API E2E | Full backend stack | 100ms-2s | Full app, mocked IPFS |
| Frontend E2E | Complete application | 2-30s | Full stack |

### Test Execution Environments

**Unit Tests:**
- Run on: Developer machines, CI runners
- Dependencies: All mocked (database, IPFS, external APIs)
- Database: None (mocked)
- Secrets: None required
- Parallelization: Full parallel execution

**Integration Tests:**
- Run on: Developer machines (Docker), CI runners
- Dependencies: Real PostgreSQL in Docker, mocked IPFS/Pinata
- Database: Test database with migrations, truncated between test suites
- Secrets: Test credentials only (never production)
- Parallelization: Sequential due to shared database state

**API E2E Tests:**
- Run on: Developer machines, CI runners, optionally staging
- Dependencies: Full NestJS application, real database, mocked IPFS
- Database: Test database, reset between test suites
- Secrets: Test JWT keys, mock Web3Auth tokens

**Frontend E2E Tests (Cypress/Puppeteer):**
- Run on: Developer machines, CI runners, **staging environment**
- Dependencies: Frontend app + Backend API + Database (full stack)
- Database: Seeded with test fixtures, reset to snapshot between spec files
- Browsers: Chrome (primary), Firefox, Edge
- Parallelization: Parallel specs via Cypress Cloud

**TEE Tests:**
- Local/CI: Mock enclave, attestation skipped, test keys
- Staging: Real Phala testnet enclave, attestation verified, test keys (not production)

### Framework Requirements

*Note: This section specifies framework choices and requirements. Concrete configuration files and implementation examples will be created when the testing infrastructure is implemented.*

**Backend (NestJS):**
- Test Runner: Jest (NestJS default)
- Mocking: `@nestjs/testing` module with Jest mocks
- HTTP Testing: Supertest for API endpoint testing
- Coverage: Jest/Istanbul with enforced thresholds

**Frontend (React):**
- E2E Framework: Cypress (recommended) or Puppeteer
- Component Testing: Cypress Component Testing for complex components (optional)
- Visual Regression: Percy integration (optional)

**TEE (Rust):**
- Test Framework: Native Rust `#[test]` attributes
- Integration: Custom mock enclave harness for local testing

### TDD Requirements (Backend & TEE)

**Mandatory Workflow - Red-Green-Refactor:**
1. RED: Write a failing test for new functionality
2. GREEN: Write minimal code to make the test pass
3. REFACTOR: Clean up while keeping tests green
4. COMMIT: After each green phase
5. REPEAT: Next requirement

**TDD Rules:**
- No production code without a failing test first
- Tests must fail for the right reason before implementing
- Write the simplest code to pass the test
- Refactor only when tests are green

**What Backend Unit Tests Must Cover:**
- Service methods in isolation
- Controller request handling and response formatting
- DTOs and validation logic
- Utility functions (crypto, data conversion)
- Guards and middleware
- Error handling and edge cases

### Frontend E2E Requirements

**No TDD required** - coverage achieved through comprehensive browser automation.

**Test Coverage Must Include:**
- All critical user journeys (authentication, file upload/download, folder operations)
- Error scenarios and recovery flows
- Cross-browser compatibility (Chrome, Firefox, Edge)

**Selector Strategy:**
- Use `data-testid` attributes exclusively for test selectors
- Avoid flaky selectors (timing-based, nth-child, CSS classes)

**Test Organization:**
- Group by feature area: `auth/`, `vault/`, `settings/`
- Separate spec files per user journey
- Shared fixtures for mock data and responses
- Custom commands for common operations (login, createVault, uploadFile)

### Coverage Requirements

**Backend Coverage Thresholds:**

| Area | Line Coverage | Branch Coverage |
|------|---------------|-----------------|
| Crypto Services | 100% | 100% |
| Auth Services | 90% | 85% |
| Vault Services | 90% | 85% |
| IPFS/IPNS Services | 85% | 80% |
| Controllers | 80% | 75% |
| Guards/Middleware | 90% | 85% |
| **Overall Minimum** | **85%** | **80%** |

**TEE Coverage Thresholds:**

| Area | Coverage |
|------|----------|
| Crypto Functions | 100% |
| Key Handling | 100% |
| Error Paths | 100% |

**Frontend E2E Metrics:**

| Metric | Target |
|--------|--------|
| Critical User Journeys Covered | 100% |
| Error Scenarios Tested | 90% |
| Test Pass Rate | 100% |
| Flaky Tests | 0% |

### Mocking Guidelines

**What to Mock:**
- Database connections and queries (unit tests only)
- IPFS client operations (network calls)
- Pinata API calls
- Web3Auth verification
- External HTTP services

**What NOT to Mock:**
- Cryptographic functions - always test real encryption/decryption
- Data conversion utilities (hexToBytes, bytesToHex)
- Validation logic

### Automated Linting & Pre-commit Hooks

**Pre-commit Hook Requirements:**
- ESLint with `--max-warnings 0` (zero tolerance for lint errors)
- Prettier formatting check
- TypeScript type checking
- Unit tests for changed files only (`jest --findRelatedTests`)
- Cargo fmt and Clippy for Rust code

**Pre-push Hook Requirements:**
- Full unit test suite
- Integration tests
- Coverage threshold verification
- Build verification

**Enforcement:**
- Commits blocked if any check fails
- No `eslint-disable` comments without PR justification
- No `.skip()` or `.only()` in tests (enforced via ESLint rules)
- Bypassing hooks (`--no-verify`) requires explicit justification in PR

**CI Duplication:**
- All pre-commit checks duplicated in CI pipeline
- Catches bypassed hooks - bypassing locally only delays failure

### CI Pipeline Structure

**Stage 1: Lint & Type Check (parallel)**
- ESLint (Backend + Frontend)
- Prettier formatting verification
- TypeScript compilation check
- Cargo fmt + Clippy (TEE)

**Stage 2: Unit Tests (parallel, no services needed)**
- Backend unit tests with coverage
- TEE unit tests with coverage
- Coverage threshold enforcement

**Stage 3: Integration Tests**
- Backend integration tests
- Requires PostgreSQL service container

**Stage 4: E2E Tests (parallel)**
- API E2E tests (full backend + database)
- Frontend Cypress tests (full stack)
- Screenshot/video artifacts on failure

**Stage 5: Build & Deploy**
- Production build verification
- Deploy to staging (main branch only)

### Test Data Management

**Data Lifecycle by Test Level:**

| Level | Setup | Cleanup | Isolation |
|-------|-------|---------|-----------|
| Unit | In-memory mocks | Automatic (GC) | Per test |
| Integration | Migrations + seeds | Truncate tables | Per suite |
| API E2E | Fixtures via API | Truncate tables | Per suite |
| Frontend E2E | Seeded database | Reset to snapshot | Per spec file |

**Fixture Requirements:**
- Factory functions for test entities (users, vaults, files)
- Deterministic test keys for reproducible crypto tests
- JSON fixtures for Cypress mock responses

### Priority Test Areas

Based on project criticality:

1. **Cryptographic correctness** (highest priority)
   - Encryption/decryption roundtrips must always pass
   - Key derivation consistency
   - ECIES key wrapping integrity
   - Tamper detection (modified ciphertext, wrong keys)

2. **Authentication & Authorization**
   - Token validation and expiry
   - Permission boundaries
   - Session management

3. **Data Integrity**
   - Metadata encryption/decryption
   - File content verification
   - IPNS record signing

4. **User Journeys (E2E)**
   - Login → Create Vault → Upload File → Download File → Logout
   - Folder creation and navigation
   - Multi-device sync across devices

---

*Testing analysis: 2026-01-20*
