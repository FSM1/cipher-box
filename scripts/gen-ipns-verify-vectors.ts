/**
 * IPNS Verify Vector Generator
 *
 * Generates tests/vectors/ipns/verify.json — the shared cross-language
 * fixture consumed by both the Rust (crates/fuse/tests/ipns_verify_vectors.rs)
 * and the sdk-core (packages/sdk-core/src/__tests__/ipns.test.ts) test suites.
 *
 * 12 cases (D-11 + Phase 75):
 *   valid, tampered-sig, name-mismatch, cid-swapped, seq-mismatch,
 *   partial-fields, legacy-absent, first-publish-skew,
 *   expired-valid-sig, wrong-validity-type,
 *   malformed-rfc3339-trailing-component, malformed-rfc3339-impossible-date
 *
 * Run from the repo root (packages/core must be built first):
 *   npx tsx scripts/gen-ipns-verify-vectors.ts
 *
 * Or run with packages/core as the working directory:
 *   cd packages/core && npx tsx ../../scripts/gen-ipns-verify-vectors.ts
 *
 * The cid-swapped and seq-mismatch vectors carry REAL Ed25519 signatures over
 * their (mis-matching) CBOR data — meaning Ed25519 verification PASSES
 * but the binding check (embedded value/seq vs response cid/sequenceNumber)
 * fails. This is intentional: these vectors test the binding layer, not
 * the signature layer.
 */

import { fileURLToPath, pathToFileURL } from 'url';
import { dirname, join, resolve } from 'path';
import { writeFileSync, existsSync } from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = join(__dirname, '..');

// ---------------------------------------------------------------------------
// Resolve package paths — packages/core provides @noble/ed25519 and @cipherbox/core;
// cborg is in the pnpm virtual store as a dep of ipns@10.1.3.
// ---------------------------------------------------------------------------

// Determine the cborg path from the pnpm virtual store
const CBORG_PATH = resolve(REPO_ROOT, 'node_modules/.pnpm/cborg@4.5.8/node_modules/cborg/cborg.js');
if (!existsSync(CBORG_PATH)) {
  console.error('cborg not found at expected path:', CBORG_PATH);
  console.error('Run: pnpm install (from repo root)');
  process.exit(1);
}

// @noble/ed25519 is in the pnpm virtual store
const ED25519_PATH = resolve(
  REPO_ROOT,
  'node_modules/.pnpm/@noble+ed25519@2.3.0/node_modules/@noble/ed25519/index.js'
);
if (!existsSync(ED25519_PATH)) {
  console.error('@noble/ed25519 not found at expected path:', ED25519_PATH);
  console.error('Run: pnpm install (from repo root)');
  process.exit(1);
}

// @cipherbox/core dist (packages/core/dist/index.mjs)
const CORE_PATH = resolve(REPO_ROOT, 'packages/core/dist/index.mjs');
if (!existsSync(CORE_PATH)) {
  console.error('@cipherbox/core dist not found at:', CORE_PATH);
  console.error('Run: pnpm --filter @cipherbox/core build');
  process.exit(1);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const { encode: cborEncode } = (await import(pathToFileURL(CBORG_PATH).toString())) as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ed = (await import(pathToFileURL(ED25519_PATH).toString())) as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const { deriveIpnsName } = (await import(pathToFileURL(CORE_PATH).toString())) as any;

// ---------------------------------------------------------------------------
// Deterministic test key material (DO NOT use in production)
// ---------------------------------------------------------------------------

// Primary keypair — used for most cases
const PRIMARY_PRIV_KEY_HEX = '0101010101010101010101010101010101010101010101010101010101010101';
// Secondary keypair — used for name-mismatch (different name derived from it)
const SECONDARY_PRIV_KEY_HEX = '0202020202020202020202020202020202020202020202020202020202020202';

// Test CIDs (valid-looking base32 CIDv1 strings for vector purposes)
const CID_A = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi';
const CID_B = 'bafybeif2pall7dybz7vecqka3zo24irdwabwdi4wc55mdgataz3a5fmfkq';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface VectorEntry {
  description: string;
  ipns_name: string;
  cid: string;
  sequence_number: string;
  signature_v2: string | null;
  data: string | null;
  pub_key: string | null;
  expected_result: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

const DEFAULT_VALIDITY = '2099-01-01T00:00:00.000000000Z';

/**
 * Build CBOR data matching the Rust build_cbor_data / cipherbox-core layout.
 *
 * Field order: TTL (int), Value (bytes), Sequence (int), Validity (bytes), ValidityType (int).
 * This layout matches what the Rust build_cbor_data encodes and what the ipns npm package
 * generates — the same bytes are on both sides of the cross-language boundary.
 *
 * IMPORTANT: Uses cborg directly so we can build CBOR for "wrong" cid/seq values
 * (cid-swapped and seq-mismatch cases) without going through createIpnsRecord.
 *
 * `validity` and `validityType` are parameterized (Phase 75) so callers can emit
 * expired/malformed Validity strings and non-EOL ValidityType values while still
 * producing a real Ed25519 signature over the resulting bytes.
 */
function buildCborData(
  cid: string,
  sequenceNumber: number,
  validity: string = DEFAULT_VALIDITY,
  validityType: number = 0
): Uint8Array {
  return cborEncode({
    TTL: 300000000000,
    Value: new TextEncoder().encode(`/ipfs/${cid}`),
    Sequence: sequenceNumber,
    Validity: new TextEncoder().encode(validity),
    ValidityType: validityType,
  }) as Uint8Array;
}

/**
 * Build the signed bytes per IPFS IPNS spec:
 * "ipns-signature:" || CBOR data
 */
function buildSignedBytes(cborData: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode('ipns-signature:');
  const signed = new Uint8Array(prefix.length + cborData.length);
  signed.set(prefix, 0);
  signed.set(cborData, prefix.length);
  return signed;
}

// ---------------------------------------------------------------------------
// Main generator
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const primaryPriv = hexToBytes(PRIMARY_PRIV_KEY_HEX);
  const primaryPub = (await ed.getPublicKeyAsync(primaryPriv)) as Uint8Array;
  const primaryIpnsName = (await deriveIpnsName(primaryPub)) as string;

  const secondaryPriv = hexToBytes(SECONDARY_PRIV_KEY_HEX);
  const secondaryPub = (await ed.getPublicKeyAsync(secondaryPriv)) as Uint8Array;
  const secondaryIpnsName = (await deriveIpnsName(secondaryPub)) as string;

  console.log('Primary IPNS name:', primaryIpnsName);
  console.log('Secondary IPNS name:', secondaryIpnsName);
  if (primaryIpnsName === secondaryIpnsName) {
    throw new Error('Primary and secondary IPNS names must differ');
  }

  const SEQ = 5;
  const SEQ_DIFFERENT = 99;

  const vectors: VectorEntry[] = [];

  // ------------------------------------------------------------------
  // Case 1: valid — signature, name, cid, and sequence all match
  // ------------------------------------------------------------------
  {
    const cborData = buildCborData(CID_A, SEQ);
    const signedBytes = buildSignedBytes(cborData);
    const sig = (await ed.signAsync(signedBytes, primaryPriv)) as Uint8Array;

    vectors.push({
      description: 'valid — signature, name, cid, and sequence all match',
      ipns_name: primaryIpnsName,
      cid: CID_A,
      sequence_number: String(SEQ),
      signature_v2: bytesToBase64(sig),
      data: bytesToBase64(cborData),
      pub_key: bytesToBase64(primaryPub),
      expected_result: 'valid',
    });
    console.log('Case 1 (valid): done');
  }

  // ------------------------------------------------------------------
  // Case 2: tampered-sig — flip one byte of signatureV2 over an
  // otherwise-valid record. Ed25519 verification fails → "invalid".
  // ------------------------------------------------------------------
  {
    const cborData = buildCborData(CID_A, SEQ);
    const signedBytes = buildSignedBytes(cborData);
    const sig = (await ed.signAsync(signedBytes, primaryPriv)) as Uint8Array;
    const tamperedSig = new Uint8Array(sig);
    tamperedSig[0] ^= 0xff;

    vectors.push({
      description: 'tampered-sig — flip one byte of signatureV2',
      ipns_name: primaryIpnsName,
      cid: CID_A,
      sequence_number: String(SEQ),
      signature_v2: bytesToBase64(tamperedSig),
      data: bytesToBase64(cborData),
      pub_key: bytesToBase64(primaryPub),
      expected_result: 'invalid',
    });
    console.log('Case 2 (tampered-sig): done');
  }

  // ------------------------------------------------------------------
  // Case 3: name-mismatch — CBOR data and sig are from the secondary
  // keypair, but ipns_name is the primary name. secondaryPub derives to
  // secondaryIpnsName, which does NOT match ipns_name (primaryIpnsName).
  // Ed25519 sig is valid; name binding check fails → "invalid".
  // ------------------------------------------------------------------
  {
    const cborData = buildCborData(CID_A, SEQ);
    const signedBytes = buildSignedBytes(cborData);
    const sig = (await ed.signAsync(signedBytes, secondaryPriv)) as Uint8Array;

    vectors.push({
      description: 'name-mismatch — valid sig but pubKey derives to different IPNS name',
      ipns_name: primaryIpnsName,
      cid: CID_A,
      sequence_number: String(SEQ),
      signature_v2: bytesToBase64(sig),
      data: bytesToBase64(cborData),
      pub_key: bytesToBase64(secondaryPub),
      expected_result: 'invalid',
    });
    console.log('Case 3 (name-mismatch): done');
  }

  // ------------------------------------------------------------------
  // Case 4: cid-swapped — sig valid over CBOR data containing CID_A,
  // but response `cid` field is CID_B.
  //
  // Ed25519 signature covers: "ipns-signature:" + CBOR{Value="/ipfs/CID_A", ...}
  // → verify_ipns_resolve_signature returns Ok(Some(true)).
  // Binding check: embedded value "/ipfs/CID_A" != "/ipfs/CID_B" → fail.
  // Expected result: "invalid" (caught by binding layer, not sig layer).
  // ------------------------------------------------------------------
  {
    const cborData = buildCborData(CID_A, SEQ);
    const signedBytes = buildSignedBytes(cborData);
    const sig = (await ed.signAsync(signedBytes, primaryPriv)) as Uint8Array;

    vectors.push({
      description:
        'cid-swapped — valid sig over CBOR data with CID_A, but response cid field is CID_B',
      ipns_name: primaryIpnsName,
      cid: CID_B,
      sequence_number: String(SEQ),
      signature_v2: bytesToBase64(sig),
      data: bytesToBase64(cborData),
      pub_key: bytesToBase64(primaryPub),
      expected_result: 'invalid',
    });
    console.log('Case 4 (cid-swapped): done — sig covers CBOR with CID_A, response.cid=CID_B');
  }

  // ------------------------------------------------------------------
  // Case 5: seq-mismatch — sig valid over CBOR data with seq=99,
  // but response `sequence_number` is 5.
  //
  // Ed25519 signature covers: "ipns-signature:" + CBOR{Sequence=99, ...}
  // → verify_ipns_resolve_signature returns Ok(Some(true)).
  // Binding check: embedded seq 99 != response seq 5 → fail.
  // Expected result: "invalid" (caught by binding layer, not sig layer).
  // ------------------------------------------------------------------
  {
    const cborData = buildCborData(CID_A, SEQ_DIFFERENT);
    const signedBytes = buildSignedBytes(cborData);
    const sig = (await ed.signAsync(signedBytes, primaryPriv)) as Uint8Array;

    vectors.push({
      description:
        'seq-mismatch — valid sig over CBOR data with seq=99, but response sequenceNumber is 5',
      ipns_name: primaryIpnsName,
      cid: CID_A,
      sequence_number: String(SEQ),
      signature_v2: bytesToBase64(sig),
      data: bytesToBase64(cborData),
      pub_key: bytesToBase64(primaryPub),
      expected_result: 'invalid',
    });
    console.log('Case 5 (seq-mismatch): done — sig covers CBOR with seq=99, response.seq=5');
  }

  // ------------------------------------------------------------------
  // Case 6: partial-fields (downgrade vector) — only signatureV2 present,
  // data and pub_key are null. Fails the partial-fields guard before
  // Ed25519 verification is even attempted.
  // Expected result: "invalid" (fail-closed on partial fields).
  // ------------------------------------------------------------------
  {
    const cborData = buildCborData(CID_A, SEQ);
    const signedBytes = buildSignedBytes(cborData);
    const sig = (await ed.signAsync(signedBytes, primaryPriv)) as Uint8Array;

    vectors.push({
      description:
        'partial-fields — only signatureV2 present, data and pub_key null (downgrade vector)',
      ipns_name: primaryIpnsName,
      cid: CID_A,
      sequence_number: String(SEQ),
      signature_v2: bytesToBase64(sig),
      data: null,
      pub_key: null,
      expected_result: 'invalid',
    });
    console.log('Case 6 (partial-fields): done');
  }

  // ------------------------------------------------------------------
  // Case 7: legacy-absent — all three of signatureV2, data, pub_key null.
  // Under the strict regime (D-04), absent fields are fail-closed: Invalid.
  // Expected result: "invalid".
  // ------------------------------------------------------------------
  {
    vectors.push({
      description: 'legacy-absent — all three signature fields null (pre-signing legacy record)',
      ipns_name: primaryIpnsName,
      cid: CID_A,
      sequence_number: String(SEQ),
      signature_v2: null,
      data: null,
      pub_key: null,
      expected_result: 'invalid',
    });
    console.log('Case 7 (legacy-absent): done');
  }

  // ------------------------------------------------------------------
  // Case 8: first-publish-skew — sig valid over CBOR data with embedded
  // Sequence=0, but response `sequence_number` is 1.
  //
  // Under the strict regime (D-04/D-05), the skew allowance
  // (resp_seq==1 && embedded_seq==0) is removed. Strict equality:
  // embedded_seq must equal resp_seq. embedded=0 != resp=1 → Invalid.
  // Expected result: "invalid".
  // ------------------------------------------------------------------
  {
    const cborData = buildCborData(CID_A, 0);
    const signedBytes = buildSignedBytes(cborData);
    const sig = (await ed.signAsync(signedBytes, primaryPriv)) as Uint8Array;

    vectors.push({
      description:
        'first-publish-skew — valid sig over CBOR data with seq=0, response sequenceNumber is 1',
      ipns_name: primaryIpnsName,
      cid: CID_A,
      sequence_number: '1',
      signature_v2: bytesToBase64(sig),
      data: bytesToBase64(cborData),
      pub_key: bytesToBase64(primaryPub),
      expected_result: 'invalid',
    });
    console.log('Case 8 (first-publish-skew): done — sig covers CBOR with seq=0, response.seq=1');
  }

  // ------------------------------------------------------------------
  // Case 9: expired-valid-sig — real sig over CBOR data whose embedded
  // Validity is a past RFC3339 timestamp, ValidityType 0 (EOL). Exercises
  // the resolve-side expiry/EOL binding both languages must apply on top
  // of a passing Ed25519 signature check.
  // Expected result: "invalid".
  // ------------------------------------------------------------------
  {
    const cborData = buildCborData(CID_A, SEQ, '2020-01-01T00:00:00.000000000Z', 0);
    const signedBytes = buildSignedBytes(cborData);
    const sig = (await ed.signAsync(signedBytes, primaryPriv)) as Uint8Array;

    vectors.push({
      description:
        'expired-valid-sig — valid sig, but embedded Validity is a past RFC3339 timestamp',
      ipns_name: primaryIpnsName,
      cid: CID_A,
      sequence_number: String(SEQ),
      signature_v2: bytesToBase64(sig),
      data: bytesToBase64(cborData),
      pub_key: bytesToBase64(primaryPub),
      expected_result: 'invalid',
    });
    console.log('Case 9 (expired-valid-sig): done');
  }

  // ------------------------------------------------------------------
  // Case 10: wrong-validity-type — real sig over CBOR data with a
  // canonical (future) Validity but ValidityType encoded as CBOR integer
  // 1 (non-EOL) instead of 0. Exercises the ValidityType==0 gate both
  // languages must apply.
  // Expected result: "invalid".
  // ------------------------------------------------------------------
  {
    const cborData = buildCborData(CID_A, SEQ, DEFAULT_VALIDITY, 1);
    const signedBytes = buildSignedBytes(cborData);
    const sig = (await ed.signAsync(signedBytes, primaryPriv)) as Uint8Array;

    vectors.push({
      description:
        'wrong-validity-type — valid sig, canonical future Validity, but ValidityType is 1 (non-EOL)',
      ipns_name: primaryIpnsName,
      cid: CID_A,
      sequence_number: String(SEQ),
      signature_v2: bytesToBase64(sig),
      data: bytesToBase64(cborData),
      pub_key: bytesToBase64(primaryPub),
      expected_result: 'invalid',
    });
    console.log('Case 10 (wrong-validity-type): done');
  }

  // ------------------------------------------------------------------
  // Case 11: malformed-rfc3339-trailing-component — real sig over CBOR
  // data whose Validity string has a trailing date component the strict
  // parser must reject (e.g. an extra dash-number after the day).
  // Expected result: "invalid".
  // ------------------------------------------------------------------
  {
    const cborData = buildCborData(CID_A, SEQ, '2099-01-01-99T00:00:00.000000000Z', 0);
    const signedBytes = buildSignedBytes(cborData);
    const sig = (await ed.signAsync(signedBytes, primaryPriv)) as Uint8Array;

    vectors.push({
      description:
        'malformed-rfc3339-trailing-component — valid sig, but Validity has a trailing date component',
      ipns_name: primaryIpnsName,
      cid: CID_A,
      sequence_number: String(SEQ),
      signature_v2: bytesToBase64(sig),
      data: bytesToBase64(cborData),
      pub_key: bytesToBase64(primaryPub),
      expected_result: 'invalid',
    });
    console.log('Case 11 (malformed-rfc3339-trailing-component): done');
  }

  // ------------------------------------------------------------------
  // Case 12: malformed-rfc3339-impossible-date — real sig over CBOR data
  // whose Validity string encodes an impossible calendar date (Feb 30)
  // that leap-year-aware validation must reject.
  // Expected result: "invalid".
  // ------------------------------------------------------------------
  {
    const cborData = buildCborData(CID_A, SEQ, '2099-02-30T00:00:00.000000000Z', 0);
    const signedBytes = buildSignedBytes(cborData);
    const sig = (await ed.signAsync(signedBytes, primaryPriv)) as Uint8Array;

    vectors.push({
      description:
        'malformed-rfc3339-impossible-date — valid sig, but Validity encodes an impossible calendar date',
      ipns_name: primaryIpnsName,
      cid: CID_A,
      sequence_number: String(SEQ),
      signature_v2: bytesToBase64(sig),
      data: bytesToBase64(cborData),
      pub_key: bytesToBase64(primaryPub),
      expected_result: 'invalid',
    });
    console.log('Case 12 (malformed-rfc3339-impossible-date): done');
  }

  // ------------------------------------------------------------------
  // Sanity checks
  // ------------------------------------------------------------------
  if (vectors.length !== 12) {
    throw new Error(`Expected 12 vectors, got ${vectors.length}`);
  }

  const expectedResults = [
    'valid',
    'invalid',
    'invalid',
    'invalid',
    'invalid',
    'invalid',
    'invalid',
    'invalid',
    'invalid',
    'invalid',
    'invalid',
    'invalid',
  ];
  const expectedDescriptions = [
    'valid',
    'tampered-sig',
    'name-mismatch',
    'cid-swapped',
    'seq-mismatch',
    'partial-fields',
    'legacy-absent',
    'first-publish-skew',
    'expired-valid-sig',
    'wrong-validity-type',
    'malformed-rfc3339-trailing-component',
    'malformed-rfc3339-impossible-date',
  ];
  for (let i = 0; i < vectors.length; i++) {
    if (vectors[i].expected_result !== expectedResults[i]) {
      throw new Error(
        `Vector ${i} expected_result mismatch: got ${vectors[i].expected_result}, want ${expectedResults[i]}`
      );
    }
    if (!vectors[i].description.startsWith(expectedDescriptions[i])) {
      throw new Error(
        `Vector ${i} description should start with "${expectedDescriptions[i]}", got "${vectors[i].description}"`
      );
    }
  }

  const outPath = join(REPO_ROOT, 'tests', 'vectors', 'ipns', 'verify.json');
  writeFileSync(outPath, JSON.stringify(vectors, null, 2) + '\n', 'utf-8');
  console.log(`\nWrote ${vectors.length} vectors to: ${outPath}`);
  console.log('expected_results:', vectors.map((v) => v.expected_result).join(', '));
}

main().catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});
