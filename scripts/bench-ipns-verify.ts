/**
 * Benchmark: per-op IPNS signature verification cost
 *
 * Measures the wall-clock cost of verifyIpnsRecordSignature (the Ed25519 verify
 * anchor on the API publish path) and of a plain Map.get() cache-hit lookup,
 * so the cost-recovery from a short-TTL verified-record cache can be quantified.
 *
 * The recoverable cost applies only to the CLIENT publishRecord path.
 * The TEE re-sign path (republish.service.ts publishSignedRecord +
 * syncFolderIpnsSequence) does NOT call verifyIpnsRecordSignature — confirmed
 * by reading republish.service.ts:133-178. It pays zero verify cost.
 * The resolveRecord path also does NOT verify the record server-side.
 *
 * Run from repo root:
 *   npx tsx scripts/bench-ipns-verify.ts
 *
 * Requires packages/crypto and packages/core to be built first:
 *   pnpm --filter @cipherbox/crypto build
 *   pnpm --filter @cipherbox/core build
 */

import { existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, '..');

// ---------------------------------------------------------------------------
// Resolve runtime paths (pnpm virtual store, same pattern as gen-ipns-verify-vectors.ts)
// ---------------------------------------------------------------------------

function requirePath(label: string, p: string): string {
  if (!existsSync(p)) {
    console.error(`${label} not found at: ${p}`);
    console.error('Run: pnpm install (from repo root)');
    process.exit(1);
  }
  return p;
}

const LIBP2P_CRYPTO_PATH = requirePath(
  '@libp2p/crypto',
  resolve(
    REPO_ROOT,
    'node_modules/.pnpm/@libp2p+crypto@5.1.13/node_modules/@libp2p/crypto/dist/src/index.js'
  )
);

const IPNS_PKG_PATH = requirePath(
  'ipns',
  resolve(REPO_ROOT, 'node_modules/.pnpm/ipns@10.1.3/node_modules/ipns/dist/src/index.js')
);

const CORE_PATH = requirePath(
  '@cipherbox/core',
  resolve(REPO_ROOT, 'packages/core/dist/index.mjs')
);

const CRYPTO_PATH = requirePath(
  '@cipherbox/crypto',
  resolve(REPO_ROOT, 'packages/crypto/dist/index.mjs')
);

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const libp2pCrypto = (await import(pathToFileURL(LIBP2P_CRYPTO_PATH).toString())) as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ipnsPkg = (await import(pathToFileURL(IPNS_PKG_PATH).toString())) as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const { deriveIpnsName } = (await import(pathToFileURL(CORE_PATH).toString())) as any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const { verifyIpnsRecordSignature } = (await import(pathToFileURL(CRYPTO_PATH).toString())) as any;

// ---------------------------------------------------------------------------
// Build a valid signed IPNS record (deterministic test keypair — DO NOT use in production)
// ---------------------------------------------------------------------------

const PRIV_KEY_HEX = '0101010101010101010101010101010101010101010101010101010101010101';
const TEST_CID = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi';
const TEST_SEQ = 5;

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

const privKeyBytes = hexToBytes(PRIV_KEY_HEX);

// Build libp2p private key from raw Ed25519 seed bytes (the correct API for libp2p/crypto@5).
// generateKeyPairFromSeed for Ed25519 treats the seed as the 32-byte private key.
const privateKey = (await libp2pCrypto.keys.generateKeyPairFromSeed('Ed25519', privKeyBytes)) as {
  type: string;
  publicKey: { raw: Uint8Array };
};

const pubKeyBytes = privateKey.publicKey.raw;
const ipnsName = (await deriveIpnsName(pubKeyBytes)) as string;

// Create and marshal a valid IPNS record.
// ipns@10 createIPNSRecord accepts the value as a string path.
const ipnsRecord = await ipnsPkg.createIPNSRecord(
  privateKey,
  `/ipfs/${TEST_CID}`,
  TEST_SEQ,
  new Date(Date.now() + 86400e3) // valid for 24 hours
);
const marshalledRecord = ipnsPkg.marshalIPNSRecord(ipnsRecord) as Uint8Array;

// Sanity check: ensure verifyIpnsRecordSignature accepts the record
const isValid = (await verifyIpnsRecordSignature(ipnsName, marshalledRecord)) as boolean;
if (!isValid) {
  console.error('Sanity check FAILED: verifyIpnsRecordSignature returned false on a valid record');
  process.exit(1);
}
console.log('Sanity check PASSED: record verifies correctly');
console.log(`IPNS name: ${ipnsName}`);
console.log(`Record size: ${marshalledRecord.length} bytes`);

// ---------------------------------------------------------------------------
// Benchmark helpers
// ---------------------------------------------------------------------------

/** Run fn N times and return per-op timings in milliseconds */
async function benchAsync(fn: () => Promise<boolean | void>, N: number): Promise<number[]> {
  const times: number[] = [];
  for (let i = 0; i < N; i++) {
    const t0 = process.hrtime.bigint();
    await fn();
    const t1 = process.hrtime.bigint();
    times.push(Number(t1 - t0) / 1e6);
  }
  return times;
}

function benchSync(fn: () => void, N: number): number[] {
  const times: number[] = [];
  for (let i = 0; i < N; i++) {
    const t0 = process.hrtime.bigint();
    fn();
    const t1 = process.hrtime.bigint();
    times.push(Number(t1 - t0) / 1e6);
  }
  return times;
}

function stats(times: number[]): { mean: number; p50: number; p99: number } {
  const sorted = [...times].sort((a, b) => a - b);
  const mean = times.reduce((a, b) => a + b, 0) / times.length;
  const p50 = sorted[Math.floor(sorted.length * 0.5)];
  const p99 = sorted[Math.floor(sorted.length * 0.99)];
  return { mean, p50, p99 };
}

function fmt(n: number): string {
  return n.toFixed(4).padStart(9);
}

// ---------------------------------------------------------------------------
// Warm-up run (avoid JIT cold-start skewing first measurement)
// ---------------------------------------------------------------------------

for (let i = 0; i < 5; i++) {
  await verifyIpnsRecordSignature(ipnsName, marshalledRecord);
}

// ---------------------------------------------------------------------------
// Benchmark A: verifyIpnsRecordSignature (Ed25519 verify + protobuf parse)
// ---------------------------------------------------------------------------

const N_VERIFY = 200;
console.log(`\nBenchmark A: verifyIpnsRecordSignature (N=${N_VERIFY})`);

const verifyTimes = await benchAsync(
  () => verifyIpnsRecordSignature(ipnsName, marshalledRecord) as Promise<boolean>,
  N_VERIFY
);
const verifyStats = stats(verifyTimes);

console.log(`  mean = ${fmt(verifyStats.mean)} ms`);
console.log(`  p50  = ${fmt(verifyStats.p50)} ms`);
console.log(`  p99  = ${fmt(verifyStats.p99)} ms`);

// ---------------------------------------------------------------------------
// Benchmark B: Map.get() cache-hit lookup (the saved cost on a cache hit)
// ---------------------------------------------------------------------------

const N_CACHE = 10000;
console.log(`\nBenchmark B: Map.get() cache-hit (N=${N_CACHE})`);

// Simulate the cache key used by ipns-verify-cache.ts
// Key = `${ipnsName}:${sequenceNumber}:${base64(signatureV2Bytes)}`
// Extract signatureV2 from the unmarshalled record
const unmarshalled = ipnsPkg.unmarshalIPNSRecord(marshalledRecord);
const sigV2 = Buffer.from(unmarshalled.signatureV2).toString('base64');
const cacheKey = `${ipnsName}:${TEST_SEQ}:${sigV2}`;
const cache = new Map<string, number>();
cache.set(cacheKey, Date.now());

const cacheTimes = benchSync(() => {
  cache.get(cacheKey);
}, N_CACHE);
const cacheStats = stats(cacheTimes);

console.log(`  mean = ${fmt(cacheStats.mean)} ms`);
console.log(`  p50  = ${fmt(cacheStats.p50)} ms`);
console.log(`  p99  = ${fmt(cacheStats.p99)} ms`);

// ---------------------------------------------------------------------------
// Summary table
// ---------------------------------------------------------------------------

const recovery = verifyStats.mean - cacheStats.mean;
const recoveryPct = (recovery / verifyStats.mean) * 100;

console.log('\n--- RESULTS TABLE (for docs/CAPACITY.md §1.5) ---\n');
console.log(
  '| Measurement                                | mean (ms)  | p50 (ms)   | p99 (ms)   |'
);
console.log(
  '|--------------------------------------------|------------|------------|------------|'
);
console.log(
  `| verifyIpnsRecordSignature (Ed25519+proto)  |${fmt(verifyStats.mean)} |${fmt(verifyStats.p50)} |${fmt(verifyStats.p99)} |`
);
console.log(
  `| Map.get() cache-hit lookup                 |${fmt(cacheStats.mean)} |${fmt(cacheStats.p50)} |${fmt(cacheStats.p99)} |`
);
console.log(
  `| Recovery per skipped verify                |${fmt(recovery)} | --         | --         |`
);
console.log(`\nRecovery: ${recovery.toFixed(4)} ms / ${recoveryPct.toFixed(1)}% of baseline`);
console.log('\nNote: resolve and TEE-republish do not pay the verify cost.');
console.log('      Recovery applies to redundant client re-submissions of');
console.log('      the same signed record within the cache TTL window.');
