/**
 * Recovery-tool HTTP transport (SC1 / D-04).
 *
 * Trust-nothing IPNS resolve + IPFS fetch over plain `fetch` against a
 * caller-supplied gateway URL — no libp2p, no CipherBox API relay, no SDK
 * read chain (D-02). The only allowed workspace imports are the low-level
 * IPNS primitives from `@cipherbox/crypto` (D-03); this file must NEVER import
 * `resolveIpnsRecord` from `@cipherbox/sdk-core` (that path is API-relayed and
 * violates D-02's infra-independence).
 *
 * Security upgrade over the v2 hand-rolled recovery.html parser: the primary
 * (delegated-routing / protobuf) rung verifies the IPNS record signature with
 * `verifyIpnsRecordSignatureDetailed` — self-verifying against the Ed25519
 * public key embedded in the IPNS name, so a tampered record from a hostile
 * gateway is rejected (T-78-01). A stale-but-authentic (past-EOL) record is
 * NOT a tamper and does not abort recovery: this is a break-glass tool, so it
 * favours availability over freshness (D-04) and accepts an expired record's
 * value. The HEAD and Kubo fallback rungs carry no verifiable signature, so —
 * matching the v2 tool's graceful-degradation — they are used only when the
 * primary rung yields nothing.
 *
 * Content fetches (`fetchFromIpfs`) are content-address-verified: fetched bytes
 * are re-hashed against the CID's multihash (single raw blocks directly;
 * multi-block dag-pb files via a verified raw-block walk) so a hostile gateway
 * cannot silently swap CTR (auth-tag-less) ciphertext for corrupted bytes
 * (T-78-04). Gateways that cannot serve verifiable raw blocks fall back to the
 * plain assembled fetch (unverified) to preserve availability.
 */

import { parseIpnsRecord, verifyIpnsRecordSignatureDetailed } from '@cipherbox/crypto';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import * as dagPB from '@ipld/dag-pb';
import { UnixFS } from 'ipfs-unixfs';

const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_PRIMARY_RETRIES = 3;

async function fetchWithTimeout(
  url: string,
  init: RequestInit = {},
  timeoutMs = DEFAULT_TIMEOUT_MS
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Strip a leading `/ipfs/` prefix from a resolved IPNS value, yielding a bare CID. */
function stripIpfsPrefix(value: string): string {
  return value.startsWith('/ipfs/') ? value.slice('/ipfs/'.length) : value;
}

const CID_RE = /^(bafy|bafk|Qm)[a-zA-Z0-9]+$/;

/**
 * Resolve an IPNS name to its target CID over HTTP against a configurable
 * gateway, verifying the record signature on the primary rung.
 *
 * Rung 1 (primary, verified): delegated-routing `/routing/v1/ipns/<name>` with
 *   `Accept: application/vnd.ipfs.ipns-record` → verify signature → parse value.
 * Rung 2 (fallback, unverified): IPFS gateway `/ipns/<name>` HEAD, reading the
 *   CID from the `X-Ipfs-Roots` header.
 * Rung 3 (fallback, unverified): Kubo `/api/v0/name/resolve?arg=<name>`.
 *
 * @param ipnsName - IPNS name (CIDv1 base36, e.g. "k51qzi5uqu5...").
 * @param ipnsGatewayUrl - Delegated-routing gateway base URL (primary rung).
 * @param ipfsGatewayUrl - Optional IPFS gateway base URL for the HEAD fallback;
 *   defaults to `ipnsGatewayUrl` when omitted.
 * @returns The resolved bare CID string.
 * @throws if every rung fails to resolve the name.
 */
export async function resolveIpnsVerified(
  ipnsName: string,
  ipnsGatewayUrl: string,
  ipfsGatewayUrl?: string
): Promise<string> {
  // Rung 1: delegated routing with real signature verification (D-04 / T-78-01).
  for (let attempt = 0; attempt < MAX_PRIMARY_RETRIES; attempt++) {
    try {
      const url = `${ipnsGatewayUrl}/routing/v1/ipns/${ipnsName}`;
      const resp = await fetchWithTimeout(url, {
        headers: { Accept: 'application/vnd.ipfs.ipns-record' },
      });

      if (!resp.ok) {
        if (attempt < MAX_PRIMARY_RETRIES - 1 && (resp.status === 429 || resp.status >= 500)) {
          await sleep(1000 * 2 ** attempt);
          continue;
        }
        break;
      }

      const marshalledRecord = new Uint8Array(await resp.arrayBuffer());

      // Distinguish a forged record (reject) from a stale-but-authentic one. An
      // expired record is signed by the real key — only its EOL has lapsed — so
      // for break-glass recovery we accept its value rather than hard-stopping
      // before the unverified fallback rungs (availability over freshness, D-04).
      const verdict = await verifyIpnsRecordSignatureDetailed(ipnsName, marshalledRecord);
      if (verdict === 'invalid') {
        throw new Error('IPNS record signature verification failed — possible tampering');
      }

      const parsed = await parseIpnsRecord(marshalledRecord);
      const cid = stripIpfsPrefix(parsed.value);
      if (cid) return cid;
      break;
    } catch (err) {
      // A signature-verification failure is a hard security stop — do not fall
      // through to the unverified rungs when we actually got a (tampered) record.
      if (err instanceof Error && err.message.includes('signature verification failed')) {
        throw err;
      }
      if (attempt < MAX_PRIMARY_RETRIES - 1) {
        await sleep(1000 * 2 ** attempt);
        continue;
      }
    }
  }

  // Rung 2 (unverified): IPFS gateway /ipns/ HEAD → X-Ipfs-Roots header.
  const gwBase = ipfsGatewayUrl || ipnsGatewayUrl;
  try {
    const resp = await fetchWithTimeout(`${gwBase}/ipns/${ipnsName}`, { method: 'HEAD' });
    if (resp.ok) {
      const roots = resp.headers.get('X-Ipfs-Roots');
      if (roots) {
        const cid = roots.split(',')[0].trim();
        if (cid) return cid;
      }
    }
  } catch {
    // Gateway does not support the /ipns/ path — fall through.
  }

  // Rung 3 (unverified): Kubo /api/v0/name/resolve.
  const kuboBase = ipnsGatewayUrl.replace(/\/routing\/v1.*$/, '').replace(/\/$/, '');
  try {
    const resp = await fetchWithTimeout(`${kuboBase}/api/v0/name/resolve?arg=${ipnsName}`, {
      method: 'POST',
    });
    if (resp.ok) {
      const json = (await resp.json()) as { Path?: string };
      if (json.Path) {
        const cid = stripIpfsPrefix(json.Path);
        if (CID_RE.test(cid)) return cid;
      }
    }
  } catch {
    // Kubo API not available or CORS-blocked — fall through to the final throw.
  }

  throw new Error(`Failed to resolve IPNS name: ${ipnsName}`);
}

/** IPLD codec / multihash constants (multiformats table). */
const RAW_CODE = 0x55;
const DAG_PB_CODE = 0x70;
const SHA2_256_CODE = 0x12;

/**
 * Signals that the gateway cannot serve a single addressed block as
 * `application/vnd.ipld.raw` (no trustless-gateway support). Distinct from a
 * content-hash mismatch so the caller can fall back to an unverified assembled
 * fetch for availability WITHOUT swallowing genuine tamper errors.
 */
class RawBlockUnsupportedError extends Error {
  constructor(status: number) {
    super(`gateway does not serve verifiable raw blocks (status ${status})`);
    this.name = 'RawBlockUnsupportedError';
  }
}

/** Constant-length byte comparison for two equal-length digests. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Concatenate a list of byte arrays into one buffer. */
function concatBytes(parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/**
 * Re-hash `bytes` and assert the digest matches the CID's multihash — the core
 * content-address integrity check. Only sha2-256 (Kubo's default, the only hash
 * CipherBox emits) is supported; any other multihash code fails closed rather
 * than trusting unverifiable bytes.
 *
 * @throws if the multihash is unsupported or the digest does not match.
 */
async function assertCidDigest(cid: CID, bytes: Uint8Array): Promise<void> {
  if (cid.multihash.code !== SHA2_256_CODE) {
    throw new Error(
      `unsupported multihash 0x${cid.multihash.code.toString(16)} for CID ${cid.toString()}`
    );
  }
  const digest = await sha256.digest(bytes);
  if (!bytesEqual(digest.digest, cid.multihash.digest)) {
    throw new Error(
      `content hash mismatch for CID ${cid.toString()} — gateway returned tampered or wrong bytes`
    );
  }
}

/** Plain assembled `/ipfs/<cid>` fetch (UnixFS-reconstructed bytes; unverified). */
async function fetchAssembled(cid: string, ipfsGatewayUrl: string): Promise<Uint8Array> {
  const resp = await fetchWithTimeout(`${ipfsGatewayUrl}/ipfs/${cid}`);
  if (!resp.ok) {
    throw new Error(`IPFS fetch failed for ${cid}: ${resp.status}`);
  }
  return new Uint8Array(await resp.arrayBuffer());
}

/**
 * Fetch a single addressed block as `application/vnd.ipld.raw` (trustless
 * gateway). If the gateway ignored `?format=raw` and served reconstructed
 * content, the bytes are NOT the block — hashing them would false-reject a valid
 * file — so that is treated as {@link RawBlockUnsupportedError}, not a mismatch.
 */
async function fetchRawBlock(cid: CID, ipfsGatewayUrl: string): Promise<Uint8Array> {
  const resp = await fetchWithTimeout(`${ipfsGatewayUrl}/ipfs/${cid.toString()}?format=raw`, {
    headers: { Accept: 'application/vnd.ipld.raw' },
  });
  if (!resp.ok) {
    throw new RawBlockUnsupportedError(resp.status);
  }
  const contentType = resp.headers.get('Content-Type') ?? '';
  if (!contentType.includes('application/vnd.ipld.raw')) {
    throw new RawBlockUnsupportedError(resp.status);
  }
  return new Uint8Array(await resp.arrayBuffer());
}

/**
 * Reconstruct a file's bytes from content-address-VERIFIED raw blocks. Each
 * block (root and every dag-pb child) is fetched via the raw-block API and
 * re-hashed against its CID before use, so no leaf can be silently tampered.
 * Handles Kubo's default cidv1 layout (raw leaves under a dag-pb file root) and
 * any inline UnixFS data carried in a dag-pb node.
 */
async function fetchVerifiedDag(cid: CID, ipfsGatewayUrl: string): Promise<Uint8Array> {
  const block = await fetchRawBlock(cid, ipfsGatewayUrl);
  await assertCidDigest(cid, block);

  if (cid.code === RAW_CODE) {
    return block;
  }
  if (cid.code === DAG_PB_CODE) {
    const node = dagPB.decode(block);
    const parts: Uint8Array[] = [];
    if (node.Data && node.Data.length > 0) {
      // Non-raw-leaf layouts carry the chunk bytes inline in the UnixFS Data.
      const unixfs = UnixFS.unmarshal(node.Data);
      if (unixfs.data && unixfs.data.length > 0) {
        parts.push(unixfs.data);
      }
    }
    for (const link of node.Links) {
      parts.push(await fetchVerifiedDag(link.Hash, ipfsGatewayUrl));
    }
    return concatBytes(parts);
  }
  throw new Error(`unsupported CID codec 0x${cid.code.toString(16)} for ${cid.toString()}`);
}

/**
 * Fetch content-addressed bytes for a CID over HTTP against a configurable IPFS
 * gateway (D-04), verifying the returned bytes against the CID's multihash so a
 * hostile/misconfigured gateway cannot silently corrupt recovered plaintext.
 *
 * GCM-sealed envelopes and GCM file bodies fail closed on tampering via their
 * auth-tag, but CTR (large-file) bodies carry no auth tag — this content-address
 * check closes that gap (T-78-04). Single raw blocks are verified directly;
 * multi-block dag-pb files are reconstructed from verified raw blocks. A gateway
 * that cannot serve verifiable raw blocks falls back to a plain assembled fetch
 * (UNVERIFIED) so recovery still works — but a genuine hash mismatch is a hard
 * reject and is never downgraded to the fallback.
 *
 * @param cid - The content CID to fetch.
 * @param ipfsGatewayUrl - IPFS gateway base URL (e.g. "https://ipfs.io").
 * @returns The verified (or, on unsupported gateways, best-effort) content bytes.
 * @throws if the gateway responds non-2xx or the content fails its hash check.
 */
export async function fetchFromIpfs(cid: string, ipfsGatewayUrl: string): Promise<Uint8Array> {
  let parsed: CID;
  try {
    parsed = CID.parse(cid);
  } catch {
    // Not a parseable CID — fall back to the raw assembled fetch (unverified).
    return fetchAssembled(cid, ipfsGatewayUrl);
  }

  // Raw single block: the plain `/ipfs/<cid>` response bytes ARE the addressed
  // block, so verify them directly (one request, no raw-block API needed).
  if (parsed.code === RAW_CODE) {
    const bytes = await fetchAssembled(cid, ipfsGatewayUrl);
    await assertCidDigest(parsed, bytes);
    return bytes;
  }

  // dag-pb / CIDv0: the assembled response is reconstructed, not the block, so it
  // cannot be hashed against the root multihash. Rebuild from verified blocks.
  try {
    return await fetchVerifiedDag(parsed, ipfsGatewayUrl);
  } catch (err) {
    if (err instanceof RawBlockUnsupportedError) {
      // Availability fallback (D-04): gateway can't serve verifiable raw blocks.
      return fetchAssembled(cid, ipfsGatewayUrl);
    }
    throw err;
  }
}

/**
 * Assert that `bytes` hash to the given single-block (raw-codec) CID. Exposed for
 * deterministic unit coverage of the content-address integrity check.
 *
 * @throws if the CID is not a raw single block, the multihash is unsupported, or
 *   the digest does not match.
 */
export async function verifyRawBlockBytes(cid: string, bytes: Uint8Array): Promise<void> {
  const parsed = CID.parse(cid);
  if (parsed.code !== RAW_CODE) {
    throw new Error(`CID ${cid} is not a raw single block (codec 0x${parsed.code.toString(16)})`);
  }
  await assertCidDigest(parsed, bytes);
}
