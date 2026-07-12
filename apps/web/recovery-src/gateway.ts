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
 */

import { parseIpnsRecord, verifyIpnsRecordSignatureDetailed } from '@cipherbox/crypto';

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

/**
 * Fetch content-addressed bytes for a CID over HTTP against a configurable
 * IPFS gateway (D-04). This transport does NOT re-hash the fetched bytes
 * against the CID multihash. GCM-sealed envelopes and GCM file bodies fail
 * closed on tampering via their auth-tag during unseal/decrypt, but CTR
 * (large-file) bodies carry no auth tag — so a hostile gateway can silently
 * tamper a CTR body. Verifying content against the CID here (to fully close the
 * trust-nothing model) is tracked as a recovery-tool hardening follow-up.
 *
 * @param cid - The content CID to fetch.
 * @param ipfsGatewayUrl - IPFS gateway base URL (e.g. "https://ipfs.io").
 * @returns The raw content bytes.
 * @throws if the gateway responds non-2xx.
 */
export async function fetchFromIpfs(cid: string, ipfsGatewayUrl: string): Promise<Uint8Array> {
  const url = `${ipfsGatewayUrl}/ipfs/${cid}`;
  const resp = await fetchWithTimeout(url);
  if (!resp.ok) {
    throw new Error(`IPFS fetch failed for ${cid}: ${resp.status}`);
  }
  return new Uint8Array(await resp.arrayBuffer());
}
