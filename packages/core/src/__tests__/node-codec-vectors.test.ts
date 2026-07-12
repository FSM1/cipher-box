/**
 * @cipherbox/core - Node Codec Wire-Format Golden Vectors
 *
 * TDD suite for Plan 02: seal/unseal layer + frozen byte vectors (D-04, NODE-05).
 *
 * Three lock levels:
 *   1. PRIMARY LOCK (body_vectors): `toHex(encodeReadBody(node)) === expected_read_body_hex`
 *      IV-independent — verifies the JSON wire format is frozen.
 *   2. FULL-SEAL LOCK (seal_vectors): fixed key/IV → exact IV ‖ ciphertext ‖ tag bytes.
 *      Proves AAD flows into the AEAD identically to the Phase-69 Rust twin.
 *   3. ROUND-TRIP: sealNode → unsealNode recovers the original Node (three kinds).
 *
 * Additional: AAD-transplant rejection, content self-seal (role 0x03),
 * child-readkey seal/unseal (role 0x02).
 *
 * Requirements: NODE-01, NODE-02, NODE-03, NODE-04, NODE-05 (freeze)
 * Security: T-62-01 (AAD transplant), T-62-06 (AAD byte-encoding drift)
 */

import { describe, it, expect } from 'vitest';
import { encryptAesGcmAad, buildNodeAad } from '@cipherbox/crypto';
import { encodeReadBody, encodeWriteBody } from '../node/encode';
import {
  sealNode,
  unsealNode,
  sealChildReadKey,
  unsealChildReadKey,
  sealContent,
  unsealContent,
} from '../node/seal';
import type { Node, NodeContent } from '../node/types';
import VECTORS from '../../../../tests/vectors/node-codec.json';

// ---------------------------------------------------------------------------
// Helpers (copied verbatim from vault-blob-vectors.test.ts lines 17-29)
// ---------------------------------------------------------------------------

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function uint8ArrayToBase64(bytes: Uint8Array): string {
  const CHUNK_SIZE = 32768;
  let result = '';
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, Math.min(i + CHUNK_SIZE, bytes.length));
    result += String.fromCharCode(...chunk);
  }
  return btoa(result);
}

/**
 * Mirrors packages/core/src/node/decode.ts's private base64ToUint8Array — the
 * production decode path this KAT protects (SC2, T-75-09/T-75-10). Deliberately
 * NOT the fromHex() helper above: substituting a hex decode here for a fileIv
 * sample from tests/vectors/node-codec.json would throw or produce the wrong
 * length, which is exactly the encoding-lock this test asserts.
 */
function base64ToUint8Array(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

/**
 * Reconstructs an in-memory Node from a JSON fixture object.
 * For file nodes: converts `file_key_hex` fields → Uint8Array (JSON cannot carry Uint8Array).
 * For folder/root: returned as-is (no Uint8Array fields).
 */
function nodeFromFixture(raw: Record<string, unknown>): Node {
  const kind = raw.kind as string;
  if (kind === 'file') {
    const rawContent = raw.content as Record<string, unknown>;
    const content: NodeContent = {
      cid: rawContent.cid as string,
      fileIv: rawContent.fileIv as string,
      size: rawContent.size as number,
      mimeType: rawContent.mimeType as string,
      encryptionMode: rawContent.encryptionMode as 'GCM' | 'CTR',
      fileKey: fromHex(rawContent.file_key_hex as string),
      versions: (rawContent.versions as Record<string, unknown>[]).map((v) => ({
        versionId: v.versionId as string,
        cid: v.cid as string,
        fileIv: v.fileIv as string,
        size: v.size as number,
        createdAt: v.createdAt as number,
        encryptionMode: v.encryptionMode as 'GCM' | 'CTR',
        fileKey: fromHex(v.file_key_hex as string),
      })),
    };
    return {
      schema: 'node/v3',
      kind: 'file',
      id: raw.id as string,
      generation: raw.generation as number,
      createdAt: raw.createdAt as number,
      modifiedAt: raw.modifiedAt as number,
      content,
    };
  }
  // folder or root — no Uint8Array fields in JSON
  return raw as unknown as Node;
}

// ---------------------------------------------------------------------------
// 1. PRIMARY LOCK — body bytes are IV-independent (D-04)
// ---------------------------------------------------------------------------

describe('Node Codec — Body Bytes PRIMARY LOCK (D-04, NODE-05)', () => {
  it('folder node read-body hex matches frozen vector [0]', () => {
    const vector = VECTORS.body_vectors[0];
    const node = nodeFromFixture(vector.node as Record<string, unknown>);
    expect(toHex(encodeReadBody(node))).toBe(vector.expected_read_body_hex);
  });

  it('file node read-body hex matches frozen vector [1] — GCM VersionEntry', () => {
    const vector = VECTORS.body_vectors[1];
    const node = nodeFromFixture(vector.node as Record<string, unknown>);
    expect(toHex(encodeReadBody(node))).toBe(vector.expected_read_body_hex);
  });

  it('file node read-body hex matches frozen vector [2] — CTR VersionEntry', () => {
    const vector = VECTORS.body_vectors[2];
    const node = nodeFromFixture(vector.node as Record<string, unknown>);
    expect(toHex(encodeReadBody(node))).toBe(vector.expected_read_body_hex);
  });

  it('root node read-body hex matches frozen vector [3]', () => {
    const vector = VECTORS.body_vectors[3];
    const node = nodeFromFixture(vector.node as Record<string, unknown>);
    expect(toHex(encodeReadBody(node))).toBe(vector.expected_read_body_hex);
  });
});

// ---------------------------------------------------------------------------
// 1b. fileIv ENCODING LOCK (SC2, T-75-09/T-75-10) — base64-decode-and-assert
//
// The PRIMARY LOCK block above only round-trips fileIv as an opaque string —
// it never decodes it, so a hex-vs-base64 implementation divergence (the
// Phase 69 desktop-e2e "Decryption failed" root cause) would still pass
// silently. This block closes that gap: base64-decode content.fileIv and
// every versions[].fileIv, and assert the decoded length matches the pinned
// expected_file_iv_len_bytes. A hex decode substituted here would throw or
// disagree with the pinned length, given the non-hex/padded samples chosen
// in tests/vectors/node-codec.json.
// ---------------------------------------------------------------------------

describe('Node Codec — fileIv Encoding Lock (SC2, T-75-09/T-75-10)', () => {
  const fileVectorsWithExpectedLen = VECTORS.body_vectors.filter(
    (v): v is typeof v & { expected_file_iv_len_bytes: number } =>
      typeof (v as { expected_file_iv_len_bytes?: number }).expected_file_iv_len_bytes === 'number'
  );

  it('has at least the GCM and CTR file body vectors carrying expected_file_iv_len_bytes', () => {
    // Non-vacuous guard — folder/root vectors carry no content.fileIv at all.
    expect(fileVectorsWithExpectedLen.length).toBeGreaterThanOrEqual(2);
  });

  it.each(fileVectorsWithExpectedLen.map((v) => [v.description, v] as const))(
    'fileIv (base64, not hex) decodes to expected_file_iv_len_bytes for: %s',
    (_description, vector) => {
      const content = (vector.node as Record<string, unknown>).content as Record<string, unknown>;
      const expectedLen = vector.expected_file_iv_len_bytes;

      const decodedFileIv = base64ToUint8Array(content.fileIv as string);
      expect(decodedFileIv.length).toBe(expectedLen);

      const versions = content.versions as Record<string, unknown>[];
      for (const version of versions) {
        const decodedVersionFileIv = base64ToUint8Array(version.fileIv as string);
        expect(decodedVersionFileIv.length).toBe(expectedLen);
      }
    }
  );
});

// ---------------------------------------------------------------------------
// 2. FULL-SEAL LOCK — fixed key/IV produces deterministic ciphertext (D-04, T-62-06)
//
// The test reconstructs the expected sealed blob deterministically:
//   fixedIv ‖ encryptAesGcmAad(bodyBytes, key, fixedIv, buildNodeAad(...))
// and compares to the frozen fixture. This verifies that AAD flows into the AEAD
// identically to the Phase-69 Rust twin without depending on sealNode's random IV.
// ---------------------------------------------------------------------------

describe('Node Codec — FULL-SEAL LOCK (D-04, T-62-06)', () => {
  it('folder node readSealed base64 matches frozen vector', async () => {
    const sv = VECTORS.seal_vectors[0];
    const readKey = fromHex(sv.read_key);
    const fixedIv = fromHex(sv.fixed_iv);

    // Reconstruct the folder node (read-body only — no writeBody needed for readSealed)
    const folderNode: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: sv.node_id,
      generation: sv.generation,
      children: [],
      createdAt: 1719532800000,
      modifiedAt: 1719532800000,
    };

    const bodyBytes = encodeReadBody(folderNode);
    const aad = buildNodeAad(sv.node_id, sv.kind, sv.generation, 0x01 /* body */);
    const ciphertext = await encryptAesGcmAad(bodyBytes, readKey, fixedIv, aad);

    // IV ‖ ciphertext ‖ tag (encryptAesGcmAad already appends the 16-byte tag)
    const sealedBlob = new Uint8Array(fixedIv.length + ciphertext.length);
    sealedBlob.set(fixedIv);
    sealedBlob.set(ciphertext, fixedIv.length);
    const reconstructedReadSealed = uint8ArrayToBase64(sealedBlob);

    expect(reconstructedReadSealed).toBe(sv.expected_published_node.readSealed);
  });

  it('folder node writeSealed base64 matches frozen vector', async () => {
    const sv = VECTORS.seal_vectors[0];
    const writeKey = fromHex(sv.write_key);
    const fixedIv = fromHex(sv.fixed_iv);
    const ipnsPrivateKey = fromHex(sv.ipns_private_key_hex);

    // Reconstruct the folder node with writeBody to produce writeSealed
    const folderNode: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: sv.node_id,
      generation: sv.generation,
      children: [],
      createdAt: 1719532800000,
      modifiedAt: 1719532800000,
      writeBody: { ipnsPrivateKey, writeChildren: [] },
    };

    const bodyBytes = encodeWriteBody(folderNode);
    const aad = buildNodeAad(sv.node_id, sv.kind, sv.generation, 0x01 /* body */);
    const ciphertext = await encryptAesGcmAad(bodyBytes, writeKey, fixedIv, aad);

    const sealedBlob = new Uint8Array(fixedIv.length + ciphertext.length);
    sealedBlob.set(fixedIv);
    sealedBlob.set(ciphertext, fixedIv.length);
    const reconstructedWriteSealed = uint8ArrayToBase64(sealedBlob);

    expect(reconstructedWriteSealed).toBe(sv.expected_published_node.writeSealed);
  });

  it('folder node writeSealed with non-empty recipientPins matches frozen vector [1] (D-03b)', async () => {
    const sv = VECTORS.seal_vectors[1];
    const writeKey = fromHex(sv.write_key);
    const fixedIv = fromHex(sv.fixed_iv);
    const ipnsPrivateKey = fromHex(sv.ipns_private_key_hex);
    const recipientPins = (sv as { recipient_pins: string[] }).recipient_pins;

    // Non-vacuous guard: this KAT must exercise a populated pin list.
    expect(recipientPins.length).toBeGreaterThanOrEqual(2);

    // Reconstruct the folder node with a pinned writeBody to produce writeSealed
    const folderNode: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: sv.node_id,
      generation: sv.generation,
      children: [],
      createdAt: 1719532800000,
      modifiedAt: 1719532800000,
      writeBody: { ipnsPrivateKey, writeChildren: [], recipientPins },
    };

    const bodyBytes = encodeWriteBody(folderNode);
    const aad = buildNodeAad(sv.node_id, sv.kind, sv.generation, 0x01 /* body */);
    const ciphertext = await encryptAesGcmAad(bodyBytes, writeKey, fixedIv, aad);

    const sealedBlob = new Uint8Array(fixedIv.length + ciphertext.length);
    sealedBlob.set(fixedIv);
    sealedBlob.set(ciphertext, fixedIv.length);
    const reconstructedWriteSealed = uint8ArrayToBase64(sealedBlob);

    expect(reconstructedWriteSealed).toBe(sv.expected_published_node.writeSealed);
  });
});

// ---------------------------------------------------------------------------
// 3. ROUND-TRIP — sealNode → unsealNode recovers the original Node (NODE-01)
// ---------------------------------------------------------------------------

describe('Node Codec — Round-Trip (NODE-01)', () => {
  const READ_KEY = new Uint8Array(32).fill(0x01);
  const WRITE_KEY = new Uint8Array(32).fill(0x02);

  it('folder node seal→unseal round-trips', async () => {
    const node: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: '550e8400-e29b-41d4-a716-446655440000',
      generation: 5,
      children: [],
      createdAt: 1719532800000,
      modifiedAt: 1719532800001,
    };
    const published = await sealNode(node, READ_KEY, WRITE_KEY);
    const recovered = await unsealNode(published, READ_KEY, WRITE_KEY);
    expect(recovered).toEqual(node);
  });

  it('file node seal→unseal round-trips (GCM + CTR versions)', async () => {
    const node: Node = {
      schema: 'node/v3',
      kind: 'file',
      id: '550e8400-e29b-41d4-a716-446655440001',
      generation: 0,
      createdAt: 1719532800000,
      modifiedAt: 1719532800000,
      content: {
        cid: 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi',
        fileIv: '000102030405060708090a0b',
        size: 2048,
        mimeType: 'application/octet-stream',
        encryptionMode: 'GCM',
        fileKey: new Uint8Array(32).fill(0x07),
        versions: [
          {
            versionId: 'ver-ctr-1',
            cid: 'bafyCTRv1',
            fileIv: '0a0b0c0d0e0f101112131415',
            size: 1024,
            createdAt: 1719000000000,
            encryptionMode: 'CTR',
            fileKey: new Uint8Array(32).fill(0x08),
          },
        ],
      },
    };
    const published = await sealNode(node, READ_KEY, WRITE_KEY);
    const recovered = await unsealNode(published, READ_KEY, WRITE_KEY);
    expect(recovered).toEqual(node);
  });

  it('root node seal→unseal round-trips', async () => {
    const node: Node = {
      schema: 'node/v3',
      kind: 'root',
      id: '550e8400-e29b-41d4-a716-446655440003',
      generation: 0,
      children: [],
      createdAt: 1719532800000,
      modifiedAt: 1719532800000,
    };
    const published = await sealNode(node, READ_KEY, WRITE_KEY);
    const recovered = await unsealNode(published, READ_KEY, WRITE_KEY);
    expect(recovered).toEqual(node);
  });

  it('folder node with writeBody seal→unseal round-trips', async () => {
    const node: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: '550e8400-e29b-41d4-a716-446655440000',
      generation: 1,
      children: [],
      createdAt: 1719532800000,
      modifiedAt: 1719532800001,
      writeBody: {
        ipnsPrivateKey: new Uint8Array(32).fill(0x44),
        writeChildren: [],
      },
    };
    const published = await sealNode(node, READ_KEY, WRITE_KEY);
    expect(published.writeSealed).toBeDefined();
    const recovered = await unsealNode(published, READ_KEY, WRITE_KEY);
    expect(recovered).toEqual(node);
  });

  it('file node without writeBody produces no writeSealed field', async () => {
    const node: Node = {
      schema: 'node/v3',
      kind: 'file',
      id: '550e8400-e29b-41d4-a716-446655440001',
      generation: 0,
      createdAt: 1719532800000,
      modifiedAt: 1719532800000,
      content: {
        cid: 'bafytest',
        fileIv: '000102030405060708090a0b',
        size: 100,
        mimeType: 'text/plain',
        encryptionMode: 'GCM',
        fileKey: new Uint8Array(32).fill(0x0f),
        versions: [],
      },
    };
    const published = await sealNode(node, READ_KEY, WRITE_KEY);
    expect(published.writeSealed).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// 4. AAD TRANSPLANT REJECTION (T-62-01, NODE-03, NODE-04)
// ---------------------------------------------------------------------------

describe('Node Codec — AAD Transplant Rejection (T-62-01)', () => {
  const PARENT_READ_KEY = new Uint8Array(32).fill(0x11);
  const CHILD_ID_A = '550e8400-e29b-41d4-a716-446655440010';
  const CHILD_ID_B = '550e8400-e29b-41d4-a716-446655440011';
  const CHILD_READ_KEY = new Uint8Array(32).fill(0x33);

  it('readKeySealed for child A cannot be unsealed with child B id (role 0x02)', async () => {
    const sealed = await sealChildReadKey(CHILD_READ_KEY, PARENT_READ_KEY, CHILD_ID_A, 'folder', 0);
    await expect(
      unsealChildReadKey(sealed, PARENT_READ_KEY, CHILD_ID_B, 'folder', 0)
    ).rejects.toThrow();
  });

  it('readKeySealed at generation 0 cannot be unsealed at generation 1', async () => {
    const sealed = await sealChildReadKey(CHILD_READ_KEY, PARENT_READ_KEY, CHILD_ID_A, 'folder', 0);
    await expect(
      unsealChildReadKey(sealed, PARENT_READ_KEY, CHILD_ID_A, 'folder', 1)
    ).rejects.toThrow();
  });

  it('node body sealed at generation 5 fails unseal when envelope generation tampered to 6', async () => {
    const READ_KEY = new Uint8Array(32).fill(0x55);
    const WRITE_KEY = new Uint8Array(32).fill(0x66);
    const node: Node = {
      schema: 'node/v3',
      kind: 'folder',
      id: '550e8400-e29b-41d4-a716-446655440000',
      generation: 5,
      children: [],
      createdAt: 1719532800000,
      modifiedAt: 1719532800000,
    };
    const published = await sealNode(node, READ_KEY, WRITE_KEY);
    const tampered = { ...published, generation: 6 };
    await expect(unsealNode(tampered, READ_KEY, WRITE_KEY)).rejects.toThrow();
  });

  it('child readKeySealed round-trips: sealChildReadKey → unsealChildReadKey', async () => {
    const sealed = await sealChildReadKey(CHILD_READ_KEY, PARENT_READ_KEY, CHILD_ID_A, 'folder', 3);
    const recovered = await unsealChildReadKey(sealed, PARENT_READ_KEY, CHILD_ID_A, 'folder', 3);
    expect(toHex(recovered)).toBe(toHex(CHILD_READ_KEY));
  });
});

// ---------------------------------------------------------------------------
// 5. CONTENT SELF-SEAL — role 0x03, file node's own readKey (NODE-02, design §2.9)
// ---------------------------------------------------------------------------

describe('Node Codec — Content Self-Seal (NODE-02, role 0x03)', () => {
  const FILE_NODE_ID = '550e8400-e29b-41d4-a716-446655440001';
  const FILE_READ_KEY = new Uint8Array(32).fill(0x77);

  const GCM_CONTENT: NodeContent = {
    cid: 'bafyGCMcontent',
    fileIv: '000102030405060708090a0b',
    size: 4096,
    mimeType: 'image/png',
    encryptionMode: 'GCM',
    fileKey: new Uint8Array(32).fill(0x99),
    versions: [],
  };

  const CTR_CONTENT: NodeContent = {
    cid: 'bafyCTRcontent',
    fileIv: '0a0b0c0d0e0f101112131415',
    size: 10485760,
    mimeType: 'video/mp4',
    encryptionMode: 'CTR',
    fileKey: new Uint8Array(32).fill(0xaa),
    versions: [],
  };

  it('sealContent + unsealContent round-trips GCM content; fileKey recovered as 32-byte Uint8Array', async () => {
    const sealed = await sealContent(GCM_CONTENT, FILE_READ_KEY, FILE_NODE_ID, 0);
    const recovered = await unsealContent(sealed, FILE_READ_KEY, FILE_NODE_ID, 0);
    expect(recovered.cid).toBe(GCM_CONTENT.cid);
    expect(recovered.encryptionMode).toBe('GCM');
    expect(recovered.fileKey).toBeInstanceOf(Uint8Array);
    expect(recovered.fileKey.length).toBe(32);
    expect(toHex(recovered.fileKey)).toBe(toHex(GCM_CONTENT.fileKey));
  });

  it('sealContent + unsealContent round-trips CTR content; fileKey recovered as 32-byte Uint8Array', async () => {
    const sealed = await sealContent(CTR_CONTENT, FILE_READ_KEY, FILE_NODE_ID, 0);
    const recovered = await unsealContent(sealed, FILE_READ_KEY, FILE_NODE_ID, 0);
    expect(recovered.cid).toBe(CTR_CONTENT.cid);
    expect(recovered.encryptionMode).toBe('CTR');
    expect(recovered.fileKey).toBeInstanceOf(Uint8Array);
    expect(toHex(recovered.fileKey)).toBe(toHex(CTR_CONTENT.fileKey));
  });

  it('unsealing content with wrong key throws', async () => {
    const sealed = await sealContent(GCM_CONTENT, FILE_READ_KEY, FILE_NODE_ID, 0);
    const wrongKey = new Uint8Array(32).fill(0xbb);
    await expect(unsealContent(sealed, wrongKey, FILE_NODE_ID, 0)).rejects.toThrow();
  });

  it('unsealing content with wrong nodeId throws', async () => {
    const sealed = await sealContent(GCM_CONTENT, FILE_READ_KEY, FILE_NODE_ID, 0);
    await expect(
      unsealContent(sealed, FILE_READ_KEY, '550e8400-e29b-41d4-a716-aaaaaaaaaaaa', 0)
    ).rejects.toThrow();
  });

  it('unsealing content with wrong generation throws', async () => {
    const sealed = await sealContent(GCM_CONTENT, FILE_READ_KEY, FILE_NODE_ID, 0);
    await expect(unsealContent(sealed, FILE_READ_KEY, FILE_NODE_ID, 1)).rejects.toThrow();
  });
});
