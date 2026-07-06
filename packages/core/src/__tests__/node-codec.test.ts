/**
 * @cipherbox/core - Node Codec Round-Trip and Validation Suite
 *
 * TDD suite (RED phase): tests for NODE-01..NODE-04 requirements.
 * This file imports from node/encode and node/decode which do NOT exist yet;
 * the suite is expected to fail (RED) until Task 3 provides those modules.
 *
 * Requirements coverage:
 *   NODE-01: encode/decode round-trips all three kinds losslessly
 *   NODE-02: GCM+CTR modes preserved; content.fileKey survives as 32-byte Uint8Array
 *   NODE-03: SealedChildRef carries no write field (structural key-set assertion)
 *   NODE-04: generation range [0, 2^32-1] validated fail-closed
 */

import { describe, it, expect } from 'vitest';
import { encodeReadBody } from '../node/encode';
import { decodeReadBody } from '../node/decode';
import type { Node, SealedChildRef, VersionEntry } from '../node/types';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** A single 32-byte fileKey filled with 0x07 (all-same for determinism in tests). */
const FILE_KEY = new Uint8Array(32).fill(0x07);

/** A GCM version entry fixture. */
const GCM_VERSION: VersionEntry = {
  versionId: 'ver-gcm-1',
  cid: 'bafyGCM',
  fileIv: 'aabbccdd00112233445566',
  size: 1024,
  createdAt: 1000000,
  encryptionMode: 'GCM',
  fileKey: new Uint8Array(32).fill(0x0a),
};

/** A CTR version entry fixture. */
const CTR_VERSION: VersionEntry = {
  versionId: 'ver-ctr-2',
  cid: 'bafyCTR',
  fileIv: 'ffeeddccbbaa998877665544',
  size: 8192000,
  createdAt: 2000000,
  encryptionMode: 'CTR',
  fileKey: new Uint8Array(32).fill(0x0b),
};

/** Minimal SealedChildRef (read-only). */
const CHILD_REF: SealedChildRef = {
  name: 'subfolder',
  ipnsName: 'k51qzi5uqu5dk1n0uxq0qhel6qmzp5',
  generation: 3,
  versionFloor: 42n,
  readKeySealed: 'YWJjZGVmZ2g=', // arbitrary base64
};

/** A folder node with one child. */
const FOLDER_NODE: Node = {
  schema: 'node/v3',
  kind: 'folder',
  id: '550e8400-e29b-41d4-a716-446655440001',
  generation: 0,
  createdAt: 1000,
  modifiedAt: 2000,
  children: [CHILD_REF],
};

/** A root node with no children (empty array). */
const ROOT_NODE: Node = {
  schema: 'node/v3',
  kind: 'root',
  id: '550e8400-e29b-41d4-a716-446655440002',
  generation: 0,
  createdAt: 1000,
  modifiedAt: 2000,
  children: [],
};

/** A file node with GCM and CTR versions. */
const FILE_NODE: Node = {
  schema: 'node/v3',
  kind: 'file',
  id: '550e8400-e29b-41d4-a716-446655440003',
  generation: 1,
  createdAt: 3000,
  modifiedAt: 4000,
  content: {
    cid: 'bafyFileMain',
    fileIv: '001122334455667788990011',
    size: 512000,
    mimeType: 'application/pdf',
    encryptionMode: 'GCM',
    fileKey: FILE_KEY,
    versions: [GCM_VERSION, CTR_VERSION],
  },
};

// ---------------------------------------------------------------------------
// Test 1 (NODE-01): Folder node round-trip
// ---------------------------------------------------------------------------

describe('NODE-01: encode/decode round-trip', () => {
  it('folder node round-trips to deep-equal Node', () => {
    const bytes = encodeReadBody(FOLDER_NODE);
    const recovered = decodeReadBody(bytes);

    expect(recovered.schema).toBe('node/v3');
    expect(recovered.kind).toBe('folder');
    expect(recovered.id).toBe(FOLDER_NODE.id);
    expect(recovered.generation).toBe(FOLDER_NODE.generation);
    expect(recovered.createdAt).toBe(FOLDER_NODE.createdAt);
    expect(recovered.modifiedAt).toBe(FOLDER_NODE.modifiedAt);
    expect(Array.isArray(recovered.children)).toBe(true);
    expect(recovered.children).toHaveLength(1);
    expect(recovered.children![0].name).toBe(CHILD_REF.name);
    expect(recovered.children![0].ipnsName).toBe(CHILD_REF.ipnsName);
    expect(recovered.children![0].generation).toBe(CHILD_REF.generation);
    // versionFloor must survive as bigint
    expect(recovered.children![0].versionFloor).toBe(CHILD_REF.versionFloor);
    expect(recovered.children![0].readKeySealed).toBe(CHILD_REF.readKeySealed);
  });

  it('root node round-trips to deep-equal Node', () => {
    const bytes = encodeReadBody(ROOT_NODE);
    const recovered = decodeReadBody(bytes);

    expect(recovered.schema).toBe('node/v3');
    expect(recovered.kind).toBe('root');
    expect(recovered.id).toBe(ROOT_NODE.id);
    expect(recovered.generation).toBe(ROOT_NODE.generation);
    expect(Array.isArray(recovered.children)).toBe(true);
    expect(recovered.children).toHaveLength(0);
  });

  it('file node round-trips to deep-equal Node (content fields preserved)', () => {
    const bytes = encodeReadBody(FILE_NODE);
    const recovered = decodeReadBody(bytes);

    expect(recovered.schema).toBe('node/v3');
    expect(recovered.kind).toBe('file');
    expect(recovered.id).toBe(FILE_NODE.id);
    expect(recovered.generation).toBe(FILE_NODE.generation);
    expect(recovered.content).toBeDefined();
    expect(recovered.content!.cid).toBe(FILE_NODE.content!.cid);
    expect(recovered.content!.fileIv).toBe(FILE_NODE.content!.fileIv);
    expect(recovered.content!.size).toBe(FILE_NODE.content!.size);
    expect(recovered.content!.mimeType).toBe(FILE_NODE.content!.mimeType);
    expect(recovered.content!.encryptionMode).toBe(FILE_NODE.content!.encryptionMode);
  });
});

// ---------------------------------------------------------------------------
// Test 3 (NODE-02): GCM + CTR version entries; fileKey as Uint8Array
// ---------------------------------------------------------------------------

describe('NODE-02: fileKey survives as 32-byte Uint8Array; GCM+CTR modes preserved', () => {
  it('content.fileKey is a Uint8Array of length 32 after decode', () => {
    const bytes = encodeReadBody(FILE_NODE);
    const recovered = decodeReadBody(bytes);

    expect(recovered.content!.fileKey).toBeInstanceOf(Uint8Array);
    expect(recovered.content!.fileKey.length).toBe(32);
  });

  it('content.fileKey bytes are identical to input after round-trip', () => {
    const bytes = encodeReadBody(FILE_NODE);
    const recovered = decodeReadBody(bytes);

    expect(Array.from(recovered.content!.fileKey)).toEqual(Array.from(FILE_KEY));
  });

  it('GCM version fileKey is a Uint8Array of length 32 after decode', () => {
    const bytes = encodeReadBody(FILE_NODE);
    const recovered = decodeReadBody(bytes);

    const gcm = recovered.content!.versions.find((v) => v.encryptionMode === 'GCM')!;
    expect(gcm).toBeDefined();
    expect(gcm.fileKey).toBeInstanceOf(Uint8Array);
    expect(gcm.fileKey.length).toBe(32);
  });

  it('CTR version fileKey is a Uint8Array of length 32 after decode', () => {
    const bytes = encodeReadBody(FILE_NODE);
    const recovered = decodeReadBody(bytes);

    const ctr = recovered.content!.versions.find((v) => v.encryptionMode === 'CTR')!;
    expect(ctr).toBeDefined();
    expect(ctr.fileKey).toBeInstanceOf(Uint8Array);
    expect(ctr.fileKey.length).toBe(32);
  });

  it('both GCM and CTR encryptionMode values are preserved after round-trip', () => {
    const bytes = encodeReadBody(FILE_NODE);
    const recovered = decodeReadBody(bytes);

    const modes = recovered.content!.versions.map((v) => v.encryptionMode);
    expect(modes).toContain('GCM');
    expect(modes).toContain('CTR');
  });
});

// ---------------------------------------------------------------------------
// Test 4 (NODE-03): SealedChildRef field set is exactly the 5 read-only keys
// ---------------------------------------------------------------------------

describe('NODE-03: SealedChildRef has no write field — structural assertion', () => {
  it('decoded SealedChildRef keys equal exactly {generation,ipnsName,name,readKeySealed,versionFloor}', () => {
    const bytes = encodeReadBody(FOLDER_NODE);
    const recovered = decodeReadBody(bytes);

    const child = recovered.children![0];
    const keys = Object.keys(child).sort();
    expect(keys).toEqual(['generation', 'ipnsName', 'name', 'readKeySealed', 'versionFloor']);
  });
});

// ---------------------------------------------------------------------------
// Test 5 (NODE-04): generation range validation fail-closed
// ---------------------------------------------------------------------------

describe('NODE-04: generation range [0, 2^32-1] validated fail-closed', () => {
  it('throws when generation is 0x100000000 (one above u32 max)', () => {
    const badNode: Node = { ...FOLDER_NODE, generation: 0x100000000 };
    const bytes = encodeReadBody(badNode);
    expect(() => decodeReadBody(bytes)).toThrow();
  });

  it('throws when generation is -1 (negative)', () => {
    const badNode: Node = { ...FOLDER_NODE, generation: -1 };
    const bytes = encodeReadBody(badNode);
    expect(() => decodeReadBody(bytes)).toThrow();
  });

  it('throws when generation is 1.5 (non-integer)', () => {
    const badNode: Node = { ...FOLDER_NODE, generation: 1.5 };
    const bytes = encodeReadBody(badNode);
    expect(() => decodeReadBody(bytes)).toThrow();
  });

  it('accepts generation = 0 (minimum valid)', () => {
    const minNode: Node = { ...FOLDER_NODE, generation: 0 };
    const bytes = encodeReadBody(minNode);
    expect(() => decodeReadBody(bytes)).not.toThrow();
  });

  it('accepts generation = 0xffffffff (u32 maximum)', () => {
    const maxNode: Node = { ...FOLDER_NODE, generation: 0xffffffff };
    const bytes = encodeReadBody(maxNode);
    expect(() => decodeReadBody(bytes)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Test 6 (NODE-02): wire bytes do NOT contain raw Uint8Array serialization
// ---------------------------------------------------------------------------

describe('NODE-02: wire bytes serialize fileKey as string, not raw object map', () => {
  it('JSON-parsed wire bytes expose content.fileKey as a string, not an object', () => {
    const bytes = encodeReadBody(FILE_NODE);
    const wireObj = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
    const content = wireObj.content as Record<string, unknown>;
    // A raw Uint8Array JSON-serializes to { "0": 7, "1": 7, ... }; a base64 string is a string
    expect(typeof content.fileKey).toBe('string');
  });
});
