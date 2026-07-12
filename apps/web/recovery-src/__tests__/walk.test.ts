/**
 * Recovery-tool walk cycle-guard coverage (SC1).
 *
 * A corrupted / rolled-back vault graph can point a child IPNS name back at an
 * ancestor. Without a visited-set guard the recursive walk would loop forever
 * (hang / OOM / gateway rate-limit). This test builds a deliberate A -> B -> A
 * cycle with mocked gateway + core primitives and asserts the walk TERMINATES,
 * reporting the revisit instead of recursing into it.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Node, PublishedNode } from '@cipherbox/core';

// --- Mock the HTTP transport: resolve each IPNS name to a CID == the name, and
//     return a PublishedNode envelope whose id echoes that name. --------------
vi.mock('../gateway', () => ({
  resolveIpnsVerified: vi.fn(async (name: string) => name),
  fetchFromIpfs: vi.fn(async (cid: string) =>
    new TextEncoder().encode(JSON.stringify({ id: cid, kind: 'folder' }))
  ),
}));

// --- Mock the crypto/codec primitives: unseal returns the graph node keyed by
//     the published envelope's id (== the IPNS name). ---------------------------
const nodeGraph: Record<string, Node> = {};
vi.mock('@cipherbox/core', () => ({
  unsealChildReadKey: vi.fn(async () => new Uint8Array(32)),
  unsealNode: vi.fn(async (published: PublishedNode) => nodeGraph[published.id]),
}));

import { recoverTree } from '../walk';
import type { RecoveryGatewayConfig } from '../walk';

const gatewayConfig: RecoveryGatewayConfig = {
  ipfsGateway: 'http://gw.test',
  ipnsGateway: 'http://gw.test',
};

function folder(id: string, children: Node['children']): Node {
  return { id, kind: 'folder', children } as unknown as Node;
}

function childRef(name: string, ipnsName: string) {
  return {
    name,
    ipnsName,
    readKeySealed: new Uint8Array(0),
    generation: 0,
  } as unknown as NonNullable<Node['children']>[number];
}

describe('recoverTree cycle guard', () => {
  beforeEach(() => {
    for (const k of Object.keys(nodeGraph)) delete nodeGraph[k];
  });

  it('terminates on an A -> B -> A cycle and reports the revisit', async () => {
    // nameA folder -> child B ; nameB folder -> child pointing back at nameA.
    nodeGraph['nameA'] = folder('nameA', [childRef('B', 'nameB')]);
    nodeGraph['nameB'] = folder('nameB', [childRef('A-again', 'nameA')]);

    const rootNode = folder('root', [childRef('A', 'nameA')]);
    const messages: Array<{ msg: string; level?: string }> = [];

    // If the guard failed this would recurse forever; a passing test proves it
    // terminates. Guard with a timeout as a belt-and-braces safety net.
    const result = await Promise.race([
      recoverTree(
        rootNode,
        new Uint8Array(32),
        gatewayConfig,
        (msg, level) => messages.push({ msg, level }),
        'root'
      ),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('walk did not terminate — cycle guard failed')), 5000)
      ),
    ]);

    expect(result).toEqual([]); // folders only, no files recovered
    const cycleMsg = messages.find((m) => /cycle detected/i.test(m.msg));
    expect(cycleMsg).toBeDefined();
    expect(cycleMsg?.level).toBe('warn');
  });

  it('seeds the visited set with the root so a descendant -> root loop is caught', async () => {
    // nameA folder -> child pointing back at the root IPNS name.
    nodeGraph['nameA'] = folder('nameA', [childRef('root-again', 'root')]);

    const rootNode = folder('root', [childRef('A', 'nameA')]);
    const messages: Array<{ msg: string; level?: string }> = [];

    const result = await Promise.race([
      recoverTree(
        rootNode,
        new Uint8Array(32),
        gatewayConfig,
        (msg, level) => messages.push({ msg, level }),
        'root'
      ),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('walk did not terminate — root not seeded')), 5000)
      ),
    ]);

    expect(result).toEqual([]);
    expect(messages.some((m) => /cycle detected/i.test(m.msg))).toBe(true);
  });
});
