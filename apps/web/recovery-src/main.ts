/**
 * Recovery-tool entry point (SC1) — full DOM wiring.
 *
 * Trust-nothing, infra-independent vault recovery (D-01/D-02): given ONLY the
 * user's `privateKey`, this walks the IPNS → IPFS link tree over a configurable
 * HTTP gateway and decrypts the whole folder/file tree with ZERO dependency on
 * the CipherBox API relay, Web3Auth, or the `@cipherbox/sdk` / `@cipherbox/sdk-core`
 * read chain. The only allowed workspace imports are the low-level primitives
 * from `@cipherbox/crypto` and `@cipherbox/core` (D-03) — no crypto/codec is
 * hand-rolled here.
 *
 * The pasted `privateKey` is used in-memory only: it is NEVER written to any
 * persistent browser storage (CLAUDE.md Rule 1 / T-78-06) and is zeroed after
 * the recovery walk completes.
 *
 * This module is the esbuild bundle entry `recovery-src/build.ts` splices into
 * `public/recovery.html`'s `<!-- RECOVERY_BUNDLE -->` placeholder.
 */

import {
  deriveVaultIpnsKeypair,
  deriveVaultKeyIpnsKeypair,
  hexToBytes,
  unwrapKey,
} from '@cipherbox/crypto';
import { deserializeVaultBlobV3, unsealNode } from '@cipherbox/core';
import { zipSync, type Zippable } from 'fflate';

import { fetchFromIpfs, resolveIpnsVerified } from './gateway';
import { fetchPublishedNode, recoverTree, type RecoveredFile } from './walk';
import type { RecoveryGatewayConfig } from './walk';

// ---------------------------------------------------------------------------
// DOM handles (query the stable data-testid selectors the e2e spec depends on)
// ---------------------------------------------------------------------------

function requireEl<T extends HTMLElement>(selector: string): T {
  const el = document.querySelector<T>(selector);
  if (!el) throw new Error(`Recovery UI element not found: ${selector}`);
  return el;
}

// ---------------------------------------------------------------------------
// Progress log + step navigation
// ---------------------------------------------------------------------------

function makeLogger(logEl: HTMLElement) {
  return (message: string, level: 'info' | 'success' | 'error' | 'warn' = 'info'): void => {
    const entry = document.createElement('div');
    entry.className = `log-entry ${level}`;
    entry.textContent = message;
    logEl.appendChild(entry);
    logEl.scrollTop = logEl.scrollHeight;
  };
}

function showStep(n: number): void {
  for (let i = 1; i <= 2; i++) {
    document.getElementById(`step-${i}`)?.classList.toggle('visible', i === n);
    const dot = document.getElementById(`dot-${i}`);
    if (!dot) continue;
    dot.classList.remove('active', 'complete', 'pending');
    if (i < n) dot.classList.add('complete');
    else if (i === n) dot.classList.add('active');
    else dot.classList.add('pending');
  }
}

function showError(stepN: number, msg: string): void {
  const el = document.getElementById(`error-${stepN}`);
  if (!el) return;
  el.textContent = msg;
  el.classList.add('visible');
}

function clearError(stepN: number): void {
  const el = document.getElementById(`error-${stepN}`);
  if (!el) return;
  el.textContent = '';
  el.classList.remove('visible');
}

/** Parse a hex private key, tolerating a 0x prefix; fail closed on bad input. */
function parsePrivateKey(raw: string): Uint8Array {
  const clean = raw.startsWith('0x') || raw.startsWith('0X') ? raw.slice(2) : raw;
  const bytes = hexToBytes(clean);
  if (bytes.length !== 32) {
    bytes.fill(0);
    throw new Error(`Private key must be 32 bytes (got ${bytes.length} bytes).`);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Recovery flow: privateKey → vault-key blob → rootReadKey → root → walk → zip
// ---------------------------------------------------------------------------

async function runRecovery(
  privateKey: Uint8Array,
  gatewayConfig: RecoveryGatewayConfig,
  log: ReturnType<typeof makeLogger>
): Promise<RecoveredFile[]> {
  // 1. Derive the two vault IPNS names from the private key (real crypto, D-03).
  const rootKeypair = await deriveVaultIpnsKeypair(privateKey);
  const vaultKeyKeypair = await deriveVaultKeyIpnsKeypair(privateKey);
  log(`Derived vault-key IPNS: ${vaultKeyKeypair.ipnsName}`, 'info');
  log(`Derived root IPNS: ${rootKeypair.ipnsName}`, 'info');
  // Recovery is read-only: the derived Ed25519 IPNS *signing* keys are never
  // used (only their ipnsName), so zero them now that both names are consumed.
  rootKeypair.privateKey.fill(0);
  vaultKeyKeypair.privateKey.fill(0);

  // 2. Fetch + deserialize the v3 vault key blob (a raw serialized blob, NOT a
  //    PublishedNode envelope), then ECIES-unwrap the root read key.
  log('Resolving vault key blob...', 'info');
  const blobCid = await resolveIpnsVerified(
    vaultKeyKeypair.ipnsName,
    gatewayConfig.ipnsGateway,
    gatewayConfig.ipfsGateway
  );
  const blobBytes = await fetchFromIpfs(blobCid, gatewayConfig.ipfsGateway);
  const { encryptedRootReadKey } = deserializeVaultBlobV3(blobBytes);
  const rootReadKey = await unwrapKey(encryptedRootReadKey, privateKey);
  log('Unwrapped root read key.', 'success');

  // 3. Unseal the root node and recurse (read-only — no writeKey argument).
  try {
    log('Resolving root folder...', 'info');
    const rootPublished = await fetchPublishedNode(rootKeypair.ipnsName, gatewayConfig);
    const rootNode = await unsealNode(rootPublished, rootReadKey);
    log('Unsealed root node. Walking tree...', 'info');
    return await recoverTree(rootNode, rootReadKey, gatewayConfig, log);
  } finally {
    rootReadKey.fill(0);
  }
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

function wire(): void {
  const keyInput = requireEl<HTMLTextAreaElement>('[data-testid="recovery-key-input"]');
  const ipfsGatewayInput = requireEl<HTMLInputElement>('[data-testid="recovery-ipfs-gateway"]');
  const ipnsGatewayInput = requireEl<HTMLInputElement>('[data-testid="recovery-ipns-gateway"]');
  const startBtn = requireEl<HTMLButtonElement>('[data-testid="recovery-start-btn"]');
  const progressLog = requireEl<HTMLElement>('[data-testid="recovery-progress-log"]');
  const downloadBtn = requireEl<HTMLButtonElement>('[data-testid="recovery-download-btn"]');

  const log = makeLogger(progressLog);
  let zipBytes: Uint8Array | null = null;

  startBtn.addEventListener('click', async () => {
    clearError(1);
    clearError(2);

    let privateKey: Uint8Array;
    try {
      privateKey = parsePrivateKey(keyInput.value.trim());
    } catch (err) {
      showError(1, err instanceof Error ? err.message : 'Invalid private key.');
      return;
    }

    const gatewayConfig: RecoveryGatewayConfig = {
      ipfsGateway: ipfsGatewayInput.value.trim().replace(/\/+$/, ''),
      ipnsGateway: ipnsGatewayInput.value.trim().replace(/\/+$/, ''),
    };
    if (!gatewayConfig.ipfsGateway || !gatewayConfig.ipnsGateway) {
      privateKey.fill(0);
      showError(1, 'Both an IPFS gateway and an IPNS resolution gateway are required.');
      return;
    }

    startBtn.disabled = true;
    startBtn.textContent = '[ Recovering... ]';
    downloadBtn.classList.remove('visible');
    progressLog.innerHTML = '';
    zipBytes = null;
    showStep(2);

    log('CipherBox v3 vault recovery starting...', 'info');
    log(`IPFS gateway: ${gatewayConfig.ipfsGateway}`, 'info');
    log(`IPNS gateway: ${gatewayConfig.ipnsGateway}`, 'info');

    try {
      const files = await runRecovery(privateKey, gatewayConfig, log);

      if (files.length === 0) {
        log('Recovery complete. No files found (vault empty).', 'warn');
      } else {
        const zippable: Zippable = {};
        for (const file of files) {
          zippable[file.path] = file.bytes;
        }
        zipBytes = zipSync(zippable);
        log(`Recovery complete. ${files.length} file(s) packed into a zip.`, 'success');
        downloadBtn.classList.add('visible');
      }
      document.getElementById('post-note')?.classList.add('visible');
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      log(`FATAL: ${message}`, 'error');
      showError(2, `Recovery failed: ${message}`);
      document.getElementById('post-note')?.classList.add('visible');
    } finally {
      // The pasted key is used in-memory only — zero it and never persist it.
      privateKey.fill(0);
      startBtn.disabled = false;
      startBtn.textContent = '[ Start Recovery ]';
    }
  });

  downloadBtn.addEventListener('click', () => {
    if (!zipBytes) return;
    const blob = new Blob([zipBytes as BlobPart], { type: 'application/zip' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const date = new Date().toISOString().slice(0, 10);
    a.href = url;
    a.download = `cipherbox-recovery-${date}.zip`;
    a.click();
    URL.revokeObjectURL(url);
    log('Zip download started.', 'success');
  });
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wire);
  } else {
    wire();
  }
}
