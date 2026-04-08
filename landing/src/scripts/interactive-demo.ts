/**
 * Interactive vault explorer UI.
 * Renders a terminal-style chain of resolve → fetch → decrypt steps.
 * Users click through IPNS names and CIDs to explore the encryption layers.
 */

import { hexEncode, hexDecode, truncateHex, decryptMetadata, aesGcmDecrypt, base64Decode } from './demo-crypto';
import {
  generateDemoVault,
  VAULT_PRIVATE_KEY,
  VAULT_PUBLIC_KEY,
  ROOT_FOLDER_KEY,
  DOCS_FOLDER_KEY,
  FILE_KEY,
  ROOT_IPNS_NAME,
  DOCS_IPNS_NAME,
  FILE_IPNS_NAME,
  FILE_CONTENT_IV,
  FILE_PLAINTEXT,
  type DemoVault,
} from './demo-data';

// ---- State ----

let vault: DemoVault | null = null;
let log: HTMLElement;

// Maps for lookups
const ipnsToLabel = new Map<string, string>();
const ipnsToCid = new Map<string, string>();
const cidToContent = new Map<string, { type: string; data: unknown; key?: string; label: string }>();

// ---- Initialization ----

export async function initInteractiveDemo(container: HTMLElement): Promise<void> {
  log = container.querySelector('#demo-log')!;
  if (!log) return;

  vault = await generateDemoVault();

  // Build lookup maps
  ipnsToLabel.set(ROOT_IPNS_NAME, 'Root Folder');
  ipnsToLabel.set(DOCS_IPNS_NAME, 'Documents');
  ipnsToLabel.set(FILE_IPNS_NAME, 'secret-note.txt metadata');

  ipnsToCid.set(ROOT_IPNS_NAME, vault.rootFolderCid);
  ipnsToCid.set(DOCS_IPNS_NAME, vault.docsFolderCid);
  ipnsToCid.set(FILE_IPNS_NAME, vault.fileMetaCid);

  cidToContent.set(vault.rootFolderCid, {
    type: 'encrypted-metadata',
    data: vault.rootFolderEncrypted,
    key: ROOT_FOLDER_KEY,
    label: 'Root Folder Metadata',
  });
  cidToContent.set(vault.docsFolderCid, {
    type: 'encrypted-metadata',
    data: vault.docsFolderEncrypted,
    key: DOCS_FOLDER_KEY,
    label: 'Documents Folder Metadata',
  });
  cidToContent.set(vault.fileMetaCid, {
    type: 'encrypted-metadata',
    data: vault.fileMetaEncrypted,
    key: ROOT_FOLDER_KEY,
    label: 'File Metadata (secret-note.txt)',
  });
  cidToContent.set(vault.fileContentCid, {
    type: 'encrypted-file',
    data: vault.fileContentEncrypted,
    key: FILE_KEY,
    label: 'Encrypted File Content',
  });

  renderInitialState();
}

// ---- Rendering ----

function renderInitialState(): void {
  addEntry('info', `<span class="demo-dim">VaultKey (secp256k1):</span>`);
  addEntry(
    'data',
    `<span class="demo-label">Private:</span> <span class="demo-key">${truncateHex(VAULT_PRIVATE_KEY, 16)}</span> <span class="demo-dim">(32 bytes, RAM only)</span>`
  );
  addEntry(
    'data',
    `<span class="demo-label">Public:</span>  <span class="demo-muted">${truncateHex(VAULT_PUBLIC_KEY, 16)}</span> <span class="demo-dim">(65 bytes, uncompressed)</span>`
  );
  addEntry('spacer', '');

  addEntry('info', `<span class="demo-dim">IPNS Registry (Ed25519-signed mutable pointers):</span>`);

  for (const [name, label] of ipnsToLabel) {
    addEntry(
      'ipns-row',
      `<span class="demo-ipns-name">${truncateHex(name, 20)}</span>` +
        `<span class="demo-label-tag">${label}</span>` +
        `<button class="demo-btn" data-action="resolve" data-ipns="${name}">resolve &rarr;</button>`
    );
  }

  addEntry('spacer', '');
  addEntry('info', '<span class="demo-dim">Click "resolve" on any IPNS name to begin exploring the encryption layers.</span>');

  // Bind click handlers (event delegation)
  log.addEventListener('click', handleClick);
}

async function handleClick(e: Event): Promise<void> {
  const btn = (e.target as HTMLElement).closest('[data-action]') as HTMLElement | null;
  if (!btn || !vault) return;

  const action = btn.dataset.action!;
  btn.classList.add('demo-btn-used');
  btn.removeAttribute('data-action');

  if (action === 'resolve') {
    await handleResolve(btn.dataset.ipns!);
  } else if (action === 'fetch') {
    await handleFetch(btn.dataset.cid!);
  } else if (action === 'decrypt-meta') {
    await handleDecryptMeta(btn.dataset.cid!);
  } else if (action === 'decrypt-file') {
    await handleDecryptFile(btn.dataset.cid!);
  }
}

async function handleResolve(ipnsName: string): Promise<void> {
  const label = ipnsToLabel.get(ipnsName) || '';
  const cid = ipnsToCid.get(ipnsName);

  addEntry('spacer', '');
  addEntry('command', `<span class="demo-prompt">&gt;</span> ipns resolve <span class="demo-ipns-name">${truncateHex(ipnsName, 20)}</span>`);

  if (!cid) {
    addEntry('error', 'IPNS name not found');
    return;
  }

  addEntry(
    'result',
    `<span class="demo-dim">&rarr;</span> <span class="demo-cid">${truncateHex(cid, 20)}</span> ` +
      `<span class="demo-dim">(${label})</span> ` +
      `<button class="demo-btn" data-action="fetch" data-cid="${cid}">fetch &rarr;</button>`
  );
}

async function handleFetch(cid: string): Promise<void> {
  const content = cidToContent.get(cid);
  if (!content) {
    addEntry('error', 'CID not found in IPFS');
    return;
  }

  addEntry('spacer', '');
  addEntry('command', `<span class="demo-prompt">&gt;</span> ipfs cat <span class="demo-cid">${truncateHex(cid, 20)}</span>`);

  if (content.type === 'encrypted-metadata') {
    const meta = content.data as { iv: string; data: string };
    addEntry('result-box', formatEncryptedBlob(meta, content.label, cid));
  } else if (content.type === 'encrypted-file') {
    const b64 = content.data as string;
    addEntry(
      'result-box',
      `<div class="demo-blob">` +
        `<div class="demo-blob-header">${content.label}</div>` +
        `<div class="demo-blob-row"><span class="demo-label">encoding:</span> <span class="demo-muted">AES-256-GCM ciphertext + 16-byte auth tag</span></div>` +
        `<div class="demo-blob-row"><span class="demo-label">size:</span> <span class="demo-muted">${base64Decode(b64).length} bytes</span></div>` +
        `<div class="demo-blob-row"><span class="demo-label">data:</span> <span class="demo-cipher">${b64.slice(0, 60)}...</span></div>` +
        `<div class="demo-blob-row"><span class="demo-dim">The server stores this blob. It cannot read the content.</span></div>` +
        `<button class="demo-btn demo-btn-decrypt" data-action="decrypt-file" data-cid="${cid}">` +
        `decrypt with fileKey &rarr;</button>` +
        `</div>`
    );
  }
}

async function handleDecryptMeta(cid: string): Promise<void> {
  const content = cidToContent.get(cid);
  if (!content || content.type !== 'encrypted-metadata') return;

  const encrypted = content.data as { iv: string; data: string };
  const keyHex = content.key!;
  const keyBytes = hexDecode(keyHex);

  const keyLabel = keyHex === ROOT_FOLDER_KEY ? 'rootFolderKey' : 'docsFolderKey';

  addEntry('spacer', '');
  addEntry(
    'command',
    `<span class="demo-prompt">&gt;</span> decrypt <span class="demo-dim">with</span> ` +
      `<span class="demo-key">${keyLabel}</span> <span class="demo-dim">(${truncateHex(keyHex, 10)})</span>`
  );

  try {
    const decrypted = await decryptMetadata(encrypted, keyBytes);
    const json = JSON.stringify(decrypted, null, 2);
    const highlighted = highlightJson(json);
    addEntry('result-box', `<div class="demo-decrypted"><pre>${highlighted}</pre></div>`);
  } catch (err) {
    addEntry('error', `Decryption failed: ${err}`);
  }
}

async function handleDecryptFile(cid: string): Promise<void> {
  const content = cidToContent.get(cid);
  if (!content || content.type !== 'encrypted-file') return;

  const b64 = content.data as string;
  const ciphertextWithTag = base64Decode(b64);
  const keyBytes = hexDecode(FILE_KEY);
  const ivBytes = hexDecode(FILE_CONTENT_IV);

  addEntry('spacer', '');
  addEntry(
    'command',
    `<span class="demo-prompt">&gt;</span> decrypt <span class="demo-dim">with</span> ` +
      `<span class="demo-key">fileKey</span> <span class="demo-dim">(${truncateHex(FILE_KEY, 10)})</span>`
  );

  try {
    const plaintext = await aesGcmDecrypt(ciphertextWithTag, keyBytes, ivBytes);
    const text = new TextDecoder().decode(plaintext);
    addEntry(
      'result-box',
      `<div class="demo-decrypted">` +
        `<div class="demo-blob-header">Decrypted File Content</div>` +
        `<div class="demo-plaintext">${escapeHtml(text)}</div>` +
        `<div class="demo-dim" style="margin-top:8px">This plaintext never leaves your device. The server only ever saw the encrypted blob above.</div>` +
        `</div>`
    );
  } catch (err) {
    addEntry('error', `Decryption failed: ${err}`);
  }
}

// ---- Helpers ----

function formatEncryptedBlob(meta: { iv: string; data: string }, label: string, cid: string): string {
  return (
    `<div class="demo-blob">` +
    `<div class="demo-blob-header">${label} <span class="demo-dim">(Encrypted)</span></div>` +
    `<div class="demo-blob-row"><span class="demo-label">iv:</span> <span class="demo-cipher">${meta.iv}</span> <span class="demo-dim">(12 bytes)</span></div>` +
    `<div class="demo-blob-row"><span class="demo-label">data:</span> <span class="demo-cipher">${meta.data.slice(0, 60)}...</span></div>` +
    `<div class="demo-blob-row"><span class="demo-dim">AES-256-GCM encrypted. The IV is not secret, but without the key this is unreadable.</span></div>` +
    `<button class="demo-btn demo-btn-decrypt" data-action="decrypt-meta" data-cid="${cid}">` +
    `decrypt &rarr;</button>` +
    `</div>`
  );
}

function addEntry(type: string, html: string): void {
  const div = document.createElement('div');
  div.className = `demo-entry demo-${type}`;
  div.innerHTML = html;
  log.appendChild(div);

  // Scroll to new entry
  div.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function highlightJson(json: string): string {
  return escapeHtml(json)
    // String values (including those in arrays)
    .replace(/"([^"]+)"(?=\s*[,:\]\}])/g, (match, val) => {
      // IPNS names
      if (val.startsWith('k51')) {
        const ipnsLabel = ipnsToLabel.get(val);
        return `"<span class="demo-ipns-name demo-clickable" data-action="resolve" data-ipns="${val}">${val}</span>"` +
          (ipnsLabel ? ` <span class="demo-dim">&larr; ${ipnsLabel}</span>` : '');
      }
      // CIDs
      if (val.startsWith('bafy')) {
        const cidContent = cidToContent.get(val);
        return `"<span class="demo-cid demo-clickable" data-action="fetch" data-cid="${val}">${val}</span>"` +
          (cidContent ? ` <span class="demo-dim">&larr; click to fetch</span>` : '');
      }
      // ECIES-wrapped keys (long hex starting with 04)
      if (val.startsWith('04') && val.length > 100) {
        return `"<span class="demo-cipher" title="${val}">${val.slice(0, 20)}...${val.slice(-12)}</span>"` +
          ` <span class="demo-dim">&larr; ECIES-wrapped</span>`;
      }
      // Hex-like values (IVs, short hex)
      if (/^[0-9a-f]{16,}$/.test(val)) {
        return `"<span class="demo-cipher">${val}</span>"`;
      }
      return `"<span class="demo-string">${val}</span>"`;
    })
    // Property names
    .replace(/"(\w+)"(?=\s*:)/g, '"<span class="demo-prop">$1</span>"')
    // Numbers
    .replace(/:\s*(\d+)/g, ': <span class="demo-number">$1</span>')
    // Booleans
    .replace(/:\s*(true|false)/g, ': <span class="demo-bool">$1</span>');
}
