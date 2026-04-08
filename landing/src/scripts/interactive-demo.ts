/**
 * Interactive vault explorer UI.
 * Renders a terminal-style chain of resolve -> fetch -> decrypt steps.
 * All data is pre-computed — no async crypto needed.
 */

import {
  truncHex,
  VAULT_PRIVATE_KEY,
  VAULT_PUBLIC_KEY,
  ROOT_FOLDER_KEY,
  DOCS_FOLDER_KEY,
  FILE_KEY,
  ROOT_IPNS,
  DOCS_IPNS,
  FILE_IPNS,
  ROOT_FOLDER_CID,
  DOCS_FOLDER_CID,
  FILE_META_CID,
  FILE_CONTENT_CID,
  ROOT_FOLDER_ENCRYPTED,
  DOCS_FOLDER_ENCRYPTED,
  FILE_META_ENCRYPTED,
  FILE_CONTENT_ENCRYPTED,
  ROOT_FOLDER_META,
  DOCS_FOLDER_META,
  FILE_META,
  FILE_PLAINTEXT,
} from './demo-data';

// ---- Lookup tables ----

const ipnsLabels: Record<string, string> = {
  [ROOT_IPNS]: 'Root Folder',
  [DOCS_IPNS]: 'Documents',
  [FILE_IPNS]: 'secret-note.txt metadata',
};

const ipnsToCid: Record<string, string> = {
  [ROOT_IPNS]: ROOT_FOLDER_CID,
  [DOCS_IPNS]: DOCS_FOLDER_CID,
  [FILE_IPNS]: FILE_META_CID,
};

interface ContentEntry {
  type: 'encrypted-metadata' | 'encrypted-file';
  encrypted: { iv: string; data: string } | string;
  decrypted: object | string;
  keyHex: string;
  keyLabel: string;
  label: string;
}

const cidToContent: Record<string, ContentEntry> = {
  [ROOT_FOLDER_CID]: {
    type: 'encrypted-metadata',
    encrypted: ROOT_FOLDER_ENCRYPTED,
    decrypted: ROOT_FOLDER_META,
    keyHex: ROOT_FOLDER_KEY,
    keyLabel: 'rootFolderKey',
    label: 'Root Folder Metadata',
  },
  [DOCS_FOLDER_CID]: {
    type: 'encrypted-metadata',
    encrypted: DOCS_FOLDER_ENCRYPTED,
    decrypted: DOCS_FOLDER_META,
    keyHex: DOCS_FOLDER_KEY,
    keyLabel: 'docsFolderKey',
    label: 'Documents Folder Metadata',
  },
  [FILE_META_CID]: {
    type: 'encrypted-metadata',
    encrypted: FILE_META_ENCRYPTED,
    decrypted: FILE_META,
    keyHex: ROOT_FOLDER_KEY,
    keyLabel: 'rootFolderKey',
    label: 'File Metadata (secret-note.txt)',
  },
  [FILE_CONTENT_CID]: {
    type: 'encrypted-file',
    encrypted: FILE_CONTENT_ENCRYPTED,
    decrypted: FILE_PLAINTEXT,
    keyHex: FILE_KEY,
    keyLabel: 'fileKey',
    label: 'Encrypted File Content',
  },
};

// ---- Init ----

let log: HTMLElement;

export function initInteractiveDemo(container: HTMLElement): void {
  log = container.querySelector('#demo-log')!;
  if (!log) return;

  // Vault key info
  add('info', `<span class="demo-dim">VaultKey (secp256k1):</span>`);
  add(
    'data',
    `<span class="demo-label">Private:</span> <span class="demo-key">${truncHex(VAULT_PRIVATE_KEY, 16)}</span> <span class="demo-dim">(32 bytes, RAM only)</span>`
  );
  add(
    'data',
    `<span class="demo-label">Public:</span>  <span class="demo-muted">${truncHex(VAULT_PUBLIC_KEY, 16)}</span> <span class="demo-dim">(65 bytes, uncompressed)</span>`
  );
  add('spacer', '');
  add('info', `<span class="demo-dim">IPNS Registry (Ed25519-signed mutable pointers):</span>`);

  for (const [name, label] of Object.entries(ipnsLabels)) {
    add(
      'ipns-row',
      `<span class="demo-ipns-name">${truncHex(name, 20)}</span>` +
        `<span class="demo-label-tag">${label}</span>` +
        `<button class="demo-btn" data-action="resolve" data-ipns="${name}">resolve &rarr;</button>`
    );
  }

  add('spacer', '');
  add(
    'info',
    '<span class="demo-dim">Click "resolve" on any IPNS name to begin exploring the encryption layers.</span>'
  );

  log.addEventListener('click', handleClick);
}

// ---- Event handling ----

function handleClick(e: Event): void {
  const btn = (e.target as HTMLElement).closest<HTMLElement>('[data-action]');
  if (!btn) return;

  const action = btn.dataset.action!;
  btn.classList.add('demo-btn-used');
  btn.removeAttribute('data-action');

  switch (action) {
    case 'resolve':
      doResolve(btn.dataset.ipns!);
      break;
    case 'fetch':
      doFetch(btn.dataset.cid!);
      break;
    case 'decrypt':
      doDecrypt(btn.dataset.cid!);
      break;
  }
}

function doResolve(ipns: string): void {
  const cid = ipnsToCid[ipns];
  const label = ipnsLabels[ipns] || '';

  add('spacer', '');
  add(
    'command',
    `<span class="demo-prompt">&gt;</span> ipns resolve <span class="demo-ipns-name">${truncHex(ipns, 20)}</span>`
  );

  if (!cid) {
    add('error', 'IPNS name not found');
    return;
  }

  add(
    'result',
    `<span class="demo-dim">&rarr;</span> <span class="demo-cid">${truncHex(cid, 20)}</span> ` +
      `<span class="demo-dim">(${label})</span> ` +
      `<button class="demo-btn" data-action="fetch" data-cid="${cid}">fetch &rarr;</button>`
  );
}

function doFetch(cid: string): void {
  const entry = cidToContent[cid];
  if (!entry) {
    add('error', 'CID not found');
    return;
  }

  add('spacer', '');
  add(
    'command',
    `<span class="demo-prompt">&gt;</span> ipfs cat <span class="demo-cid">${truncHex(cid, 20)}</span>`
  );

  if (entry.type === 'encrypted-metadata') {
    const meta = entry.encrypted as { iv: string; data: string };
    add(
      'result-box',
      `<div class="demo-blob">` +
        `<div class="demo-blob-header">${entry.label} <span class="demo-dim">(Encrypted)</span></div>` +
        `<div class="demo-blob-row"><span class="demo-label">iv:</span> <span class="demo-cipher">${meta.iv}</span> <span class="demo-dim">(12 bytes)</span></div>` +
        `<div class="demo-blob-row"><span class="demo-label">data:</span> <span class="demo-cipher">${meta.data.slice(0, 48)}...</span></div>` +
        `<div class="demo-blob-row"><span class="demo-dim">AES-256-GCM encrypted. Without the key this is unreadable.</span></div>` +
        `<button class="demo-btn demo-btn-decrypt" data-action="decrypt" data-cid="${cid}">decrypt with ${entry.keyLabel} &rarr;</button>` +
        `</div>`
    );
  } else {
    const b64 = entry.encrypted as string;
    add(
      'result-box',
      `<div class="demo-blob">` +
        `<div class="demo-blob-header">${entry.label}</div>` +
        `<div class="demo-blob-row"><span class="demo-label">encoding:</span> <span class="demo-muted">AES-256-GCM ciphertext + 16-byte auth tag</span></div>` +
        `<div class="demo-blob-row"><span class="demo-label">data:</span> <span class="demo-cipher">${b64.slice(0, 48)}...</span></div>` +
        `<div class="demo-blob-row"><span class="demo-dim">The server stores this blob. It cannot read the content.</span></div>` +
        `<button class="demo-btn demo-btn-decrypt" data-action="decrypt" data-cid="${cid}">decrypt with ${entry.keyLabel} &rarr;</button>` +
        `</div>`
    );
  }
}

function doDecrypt(cid: string): void {
  const entry = cidToContent[cid];
  if (!entry) return;

  add('spacer', '');
  add(
    'command',
    `<span class="demo-prompt">&gt;</span> decrypt <span class="demo-dim">with</span> ` +
      `<span class="demo-key">${entry.keyLabel}</span> <span class="demo-dim">(${truncHex(entry.keyHex, 10)})</span>`
  );

  if (entry.type === 'encrypted-metadata') {
    const json = JSON.stringify(entry.decrypted, null, 2);
    add('result-box', `<div class="demo-decrypted"><pre>${highlightJson(json)}</pre></div>`);
  } else {
    const text = entry.decrypted as string;
    add(
      'result-box',
      `<div class="demo-decrypted">` +
        `<div class="demo-blob-header">Decrypted File Content</div>` +
        `<div class="demo-plaintext">${esc(text)}</div>` +
        `<div class="demo-dim" style="margin-top:8px">This plaintext never leaves your device. The server only ever saw the encrypted blob above.</div>` +
        `</div>`
    );
  }
}

// ---- Helpers ----

function add(type: string, html: string): void {
  const div = document.createElement('div');
  div.className = `demo-entry demo-${type}`;
  div.innerHTML = html;
  log.appendChild(div);
  div.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function highlightJson(json: string): string {
  return esc(json)
    .replace(/"([^"]+)"(?=\s*[,\]}])/g, (_match, val: string) => {
      if (val.startsWith('k51')) {
        const label = ipnsLabels[val];
        return (
          `"<span class="demo-ipns-name demo-clickable" data-action="resolve" data-ipns="${val}">${val}</span>"` +
          (label ? ` <span class="demo-dim">&larr; ${label}</span>` : '')
        );
      }
      if (val.startsWith('bafy')) {
        return (
          `"<span class="demo-cid demo-clickable" data-action="fetch" data-cid="${val}">${val}</span>"` +
          (cidToContent[val] ? ` <span class="demo-dim">&larr; click to fetch</span>` : '')
        );
      }
      if (val.startsWith('04') && val.length > 100) {
        return (
          `"<span class="demo-cipher" title="${val}">${val.slice(0, 16)}...${val.slice(-8)}</span>"` +
          ` <span class="demo-dim">&larr; ECIES-wrapped</span>`
        );
      }
      if (/^[0-9a-f]{16,}$/.test(val)) {
        return `"<span class="demo-cipher">${val}</span>"`;
      }
      return `"<span class="demo-string">${val}</span>"`;
    })
    .replace(/"(\w+)"(?=\s*:)/g, '"<span class="demo-prop">$1</span>"')
    .replace(/:\s*(\d+)/g, ': <span class="demo-number">$1</span>')
    .replace(/:\s*(true|false)/g, ': <span class="demo-bool">$1</span>');
}
