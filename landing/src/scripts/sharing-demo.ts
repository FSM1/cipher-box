/**
 * Interactive sharing flow demo.
 * Shows how Alice shares a file with Bob by re-wrapping the fileKey
 * with Bob's public key using ECIES.
 */

import { truncateHex } from './demo-crypto';
import {
  VAULT_PRIVATE_KEY,
  VAULT_PUBLIC_KEY,
  BOB_PRIVATE_KEY,
  BOB_PUBLIC_KEY,
  FILE_KEY,
  FILE_KEY_ECIES,
  FILE_KEY_ECIES_BOB,
  FILE_PLAINTEXT,
} from './demo-data';

let log: HTMLElement;
let step = 0;

export function initSharingDemo(container: HTMLElement): void {
  log = container.querySelector('#sharing-log')!;
  if (!log) return;

  renderInitialState();
  log.addEventListener('click', handleClick);
}

function renderInitialState(): void {
  addEntry('info', '<span class="demo-dim">Two users: Alice (vault owner) and Bob (recipient)</span>');
  addEntry('spacer', '');

  addEntry('data',
    `<span class="demo-label">Alice\'s Key:</span> <span class="demo-key">${truncateHex(VAULT_PUBLIC_KEY, 16)}</span>`
  );
  addEntry('data',
    `<span class="demo-label">Bob\'s Key:</span>   <span class="demo-key" style="color:#00BCD4">${truncateHex(BOB_PUBLIC_KEY, 16)}</span>`
  );

  addEntry('spacer', '');
  addEntry('info',
    '<span class="demo-dim">Alice owns "secret-note.txt". The fileKey is ECIES-wrapped with her public key.</span>'
  );
  addEntry('spacer', '');

  addEntry('result-box',
    `<div class="demo-blob">` +
    `<div class="demo-blob-header">Current State: Alice's Vault</div>` +
    `<div class="demo-blob-row"><span class="demo-label">fileKey (encrypted):</span></div>` +
    `<div class="demo-blob-row"><span class="demo-cipher">${truncateHex(FILE_KEY_ECIES, 30)}</span></div>` +
    `<div class="demo-blob-row"><span class="demo-dim">Wrapped with Alice's secp256k1 public key. Only Alice can unwrap this.</span></div>` +
    `</div>`
  );

  addEntry('spacer', '');
  addEntry('action',
    `<button class="demo-btn" data-action="step1">Alice shares "secret-note.txt" with Bob &rarr;</button>`
  );
}

function handleClick(e: Event): void {
  const btn = (e.target as HTMLElement).closest('[data-action]') as HTMLElement | null;
  if (!btn) return;

  const action = btn.dataset.action!;
  btn.classList.add('demo-btn-used');
  btn.removeAttribute('data-action');

  if (action === 'step1') showStep1();
  else if (action === 'step2') showStep2();
  else if (action === 'step3') showStep3();
  else if (action === 'step4') showStep4();
}

function showStep1(): void {
  addEntry('spacer', '');
  addEntry('command',
    `<span class="demo-prompt">&gt;</span> ecies_unwrap <span class="demo-dim">fileKey with</span> <span class="demo-key">Alice's privateKey</span>`
  );
  addEntry('spacer', '');

  addEntry('result-box',
    `<div class="demo-blob">` +
    `<div class="demo-blob-header">Step 1: Unwrap fileKey</div>` +
    `<div class="demo-blob-row"><span class="demo-label">input:</span> <span class="demo-cipher">${truncateHex(FILE_KEY_ECIES, 24)}</span></div>` +
    `<div class="demo-blob-row"><span class="demo-label">using:</span> <span class="demo-key">Alice's privateKey</span> <span class="demo-dim">(${truncateHex(VAULT_PRIVATE_KEY, 10)})</span></div>` +
    `<div class="demo-blob-row"><span class="demo-label">output:</span> <span class="demo-key">${truncateHex(FILE_KEY, 16)}</span> <span class="demo-dim">&larr; plaintext fileKey (32 bytes)</span></div>` +
    `<div class="demo-blob-row"><span class="demo-dim">The plaintext fileKey exists only in RAM. It will be zeroed after re-wrapping.</span></div>` +
    `</div>`
  );

  addEntry('spacer', '');
  addEntry('action',
    `<button class="demo-btn" data-action="step2">Re-wrap with Bob's public key &rarr;</button>`
  );
}

function showStep2(): void {
  addEntry('spacer', '');
  addEntry('command',
    `<span class="demo-prompt">&gt;</span> ecies_wrap <span class="demo-dim">fileKey with</span> <span class="demo-key" style="color:#00BCD4">Bob's publicKey</span>`
  );
  addEntry('spacer', '');

  addEntry('result-box',
    `<div class="demo-blob">` +
    `<div class="demo-blob-header">Step 2: Re-wrap for Bob</div>` +
    `<div class="demo-blob-row"><span class="demo-label">input:</span> <span class="demo-key">${truncateHex(FILE_KEY, 16)}</span> <span class="demo-dim">(plaintext fileKey)</span></div>` +
    `<div class="demo-blob-row"><span class="demo-label">using:</span> <span class="demo-key" style="color:#00BCD4">Bob's publicKey</span> <span class="demo-dim">(${truncateHex(BOB_PUBLIC_KEY, 10)})</span></div>` +
    `<div class="demo-blob-row"><span class="demo-label">output:</span> <span class="demo-cipher" style="color:#00838F">${truncateHex(FILE_KEY_ECIES_BOB, 24)}</span></div>` +
    `<div class="demo-blob-row"><span class="demo-dim">Same fileKey, new ECIES envelope. The plaintext key is zeroed from memory.</span></div>` +
    `</div>`
  );

  addEntry('spacer', '');
  addEntry('action',
    `<button class="demo-btn" data-action="step3">See the sharing record &rarr;</button>`
  );
}

function showStep3(): void {
  addEntry('spacer', '');
  addEntry('command',
    `<span class="demo-prompt">&gt;</span> <span class="demo-dim">Share record stored on server:</span>`
  );
  addEntry('spacer', '');

  const shareRecord = {
    fileId: '7c9e6679-7425-40de-944b-e07fc1f90ae7',
    recipientPublicKey: BOB_PUBLIC_KEY,
    fileKeyEncrypted: FILE_KEY_ECIES_BOB,
    permission: 'read-only',
  };

  addEntry('result-box',
    `<div class="demo-decrypted">` +
    `<div class="demo-blob-header">Share Record</div>` +
    `<pre>${highlightShareJson(JSON.stringify(shareRecord, null, 2))}</pre>` +
    `<div class="demo-dim" style="margin-top:8px">The server stores this record but cannot derive the fileKey from it.<br>` +
    `Both Alice's and Bob's wrapped keys decrypt to the same fileKey.</div>` +
    `</div>`
  );

  addEntry('spacer', '');
  addEntry('action',
    `<button class="demo-btn" data-action="step4">Bob decrypts the file &rarr;</button>`
  );
}

function showStep4(): void {
  addEntry('spacer', '');
  addEntry('command',
    `<span class="demo-prompt">&gt;</span> <span class="demo-dim">Bob receives the share and decrypts:</span>`
  );
  addEntry('spacer', '');

  addEntry('result-box',
    `<div class="demo-blob">` +
    `<div class="demo-blob-header">Step 3: Bob Unwraps fileKey</div>` +
    `<div class="demo-blob-row"><span class="demo-label">input:</span> <span class="demo-cipher" style="color:#00838F">${truncateHex(FILE_KEY_ECIES_BOB, 24)}</span></div>` +
    `<div class="demo-blob-row"><span class="demo-label">using:</span> <span class="demo-key" style="color:#00BCD4">Bob's privateKey</span> <span class="demo-dim">(${truncateHex(BOB_PRIVATE_KEY, 10)})</span></div>` +
    `<div class="demo-blob-row"><span class="demo-label">output:</span> <span class="demo-key">${truncateHex(FILE_KEY, 16)}</span> <span class="demo-dim">&larr; same fileKey!</span></div>` +
    `</div>`
  );

  addEntry('spacer', '');

  addEntry('result-box',
    `<div class="demo-decrypted">` +
    `<div class="demo-blob-header">Bob Decrypts the File</div>` +
    `<div class="demo-plaintext">${escapeHtml(FILE_PLAINTEXT)}</div>` +
    `<div class="demo-dim" style="margin-top:8px">` +
    `Same file, same CID on IPFS. Alice and Bob each have their own ECIES envelope ` +
    `wrapping the same symmetric fileKey. The server never saw the plaintext.` +
    `</div>` +
    `</div>`
  );

  addEntry('spacer', '');
  addEntry('info',
    `<span class="demo-dim">If Alice revokes Bob's access, she rotates the fileKey. ` +
    `Bob's old envelope becomes useless for future versions.</span>`
  );
}

// ---- Helpers ----

function addEntry(type: string, html: string): void {
  const div = document.createElement('div');
  div.className = `demo-entry demo-${type}`;
  div.innerHTML = html;
  log.appendChild(div);
  div.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function highlightShareJson(json: string): string {
  return escapeHtml(json)
    .replace(/"([^"]+)"(?=\s*[,:\]\}])/g, (match, val) => {
      if (val.startsWith('04') && val.length > 100) {
        return `"<span class="demo-cipher" style="color:#00838F">${val.slice(0, 20)}...${val.slice(-12)}</span>"`;
      }
      if (/^[0-9a-f-]{20,}$/.test(val)) {
        return `"<span class="demo-muted">${val}</span>"`;
      }
      return `"<span class="demo-string">${val}</span>"`;
    })
    .replace(/"(\w+)"(?=\s*:)/g, '"<span class="demo-prop">$1</span>"');
}
