/**
 * Interactive sharing flow demo.
 * Shows how Alice shares a file with Bob by re-wrapping the fileKey.
 */

import {
  truncHex,
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

export function initSharingDemo(container: HTMLElement): void {
  log = container.querySelector('#sharing-log')!;
  if (!log) return;

  add('info', '<span class="demo-dim">Two users: Alice (vault owner) and Bob (recipient)</span>');
  add('spacer', '');

  add('data',
    `<span class="demo-label">Alice's Key:</span> <span class="demo-key">${truncHex(VAULT_PUBLIC_KEY, 16)}</span>`
  );
  add('data',
    `<span class="demo-label">Bob's Key:</span>   <span class="demo-key" style="color:#00BCD4">${truncHex(BOB_PUBLIC_KEY, 16)}</span>`
  );

  add('spacer', '');
  add('info',
    '<span class="demo-dim">Alice owns "secret-note.txt". The fileKey is ECIES-wrapped with her public key.</span>'
  );
  add('spacer', '');

  add('result-box',
    `<div class="demo-blob">` +
    `<div class="demo-blob-header">Current State: Alice's Vault</div>` +
    `<div class="demo-blob-row"><span class="demo-label">fileKey (encrypted):</span></div>` +
    `<div class="demo-blob-row"><span class="demo-cipher">${truncHex(FILE_KEY_ECIES, 30)}</span></div>` +
    `<div class="demo-blob-row"><span class="demo-dim">Wrapped with Alice's secp256k1 public key. Only Alice can unwrap this.</span></div>` +
    `</div>`
  );

  add('spacer', '');
  add('action',
    `<button class="demo-btn" data-action="step1">Alice shares "secret-note.txt" with Bob &rarr;</button>`
  );

  log.addEventListener('click', handleClick);
}

function handleClick(e: Event): void {
  const btn = (e.target as HTMLElement).closest<HTMLElement>('[data-action]');
  if (!btn) return;

  const action = btn.dataset.action!;
  btn.classList.add('demo-btn-used');
  btn.removeAttribute('data-action');

  switch (action) {
    case 'step1': showStep1(); break;
    case 'step2': showStep2(); break;
    case 'step3': showStep3(); break;
    case 'step4': showStep4(); break;
  }
}

function showStep1(): void {
  add('spacer', '');
  add('command',
    `<span class="demo-prompt">&gt;</span> ecies_unwrap <span class="demo-dim">fileKey with</span> <span class="demo-key">Alice's privateKey</span>`
  );
  add('spacer', '');

  add('result-box',
    `<div class="demo-blob">` +
    `<div class="demo-blob-header">Step 1: Unwrap fileKey</div>` +
    `<div class="demo-blob-row"><span class="demo-label">input:</span> <span class="demo-cipher">${truncHex(FILE_KEY_ECIES, 24)}</span></div>` +
    `<div class="demo-blob-row"><span class="demo-label">using:</span> <span class="demo-key">Alice's privateKey</span> <span class="demo-dim">(${truncHex(VAULT_PRIVATE_KEY, 10)})</span></div>` +
    `<div class="demo-blob-row"><span class="demo-label">output:</span> <span class="demo-key">${truncHex(FILE_KEY, 16)}</span> <span class="demo-dim">&larr; plaintext fileKey (32 bytes)</span></div>` +
    `<div class="demo-blob-row"><span class="demo-dim">The plaintext fileKey exists only in RAM. It will be zeroed after re-wrapping.</span></div>` +
    `</div>`
  );

  add('spacer', '');
  add('action',
    `<button class="demo-btn" data-action="step2">Re-wrap with Bob's public key &rarr;</button>`
  );
}

function showStep2(): void {
  add('spacer', '');
  add('command',
    `<span class="demo-prompt">&gt;</span> ecies_wrap <span class="demo-dim">fileKey with</span> <span class="demo-key" style="color:#00BCD4">Bob's publicKey</span>`
  );
  add('spacer', '');

  add('result-box',
    `<div class="demo-blob">` +
    `<div class="demo-blob-header">Step 2: Re-wrap for Bob</div>` +
    `<div class="demo-blob-row"><span class="demo-label">input:</span> <span class="demo-key">${truncHex(FILE_KEY, 16)}</span> <span class="demo-dim">(plaintext fileKey)</span></div>` +
    `<div class="demo-blob-row"><span class="demo-label">using:</span> <span class="demo-key" style="color:#00BCD4">Bob's publicKey</span> <span class="demo-dim">(${truncHex(BOB_PUBLIC_KEY, 10)})</span></div>` +
    `<div class="demo-blob-row"><span class="demo-label">output:</span> <span class="demo-cipher" style="color:#00838F">${truncHex(FILE_KEY_ECIES_BOB, 24)}</span></div>` +
    `<div class="demo-blob-row"><span class="demo-dim">Same fileKey, new ECIES envelope. The plaintext key is zeroed from memory.</span></div>` +
    `</div>`
  );

  add('spacer', '');
  add('action',
    `<button class="demo-btn" data-action="step3">See the sharing record &rarr;</button>`
  );
}

function showStep3(): void {
  add('spacer', '');
  add('command',
    `<span class="demo-prompt">&gt;</span> <span class="demo-dim">Share record stored on server:</span>`
  );
  add('spacer', '');

  add('result-box',
    `<div class="demo-decrypted">` +
    `<div class="demo-blob-header">Share Record</div>` +
    `<pre>` +
    `{\n` +
    `  "<span class="demo-prop">fileId</span>": "<span class="demo-muted">7c9e6679-7425-40de-944b-e07fc1f90ae7</span>",\n` +
    `  "<span class="demo-prop">recipientPublicKey</span>": "<span class="demo-cipher" style="color:#00838F">${truncHex(BOB_PUBLIC_KEY, 16)}</span>",\n` +
    `  "<span class="demo-prop">fileKeyEncrypted</span>": "<span class="demo-cipher" style="color:#00838F">${truncHex(FILE_KEY_ECIES_BOB, 16)}</span>",\n` +
    `  "<span class="demo-prop">permission</span>": "<span class="demo-string">read-only</span>"\n` +
    `}` +
    `</pre>` +
    `<div class="demo-dim" style="margin-top:8px">The server stores this record but cannot derive the fileKey from it.</div>` +
    `</div>`
  );

  add('spacer', '');
  add('action',
    `<button class="demo-btn" data-action="step4">Bob decrypts the file &rarr;</button>`
  );
}

function showStep4(): void {
  add('spacer', '');
  add('command',
    `<span class="demo-prompt">&gt;</span> <span class="demo-dim">Bob receives the share and decrypts:</span>`
  );
  add('spacer', '');

  add('result-box',
    `<div class="demo-blob">` +
    `<div class="demo-blob-header">Step 3: Bob Unwraps fileKey</div>` +
    `<div class="demo-blob-row"><span class="demo-label">input:</span> <span class="demo-cipher" style="color:#00838F">${truncHex(FILE_KEY_ECIES_BOB, 24)}</span></div>` +
    `<div class="demo-blob-row"><span class="demo-label">using:</span> <span class="demo-key" style="color:#00BCD4">Bob's privateKey</span> <span class="demo-dim">(${truncHex(BOB_PRIVATE_KEY, 10)})</span></div>` +
    `<div class="demo-blob-row"><span class="demo-label">output:</span> <span class="demo-key">${truncHex(FILE_KEY, 16)}</span> <span class="demo-dim">&larr; same fileKey!</span></div>` +
    `</div>`
  );

  add('spacer', '');

  add('result-box',
    `<div class="demo-decrypted">` +
    `<div class="demo-blob-header">Bob Decrypts the File</div>` +
    `<div class="demo-plaintext">${esc(FILE_PLAINTEXT)}</div>` +
    `<div class="demo-dim" style="margin-top:8px">` +
    `Same file, same CID on IPFS. Alice and Bob each have their own ECIES envelope ` +
    `wrapping the same symmetric fileKey. The server never saw the plaintext.` +
    `</div>` +
    `</div>`
  );

  add('spacer', '');
  add('info',
    `<span class="demo-dim">If Alice revokes Bob's access, she rotates the fileKey. ` +
    `Bob's old envelope becomes useless for future versions.</span>`
  );
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
