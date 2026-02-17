/// <reference lib="webworker" />
/**
 * Service Worker for transparent AES-CTR media decryption.
 *
 * Intercepts fetch requests to /decrypt-stream/* URLs, fetches encrypted
 * content from the API, decrypts with AES-CTR, and returns proper HTTP
 * responses (200/206). This makes encryption invisible to <video>/<audio>.
 */

// Cast self to ServiceWorkerGlobalScope (available with WebWorker lib)
const sw = self as unknown as ServiceWorkerGlobalScope;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type StreamContext = {
  fileKey: string; // hex-encoded AES-256 key
  iv: string; // hex-encoded 16-byte CTR IV
  cid: string; // IPFS CID of encrypted content
  totalSize: number; // Original file size in bytes
  mimeType: string; // MIME type for response
};

type RegisterStreamMessage = {
  type: 'register-stream';
  fileMetaIpnsName: string;
} & StreamContext;

type UnregisterStreamMessage = {
  type: 'unregister-stream';
  fileMetaIpnsName: string;
};

type UpdateTokenMessage = {
  type: 'update-token';
  token: string;
};

type SetApiBaseMessage = {
  type: 'set-api-base';
  url: string;
};

type SwMessage =
  | RegisterStreamMessage
  | UnregisterStreamMessage
  | UpdateTokenMessage
  | SetApiBaseMessage;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/** Active decrypt contexts keyed by fileMetaIpnsName */
const streamRegistry = new Map<string, StreamContext>();

/** In-memory cache of fetched encrypted files (full file per CID) */
const encryptedCache = new Map<string, Uint8Array>();

/** Auth token for API requests */
let authToken: string | null = null;

/** API base URL (e.g. http://localhost:3000) */
let apiBaseUrl = '';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Decrypt an arbitrary byte range from AES-CTR-encrypted data.
 *
 * Computes the block-aligned slice and counter offset, decrypts via
 * Web Crypto, and extracts the exact requested bytes.
 */
async function decryptRange(
  encrypted: Uint8Array,
  keyHex: string,
  ivHex: string,
  start: number,
  end: number
): Promise<Uint8Array> {
  const keyBytes = hexToBytes(keyHex);
  const ivBytes = hexToBytes(ivHex);

  const blockSize = 16;
  const startBlock = Math.floor(start / blockSize);

  // Build counter for the starting block
  const counter = new Uint8Array(16);
  counter.set(ivBytes.subarray(0, 8), 0); // 8-byte nonce
  const baseCounter = new DataView(
    ivBytes.buffer as ArrayBuffer,
    ivBytes.byteOffset,
    ivBytes.byteLength
  ).getBigUint64(8, false);
  const counterView = new DataView(
    counter.buffer as ArrayBuffer,
    counter.byteOffset,
    counter.byteLength
  );
  counterView.setBigUint64(8, baseCounter + BigInt(startBlock), false);

  // Import key
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes as BufferSource,
    { name: 'AES-CTR' },
    false,
    ['decrypt']
  );

  // Block-aligned range
  const blockAlignedStart = startBlock * blockSize;
  const blockAlignedEnd = Math.min((Math.floor(end / blockSize) + 1) * blockSize, encrypted.length);

  // Decrypt block-aligned slice
  const slice = encrypted.subarray(blockAlignedStart, blockAlignedEnd);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-CTR', counter: counter as BufferSource, length: 64 },
    cryptoKey,
    slice as BufferSource
  );

  // Extract exact requested bytes
  const offsetInFirstBlock = start - blockAlignedStart;
  const requestedLength = end - start + 1;
  return new Uint8Array(decrypted).subarray(
    offsetInFirstBlock,
    offsetInFirstBlock + requestedLength
  );
}

/**
 * Post a message to all controlled clients.
 */
async function postToClients(message: unknown): Promise<void> {
  const allClients = await sw.clients.matchAll({ type: 'window' });
  for (const client of allClients) {
    client.postMessage(message);
  }
}

// ---------------------------------------------------------------------------
// Message handler (main thread -> SW)
// ---------------------------------------------------------------------------

sw.addEventListener('message', (event) => {
  const data = event.data as SwMessage;

  switch (data.type) {
    case 'register-stream': {
      const { fileMetaIpnsName, fileKey, iv, cid, totalSize, mimeType } =
        data as RegisterStreamMessage;
      streamRegistry.set(fileMetaIpnsName, {
        fileKey,
        iv,
        cid,
        totalSize,
        mimeType,
      });
      break;
    }

    case 'unregister-stream': {
      const { fileMetaIpnsName } = data as UnregisterStreamMessage;
      streamRegistry.delete(fileMetaIpnsName);
      encryptedCache.delete(fileMetaIpnsName);
      break;
    }

    case 'update-token': {
      authToken = (data as UpdateTokenMessage).token;
      break;
    }

    case 'set-api-base': {
      apiBaseUrl = (data as SetApiBaseMessage).url;
      break;
    }
  }
});

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

sw.addEventListener('install', () => {
  void sw.skipWaiting();
});

sw.addEventListener('activate', (event) => {
  event.waitUntil(sw.clients.claim());
});

// ---------------------------------------------------------------------------
// Fetch handler
// ---------------------------------------------------------------------------

sw.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Only intercept /decrypt-stream/* URLs
  if (!url.pathname.startsWith('/decrypt-stream/')) return;

  const ipnsName = url.pathname.split('/decrypt-stream/')[1];
  if (!ipnsName) {
    event.respondWith(new Response('Not found', { status: 404 }));
    return;
  }

  const ctx = streamRegistry.get(ipnsName);
  if (!ctx) {
    event.respondWith(new Response('Not found', { status: 404 }));
    return;
  }

  event.respondWith(handleDecryptStream(event.request, ctx, ipnsName));
});

// ---------------------------------------------------------------------------
// Decrypt stream handler
// ---------------------------------------------------------------------------

async function handleDecryptStream(
  request: Request,
  ctx: StreamContext,
  cacheKey: string
): Promise<Response> {
  // 1. Get encrypted data (from cache or fetch)
  let encrypted = encryptedCache.get(cacheKey);

  if (!encrypted) {
    const fetchUrl = `${apiBaseUrl}/ipfs/${ctx.cid}`;
    const fetchHeaders: Record<string, string> = {};
    if (authToken) {
      fetchHeaders['Authorization'] = `Bearer ${authToken}`;
    }

    let response: Response;
    try {
      response = await fetch(fetchUrl, { headers: fetchHeaders });
    } catch {
      return new Response('Failed to fetch encrypted content', { status: 502 });
    }

    if (response.status === 401) {
      // Request token refresh from main thread
      await postToClients({ type: 'token-expired' });
      return new Response('Unauthorized', { status: 401 });
    }

    if (!response.ok) {
      return new Response('Failed to fetch encrypted content', {
        status: response.status,
      });
    }

    encrypted = new Uint8Array(await response.arrayBuffer());
    encryptedCache.set(cacheKey, encrypted);
  }

  // 2. Parse Range header
  const rangeHeader = request.headers.get('Range');
  let start = 0;
  let end = ctx.totalSize - 1;
  let isRangeRequest = false;

  if (rangeHeader) {
    const match = rangeHeader.match(/bytes=(\d+)-(\d*)/);
    if (match) {
      isRangeRequest = true;
      start = parseInt(match[1], 10);
      end = match[2] ? parseInt(match[2], 10) : ctx.totalSize - 1;

      // Clamp to valid range
      if (end >= ctx.totalSize) end = ctx.totalSize - 1;
      if (start > end) {
        return new Response('Range Not Satisfiable', {
          status: 416,
          headers: {
            'Content-Range': `bytes */${ctx.totalSize}`,
          },
        });
      }
    }
  }

  // 3. Decrypt the requested range
  let decrypted: Uint8Array;
  try {
    decrypted = await decryptRange(encrypted, ctx.fileKey, ctx.iv, start, end);
  } catch {
    return new Response('Decryption failed', { status: 500 });
  }

  // 4. Build response
  const headers: Record<string, string> = {
    'Content-Type': ctx.mimeType,
    'Content-Length': String(decrypted.byteLength),
    'Accept-Ranges': 'bytes',
  };

  // Slice to exact ArrayBuffer for Response body (TS 5.9 Uint8Array<ArrayBufferLike> compat)
  const body = (decrypted.buffer as ArrayBuffer).slice(
    decrypted.byteOffset,
    decrypted.byteOffset + decrypted.byteLength
  );

  if (isRangeRequest) {
    headers['Content-Range'] = `bytes ${start}-${end}/${ctx.totalSize}`;
    return new Response(body, { status: 206, headers });
  }

  return new Response(body, { status: 200, headers });
}
