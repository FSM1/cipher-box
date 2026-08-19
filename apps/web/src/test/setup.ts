import { cleanup } from '@testing-library/react';
import { Buffer as BufferShim } from 'buffer';
import { afterEach } from 'vitest';

// The same shim `polyfills.ts` installs for the app. Node's own `Buffer` is a
// subclass of Node's `Uint8Array`, which jsdom's realm does not recognise as
// its own — so tkey's serializers fail an `instanceof` check here that passes
// in a browser.
globalThis.Buffer = BufferShim;

// Testing Library only self-registers cleanup when Vitest globals are on; this
// suite imports its APIs explicitly, so unmount between tests here.
afterEach(cleanup);
