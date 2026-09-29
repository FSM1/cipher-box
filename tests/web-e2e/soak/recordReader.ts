import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

import { openIpnsRecordReader, type IpnsRecordReader } from '@cipherbox/client';

/** The engine's IPNS record read, over a wasm-bindgen module built to disk. */
export function recordReaderFrom(gluePath: string, wasmPath: string): Promise<IpnsRecordReader> {
  return openIpnsRecordReader(pathToFileURL(gluePath), readFileSync(wasmPath));
}
