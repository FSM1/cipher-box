/**
 * The soak's view of a name on the public routing path: fetch the record from
 * `delegated-ipfs.dev` and read it with the engine's record read (ADR 0057 D1),
 * over a wasm-bindgen module built to disk with the `observer` feature of
 * `crates/wasm`.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  openIpnsRecordReader,
  type IpnsRecordReader,
  type IpnsRecordReading,
} from '@cipherbox/client';
import type { Env } from '../../tools/loginSecretExport';

export const PUBLIC_ROUTING = 'https://delegated-ipfs.dev';

const IPNS_RECORD = 'application/vnd.ipfs.ipns-record';

export const OBSERVER_DIR_ENV = 'SOAK_OBSERVER_WASM_DIR';

/** Where `pnpm --filter @cipherbox/client build:wasm-conformance` writes a module with the feature. */
const DEFAULT_OBSERVER_DIR = fileURLToPath(
  new URL('../../../../packages/client/test/browser/pkg', import.meta.url)
);

const POLL_MS = 15_000;

export function observerModule(env: Env): { glue: string; wasm: string } {
  const dir = env[OBSERVER_DIR_ENV]?.trim() || DEFAULT_OBSERVER_DIR;
  return { glue: join(dir, 'cipherbox_wasm.js'), wasm: join(dir, 'cipherbox_wasm_bg.wasm') };
}

export function recordUrl(ipnsName: string): string {
  return `${PUBLIC_ROUTING}/routing/v1/ipns/${encodeURIComponent(ipnsName)}`;
}

/** The module is large, so a worker process instantiates it once. */
let reader: Promise<IpnsRecordReader> | undefined;

function observerReader(): Promise<IpnsRecordReader> {
  if (reader === undefined) {
    const { glue, wasm } = observerModule(process.env);
    reader = openIpnsRecordReader(pathToFileURL(glue), readFileSync(wasm));
  }
  return reader;
}

/** The record the public path serves for `ipnsName`, or `null` where it serves none. */
async function fetchRecord(ipnsName: string): Promise<Uint8Array | null> {
  const response = await fetch(recordUrl(ipnsName), {
    headers: { Accept: IPNS_RECORD },
    signal: AbortSignal.timeout(30_000),
  });
  if (response.status === 404) {
    await response.body?.cancel();
    return null;
  }
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error(`${PUBLIC_ROUTING} answered ${response.status} for ${ipnsName}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

/**
 * Resolves `ipnsName` until `accept` takes the verified reading or `timeoutMs`
 * passes, and returns the last reading, `null` where the path served none. A
 * routing answer propagates and the endpoint can fail for a while, so both are
 * asked again; a record the read refuses fails at once.
 */
export async function resolveUntil(
  ipnsName: string,
  accept: (reading: IpnsRecordReading) => boolean,
  timeoutMs: number
): Promise<IpnsRecordReading | null> {
  const read = await observerReader();
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    let record: Uint8Array | null = null;
    let failure: unknown = null;
    try {
      record = await fetchRecord(ipnsName);
    } catch (error) {
      failure = error;
    }
    const reading = record === null ? null : read(ipnsName, record);
    if (reading !== null && accept(reading)) return reading;
    if (Date.now() + POLL_MS > deadline) {
      if (failure !== null) throw failure;
      return reading;
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_MS));
  }
}
