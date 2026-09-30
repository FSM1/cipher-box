/**
 * The soak's view of a name on the public routing path: fetch the record from
 * `delegated-ipfs.dev` and read it with the engine's record read (ADR 0057 D1),
 * over a wasm-bindgen module built to disk with the `observer` feature of
 * `crates/wasm`.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  FetchRecordTransport,
  openIpnsRecordReader,
  type IpnsRecordReader,
  type IpnsRecordReading,
} from '@cipherbox/client';
import type { Env } from '../../tools/loginSecretExport';
import { SoakFailure } from './reasons';

const PUBLIC_ROUTING = 'https://delegated-ipfs.dev';

export const OBSERVER_DIR_ENV = 'SOAK_OBSERVER_WASM_DIR';

/** Where `pnpm --filter @cipherbox/client build:wasm-conformance` writes a module with the feature. */
const DEFAULT_OBSERVER_DIR = fileURLToPath(
  new URL('../../../../packages/client/test/browser/pkg', import.meta.url)
);

const POLL_MS = 15_000;

/** `MAX_RECORD_BYTES` in `crates/engine/src/net/fanout.rs`. */
const RECORD_LIMIT = 10 * 1024;

export function observerModule(env: Env): { glue: string; wasm: string } {
  const dir = env[OBSERVER_DIR_ENV]?.trim() || DEFAULT_OBSERVER_DIR;
  return { glue: join(dir, 'cipherbox_wasm.js'), wasm: join(dir, 'cipherbox_wasm_bg.wasm') };
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

/** A name cut to a short prefix: an error outside a {@link SoakFailure} reaches the public summary. */
export function namePrefix(ipnsName: string): string {
  return `${ipnsName.slice(0, 12)}...`;
}

/**
 * Resolves `ipnsName` until `accept` takes the verified reading or `timeoutMs`
 * passes, and returns the last reading. A routing answer propagates and the
 * endpoint can fail for a while, so both are asked again; a record the read
 * refuses fails at once. A poll that never got a record fails as
 * `routing-unavailable`.
 */
export async function resolveUntil(
  ipnsName: string,
  accept: (reading: IpnsRecordReading) => boolean,
  timeoutMs: number
): Promise<IpnsRecordReading> {
  const read = await observerReader();
  const transport = new FetchRecordTransport([PUBLIC_ROUTING]);
  const deadline = Date.now() + timeoutMs;
  let last: IpnsRecordReading | null = null;
  let miss = 'the endpoint served no record';
  for (;;) {
    let record: Uint8Array | null = null;
    try {
      const answer = await transport.getRecord(PUBLIC_ROUTING, ipnsName, RECORD_LIMIT);
      if (answer.kind === 'tooLarge') {
        miss = `the endpoint served ${answer.observed} bytes, above ${RECORD_LIMIT}`;
      } else {
        record = answer.record;
      }
    } catch (error) {
      miss = error instanceof Error ? error.message : String(error);
    }
    if (record !== null) {
      last = read(ipnsName, record);
      if (accept(last)) return last;
    }
    if (Date.now() + POLL_MS > deadline) {
      if (last !== null) return last;
      throw new SoakFailure(
        'routing-unavailable',
        `${PUBLIC_ROUTING} for ${namePrefix(ipnsName)}: ${miss}`
      );
    }
    await sleep(POLL_MS);
  }
}
