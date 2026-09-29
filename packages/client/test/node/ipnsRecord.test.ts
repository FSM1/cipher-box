import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';

import { openIpnsRecordReader, type IpnsRecordReader } from '../../src/index.js';

const here = import.meta.dirname;
const pkg = resolve(here, '../browser/pkg');
const vectors = resolve(here, '../../../../crates/core/kat/vectors/ipns');

interface AcceptVector {
  name: string;
  ipnsName: string;
  sequence: number;
  validity: string;
  record: string;
}

interface RejectVector {
  name: string;
  ipnsName: string;
  record: string;
  check: string;
}

function kat<T>(file: string): T[] {
  return JSON.parse(readFileSync(resolve(vectors, file), 'utf8')) as T[];
}

function bytes(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

let read: IpnsRecordReader;

beforeAll(async () => {
  read = await openIpnsRecordReader(
    pathToFileURL(resolve(pkg, 'cipherbox_wasm.js')),
    readFileSync(resolve(pkg, 'cipherbox_wasm_bg.wasm'))
  );
});

describe('the IPNS record read under Node', () => {
  it.each(kat<AcceptVector>('record_accept.json'))(
    'reads the sequence and validity of KAT $name',
    (vector) => {
      const reading = read(vector.ipnsName, bytes(vector.record));

      expect(reading.sequence).toBe(BigInt(vector.sequence));
      expect(reading.validity).toBe(vector.validity);
      expect(reading.validUntil).toBe(BigInt(Date.parse(vector.validity.slice(0, 19) + 'Z')));
    }
  );

  it.each(kat<RejectVector>('record_reject.json'))('refuses KAT $name as $check', (vector) => {
    expect(() => read(vector.ipnsName, bytes(vector.record))).toThrow(vector.check);
  });

  it('refuses a record read under a name whose key did not sign it', () => {
    const [signed, other] = kat<AcceptVector>('record_accept.json');

    expect(() => read(other.ipnsName, bytes(signed.record))).toThrow('ipns-signature-invalid');
  });

  it('refuses a name that does not parse', () => {
    const [signed] = kat<AcceptVector>('record_accept.json');

    expect(() => read('bxyz', bytes(signed.record))).toThrow('ipns-name-malformed');
  });
});
