import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';

import { fromHex, openIpnsRecordReader, type IpnsRecordReader } from '../../src/index.js';
import { recordReaderOver } from '../../src/ipnsRecord.js';

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

const glueUrl = pathToFileURL(resolve(pkg, 'cipherbox_wasm.js'));

let read: IpnsRecordReader;

beforeAll(async () => {
  read = await openIpnsRecordReader(glueUrl, readFileSync(resolve(pkg, 'cipherbox_wasm_bg.wasm')));
});

describe('the observer feature', () => {
  it('puts the record read in the module built with it', async () => {
    const glue = (await import(glueUrl.href)) as Record<string, unknown>;

    expect(typeof glue.readIpnsRecord).toBe('function');
  });

  it('refuses a module with no record read by naming the feature', async () => {
    let instantiated = false;
    const production = {
      default: () => {
        instantiated = true;
        return Promise.resolve();
      },
    };

    await expect(recordReaderOver(production, new Uint8Array())).rejects.toThrow(
      'the WASM module exports no readIpnsRecord: it was built with no `observer` feature'
    );
    expect(instantiated).toBe(false);
  });
});

describe('the IPNS record read under Node', () => {
  it.each(kat<AcceptVector>('record_accept.json'))(
    'reads the sequence and validity of KAT $name',
    (vector) => {
      const reading = read(vector.ipnsName, fromHex(vector.record));

      expect(reading.sequence).toBe(BigInt(vector.sequence));
      expect(reading.validity).toBe(vector.validity);
      expect(reading.validUntil).toBe(BigInt(Date.parse(vector.validity.slice(0, 19) + 'Z')));
    }
  );

  it.each(kat<RejectVector>('record_reject.json'))('refuses KAT $name as $check', (vector) => {
    expect(() => read(vector.ipnsName, fromHex(vector.record))).toThrow(vector.check);
  });

  it('refuses a record read under a name whose key did not sign it', () => {
    const [signed, other] = kat<AcceptVector>('record_accept.json');

    expect(() => read(other.ipnsName, fromHex(signed.record))).toThrow('ipns-signature-invalid');
  });

  it('refuses a name that does not parse', () => {
    const [signed] = kat<AcceptVector>('record_accept.json');

    expect(() => read('bxyz', fromHex(signed.record))).toThrow('ipns-name-malformed');
  });
});
