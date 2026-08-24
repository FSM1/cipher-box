import { describe, expect, it } from 'vitest';
import { MinimalIpnsSequenceReader } from '../republisher/record-sequence-reader';
import { minimalIpnsRecord } from './ipns-record';

describe('minimalIpnsRecord', () => {
  const reader = new MinimalIpnsSequenceReader();

  it.each([0n, 1n, 127n, 128n, (1n << 64n) - 1n])(
    'round-trips sequence %s through the reader the republisher uses',
    (sequence) => {
      expect(reader.read(minimalIpnsRecord(sequence))).toBe(sequence);
    }
  );

  it.each([-1n, -128n, 1n << 64n])('refuses sequence %s as out of uint64 range', (sequence) => {
    expect(() => minimalIpnsRecord(sequence)).toThrow(RangeError);
  });
});
