import { ArgumentMetadata, BadRequestException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { MAX_BATCH } from './dto/registry.dto';
import { REGISTRY_BATCH_REFUSED } from './registry-error-codes';
import { registerBodyPipes, retireBodyPipes } from './registry.pipes';

/**
 * The batch gates in isolation. `ParseArrayPipe` SPLITS a bare string on commas
 * and parses each piece as an entry, so a guard that lets a non-array through
 * would hand the service a batch of unbounded length. The gates fail closed on
 * their own, without relying on the body parser's strict-JSON setting.
 */

const BODY: ArgumentMetadata = { type: 'body' };

const transform = async (pipes: readonly unknown[], value: unknown): Promise<unknown> => {
  let carried = value;
  for (const pipe of pipes) {
    carried = await (pipe as { transform: (v: unknown, m: ArgumentMetadata) => unknown }).transform(
      carried,
      BODY
    );
  }
  return carried;
};

const refusal = async (pipes: readonly unknown[], value: unknown): Promise<unknown> => {
  try {
    await transform(pipes, value);
  } catch (error) {
    expect(error).toBeInstanceOf(BadRequestException);
    return (error as BadRequestException).getResponse();
  }
  throw new Error('the gate accepted the value');
};

describe('registry batch gates', () => {
  it.each([
    ['retire', retireBodyPipes],
    ['register', registerBodyPipes],
  ])(
    '%s refuses a bare string body rather than letting it split into entries',
    async (_, pipes) => {
      const smuggled = Array.from({ length: MAX_BATCH + 1 }, () => '{"targets":["bafySmuggled"]}');
      expect(await refusal(pipes, smuggled.join(','))).toMatchObject({
        code: REGISTRY_BATCH_REFUSED,
      });
    }
  );

  it.each([
    ['retire', retireBodyPipes],
    ['register', registerBodyPipes],
  ])('%s refuses a bare object body', async (_, pipes) => {
    expect(await refusal(pipes, { targets: ['bafyLone'] })).toMatchObject({
      code: REGISTRY_BATCH_REFUSED,
    });
  });

  it('retire refuses more entries than the batch cap', async () => {
    const entries = Array.from({ length: MAX_BATCH + 1 }, () => ({ targets: [] }));
    expect(await refusal(retireBodyPipes, entries)).toMatchObject({
      code: REGISTRY_BATCH_REFUSED,
    });
  });

  it('retire accepts a well-formed batch and answers the parsed entries', async () => {
    const accepted = await transform(retireBodyPipes, [
      { ipnsName: 'k51gate', targets: ['bafyGate'] },
    ]);
    expect(accepted).toEqual([{ ipnsName: 'k51gate', targets: ['bafyGate'] }]);
  });
});
