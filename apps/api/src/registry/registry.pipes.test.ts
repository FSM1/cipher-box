import { ArgumentMetadata, BadRequestException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import { MAX_BATCH, MAX_REGISTER_CONTENT_CIDS_TOTAL } from './dto/registry.dto';
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

  // Split into entries under the per-entry cap, so only the total can refuse it.
  const registerWithCids = (total: number) =>
    Array.from({ length: Math.ceil(total / 500) }, (_, entry) => ({
      ipnsName: `k51total${entry}`,
      contentCids: Array.from(
        { length: Math.min(500, total - entry * 500) },
        (_, i) => `bafy${entry}x${i}`
      ),
    }));

  it('register refuses a batch whose TOTAL contentCids exceed the cap, however it is split', async () => {
    expect(
      await refusal(registerBodyPipes, registerWithCids(MAX_REGISTER_CONTENT_CIDS_TOTAL + 1))
    ).toMatchObject({ code: REGISTRY_BATCH_REFUSED });
  });

  it('register accepts a batch at the total contentCids cap', async () => {
    const entries = registerWithCids(MAX_REGISTER_CONTENT_CIDS_TOTAL);
    expect(await transform(registerBodyPipes, entries)).toHaveLength(entries.length);
  });

  it('retire accepts a well-formed batch and answers the parsed entries', async () => {
    const accepted = await transform(retireBodyPipes, [
      { ipnsName: 'k51gate', targets: ['bafyGate'] },
    ]);
    expect(accepted).toEqual([{ ipnsName: 'k51gate', targets: ['bafyGate'] }]);
  });
});
