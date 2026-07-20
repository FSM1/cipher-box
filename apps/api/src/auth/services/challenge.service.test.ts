import { UnauthorizedException } from '@nestjs/common';
import { beforeEach, describe, expect, it } from 'vitest';
import { FakeClock, FakeEntropy, fakeConfig } from '../../testing/fakes';
import { ChallengeService, IDENTITY_CHALLENGE_PREFIX } from './challenge.service';

const PUBLIC_KEY = '02'.padEnd(66, 'a');
const OTHER_KEY = '03'.padEnd(66, 'b');

describe('ChallengeService', () => {
  let clock: FakeClock;
  let service: ChallengeService;

  beforeEach(() => {
    clock = new FakeClock();
    service = new ChallengeService(clock, new FakeEntropy(), fakeConfig({}).service);
  });

  it('issues identity challenges with the v2 prefix and a TTL', () => {
    const { challenge, expiresAt } = service.issueIdentityChallenge(PUBLIC_KEY);
    expect(challenge.startsWith(IDENTITY_CHALLENGE_PREFIX)).toBe(true);
    expect(expiresAt.getTime()).toBe(clock.now().getTime() + 300_000);
  });

  it('consumes a live challenge exactly once', () => {
    const { challenge } = service.issueIdentityChallenge(PUBLIC_KEY);
    service.consume(challenge, 'identity', PUBLIC_KEY);
    expect(() => service.consume(challenge, 'identity', PUBLIC_KEY)).toThrow(UnauthorizedException);
  });

  it('rejects an expired challenge', () => {
    const { challenge } = service.issueIdentityChallenge(PUBLIC_KEY);
    clock.advanceMs(300_001);
    expect(() => service.consume(challenge, 'identity', PUBLIC_KEY)).toThrow(UnauthorizedException);
  });

  it('rejects a challenge bound to a different publicKey', () => {
    const { challenge } = service.issueIdentityChallenge(PUBLIC_KEY);
    expect(() => service.consume(challenge, 'identity', OTHER_KEY)).toThrow(UnauthorizedException);
  });

  it('rejects kind confusion between identity challenges and SIWE nonces', () => {
    const { nonce } = service.issueSiweNonce();
    expect(() => service.consume(nonce, 'identity', PUBLIC_KEY)).toThrow(UnauthorizedException);
    const { challenge } = service.issueIdentityChallenge(PUBLIC_KEY);
    expect(() => service.consume(challenge, 'siwe')).toThrow(UnauthorizedException);
  });

  it('rejects unknown challenges', () => {
    expect(() => service.consume('never-issued', 'identity', PUBLIC_KEY)).toThrow(
      UnauthorizedException
    );
  });
});
