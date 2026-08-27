import { UnauthorizedException } from '@nestjs/common';
import { beforeEach, describe, expect, it } from 'vitest';
import { FakeClock, FakeEntropy, fakeConfig } from '../../testing/fakes';
import {
  ChallengeService,
  IDENTITY_CHALLENGE_PREFIXES,
  type IdentityChallengeKind,
  type SiweChallengeKind,
} from './challenge.service';

const PUBLIC_KEY = '02'.padEnd(66, 'a');
const OTHER_KEY = '03'.padEnd(66, 'b');

const IDENTITY_KINDS: readonly IdentityChallengeKind[] = [
  'identity-login',
  'identity-link',
  'identity-unlink',
];
const SIWE_KINDS: readonly SiweChallengeKind[] = ['siwe-login', 'siwe-link'];

/** Every ordered pair of distinct kinds inside one family. */
function crossPairs<T>(kinds: readonly T[]): Array<[T, T]> {
  return kinds.flatMap((minted) =>
    kinds.filter((spent) => spent !== minted).map((spent): [T, T] => [minted, spent])
  );
}

describe('ChallengeService', () => {
  let clock: FakeClock;
  let service: ChallengeService;

  beforeEach(() => {
    clock = new FakeClock();
    service = new ChallengeService(clock, new FakeEntropy(), fakeConfig({}).service);
  });

  it('issues identity challenges with the operation prefix and a TTL', () => {
    for (const kind of IDENTITY_KINDS) {
      const { challenge, expiresAt } = service.issueIdentityChallenge(kind, {
        publicKey: PUBLIC_KEY,
      });
      expect(challenge.startsWith(IDENTITY_CHALLENGE_PREFIXES[kind])).toBe(true);
      expect(expiresAt.getTime()).toBe(clock.now().getTime() + 300_000);
    }
  });

  // The engine pins this exact shape before it will sign a challenge, and
  // refuses anything else. Narrowing the tail here fails every login, so the
  // contract is pinned on both sides rather than only in Rust.
  it('issues a tail the engine will sign: 32 bytes of lowercase hex', () => {
    for (const kind of IDENTITY_KINDS) {
      const { challenge } = service.issueIdentityChallenge(kind, { publicKey: PUBLIC_KEY });
      expect(challenge).toMatch(new RegExp(`^${IDENTITY_CHALLENGE_PREFIXES[kind]}[0-9a-f]{64}$`));
    }
  });

  it('gives every identity operation a distinct domain tag', () => {
    const tags = Object.values(IDENTITY_CHALLENGE_PREFIXES);
    expect(new Set(tags).size).toBe(tags.length);
  });

  it('consumes a live challenge exactly once', () => {
    const { challenge } = service.issueIdentityChallenge('identity-login', {
      publicKey: PUBLIC_KEY,
    });
    service.consume(challenge, 'identity-login', { publicKey: PUBLIC_KEY });
    expect(() => service.consume(challenge, 'identity-login', { publicKey: PUBLIC_KEY })).toThrow(
      UnauthorizedException
    );
  });

  it('rejects an expired challenge', () => {
    const { challenge } = service.issueIdentityChallenge('identity-login', {
      publicKey: PUBLIC_KEY,
    });
    clock.advanceMs(300_001);
    expect(() => service.consume(challenge, 'identity-login', { publicKey: PUBLIC_KEY })).toThrow(
      UnauthorizedException
    );
  });

  it('rejects a challenge bound to a different publicKey', () => {
    const { challenge } = service.issueIdentityChallenge('identity-login', {
      publicKey: PUBLIC_KEY,
    });
    expect(() => service.consume(challenge, 'identity-login', { publicKey: OTHER_KEY })).toThrow(
      UnauthorizedException
    );
  });

  // The pools are disjoint per operation, not per protocol, so possession of a
  // live challenge authorises exactly one thing.
  it.each(crossPairs(IDENTITY_KINDS))('refuses a %s challenge spent as %s', (minted, spent) => {
    const { challenge } = service.issueIdentityChallenge(minted, { publicKey: PUBLIC_KEY });
    expect(() => service.consume(challenge, spent, { publicKey: PUBLIC_KEY })).toThrow(
      UnauthorizedException
    );
    // The refusal did not burn it: the operation it was minted for still works.
    expect(() => service.consume(challenge, minted, { publicKey: PUBLIC_KEY })).not.toThrow();
  });

  it.each(crossPairs(SIWE_KINDS))('refuses a %s nonce spent as %s', (minted, spent) => {
    const { nonce } = service.issueSiweNonce(minted);
    expect(() => service.consume(nonce, spent)).toThrow(UnauthorizedException);
    expect(() => service.consume(nonce, minted)).not.toThrow();
  });

  it('rejects kind confusion between identity challenges and SIWE nonces', () => {
    const { nonce } = service.issueSiweNonce('siwe-login');
    expect(() => service.consume(nonce, 'identity-login', { publicKey: PUBLIC_KEY })).toThrow(
      UnauthorizedException
    );
    const { challenge } = service.issueIdentityChallenge('identity-login', {
      publicKey: PUBLIC_KEY,
    });
    expect(() => service.consume(challenge, 'siwe-login')).toThrow(UnauthorizedException);
  });

  // The engine hard-rejects a nonce outside this class, because the nonce lands
  // verbatim in the text a wallet signs. Pinned here, at the producer, so a
  // change of alphabet fails a unit gate rather than every wallet login.
  it('issues a nonce inside the EIP-4361 class the engine enforces', () => {
    for (const kind of SIWE_KINDS) {
      expect(service.issueSiweNonce(kind).nonce).toMatch(/^[A-Za-z0-9]{8,128}$/);
    }
  });

  it('rejects unknown challenges', () => {
    expect(() =>
      service.consume('never-issued', 'identity-login', { publicKey: PUBLIC_KEY })
    ).toThrow(UnauthorizedException);
  });
});
