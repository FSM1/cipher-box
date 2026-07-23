import { describe, expect, it } from 'vitest';
import { isDisabled } from './env-flag';

describe('isDisabled (default-on env-flag opt-out parse)', () => {
  it('treats every explicit falsey token as disabled, case-insensitively', () => {
    for (const raw of ['false', 'False', 'FALSE', '0', 'no', 'NO', 'off', 'OFF', ' false ']) {
      expect(isDisabled(raw)).toBe(true);
    }
  });

  it('stays enabled for unset or any non-falsey value', () => {
    for (const raw of [undefined, '', 'true', 'True', '1', 'yes', 'on', 'enabled', 'random']) {
      expect(isDisabled(raw)).toBe(false);
    }
  });
});
