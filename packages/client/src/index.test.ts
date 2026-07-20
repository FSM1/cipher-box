import { describe, expect, it } from 'vitest';
import { CLIENT_PACKAGE } from './index.js';

describe('@cipherbox/client scaffold', () => {
  it('exports the package identifier', () => {
    expect(CLIENT_PACKAGE).toBe('@cipherbox/client');
  });
});
