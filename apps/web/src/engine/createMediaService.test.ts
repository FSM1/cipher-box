import { describe, expect, it } from 'vitest';
import { serviceWorkerScript } from './createMediaService';

describe('serviceWorkerScript', () => {
  it('registers the transformed source entry as a module in dev', () => {
    expect(serviceWorkerScript({ DEV: true })).toEqual({ url: '/src/sw.ts', type: 'module' });
  });

  it('registers the built root script as a classic worker in a build', () => {
    expect(serviceWorkerScript({ DEV: false })).toEqual({ url: '/sw.js', type: 'classic' });
  });
});
