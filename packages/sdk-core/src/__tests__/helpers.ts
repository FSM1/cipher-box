import { vi } from 'vitest';
import type { SdkContext } from '../types';

export function createMockContext(): SdkContext {
  return {
    apiUrl: 'http://localhost:3000',
    getAccessToken: vi.fn().mockResolvedValue('test-token'),
  };
}
