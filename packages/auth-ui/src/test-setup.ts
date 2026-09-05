import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

// Testing Library only self-registers cleanup when Vitest globals are on; this
// suite imports its APIs explicitly, so unmount between tests here.
afterEach(cleanup);
