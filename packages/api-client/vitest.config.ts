import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    passWithNoTests: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      reportsDirectory: './coverage',
      include: ['src/**/*.ts'],
      exclude: [
        'src/**/*.spec.ts',
        'src/**/*.test.ts',
        'src/**/index.ts',
        'src/generated/**',
        'src/models/**',
      ],
      thresholds: {
        lines: 0,
        branches: 0,
        functions: 0,
        statements: 0,
      },
    },
  },
});
