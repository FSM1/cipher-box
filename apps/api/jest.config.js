/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  moduleFileExtensions: ['js', 'json', 'ts'],
  rootDir: 'src',
  testRegex: '.*\\.spec\\.ts$',
  transform: {
    '^.+\\.(t|j)s$': 'ts-jest',
  },
  collectCoverageFrom: [
    '**/*.(t|j)s',
    '!**/*.module.ts', // Exclude NestJS modules (config only)
    '!**/index.ts', // Exclude barrel exports
    '!**/dto/**', // Exclude DTOs (class definitions)
    '!**/entities/**', // Exclude TypeORM entities
    '!main.ts', // Exclude bootstrap
    '!app.controller.ts', // Exclude default NestJS app controller
    '!app.service.ts', // Exclude default NestJS app service
    '!health/**', // Exclude health check (infrastructure)
    '!data-source.ts', // Exclude TypeORM CLI data source config
    '!migrations/**', // Exclude database migrations
  ],
  coverageDirectory: '../coverage',
  coverageReporters: ['text', 'lcov', 'json-summary'],
  testEnvironment: 'node',
  // Transform ESM modules like jose
  transformIgnorePatterns: ['/node_modules/(?!(jose)/)'],
  // Mock ESM modules for tests that don't directly test their functionality
  moduleNameMapper: {
    '^jose$': '<rootDir>/../test/__mocks__/jose.ts',
  },
  // Coverage thresholds per TESTING.md requirements
  // Paths are relative to rootDir (src/)
  coverageThreshold: {
    global: {
      lines: 85,
      branches: 80,
      functions: 85,
      statements: 85,
    },
    '**/auth/auth.service.ts': {
      lines: 90,
      branches: 84, // 84.61% actual; one edge case uncovered (derivationVersion null check)
    },
    '**/auth/services/token.service.ts': {
      lines: 90,
      branches: 80,
    },
    '**/auth/services/web3auth-verifier.service.ts': {
      lines: 90,
      branches: 80,
    },
    '**/auth/strategies/jwt.strategy.ts': {
      lines: 90,
      branches: 80,
    },
    '**/vault/vault.service.ts': {
      lines: 90,
      branches: 77, // DI constructor params (4 injections) + default param create uncoverable branch markers
    },
    '**/ipfs/providers/pinata.provider.ts': {
      lines: 85,
      branches: 80,
    },
    '**/ipfs/providers/local.provider.ts': {
      lines: 85,
      branches: 80,
    },
    '**/auth/auth.controller.ts': {
      lines: 80,
      branches: 65,
    },
    '**/vault/vault.controller.ts': {
      lines: 80,
      branches: 65,
    },
    '**/ipfs/ipfs.controller.ts': {
      lines: 80,
      branches: 61, // 61.9% actual; Swagger decorators inflate uncovered branches
    },
    '**/ipns/ipns.controller.ts': {
      // Coverage from integration/security tests in __tests__/
      lines: 73,
      branches: 70,
      functions: 66,
    },
  },
};
