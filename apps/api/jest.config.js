/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  moduleFileExtensions: ['js', 'json', 'ts'],
  rootDir: 'src',
  testRegex: '.*\\.spec\\.ts$',
  transform: {
    '^.+\\.(t|j)s$': 'ts-jest',
  },
  collectCoverageFrom: ['**/*.(t|j)s'],
  coverageDirectory: '../coverage',
  testEnvironment: 'node',
  // Transform ESM modules like jose
  transformIgnorePatterns: ['/node_modules/(?!(jose)/)'],
  // Mock jose module for tests that don't directly test Web3AuthVerifierService
  moduleNameMapper: {
    '^jose$': '<rootDir>/../test/__mocks__/jose.ts',
  },
};
