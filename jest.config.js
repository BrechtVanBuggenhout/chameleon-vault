/** @type {import('ts-jest').JestConfigWithTsJest} */
export default {
  resolver: 'jest-ts-webcompat-resolver',
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@crypto/(.*)$': '<rootDir>/src/crypto/$1',
    '^@gcp/(.*)$': '<rootDir>/src/gcp/$1',
    '^@routes/(.*)$': '<rootDir>/src/routes/$1',
    '^@services/(.*)$': '<rootDir>/src/services/$1',
    '^@middleware/(.*)$': '<rootDir>/src/middleware/$1',
    '^@logging/(.*)$': '<rootDir>/src/logging/$1',
    '^@types/(.*)$': '<rootDir>/src/types/$1',
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      { useESM: true },
    ],
  },
  testPathIgnorePatterns: ['/node_modules/', '/dist/'],
  testMatch: ['<rootDir>/test/**/*.test.ts', '<rootDir>/src/**/*.test.ts'],
};