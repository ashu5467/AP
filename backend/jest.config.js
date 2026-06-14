process.env.DATABASE_URL = "mysql://root:root@localhost:3306/ap_test";
process.env.NODE_ENV = "test";
process.env.JWT_ACCESS_SECRET = "test_access_secret_999";
process.env.JWT_REFRESH_SECRET = "test_refresh_secret_999";

module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  testMatch: ['<rootDir>/tests/**/*.test.ts'],
  testPathIgnorePatterns: ['/node_modules/', '/node_modules_old/'],
  verbose: true,
  forceExit: true,
  clearMocks: true,
  resetMocks: true,
  restoreMocks: true,
};
