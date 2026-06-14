import { execSync } from 'child_process';
import prisma from '../src/config/prisma';
import fs from 'fs';
import path from 'path';

beforeAll(async () => {
  // Sync the schema to the test SQLite database file
  // We use --accept-data-loss to automatically overwrite schema changes during testing
  execSync('npx prisma db push --accept-data-loss --skip-generate', { stdio: 'inherit' });
});

afterAll(async () => {
  // Disconnect the Prisma client connection pool
  await prisma.$disconnect();
});

beforeEach(async () => {
  // Clear the database records before each test to guarantee complete test isolation.
  // RefreshToken has a foreign key to User, so delete RefreshTokens first.
  await prisma.refreshToken.deleteMany({});
  await prisma.user.deleteMany({});
});
