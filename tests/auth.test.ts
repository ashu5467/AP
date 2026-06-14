import request from 'supertest';
import app from '../src/index';
import prisma from '../src/config/prisma';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const testUser = {
  email: 'test@example.com',
  password: 'Password123!',
  name: 'Test User',
};

describe('Authentication API Integration Tests', () => {

  describe('POST /api/auth/register', () => {
    it('should register a new user successfully and return tokens', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send(testUser);

      expect(res.status).toBe(201);
      expect(res.body).toHaveProperty('status', 'success');
      expect(res.body.data).toHaveProperty('accessToken');
      expect(res.body.data.user).toEqual({
        id: expect.any(Number),
        email: testUser.email,
        name: testUser.name,
        isVerified: false,
      });

      // Verify cookie is set
      const cookies = res.headers['set-cookie'];
      expect(cookies).toBeDefined();
      expect(cookies[0]).toContain('refreshToken=');

      // Verify user in database
      const dbUser = await prisma.user.findUnique({ where: { email: testUser.email } });
      expect(dbUser).not.toBeNull();
      expect(dbUser?.name).toBe(testUser.name);
    });

    it('should fail registration with invalid input types', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          email: 'not-an-email',
          password: '123', // less than 6 chars
        });

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('status', 'fail');
    });

    it('should handle duplicate email registration gracefully', async () => {
      // Create a user first
      const hashedPassword = await bcrypt.hash(testUser.password, 10);
      await prisma.user.create({
        data: {
          email: testUser.email,
          passwordHash: hashedPassword,
          name: testUser.name,
        },
      });

      // Attempt to register again
      const res = await request(app)
        .post('/api/auth/register')
        .send(testUser);

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('status', 'fail');
      expect(res.body.message).toContain('Email already in use');
    });
  });

  describe('POST /api/auth/login', () => {
    beforeEach(async () => {
      // Pre-register user
      const hashedPassword = await bcrypt.hash(testUser.password, 10);
      await prisma.user.create({
        data: {
          email: testUser.email,
          passwordHash: hashedPassword,
          name: testUser.name,
        },
      });
    });

    it('should log in successfully with valid credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: testUser.email,
          password: testUser.password,
        });

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('status', 'success');
      expect(res.body.data).toHaveProperty('accessToken');
      
      const cookies = res.headers['set-cookie'];
      expect(cookies).toBeDefined();
      expect(cookies[0]).toContain('refreshToken=');
    });

    it('should fail login with wrong password', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: testUser.email,
          password: 'wrongpassword',
        });

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('status', 'fail');
      expect(res.body.message).toContain('Invalid email or password');
    });

    it('should fail login with non-existent email', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'wrong@example.com',
          password: testUser.password,
        });

      expect(res.status).toBe(400);
      expect(res.body).toHaveProperty('status', 'fail');
    });
  });

  describe('GET /api/auth/me', () => {
    let accessToken: string;
    let userId: number;

    beforeEach(async () => {
      const hashedPassword = await bcrypt.hash(testUser.password, 10);
      const user = await prisma.user.create({
        data: {
          email: testUser.email,
          passwordHash: hashedPassword,
          name: testUser.name,
        },
      });
      userId = user.id;
      accessToken = jwt.sign(
        { userId: user.id },
        process.env.JWT_ACCESS_SECRET || 'test_access_secret_999',
        { expiresIn: '15m' }
      );
    });

    it('should fetch current user profile successfully', async () => {
      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${accessToken}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveProperty('status', 'success');
      expect(res.body.data.user).toEqual({
        id: userId,
        email: testUser.email,
        name: testUser.name,
        isVerified: false,
      });
    });

    it('should return 401 when authorization header is missing', async () => {
      const res = await request(app).get('/api/auth/me');
      expect(res.status).toBe(401);
      expect(res.body.message).toContain('Authentication required');
    });

    it('should return 401 with an invalid/expired token', async () => {
      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', 'Bearer invalidtoken');
      expect(res.status).toBe(401);
      expect(res.body.message).toContain('Invalid or expired access token');
    });
  });

  describe('POST /api/auth/logout', () => {
    let accessToken: string;
    let refreshToken: string;
    let dbTokenId: number;

    beforeEach(async () => {
      const hashedPassword = await bcrypt.hash(testUser.password, 10);
      const user = await prisma.user.create({
        data: {
          email: testUser.email,
          passwordHash: hashedPassword,
          name: testUser.name,
        },
      });

      const tokenString = 'test-token-id-123';
      const createdToken = await prisma.refreshToken.create({
        data: {
          token: tokenString,
          userId: user.id,
          expiresAt: new Date(Date.now() + 1000000),
        },
      });
      dbTokenId = createdToken.id;

      accessToken = jwt.sign(
        { userId: user.id },
        process.env.JWT_ACCESS_SECRET || 'test_access_secret_999',
        { expiresIn: '15m' }
      );

      refreshToken = jwt.sign(
        { userId: user.id, jti: dbTokenId },
        process.env.JWT_REFRESH_SECRET || 'test_refresh_secret_999',
        { expiresIn: '7d' }
      );
    });

    it('should log out successfully, revoke token, and clear cookies', async () => {
      const res = await request(app)
        .post('/api/auth/logout')
        .set('Authorization', `Bearer ${accessToken}`)
        .set('Cookie', [`refreshToken=${refreshToken}`]);

      expect(res.status).toBe(200);
      expect(res.body.message).toContain('Successfully logged out');

      // Assert database token is revoked
      const dbToken = await prisma.refreshToken.findUnique({ where: { id: dbTokenId } });
      expect(dbToken?.revoked).toBe(true);

      // Assert cookie is cleared
      const cookies = res.headers['set-cookie'];
      expect(cookies[0]).toContain('refreshToken=;');
    });
  });

  describe('POST /api/auth/refresh', () => {
    let user: any;
    let refreshToken: string;
    let tokenId: number;

    beforeEach(async () => {
      const hashedPassword = await bcrypt.hash(testUser.password, 10);
      user = await prisma.user.create({
        data: {
          email: testUser.email,
          passwordHash: hashedPassword,
          name: testUser.name,
        },
      });

      const tokenString = 'refresh-token-id';
      const createdToken = await prisma.refreshToken.create({
        data: {
          token: tokenString,
          userId: user.id,
          expiresAt: new Date(Date.now() + 1000 * 60 * 60), // 1 hour expiry
        },
      });
      tokenId = createdToken.id;

      refreshToken = jwt.sign(
        { userId: user.id, jti: tokenId },
        process.env.JWT_REFRESH_SECRET || 'test_refresh_secret_999',
        { expiresIn: '7d' }
      );
    });

    it('should issue a new token pair successfully', async () => {
      const res = await request(app)
        .post('/api/auth/refresh')
        .set('Cookie', [`refreshToken=${refreshToken}`]);

      expect(res.status).toBe(200);
      expect(res.body.data).toHaveProperty('accessToken');
      
      const newCookies = res.headers['set-cookie'];
      expect(newCookies).toBeDefined();
      expect(newCookies[0]).toContain('refreshToken=');

      // Verify old token is revoked
      const oldToken = await prisma.refreshToken.findUnique({ where: { id: tokenId } });
      expect(oldToken?.revoked).toBe(true);
    });

    it('should return 401 when cookie is missing', async () => {
      const res = await request(app).post('/api/auth/refresh');
      expect(res.status).toBe(401);
      expect(res.body.message).toContain('Refresh token missing');
    });

    it('should return 401 when token is revoked', async () => {
      // Revoke it manually
      await prisma.refreshToken.update({
        where: { id: tokenId },
        data: { revoked: true },
      });

      const res = await request(app)
        .post('/api/auth/refresh')
        .set('Cookie', [`refreshToken=${refreshToken}`]);

      expect(res.status).toBe(401);
      expect(res.body.message).toContain('Invalid or expired refresh token');
    });
  });

  describe('Password Reset Flow', () => {
    let user: any;

    beforeEach(async () => {
      const hashedPassword = await bcrypt.hash(testUser.password, 10);
      user = await prisma.user.create({
        data: {
          email: testUser.email,
          passwordHash: hashedPassword,
          name: testUser.name,
        },
      });
    });

    it('should generate forgot password reset link', async () => {
      const res = await request(app)
        .post('/api/auth/forgot-password')
        .send({ email: testUser.email });

      expect(res.status).toBe(200);
      expect(res.body.message).toContain('If that email exists, we have sent a reset password link');
    });

    it('should reset password successfully using a valid reset token', async () => {
      // Generate token using the secret style in controllers: JWT_SECRET + current passwordHash
      const secret = (process.env.JWT_ACCESS_SECRET || 'test_access_secret_999') + user.passwordHash;
      const resetToken = jwt.sign({ userId: user.id }, secret, { expiresIn: '15m' });

      const res = await request(app)
        .post('/api/auth/reset-password')
        .send({
          token: resetToken,
          password: 'NewPassword123!',
        });

      expect(res.status).toBe(200);
      expect(res.body.message).toContain('Password has been reset successfully');

      // Verify password changed in DB
      const updatedUser = await prisma.user.findUnique({ where: { id: user.id } });
      const isMatch = await bcrypt.compare('NewPassword123!', updatedUser!.passwordHash);
      expect(isMatch).toBe(true);
    });

    it('should fail resetting password with an invalid token', async () => {
      const res = await request(app)
        .post('/api/auth/reset-password')
        .send({
          token: 'invalidresettoken',
          password: 'NewPassword123!',
        });

      expect(res.status).toBe(400);
      expect(res.body.message).toContain('Invalid password reset token');
    });
  });
});
