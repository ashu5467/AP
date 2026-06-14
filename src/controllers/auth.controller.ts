import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { Prisma } from '@prisma/client';
import prisma from '../config/prisma';

const getCookieOptions = () => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax' as const, // Lax works better for cross-origin local setups
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days matching refresh token duration
});

const generateAccessToken = (userId: number): string => {
  return jwt.sign(
    { userId },
    process.env.JWT_ACCESS_SECRET || 'super_secret_access_key_123!',
    { expiresIn: (process.env.JWT_ACCESS_EXPIRES_IN || '15m') as jwt.SignOptions['expiresIn'] }
  );
};

const generateRefreshToken = (userId: number, tokenId: number): string => {
  return jwt.sign(
    { userId, jti: tokenId },
    process.env.JWT_REFRESH_SECRET || 'super_secret_refresh_key_456!',
    { expiresIn: (process.env.JWT_REFRESH_EXPIRES_IN || '7d') as jwt.SignOptions['expiresIn'] }
  );
};

interface TokenPayload {
  userId: number;
  jti: number;
}

export const register = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password, name } = req.body;

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      res.status(400).json({ status: 'fail', message: 'Email already in use.' });
      return;
    }

    const saltRounds = process.env.NODE_ENV === 'production' ? 10 : 1;
    const passwordHash = await bcrypt.hash(password, saltRounds);
    const user = await prisma.user.create({
      data: {
        email,
        passwordHash,
        name,
      },
    });

    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    const refreshTokenRecord = await prisma.refreshToken.create({
      data: {
        token: crypto.randomUUID(), // Storing uuid as token identifier
        userId: user.id,
        expiresAt,
      },
    });

    const accessToken = generateAccessToken(user.id);
    const refreshToken = generateRefreshToken(user.id, refreshTokenRecord.id);

    res.cookie('refreshToken', refreshToken, getCookieOptions());

    res.status(201).json({
      status: 'success',
      data: {
        accessToken,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          isVerified: user.isVerified,
        },
      },
    });
  } catch (error: any) {
    console.error('Registration error:', error);
    if (error instanceof Prisma.PrismaClientKnownRequestError) {
      if (error.code === 'P2002') {
        res.status(400).json({ status: 'fail', message: 'Email already in use.' });
        return;
      }
    }
    res.status(500).json({ status: 'error', message: 'Internal server error during registration.' });
  }
};

export const login = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      res.status(400).json({ status: 'fail', message: 'Invalid email or password.' });
      return;
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      res.status(400).json({ status: 'fail', message: 'Invalid email or password.' });
      return;
    }

    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    const refreshTokenRecord = await prisma.refreshToken.create({
      data: {
        token: crypto.randomUUID(),
        userId: user.id,
        expiresAt,
      },
    });

    const accessToken = generateAccessToken(user.id);
    const refreshToken = generateRefreshToken(user.id, refreshTokenRecord.id);

    res.cookie('refreshToken', refreshToken, getCookieOptions());

    res.status(200).json({
      status: 'success',
      data: {
        accessToken,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          isVerified: user.isVerified,
        },
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ status: 'error', message: 'Internal server error during login.' });
  }
};

export const refresh = async (req: Request, res: Response): Promise<void> => {
  try {
    const tokenFromCookie = req.cookies.refreshToken;
    if (!tokenFromCookie) {
      res.status(401).json({ status: 'fail', message: 'Refresh token missing.' });
      return;
    }

    let decoded: TokenPayload;
    try {
      decoded = jwt.verify(
        tokenFromCookie,
        process.env.JWT_REFRESH_SECRET || 'super_secret_refresh_key_456!'
      ) as unknown as TokenPayload;
    } catch (err) {
      res.status(401).json({ status: 'fail', message: 'Invalid refresh token.' });
      return;
    }

    const dbToken = await prisma.refreshToken.findUnique({
      where: { id: decoded.jti },
    });

    // Reuse detection (token is revoked or doesn't exist)
    if (!dbToken || dbToken.revoked || dbToken.expiresAt < new Date()) {
      if (dbToken && dbToken.revoked) {
        // Token reuse! Revoke all tokens for the user as a safety measure.
        await prisma.refreshToken.updateMany({
          where: { userId: decoded.userId },
          data: { revoked: true },
        });
      }
      res.status(401).json({ status: 'fail', message: 'Invalid or expired refresh token.' });
      return;
    }

    // Revoke current token and issue new pair
    await prisma.refreshToken.update({
      where: { id: dbToken.id },
      data: { revoked: true },
    });

    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    const newRefreshTokenRecord = await prisma.refreshToken.create({
      data: {
        token: crypto.randomUUID(),
        userId: decoded.userId,
        expiresAt,
      },
    });

    const newAccessToken = generateAccessToken(decoded.userId);
    const newRefreshToken = generateRefreshToken(decoded.userId, newRefreshTokenRecord.id);

    res.cookie('refreshToken', newRefreshToken, getCookieOptions());

    res.status(200).json({
      status: 'success',
      data: {
        accessToken: newAccessToken,
      },
    });
  } catch (error) {
    console.error('Refresh token error:', error);
    res.status(500).json({ status: 'error', message: 'Internal server error during token refresh.' });
  }
};

export const logout = async (req: Request, res: Response): Promise<void> => {
  try {
    const tokenFromCookie = req.cookies.refreshToken;
    if (tokenFromCookie) {
      try {
        const decoded = jwt.verify(
          tokenFromCookie,
          process.env.JWT_REFRESH_SECRET || 'super_secret_refresh_key_456!'
        ) as unknown as TokenPayload;

        // Revoke token in DB
        await prisma.refreshToken.update({
          where: { id: decoded.jti },
          data: { revoked: true },
        });
      } catch (err) {
        // Ignore JWT verification issues on logout and clear cookie anyway
      }
    }

    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
    });

    res.status(200).json({ status: 'success', message: 'Successfully logged out.' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ status: 'error', message: 'Internal server error during logout.' });
  }
};

export const getMe = async (req: Request, res: Response): Promise<void> => {
  res.status(200).json({
    status: 'success',
    data: {
      user: req.user,
    },
  });
};

export const forgotPassword = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      // Return 200 for security (prevent email enumeration)
      res.status(200).json({
        status: 'success',
        message: 'If that email exists, we have sent a reset password link.',
      });
      return;
    }

    // Dynamic secret invalidates link if password is changed
    const secret = (process.env.JWT_ACCESS_SECRET || 'super_secret_access_key_123!') + user.passwordHash;
    const resetToken = jwt.sign({ userId: user.id }, secret, { expiresIn: '15m' });

    // In a real application, you would send an email. We log to console for development.
    const resetLink = `${process.env.CLIENT_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}&email=${encodeURIComponent(email)}`;
    console.log('\n======================================');
    console.log('RESET PASSWORD EMAIL (DEVELOPMENT LOG):');
    console.log(`To: ${email}`);
    console.log(`Reset link (expires in 15 mins): ${resetLink}`);
    console.log('======================================\n');

    res.status(200).json({
      status: 'success',
      message: 'If that email exists, we have sent a reset password link.',
    });
  } catch (error) {
    console.error('ForgotPassword error:', error);
    res.status(500).json({ status: 'error', message: 'Internal server error during password reset request.' });
  }
};

export const resetPassword = async (req: Request, res: Response): Promise<void> => {
  try {
    const { token, password } = req.body;

    // Decode token first without verifying signature to extract userId
    const decoded = jwt.decode(token) as { userId: number } | null;
    if (!decoded || !decoded.userId) {
      res.status(400).json({ status: 'fail', message: 'Invalid password reset token.' });
      return;
    }

    const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
    if (!user) {
      res.status(400).json({ status: 'fail', message: 'User not found.' });
      return;
    }

    // Verify token with dynamic secret
    const secret = (process.env.JWT_ACCESS_SECRET || 'super_secret_access_key_123!') + user.passwordHash;
    try {
      jwt.verify(token, secret);
    } catch (err) {
      res.status(400).json({ status: 'fail', message: 'Invalid or expired password reset token.' });
      return;
    }

    const saltRounds = process.env.NODE_ENV === 'production' ? 10 : 1;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Update password and revoke all active refresh tokens for the user (global logout)
    await prisma.$transaction([
      prisma.user.update({
        where: { id: user.id },
        data: { passwordHash },
      }),
      prisma.refreshToken.updateMany({
        where: { userId: user.id },
        data: { revoked: true },
      }),
    ]);

    res.status(200).json({
      status: 'success',
      message: 'Password has been reset successfully. Please log in with your new password.',
    });
  } catch (error) {
    console.error('ResetPassword error:', error);
    res.status(500).json({ status: 'error', message: 'Internal server error during password reset.' });
  }
};
