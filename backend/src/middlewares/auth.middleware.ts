import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import prisma from '../config/prisma';

export interface JwtPayload {
  userId: number;
}

// Declare local Express namespace extension
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: number;
        email: string;
        name: string | null;
        isVerified: boolean;
      };
    }
  }
}

export const requireAuth = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        status: 'fail',
        message: 'Authentication required. Please provide a Bearer token.',
      });
      return;
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(
      token,
      process.env.JWT_ACCESS_SECRET || 'super_secret_access_key_123!'
    ) as JwtPayload;

    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      select: {
        id: true,
        email: true,
        name: true,
        isVerified: true,
      },
    });

    if (!user) {
      res.status(401).json({
        status: 'fail',
        message: 'User belonging to this token no longer exists.',
      });
      return;
    }

    req.user = user;
    next();
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      res.status(401).json({
        status: 'fail',
        message: 'Invalid or expired access token.',
      });
      return;
    }
    res.status(500).json({
      status: 'error',
      message: 'Internal server error during authentication.',
    });
  }
};
