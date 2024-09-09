import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { Request, Response, NextFunction } from 'express';
import errorHandler from './error';
import logger from './logger';
import { process } from 'ipaddr.js';

const tokenSchema = z.object({
  access_token: z.string().nonempty('Token is required'),
});

interface User {
  id: string;
  email: string;
}

interface AuthenticatedRequest extends Request {
  method: any;
  url: any;
  cookies(cookies: any): unknown;
  user?: User;
}

const verifyToken = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  logger.info(`Received request: ${req.method} ${req.url}`);

  const result = tokenSchema.safeParse(req.cookies);

  if (!result.success) {
    logger.warn(`Token validation failed: Access denied. No valid token provided.`);
    return next(errorHandler(401, "Access denied. No valid token provided"));
  }

  const { access_token: token } = result.data;

  try {
    if (!process.env.JWT_SECRET) {
      throw new Error('JWT secret is not defined');
    }

    const user = jwt.verify(token, process.env.JWT_SECRET) as User;

    req.user = user;
    logger.info(`Token verified successfully for user: ${user.id}`);
    next();
  } 
  catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      logger.warn('Token expired.');
      return next(errorHandler(403, 'Token expired.'));
    }
    logger.error('Error during token verification: Invalid token.');
    return next(errorHandler(403, 'Invalid token.'));
  }
};

export default verifyToken;
