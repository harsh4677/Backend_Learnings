import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { Request, Response, NextFunction } from 'express';
import errorHandler from './error';
import logger from './logger'; // Import the logger

// Zod schema to validate the token
const tokenSchema = z.object({
  access_token: z.string().nonempty('Token is required'),
});

// Interface for the decoded user payload
interface User {
  id: string;
  email: string;
}

const verifyToken = async (req: Request, res: Response, next: NextFunction) => {
  // Log the incoming request
  logger.info(`Received request: ${req.method} ${req.url}`);

  // Validate the token using Zod
  const result = tokenSchema.safeParse(req.cookies);

  if (!result.success) {
    const errorMessage = result.error.errors[0].message || 'Access denied. No token provided.';
    logger.warn(`Token validation failed: ${errorMessage}`);
    return next(errorHandler(401, errorMessage));
  }

  const { access_token: token } = result.data;

  try {
    // Verify the token and decode the user payload
    const user = await new Promise<User>((resolve, reject) => {
      jwt.verify(token, process.env.JWT_SECRET as string, (err, decoded) => {
        if (err) {
          logger.error(`Token verification failed: ${err.message}`);
          reject(err);
        } else {
          resolve(decoded as User);
        }
      });
    });

    req.user = user; // Attach user to request object
    logger.info(`Token verified successfully for user: ${user.id}`); // Log successful token verification
    next(); // Proceed to the next middleware
  } catch (err) {
    logger.error(`Error during token verification: ${err.message}`);
    return next(errorHandler(403, 'Invalid token.'));
  }
};

export default verifyToken;
