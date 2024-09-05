import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { Request, Response, NextFunction } from 'express';
import errorHandler from './error';
import { process } from 'ipaddr.js';

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
  // Validate the token using Zod
  const result = tokenSchema.safeParse(req.cookies);

  if (!result.success) {
    return next(errorHandler(401, result.error.errors[0].message || 'Access denied. No token provided.'));
  }

  const { access_token: token } = result.data;

  try {
    // Verify the token and decode the user payload
    const user = await new Promise<User>((resolve, reject) => {
      jwt.verify(token, process.env.JWT_SECRET as string, (err, decoded) => {
        if (err) {
          reject(err);
        } else {
          resolve(decoded as User);
        }
      });
    });

    req.user = user; // Attach user to request object
    next(); // Proceed to the next middleware
  } catch (err) {
    return next(errorHandler(403, 'Invalid token.'));
  }
};

export default verifyToken;
