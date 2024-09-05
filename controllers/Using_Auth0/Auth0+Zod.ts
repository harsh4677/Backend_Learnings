import { auth } from "express-oauth2-jwt-bearer";
import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import User from "../models/user";
import logger from "../utils/logger"; // Optional logger import for error logging
import { z } from 'zod'; // Zod for validation

// Zod schema to validate the Authorization header
const tokenSchema = z.object({
  authorization: z.string().startsWith('Bearer ').nonempty('Authorization header is missing or empty')
});

declare global {
  namespace Express {
    interface Request {
      userId: string;
      auth0Id: string;
    }
  }
}

// Auth0 JWT Middleware for checking the token
export const jwtCheck = auth({
  audience: process.env.AUTH0_AUDIENCE,
  issuerBaseURL: process.env.AUTH0_ISSUER_BASE_URL,
  tokenSigningAlg: "RS256",
});

// Custom middleware to parse and verify JWT
export const jwtParse = async (req: Request, res: Response, next: NextFunction) => {
  const authorization = req.headers.authorization;

  // Validate the authorization header using Zod
  const validationResult = tokenSchema.safeParse({ authorization });

  if (!validationResult.success) {
    const errorMessage = validationResult.error.errors[0].message || 'Invalid Authorization header';
    logger?.warn(`Token validation failed: ${errorMessage}`);
    return res.status(401).send(errorMessage); // Return 401 if validation fails
  }

  // Extract token from "Bearer <token>"
  const token = authorization.split(" ")[1];

  try {
    const decoded = jwt.decode(token) as jwt.JwtPayload | null;

    // If decoding fails or token is invalid, return 401
    if (!decoded || !decoded.sub) {
      return res.sendStatus(401);
    }

    const auth0Id = decoded.sub;

    // Find user based on auth0Id
    const user = await User.findOne({ auth0Id });

    if (!user) {
      return res.sendStatus(401); // User not found, unauthorized
    }

    // Attach auth0Id and userId to the request object
    req.auth0Id = auth0Id;
    req.userId = user._id.toString();

    // Proceed to the next middleware
    next();
  } catch (error) {
    // Optional logging for errors
    logger?.error(`JWT Parsing error: ${error.message}`, { error });
    return res.sendStatus(401); // Token verification error
  }
};
