import { auth } from "express-oauth2-jwt-bearer";
import jwt from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";
import User from "../models/user";
import logger from "../utils/logger"; 
import { z } from 'zod'; 

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

export const jwtCheck = auth({
  audience: process.env.AUTH0_AUDIENCE,
  issuerBaseURL: process.env.AUTH0_ISSUER_BASE_URL,
  tokenSigningAlg: "RS256",
});

export const jwtParse = async (req: Request, res: Response, next: NextFunction) => {
  const authorization = req.headers.authorization;

  const validationResult = tokenSchema.safeParse({ authorization });

  if (!validationResult.success) {
    const errorMessage = validationResult.error.errors[0].message || 'Invalid Authorization header';
    logger.warn(`Token validation failed: ${errorMessage}`);
    return res.status(401).send(errorMessage); 
  }

  const token = authorization.split(" ")[1];

  try {
    const decoded = jwt.decode(token) as jwt.JwtPayload | null;

    if (!decoded || !decoded.sub) {
      return res.sendStatus(401);
    }

    const auth0Id = decoded.sub;

    const user = await User.findOne({ auth0Id });

    if (!user) {
      logger.warn(`User not found for auth0Id: ${auth0Id}`);
      return res.sendStatus(401); 
    }

    req.auth0Id = auth0Id;
    req.userId = user._id.toString();

    next();
  } catch (error) {
    logger.error(`JWT Parsing error: ${error.message}`, { error });
    return res.sendStatus(401); 
  }
};
