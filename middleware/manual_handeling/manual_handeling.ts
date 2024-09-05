import jwt from "jsonwebtoken";
import { Request, Response, NextFunction } from 'express';
import errorHandler from "../error/error.js";
import { process } from "ipaddr.js";

interface User {
    id: string;
    email: string;
}

const verifyToken = async (req: Request, res: Response, next: NextFunction) => {
    const token = req.cookies.access_token;

    if (!token) {
        return next(errorHandler(403, "Access denied"));
    }

    try {
        const user = await new Promise<User>((resolve, reject) => {
            jwt.verify(token, process.env.JWT_SECRET as string, (err, decoded) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(decoded as User);
                }
            });
        });

        req.user = user;
        next();
    } catch (err) {
        return next(errorHandler(401, "Invalid token"));
    }
};

export default verifyToken;
