import {z} from "zod";
import jwt from "jsonwebtoken";
import errorhandler from "./error.js"

const tokenSchema = z.object({
    access_token: z.string().nonempty('Token is required'),
});

const verifyToken = async(req, res, next)=>{
    const result = tokenSchema.safeParse(req.cookies);

    if(!result.success){
        return next(errorhandler(401, result.error.errors[0].message || 'Access denied'))
    }

    const {access_token: token} = result.data;

    try{
        const user = await jwt.verify(token,  process.env.JWT_SECERT);
        req.user = user;
        next();
    }catch(err){
        return next(errorhandler(403, 'Invallid Token'))
    }
};

module.exports = verifyToken;