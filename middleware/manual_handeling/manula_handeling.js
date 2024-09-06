import jwt from  "jsonwebtoken"
import errorhandler from "./error/error.js"

const verifyToken = async(req, res, next)=>{
    const {access_token: token} = req.cookies;

    if(!token){
        return next(errorhandler(403, "Access denied"))
    }

    try{
        const user = await jwt.verify(token, process.env.JWT_SECERT)
        req.user = user;
        next()
    }
    catch(err){
        return next(errorHandler(401, "Invalid token"))
    }

}

module.exports = verifyToken
