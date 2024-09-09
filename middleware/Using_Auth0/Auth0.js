const { auth } = require("express-oauth2-jwt-bearer");
const jwt = require("jsonwebtoken");
const User = require("../models/user"); 

// Auth0 JWT Middleware for checking the token
const jwtCheck = auth({
  audience: process.env.AUTH0_AUDIENCE,
  issuerBaseURL: process.env.AUTH0_ISSUER_BASE_URL,
  tokenSigningAlg: "RS256",
});

// Custom middleware to parse and verify JWT
const jwtParse = async (req, res, next) => {
  const authorization = req.headers.authorization;

  // Early return for missing or invalid authorization header
  if (!authorization || !authorization.startsWith("Bearer ")) {
    return res.sendStatus(401);
  }

  // Extract token from "Bearer <token>"
  const token = authorization.split(" ")[1];

  try {
    const decoded = jwt.decode(token);

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

module.exports = {
  jwtCheck,
  jwtParse
};
