const jwt = require("jsonwebtoken");
require("dotenv").config();



const JWTVerification = (req, res, next) => {
    const token = req.cookies.access_token;
    if (!token) return res.status(401).json({ message: "Invalid token" });

    try { 
        const decode = jwt.verify(token, process.env.JWT_SECRETKEY);
        req.user = decode;
        next();
    } catch (e) {
        return res.status(403).json({ message : "Expired token"})
    }
};


module.exports = JWTVerification;
