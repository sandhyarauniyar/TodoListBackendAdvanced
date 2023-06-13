const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  const secretKey = process.env.ACCESS_TOKEN_SECRET_KEY;
  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {  
      return res.status(401).json({ message: 'Invalid token' });
    }
    req.user = decoded;
    next();
  });
};

module.exports = verifyToken;
