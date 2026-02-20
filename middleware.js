require("dotenv").config();
const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Wymagany token" });

  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    if (err)
      return res.status(403).json({ error: "Token nieprawidłowy lub wygasł" });
    req.user = decodedUser;
    next();
  });
}

function optionalAuthenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    req.user = null;
    return next();
  }
  jwt.verify(token, JWT_SECRET, (err, decodedUser) => {
    req.user = err ? null : decodedUser;
    next();
  });
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ error: "Brak uprawnień administratora" });
  }
  next();
}

module.exports = {
  authenticateToken,
  optionalAuthenticateToken,
  requireAdmin,
  JWT_SECRET,
};
