const jwt = require("jsonwebtoken");
const JWT_SECRET = "your_jwt_secret_key";

function verificarToken(req, res, next) {
  const header = req.headers["authorization"];
  if (!header) return res.status(401).json({ mensaje: "Token requerido" });

  const [bearer, token] = header.split(" ");
  if (bearer !== "Bearer" || !token)
    return res.status(401).json({ mensaje: "Token mal formado" });

  try {
    req.usuario = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(403).json({ mensaje: "Token inválido o expirado" });
  }
}

function permitirRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.usuario.rol))
      return res.status(403).json({ mensaje: "No autorizado" });
    next();
  };
}

module.exports = { verificarToken, permitirRoles };
