const express = require("express");
const path = require("path");
const { body, param, query, validationResult } = require("express-validator");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const GitHubStrategy = require("passport-github2").Strategy;
const bcrypt = require("bcryptjs");
const { verificarToken, permitirRoles } = require("./middlewares/auth");

const sequelize = require("./db");
const Usuario = require("./models/Usuario");
const Departamento = require("./models/Departamento");
const RefreshToken = require("./models/RefreshToken");

const app = express();
const PORT = 3000;

const JWT_SECRET = "your_jwt_secret_key";
const JWT_ACCESS_EXPIRES = "15m";
const JWT_REFRESH_EXPIRES = "7d";

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.use(passport.initialize());

function manejarErroresValidacion(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      mensaje: "Error de validación",
      errores: errors.array().map(e => ({
        campo: e.param,
        mensaje: e.msg
      }))
    });
  }
  next();
}

app.post("/login",
  [
    body("email").isEmail(),
    body("password").notEmpty()
  ],
  manejarErroresValidacion,
  async (req, res) => {

    const { email, password } = req.body;

    const usuario = await Usuario.findOne({ where: { email } });
    if (!usuario) return res.status(401).json({ mensaje: "Credenciales inválidas" });

    const esValido = await usuario.validPassword(password);
    if (!esValido) return res.status(401).json({ mensaje: "Credenciales inválidas" });

    const accessToken = jwt.sign(
      { id: usuario.id, rol: usuario.rol, email },
      JWT_SECRET,
      { expiresIn: JWT_ACCESS_EXPIRES }
    );

    const refreshToken = jwt.sign(
      { id: usuario.id, rol: usuario.rol, email },
      JWT_SECRET,
      { expiresIn: JWT_REFRESH_EXPIRES }
    );

    await RefreshToken.create({
      token: refreshToken,
      userId: usuario.id,
      expiresAt: new Date(Date.now() + 7 * 86400000)
    });

    res.json({
      mensaje: "Login exitoso",
      accessToken,
      refreshToken,
      nombre: usuario.nombre,
      rol: usuario.rol
    });
  }
);

async function generateTokensAndSaveRefresh(usuario) {
  const accessToken = jwt.sign({
    id: usuario.id,
    email: usuario.email,
    rol: usuario.rol
  }, JWT_SECRET, { expiresIn: JWT_ACCESS_EXPIRES });

  const refreshTokenValue = jwt.sign({
    id: usuario.id,
    email: usuario.email,
    rol: usuario.rol
  }, JWT_SECRET, { expiresIn: JWT_REFRESH_EXPIRES });

  await RefreshToken.create({
    token: refreshTokenValue,
    userId: usuario.id,
    expiresAt: new Date(Date.now() + 7 * 86400000)
  });

  return { accessToken, refreshToken: refreshTokenValue };
}

passport.use(new GoogleStrategy({
  clientID: "YOUR_GOOGLE_CLIENT_ID",
  clientSecret: "YOUR_GOOGLE_CLIENT_SECRET",
  callbackURL: "http://localhost:3000/auth/google/callback"
},
  async (accessToken, refreshToken, profile, done) => {
    try {
      let usuario = await Usuario.findOne({ where: { email: profile.emails[0].value } });

      if (!usuario) {
        usuario = await Usuario.create({
          nombre: profile.displayName,
          email: profile.emails[0].value,
          password: Math.random().toString(36).slice(-8),
          rol: "Usuario",
          edad: 0,
          activo: true
        });
      }
      return done(null, usuario);
    } catch (err) {
      return done(err, null);
    }
  }
));

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/callback",
  passport.authenticate("google", { session: false }),
  async (req, res) => {
    const tokens = await generateTokensAndSaveRefresh(req.user);
    res.json({
      mensaje: "Login con Google exitoso",
      ...tokens,
      rol: req.user.rol,
      nombre: req.user.nombre
    });
  }
);

passport.use(new GitHubStrategy({
  clientID: "YOUR_GITHUB_CLIENT_ID",
  clientSecret: "YOUR_GITHUB_CLIENT_SECRET",
  callbackURL: "http://localhost:3000/auth/github/callback"
},
  async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails?.[0]?.value || `${profile.username}@github.com`;

      let usuario = await Usuario.findOne({ where: { email } });

      if (!usuario) {
        usuario = await Usuario.create({
          nombre: profile.displayName || profile.username,
          email,
          password: Math.random().toString(36).slice(-8),
          rol: "Usuario",
          edad: 0,
          activo: true
        });
      }
      return done(null, usuario);
    } catch (err) {
      return done(err, null);
    }
  }
));

app.get("/auth/github", passport.authenticate("github", { scope: ["user:email"] }));

app.get("/auth/github/callback",
  passport.authenticate("github", { session: false }),
  async (req, res) => {
    const tokens = await generateTokensAndSaveRefresh(req.user);
    res.json({
      mensaje: "Login con GitHub exitoso",
      ...tokens,
      rol: req.user.rol,
      nombre: req.user.nombre
    });
  }
);

app.post("/refresh-token",
  [body("refreshToken").notEmpty()],
  manejarErroresValidacion,
  async (req, res) => {

    const { refreshToken } = req.body;

    let payload;
    try {
      payload = jwt.verify(refreshToken, JWT_SECRET);
    } catch (err) {
      return res.status(403).json({ mensaje: "Refresh Token inválido" });
    }

    const tokenDB = await RefreshToken.findOne({ where: { token: refreshToken } });
    if (!tokenDB) return res.status(403).json({ mensaje: "Refresh Token no existe" });

    await tokenDB.destroy(); // ROTACIÓN

    const newAccessToken = jwt.sign(
      { id: payload.id, email: payload.email, rol: payload.rol },
      JWT_SECRET,
      { expiresIn: JWT_ACCESS_EXPIRES }
    );

    const newRefreshToken = jwt.sign(
      { id: payload.id, email: payload.email, rol: payload.rol },
      JWT_SECRET,
      { expiresIn: JWT_REFRESH_EXPIRES }
    );

    await RefreshToken.create({
      token: newRefreshToken,
      userId: payload.id,
      expiresAt: new Date(Date.now() + 7 * 86400000)
    });

    res.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken
    });
  }
);

app.get("/usuarios",
  verificarToken,
  async (req, res) => {
    let { page = 1, limit = 10, rol, nombre, sort } = req.query;

    const where = {};
    if (rol) where.rol = rol;
    if (nombre) where.nombre = { [require("sequelize").Op.iLike]: `%${nombre}%` };

    let order = [];
    if (sort) {
      const [campo, dir] = sort.split(":");
      order.push([campo, dir.toUpperCase()]);
    }

    const offset = (page - 1) * limit;

    const { rows, count } = await Usuario.findAndCountAll({
      where,
      limit: parseInt(limit),
      offset,
      order,
      include: Departamento
    });

    return res.json({
      page: parseInt(page),
      totalPages: Math.ceil(count / limit),
      total: count,
      data: rows
    });
  }
);

app.get("/usuarios/:id",
  [param("id").isInt({ min: 1 }).withMessage("ID inválido")],
  manejarErroresValidacion,
  async (req, res) => {
    const usuario = await Usuario.findByPk(req.params.id);
    if (!usuario) return res.status(404).json({ mensaje: "No encontrado" });
    res.json(usuario);
  }
);

app.post("/usuarios",
  verificarToken,
  permitirRoles("Admin"),
  [
    body("nombre").notEmpty(),
    body("email").isEmail(),
    body("rol").isIn(["Admin", "Usuario"]),
    body("edad").isInt({ min: 0 }),
    body("activo").isBoolean()
  ],
  manejarErroresValidacion,
  async (req, res) => {
    const t = await sequelize.transaction();

    try {
      const { nombre, email, password, rol, edad, activo, departamentoId } = req.body;

      const usuario = await Usuario.create({
        nombre, email, password, rol, edad, activo, departamentoId
      }, { transaction: t });

      await sequelize.query(
        `INSERT INTO perfiles (usuario_id, created_at) VALUES (:id, NOW())`,
        { replacements: { id: usuario.id }, transaction: t }
      );

      await t.commit();
      res.status(201).json(usuario);

    } catch (error) {
      await t.rollback();
      res.status(500).json({ mensaje: "Error en transacción", error: error.message });
    }
  }
);

app.put("/usuarios/:id",
  verificarToken,
  permitirRoles("Admin"),
  async (req, res) => {
    const usuario = await Usuario.findByPk(req.params.id);
    if (!usuario) return res.status(404).json({ mensaje: "No encontrado" });

    await usuario.update(req.body);
    res.json(usuario);
  }
);

app.delete("/usuarios/:id",
  verificarToken,
  permitirRoles("Admin"),
  async (req, res) => {
    const usuario = await Usuario.findByPk(req.params.id);
    if (!usuario) return res.status(404).json({ mensaje: "No encontrado" });

    await usuario.destroy();
    res.json({ mensaje: "Usuario eliminado" });
  }
);
app.post("/register",
  [
    body("nombre").notEmpty(),
    body("email").isEmail(),
    body("password").isLength({ min: 6 })
  ],
  manejarErroresValidacion,
  async (req, res) => {
    const { nombre, email, password } = req.body;

    const existe = await Usuario.findOne({ where: { email } });
    if (existe) return res.status(409).json({ mensaje: "Email ya registrado" });

    const usuario = await Usuario.create({
      nombre,
      email,
      password,  // será hasheado automáticamente por hooks
      rol: "Usuario",
      edad: 0,
      activo: true
    });

    res.json({
      mensaje: "Registro exitoso",
      id: usuario.id
    });
  }
);

(async () => {
  try {
    await sequelize.authenticate();
    console.log("Conectado a PostgreSQL");

    await sequelize.sync({ alter: true });
    const path = require("path");

    app.get("/", (req, res) => {
      res.sendFile(path.join(__dirname, "public", "login.html"));
    });

    app.listen(PORT, () => {
      console.log(`Servidor ejecutando en http://localhost:${PORT}`);
    });

  } catch (error) {
    console.error("Error conectando a la base:", error);
  }
})();
