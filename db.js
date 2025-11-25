// db.js
const { Sequelize } = require("sequelize");

// Cambia estos valores a tu configuración
const sequelize = new Sequelize("usuariosdb", "postgres", "12345678", {
  host: "localhost",
  dialect: "postgres",
  logging: false
});

module.exports = sequelize;
