const { DataTypes } = require("sequelize");
const sequelize = require("../db");
const Usuario = require("./Usuario");

const Perfil = sequelize.define("Perfil", {
  created_at: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  },
}, {
  tableName: "perfiles",
  timestamps: false      
});

Perfil.belongsTo(Usuario, { foreignKey: "usuario_id" });

module.exports = Perfil;
