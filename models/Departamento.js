const { DataTypes } = require("sequelize");
const sequelize = require("../db");

const Departamento = sequelize.define("Departamento", {
  nombre: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  }
}, {
  tableName: "departamentos",
  timestamps: false   
});

module.exports = Departamento;
