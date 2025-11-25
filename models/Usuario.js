const { DataTypes } = require("sequelize");
const sequelize = require("../db");
const Departamento = require("./Departamento");
const bcrypt = require("bcryptjs");

const SALT_ROUNDS = 10;

const Usuario = sequelize.define("Usuario", {
  nombre: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  password: { type: DataTypes.STRING, allowNull: false },
  rol: { type: DataTypes.ENUM("Admin", "Usuario"), allowNull: false },
  edad: { type: DataTypes.INTEGER, allowNull: false },
  activo: { type: DataTypes.BOOLEAN, defaultValue: true }
}, {
  tableName: "usuarios",
  timestamps: false,
  hooks: {
    async beforeCreate(usuario) {
      if (usuario.password) {
        usuario.password = await bcrypt.hash(usuario.password, SALT_ROUNDS);
      }
    },
    async beforeUpdate(usuario) {
      if (usuario.changed("password")) {
        usuario.password = await bcrypt.hash(usuario.password, SALT_ROUNDS);
      }
    }
  }
});

Usuario.belongsTo(Departamento, {
  foreignKey: "departamentoId",
  onDelete: "SET NULL"
});

Usuario.prototype.validPassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

module.exports = Usuario;
