const { DataTypes } = require("sequelize");
const sequelize = require("../db");
const Usuario = require("./Usuario");

const RefreshToken = sequelize.define("RefreshToken", {
  token: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  expiresAt: {
    type: DataTypes.DATE,
    allowNull: false
  }
}, {
  tableName: "refresh_tokens",
  timestamps: true, // createdAt will be used to track refresh token age
  updatedAt: false // no need to update refresh tokens
});

RefreshToken.belongsTo(Usuario, {
  foreignKey: "userId",
  onDelete: "CASCADE"
});

Usuario.hasMany(RefreshToken, {
  foreignKey: "userId"
});

module.exports = RefreshToken;
