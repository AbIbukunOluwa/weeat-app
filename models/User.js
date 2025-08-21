// models/User.js
const { DataTypes } = require('sequelize');
const bcrypt = require('bcrypt');
const { sequelize } = require('../config/db');

const User = sequelize.define('User', {
  id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
  name: { type: DataTypes.STRING(100), allowNull: false },
  email: { type: DataTypes.STRING(150), allowNull: false, unique: true, validate: { isEmail: true } },
  passwordHash: { type: DataTypes.STRING, allowNull: false },
  role: { type: DataTypes.ENUM('customer','staff','admin'), defaultValue: 'customer' },
  profileImagePath: { type: DataTypes.STRING, allowNull: true }
}, {
  tableName: 'users',
  timestamps: true
});

// helper: set password
User.prototype.setPassword = async function(plain) {
  const saltRounds = 10;
  this.passwordHash = await bcrypt.hash(plain, saltRounds);
};

// helper: check password
User.prototype.verifyPassword = function(plain) {
  return bcrypt.compare(plain, this.passwordHash);
};

module.exports = { User };
