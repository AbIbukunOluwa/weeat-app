const { DataTypes, Model } = require('sequelize');
const bcrypt = require('bcrypt');

class User extends Model {
  async setPassword(password) {
    this.passwordHash = await bcrypt.hash(password, 10);
  }

  async validatePassword(password) {
    return await bcrypt.compare(password, this.passwordHash);
  }

  static associate(models) {
    // Each user has one cart
    User.hasOne(models.Cart, { foreignKey: 'userId', onDelete: 'CASCADE' });
  }
}

function initUser(sequelize) {
  User.init({
    name: { type: DataTypes.STRING, allowNull: false },
    username: { type: DataTypes.STRING, allowNull: false, unique: true },
    email: { type: DataTypes.STRING, allowNull: false, unique: true, validate: { isEmail: true } },
    passwordHash: { type: DataTypes.STRING, allowNull: false },
    role: { type: DataTypes.STRING, defaultValue: 'customer' }
  }, { sequelize, modelName: 'User' });

  return User;
}

module.exports = initUser;
