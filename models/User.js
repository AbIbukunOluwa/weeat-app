const { DataTypes, Model } = require('sequelize');
const bcrypt = require('bcrypt');

class User extends Model {
  static initModel(sequelize) {
    User.init({
      name: { type: DataTypes.STRING, allowNull: false },
      email: { type: DataTypes.STRING, allowNull: false, unique: true },
      username: { type: DataTypes.STRING, allowNull: false, unique: true },
      passwordHash: { type: DataTypes.STRING, allowNull: false },
      role: { type: DataTypes.STRING, allowNull: false, defaultValue: 'customer' }
    }, { sequelize, modelName: 'User', tableName: 'users' });
  }

  static associate(models) {
    User.hasMany(models.Order, { foreignKey: 'userId' });
    User.hasMany(models.Complaint, { foreignKey: 'userId' });
    User.hasMany(models.CartItem, { foreignKey: 'userId' });
  }

  async setPassword(password) {
    this.passwordHash = await bcrypt.hash(password, 10);
  }

  async checkPassword(password) {
    return await bcrypt.compare(password, this.passwordHash);
  }
}

module.exports = User;
