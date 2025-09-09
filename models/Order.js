const { DataTypes, Model } = require('sequelize');

class Order extends Model {
  static initModel(sequelize) {
    Order.init({
      items: { type: DataTypes.TEXT, allowNull: false },
      totalAmount: { type: DataTypes.FLOAT, allowNull: false },
      status: { type: DataTypes.STRING, allowNull: false, defaultValue: 'pending' }
    }, { sequelize, modelName: 'Order', tableName: 'orders' });
  }

  static associate(models) {
    Order.belongsTo(models.User, { foreignKey: 'userId' });
  }
}

module.exports = Order;
