const { DataTypes, Model } = require('sequelize');

class Order extends Model {}

function initOrder(sequelize) {
  Order.init({
    items: { type: DataTypes.TEXT, allowNull: false },
    totalAmount: { type: DataTypes.FLOAT, allowNull: false },
    status: { type: DataTypes.STRING, allowNull: false, defaultValue: 'pending' }
  }, { sequelize, modelName: 'Order' });

  return Order;
}

module.exports = initOrder;
