const { DataTypes, Model } = require('sequelize');

class CartItem extends Model {
  static associate(models) {
    // Each cart item belongs to a cart
    CartItem.belongsTo(models.Cart, { foreignKey: 'cartId', onDelete: 'CASCADE' });
    // Each cart item links to a product
    CartItem.belongsTo(models.Product, { foreignKey: 'productId', onDelete: 'CASCADE' });
  }
}

function initCartItem(sequelize) {
  CartItem.init({
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    quantity: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 1 }
  }, { sequelize, modelName: 'CartItem' });

  return CartItem;
}

module.exports = initCartItem;
