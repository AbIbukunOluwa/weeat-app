const { DataTypes, Model } = require('sequelize');

class Cart extends Model {
  static associate(models) {
    // Each cart belongs to one user
    Cart.belongsTo(models.User, { foreignKey: 'userId', onDelete: 'CASCADE' });
    // Each cart has many cart items
    Cart.hasMany(models.CartItem, { foreignKey: 'cartId', onDelete: 'CASCADE' });
  }
}

function initCart(sequelize) {
  Cart.init({
    // Primary key auto-generated
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true }
  }, { sequelize, modelName: 'Cart' });

  return Cart;
}

module.exports = initCart;
