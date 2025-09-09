// models/CartItem.js
module.exports = (sequelize, DataTypes) => {
  const CartItem = sequelize.define('CartItem', {
    foodName: { type: DataTypes.STRING, allowNull: false },
    price: { type: DataTypes.FLOAT, allowNull: false },
    quantity: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 1 }
  });

  CartItem.associate = models => {
    CartItem.belongsTo(models.User, { foreignKey: 'userId' });
  };

  return CartItem;
};
