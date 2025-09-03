module.exports = (sequelize, DataTypes) => {
  const Order = sequelize.define('Order', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    items: { type: DataTypes.TEXT, allowNull: false },
    totalAmount: { type: DataTypes.FLOAT, allowNull: false },
    status: { type: DataTypes.ENUM('pending','preparing','delivering','completed'), defaultValue: 'pending' },
    userId: { type: DataTypes.INTEGER, allowNull: false }
  }, {
    tableName: 'orders',
    timestamps: true
  });

  return Order;
};
