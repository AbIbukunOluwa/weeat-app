module.exports = (sequelize, DataTypes) => {
  const Complaint = sequelize.define('Complaint', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    orderId: { type: DataTypes.STRING(50), allowNull: false },
    details: { type: DataTypes.TEXT, allowNull: false },
    photo: { type: DataTypes.STRING, allowNull: true },
    userId: { type: DataTypes.INTEGER, allowNull: false }
  }, {
    tableName: 'complaints',
    timestamps: true
  });

  return Complaint;
};
