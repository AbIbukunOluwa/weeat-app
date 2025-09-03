module.exports = (sequelize, DataTypes) => {
  const Bug = sequelize.define('Bug', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    title: { type: DataTypes.STRING(150), allowNull: false },
    description: { type: DataTypes.TEXT, allowNull: false },
    severity: { type: DataTypes.ENUM('low','medium','high','critical'), defaultValue: 'low' },
    resolved: { type: DataTypes.BOOLEAN, defaultValue: false },
    assignedTo: { type: DataTypes.INTEGER, allowNull: true }
  }, {
    tableName: 'bugs',
    timestamps: true
  });

  return Bug;
};
