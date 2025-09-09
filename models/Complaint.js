const { DataTypes, Model } = require('sequelize');

class Complaint extends Model {
  static initModel(sequelize) {
    Complaint.init({
      orderId: { type: DataTypes.STRING, allowNull: false },
      details: { type: DataTypes.TEXT, allowNull: false },
      photo: { type: DataTypes.STRING }
    }, { sequelize, modelName: 'Complaint', tableName: 'complaints' });
  }

  static associate(models) {
    Complaint.belongsTo(models.User, { foreignKey: 'userId' });
  }
}

module.exports = Complaint;
