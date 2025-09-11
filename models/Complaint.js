// models/Complaint.js - Updated with proper fields
const { DataTypes, Model } = require('sequelize');

class Complaint extends Model {
  static initModel(sequelize) {
    Complaint.init({
      orderId: { 
        type: DataTypes.STRING, 
        allowNull: true  // Make orderId optional
      },
      details: { 
        type: DataTypes.TEXT, 
        allowNull: false 
      },
      photo: { 
        type: DataTypes.STRING,
        allowNull: true
      },
      category: {
        type: DataTypes.STRING,
        allowNull: true,
        defaultValue: 'other'
      },
      urgent: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      },
      contactMethod: {
        type: DataTypes.STRING,
        allowNull: true,
        defaultValue: 'email'
      },
      likes: {
        type: DataTypes.INTEGER,
        defaultValue: 0
      },
      resolved: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      },
      resolvedAt: {
        type: DataTypes.DATE,
        allowNull: true
      },
      resolvedBy: {
        type: DataTypes.INTEGER,
        allowNull: true
      },
      escalated: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      },
      escalationReason: {
        type: DataTypes.TEXT,
        allowNull: true
      },
      escalatedAt: {
        type: DataTypes.DATE,
        allowNull: true
      },
      escalatedBy: {
        type: DataTypes.INTEGER,
        allowNull: true
      }
    }, { 
      sequelize, 
      modelName: 'Complaint', 
      tableName: 'complaints' 
    });
  }

  static associate(models) {
    Complaint.belongsTo(models.User, { foreignKey: 'userId' });
  }
}

module.exports = Complaint;
