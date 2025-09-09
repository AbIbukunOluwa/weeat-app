const { DataTypes, Model } = require('sequelize');

class Complaint extends Model {}

function initComplaint(sequelize) {
  Complaint.init({
    orderId: { type: DataTypes.INTEGER, allowNull: false },
    details: { type: DataTypes.TEXT, allowNull: false },
    photo: { type: DataTypes.STRING, allowNull: true }
  }, { sequelize, modelName: 'Complaint' });

  return Complaint;
}

module.exports = initComplaint;
