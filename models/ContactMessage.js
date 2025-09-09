const { Model } = require('sequelize');

class ContactMessage extends Model {
  static initModel(sequelize, DataTypes) {
    return ContactMessage.init({
      name: { type: DataTypes.STRING, allowNull: false },
      email: { type: DataTypes.STRING, allowNull: false },
      message: { type: DataTypes.TEXT, allowNull: false }
    }, {
      sequelize,
      modelName: 'ContactMessage',
      tableName: 'contact_messages'
    });
  }
}

module.exports = ContactMessage;
