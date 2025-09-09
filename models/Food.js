const { Model, DataTypes } = require('sequelize');

class Food extends Model {
  static initModel(sequelize) {
    Food.init({
      name: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
      },
      image: {
        type: DataTypes.STRING,
        allowNull: false
      },
      price: {
        type: DataTypes.FLOAT,
        allowNull: false
      }
    }, {
      sequelize,
      modelName: 'Food',
      tableName: 'foods',
      timestamps: true
    });
    return Food;
  }
}

module.exports = Food;
