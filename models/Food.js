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
      },
      category: {
        type: DataTypes.STRING,
        allowNull: false,
        defaultValue: 'mains'
      },
      description: {
        type: DataTypes.TEXT,
        allowNull: true
      },
      status: {
        type: DataTypes.STRING,
        allowNull: false,
        defaultValue: 'active'
      },
      // Hidden fields for vulnerability testing
      cost_price: {
        type: DataTypes.FLOAT,
        allowNull: true
      },
      supplier_info: {
        type: DataTypes.TEXT,
        allowNull: true
      },
      internal_notes: {
        type: DataTypes.TEXT,
        allowNull: true
      }
    }, {
      sequelize,
      modelName: 'Food',
      tableName: 'foods',
      timestamps: true
    });
    return Food;
  }

  static associate(models) {
    // Food can have many reviews
    if (models.Review) {
      Food.hasMany(models.Review, { foreignKey: 'foodId' });
    }
  }
}

module.exports = Food;
