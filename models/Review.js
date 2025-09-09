// models/Review.js - NEW FILE FOR STORED XSS VULNERABILITY

const { DataTypes, Model } = require('sequelize');

class Review extends Model {
  static initModel(sequelize) {
    Review.init({
      foodId: { 
        type: DataTypes.INTEGER, 
        allowNull: false,
        references: { model: 'foods', key: 'id' }
      },
      userId: { 
        type: DataTypes.INTEGER, 
        allowNull: false,
        references: { model: 'users', key: 'id' }
      },
      rating: { 
        type: DataTypes.INTEGER, 
        allowNull: false,
        validate: { min: 1, max: 5 }
      },
      title: { 
        type: DataTypes.STRING, 
        allowNull: false 
        // VULNERABILITY: No XSS sanitization
      },
      comment: { 
        type: DataTypes.TEXT, 
        allowNull: false 
        // VULNERABILITY: Stored XSS - content rendered without escaping
      },
      approved: { 
        type: DataTypes.BOOLEAN, 
        defaultValue: false 
      }
    }, { 
      sequelize, 
      modelName: 'Review', 
      tableName: 'reviews',
      timestamps: true
    });
  }

  static associate(models) {
    Review.belongsTo(models.User, { foreignKey: 'userId' });
    Review.belongsTo(models.Food, { foreignKey: 'foodId' });
  }
}

module.exports = Review;
