const { Sequelize, DataTypes } = require('sequelize');
const { sequelize } = require('../config/db'); // Import sequelize instance

// Import all model files
const User = require('./User');
const Order = require('./Order');
const Complaint = require('./Complaint');
const Vulnerability = require('./Vulnerability');
const CartItem = require('./CartItem');
const Food = require('./Food');
const Review = require('./Review');

// Initialize all models
User.initModel(sequelize);
Order.initModel(sequelize);
Complaint.initModel(sequelize);
Vulnerability.initModel(sequelize);
Food.initModel(sequelize);
Review.initModel(sequelize);

// For CartItem, it uses the older export pattern
const CartItemModel = CartItem(sequelize, DataTypes);

// Set up all associations after models are initialized
if (User.associate) {
  User.associate({ 
    Order, 
    Complaint, 
    CartItem: CartItemModel, 
    Review 
  });
}

if (Order.associate) {
  Order.associate({ User });
}

if (Complaint.associate) {
  Complaint.associate({ User });
}

if (Review.associate) {
  Review.associate({ User, Food });
}

if (Food.associate) {
  Food.associate({ Review });
}

if (Vulnerability.associate) {
  Vulnerability.associate({ User });
}

// CartItem associations (older pattern)
if (CartItemModel.associate) {
  CartItemModel.associate({ User });
}

// Export all models
module.exports = {
  sequelize,
  Sequelize,
  User,
  Order,
  Complaint,
  CartItem: CartItemModel,
  Vulnerability,
  Food,
  Review
};
