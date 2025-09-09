const { Sequelize, DataTypes } = require('sequelize');
const sequelize = require('../config/db'); // make sure this exports a Sequelize instance

// Import models
const UserModel = require('./User');
const OrderModel = require('./Order');
const ComplaintModel = require('./Complaint');
const VulnerabilityModel = require('./Vulnerability');
const CartItemModel = require('./CartItem');

// Initialize models
const User = UserModel(sequelize, DataTypes);
const Order = OrderModel(sequelize, DataTypes);
const Complaint = ComplaintModel(sequelize, DataTypes);
const Vulnerability = VulnerabilityModel(sequelize, DataTypes);
const CartItem = CartItemModel(sequelize, DataTypes);

// Setup relationships
User.hasMany(Order, { foreignKey: 'userId' });
Order.belongsTo(User, { foreignKey: 'userId' });

User.hasMany(Complaint, { foreignKey: 'userId' });
Complaint.belongsTo(User, { foreignKey: 'userId' });

User.hasMany(CartItem, { foreignKey: 'userId' });
CartItem.belongsTo(User, { foreignKey: 'userId' });

// (Optional) Vulnerabilities can be assigned to staff/admin users
Vulnerability.belongsTo(User, { foreignKey: 'assignedTo', as: 'assignedUser' });
User.hasMany(Vulnerability, { foreignKey: 'assignedTo', as: 'assignedVulnerabilities' });

module.exports = {
  sequelize,
  Sequelize,
  User,
  Order,
  Complaint,
  CartItem,
  Vulnerability
};
