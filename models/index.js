const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');

// Import models as functions
const User = require('./User')(sequelize, DataTypes);
const Staff = require('./Staff')(sequelize, DataTypes);
const Complaint = require('./Complaint')(sequelize, DataTypes);
const Order = require('./Order')(sequelize, DataTypes);
const Bug = require('./Bug')(sequelize, DataTypes);

// Define relationships
User.hasMany(Complaint, { foreignKey: 'userId' });
Complaint.belongsTo(User, { foreignKey: 'userId' });

User.hasMany(Order, { foreignKey: 'userId' });
Order.belongsTo(User, { foreignKey: 'userId' });

Staff.hasMany(Bug, { foreignKey: 'assignedTo' });
Bug.belongsTo(Staff, { foreignKey: 'assignedTo' });

module.exports = {
  sequelize,
  User,
  Staff,
  Complaint,
  Order,
  Bug,
};
