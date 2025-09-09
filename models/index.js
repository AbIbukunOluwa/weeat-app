const { sequelize } = require('../config/db');
const initUser = require('./User');
const initOrder = require('./Order');
const initComplaint = require('./Complaint');
const initVulnerability = require('./Vulnerability');
const initProduct = require('./Product');
const initCart = require('./Cart');
const initCartItem = require('./CartItem');

// Initialize models
const User = initUser(sequelize);
const Order = initOrder(sequelize);
const Complaint = initComplaint(sequelize);
const Vulnerability = initVulnerability(sequelize);
const Product = initProduct(sequelize);
const Cart = initCart(sequelize);
const CartItem = initCartItem(sequelize);

// Associations

// User ↔ Orders
User.hasMany(Order, { foreignKey: 'userId' });
Order.belongsTo(User, { foreignKey: 'userId' });

// User ↔ Complaints
User.hasMany(Complaint, { foreignKey: 'userId' });
Complaint.belongsTo(User, { foreignKey: 'userId' });

// User ↔ Cart
User.hasOne(Cart, { foreignKey: 'userId', onDelete: 'CASCADE' });
Cart.belongsTo(User, { foreignKey: 'userId' });

// Cart ↔ CartItems
Cart.hasMany(CartItem, { foreignKey: 'cartId', onDelete: 'CASCADE' });
CartItem.belongsTo(Cart, { foreignKey: 'cartId' });

// Product ↔ CartItems
Product.hasMany(CartItem, { foreignKey: 'productId', onDelete: 'CASCADE' });
CartItem.belongsTo(Product, { foreignKey: 'productId' });

module.exports = { 
  sequelize, 
  User, 
  Order, 
  Complaint, 
  Vulnerability, 
  Product, 
  Cart, 
  CartItem 
};
