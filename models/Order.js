// models/Order.js - Updated with UUID support
const { DataTypes, Model } = require('sequelize');

class Order extends Model {
  static initModel(sequelize) {
    Order.init({
      // Keep integer ID for backward compatibility
      id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true
      },
      // Add UUID for external references
      uuid: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        unique: true,
        allowNull: false
      },
      // Generate human-readable order number
      orderNumber: {
        type: DataTypes.STRING,
        unique: true,
        allowNull: true
      },
      items: { 
        type: DataTypes.TEXT, 
        allowNull: false,
        validate: {
          isValidJSON(value) {
            try {
              JSON.parse(value);
            } catch (e) {
              throw new Error('Items must be valid JSON');
            }
          }
        }
      },
      totalAmount: { 
        type: DataTypes.FLOAT, 
        allowNull: false,
        validate: {
          min: 0
        }
      },
      status: { 
        type: DataTypes.STRING, 
        allowNull: false, 
        defaultValue: 'pending',
        validate: {
          isIn: [['pending', 'confirmed', 'preparing', 'ready', 'delivering', 'delivered', 'cancelled']]
        }
      },
      discountApplied: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      },
      cancellationReason: {
        type: DataTypes.TEXT,
        allowNull: true
      },
      cancelledAt: {
        type: DataTypes.DATE,
        allowNull: true
      },
      // Delivery information
      deliveryAddress: {
        type: DataTypes.TEXT,
        allowNull: true
      },
      deliveryInstructions: {
        type: DataTypes.TEXT,
        allowNull: true
      },
      estimatedDelivery: {
        type: DataTypes.DATE,
        allowNull: true
      },
      actualDelivery: {
        type: DataTypes.DATE,
        allowNull: true
      }
    }, { 
      sequelize, 
      modelName: 'Order', 
      tableName: 'orders',
      hooks: {
        beforeCreate: async (order) => {
          // Generate UUID if not present
          if (!order.uuid) {
            order.uuid = require('crypto').randomUUID();
          }
          
          // Generate human-readable order number
          if (!order.orderNumber) {
            const date = new Date();
            const year = date.getFullYear().toString().slice(-2);
            const month = (date.getMonth() + 1).toString().padStart(2, '0');
            const day = date.getDate().toString().padStart(2, '0');
            const random = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
            order.orderNumber = `WE${year}${month}${day}${random}`;
          }
        }
      }
    });
  }

  static associate(models) {
    Order.belongsTo(models.User, { 
      foreignKey: 'userId',
      as: 'customer'
    });
  }

  // Instance methods
  getItems() {
    try {
      return JSON.parse(this.items);
    } catch (e) {
      return [];
    }
  }

  setItems(items) {
    this.items = JSON.stringify(items);
  }

  // Calculate order total from items
  calculateTotal() {
    const items = this.getItems();
    return items.reduce((total, item) => {
      return total + (item.price * (item.quantity || item.qty || 1));
    }, 0);
  }

  // Get order summary for customer
  getOrderSummary() {
    return {
      uuid: this.uuid,
      orderNumber: this.orderNumber,
      status: this.status,
      totalAmount: this.totalAmount,
      items: this.getItems(),
      createdAt: this.createdAt,
      estimatedDelivery: this.estimatedDelivery
    };
  }

  // Get detailed order info (for admin/staff)
  getDetailedInfo() {
    return {
      id: this.id, // Internal ID
      uuid: this.uuid,
      orderNumber: this.orderNumber,
      userId: this.userId,
      items: this.getItems(),
      totalAmount: this.totalAmount,
      status: this.status,
      discountApplied: this.discountApplied,
      deliveryAddress: this.deliveryAddress,
      deliveryInstructions: this.deliveryInstructions,
      estimatedDelivery: this.estimatedDelivery,
      actualDelivery: this.actualDelivery,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt,
      cancellationReason: this.cancellationReason,
      cancelledAt: this.cancelledAt
    };
  }

  // Update order status with validation
  async updateStatus(newStatus, reason = null) {
    const validTransitions = {
      'pending': ['confirmed', 'cancelled'],
      'confirmed': ['preparing', 'cancelled'],
      'preparing': ['ready', 'cancelled'],
      'ready': ['delivering'],
      'delivering': ['delivered'],
      'delivered': [],
      'cancelled': []
    };

    const allowedStatuses = validTransitions[this.status] || [];
    
    if (!allowedStatuses.includes(newStatus)) {
      throw new Error(`Cannot transition from ${this.status} to ${newStatus}`);
    }

    this.status = newStatus;
    
    if (newStatus === 'cancelled') {
      this.cancellationReason = reason || 'No reason provided';
      this.cancelledAt = new Date();
    }
    
    if (newStatus === 'delivered') {
      this.actualDelivery = new Date();
    }

    await this.save();
  }

  // VULNERABILITY: Method for testing IDOR (intentional)
  static async findByOrderNumber(orderNumber, skipAuth = false) {
    const order = await Order.findOne({ where: { orderNumber } });
    
    if (!skipAuth && order) {
      // VULNERABILITY: Weak authorization check that can be bypassed
      // In a real app, this should verify user ownership
      console.log('VULNERABILITY: Order access without proper authorization check');
    }
    
    return order;
  }

  // Helper method to find order by UUID or ID
  static async findByIdentifier(identifier) {
    // Try UUID first, then order number, then ID
    if (identifier.length === 36 && identifier.includes('-')) {
      return await Order.findOne({ where: { uuid: identifier } });
    } else if (identifier.startsWith('WE')) {
      return await Order.findOne({ where: { orderNumber: identifier } });
    } else {
      return await Order.findByPk(identifier);
    }
  }
}

module.exports = Order;
