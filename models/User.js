// models/User.js - Updated with UUID support
const { DataTypes, Model } = require('sequelize');
const bcrypt = require('bcrypt');

class User extends Model {
  static initModel(sequelize) {
    User.init({
      // Keep integer ID for backward compatibility during migration
      id: {
        type: DataTypes.INTEGER,
        autoIncrement: true,
        primaryKey: true
      },
      // Add UUID as unique identifier for external references
      uuid: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        unique: true,
        allowNull: false
      },
      name: { 
        type: DataTypes.STRING, 
        allowNull: false 
      },
      email: { 
        type: DataTypes.STRING, 
        allowNull: false, 
        unique: true,
        validate: {
          isEmail: true
        }
      },
      username: { 
        type: DataTypes.STRING, 
        allowNull: false, 
        unique: true,
        validate: {
          len: [3, 50],
          isAlphanumeric: true
        }
      },
      passwordHash: { 
        type: DataTypes.STRING, 
        allowNull: false 
      },
      role: { 
        type: DataTypes.STRING, 
        allowNull: false, 
        defaultValue: 'customer',
        validate: {
          isIn: [['customer', 'staff', 'admin']]
        }
      },
      avatar: {
        type: DataTypes.STRING,
        allowNull: true
      },
      bio: {
        type: DataTypes.TEXT,
        allowNull: true
      },
      phone: {
        type: DataTypes.STRING,
        allowNull: true,
        validate: {
          is: /^[\+]?[1-9][\d]{0,15}$/ // Basic international phone validation
        }
      },
      active: {
        type: DataTypes.BOOLEAN,
        defaultValue: true
      },
      lastLogin: {
        type: DataTypes.DATE,
        allowNull: true
      },
      loginCount: {
        type: DataTypes.INTEGER,
        defaultValue: 0
      }
    }, { 
      sequelize, 
      modelName: 'User', 
      tableName: 'users',
      hooks: {
        beforeCreate: async (user) => {
          // Ensure UUID is generated
          if (!user.uuid) {
            user.uuid = require('crypto').randomUUID();
          }
        }
      }
    });
  }

  static associate(models) {
    // Use UUID for new associations, keep integer for legacy
    User.hasMany(models.Order, { 
      foreignKey: 'userId', // Legacy
      as: 'orders'
    });
    User.hasMany(models.Complaint, { 
      foreignKey: 'userId', // Legacy
      as: 'complaints'
    });
    User.hasMany(models.CartItem, { 
      foreignKey: 'userId', // Legacy
      as: 'cartItems'
    });
    User.hasMany(models.Review, { 
      foreignKey: 'userId', // Legacy
      as: 'reviews'
    });
  }

  // Instance methods
  async setPassword(password) {
    // Enhanced password validation
    if (!password || password.length < 8) {
      throw new Error('Password must be at least 8 characters long');
    }
    this.passwordHash = await bcrypt.hash(password, 12);
  }

  async checkPassword(password) {
    return await bcrypt.compare(password, this.passwordHash);
  }

  // Get public profile (safe for external use)
  getPublicProfile() {
    return {
      uuid: this.uuid, // Use UUID instead of ID
      username: this.username,
      name: this.name,
      role: this.role,
      avatar: this.avatar,
      bio: this.bio,
      createdAt: this.createdAt
    };
  }

  // Get session data (for storing in session)
  getSessionData() {
    return {
      id: this.id, // Keep for backward compatibility
      uuid: this.uuid, // New UUID identifier
      username: this.username,
      email: this.email,
      name: this.name,
      role: this.role,
      avatar: this.avatar
    };
  }

  // Generate a secure token for password reset, etc.
  generateSecureToken() {
    const crypto = require('crypto');
    return crypto.randomBytes(32).toString('hex');
  }

  // VULNERABILITY: Method that exposes sensitive info (intentional for testing)
  getDebugInfo() {
    return {
      id: this.id,
      uuid: this.uuid,
      passwordHash: this.passwordHash, // VULNERABILITY: Exposing password hash
      email: this.email,
      lastLogin: this.lastLogin,
      loginCount: this.loginCount
    };
  }

  // Helper method to find user by UUID or ID
  static async findByIdentifier(identifier) {
    // Try UUID first, then fall back to ID
    if (identifier.length === 36 && identifier.includes('-')) {
      return await User.findOne({ where: { uuid: identifier } });
    } else {
      return await User.findByPk(identifier);
    }
  }
}

module.exports = User;
