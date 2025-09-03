module.exports = (sequelize, DataTypes) => {
  const Staff = sequelize.define('Staff', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    name: { type: DataTypes.STRING(100), allowNull: false },
    email: { type: DataTypes.STRING(150), allowNull: false, unique: true, validate: { isEmail: true } },
    passwordHash: { type: DataTypes.STRING, allowNull: false },
    role: { type: DataTypes.ENUM('staff','admin'), defaultValue: 'staff' },
  }, {
    tableName: 'staff',
    timestamps: true
  });

  Staff.prototype.setPassword = async function(plain) {
    const bcrypt = require('bcrypt');
    this.passwordHash = await bcrypt.hash(plain, 10);
  };

  Staff.prototype.verifyPassword = function(plain) {
    const bcrypt = require('bcrypt');
    return bcrypt.compare(plain, this.passwordHash);
  };

  return Staff;
};
