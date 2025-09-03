require('dotenv').config();
const { sequelize } = require('./config/db');

(async () => {
  try {
    // Sync all models (creates tables if they don't exist)
    await sequelize.sync({ alter: true });
    console.log('✅ Database synced!');
    process.exit(0);
  } catch (err) {
    console.error('❌ DB sync error:', err);
    process.exit(1);
  }
})();
