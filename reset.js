require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { sequelize } = require('./config/db');

// Path to complaint uploads
const uploadsDir = path.join(__dirname, 'uploads/complaints');

(async () => {
  try {
    // Drop all tables
    await sequelize.drop();
    console.log('🗑️  Database tables dropped!');

    // Clear uploads folder
    if (fs.existsSync(uploadsDir)) {
      fs.readdirSync(uploadsDir).forEach(file => fs.unlinkSync(path.join(uploadsDir, file)));
      console.log('🧹 Uploads folder cleared.');
    } else {
      fs.mkdirSync(uploadsDir, { recursive: true });
      console.log('📁 Uploads folder created.');
    }

    console.log('✅ Reset complete! Fresh start.');
    process.exit(0);
  } catch (err) {
    console.error('❌ Reset failed:', err);
    process.exit(1);
  }
})();
