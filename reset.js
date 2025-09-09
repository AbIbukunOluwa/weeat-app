require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { sequelize } = require('./config/db');

const uploadsDir = path.join(__dirname, 'uploads/complaints');

(async () => {
  try {
    await sequelize.drop();
    console.log('🗑️  Database tables dropped!');

    if (fs.existsSync(uploadsDir)) {
      for (const file of fs.readdirSync(uploadsDir)) {
        fs.unlinkSync(path.join(uploadsDir, file));
      }
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
