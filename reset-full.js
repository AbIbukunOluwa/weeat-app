cat > reset-full.js << 'EOF'
#!/usr/bin/env node
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { sequelize } = require('./config/db');

const RESET_MODES = {
  SOFT: 'soft',    // Keep structure, clear data
  HARD: 'hard',    // Drop everything, recreate
  FULL: 'full'     // Nuclear option - reset everything including files
};

async function resetDatabase(mode = RESET_MODES.HARD) {
  console.log(`🔄 Resetting database (${mode} mode)...`);
  
  try {
    if (mode === RESET_MODES.SOFT) {
      // Clear data but keep structure
      await sequelize.query('TRUNCATE TABLE users, orders, complaints, vulnerabilities, foods, reviews, "CartItems" RESTART IDENTITY CASCADE');
      console.log('✅ Database data cleared');
    } else {
      // Drop and recreate all tables
      await sequelize.drop();
      console.log('🗑️  All tables dropped');
      await sequelize.sync({ force: true });
      console.log('✅ Database structure recreated');
    }
  } catch (err) {
    console.error('❌ Database reset failed:', err);
    throw err;
  }
}

async function clearUploads() {
  console.log('🧹 Clearing upload directories...');
  
  const uploadDirs = [
    'uploads/complaints',
    'uploads/avatars',
    'uploads/documents',
    'uploads/backups',
    'uploads/xml',
    'uploads/custom',
    'uploads/extracted',
    'uploads/misc',
    'uploads/secure',
    'uploads/profiles'
  ];
  
  for (const dir of uploadDirs) {
    const fullPath = path.join(__dirname, dir);
    if (fs.existsSync(fullPath)) {
      const files = fs.readdirSync(fullPath);
      for (const file of files) {
        if (file !== '.gitkeep') {
          fs.unlinkSync(path.join(fullPath, file));
        }
      }
      console.log(`   ✓ Cleared ${dir}`);
    }
  }
}

async function clearSessions() {
  console.log('🔐 Clearing sessions...');
  try {
    await sequelize.query('TRUNCATE TABLE session');
    console.log('   ✓ Sessions cleared');
  } catch (err) {
    console.log('   ⚠️  Session table not found or already empty');
  }
}

async function clearLogs() {
  console.log('📝 Clearing logs...');
  const logFiles = ['error.log', 'access.log', 'debug.log'];
  
  for (const logFile of logFiles) {
    const logPath = path.join(__dirname, logFile);
    if (fs.existsSync(logPath)) {
      fs.writeFileSync(logPath, '');
      console.log(`   ✓ Cleared ${logFile}`);
    }
  }
}

async function main() {
  const mode = process.argv[2] || RESET_MODES.HARD;
  
  console.log('🚨 WeEat Application Reset Tool');
  console.log('================================');
  console.log(`Mode: ${mode}`);
  console.log('');
  
  try {
    // Always clear uploads and sessions
    await clearUploads();
    await clearSessions();
    await clearLogs();
    
    // Reset database based on mode
    await resetDatabase(mode);
    
    if (mode === RESET_MODES.FULL) {
      console.log('🔥 Full reset - clearing everything...');
      
      // Clear node_modules (optional)
      if (process.argv.includes('--clear-deps')) {
        console.log('📦 Clearing dependencies...');
        const rimraf = require('rimraf');
        rimraf.sync('node_modules');
        console.log('   ✓ Dependencies cleared (run npm install)');
      }
      
      // Reset environment file to template
      if (fs.existsSync('.env.example')) {
        fs.copyFileSync('.env.example', '.env');
        console.log('   ✓ Environment file reset to template');
      }
    }
    
    console.log('');
    console.log('✅ Reset complete!');
    console.log('');
    console.log('Next steps:');
    console.log('1. Run: node seed.js (to add test data)');
    console.log('2. Run: npm start (to start the application)');
    
    process.exit(0);
  } catch (err) {
    console.error('❌ Reset failed:', err);
    process.exit(1);
  }
}

main();
EOF
