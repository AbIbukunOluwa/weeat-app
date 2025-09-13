// health-check.js - System health check for WeEat
require('dotenv').config();
const { sequelize } = require('./config/db');
const fs = require('fs');
const path = require('path');

async function checkDatabase() {
  try {
    await sequelize.authenticate();
    const [results] = await sequelize.query('SELECT COUNT(*) as count FROM users');
    console.log(`✅ Database: Connected (${results[0].count} users)`);
    return true;
  } catch (err) {
    console.log('❌ Database: Connection failed');
    console.log(`   Error: ${err.message}`);
    return false;
  }
}

async function checkTables() {
  try {
    const tables = ['users', 'orders', 'complaints', 'foods', 'reviews', 'vulnerabilities'];
    for (const table of tables) {
      const [result] = await sequelize.query(`SELECT COUNT(*) as count FROM ${table}`);
      console.log(`   ✓ Table '${table}': ${result[0].count} records`);
    }
    return true;
  } catch (err) {
    console.log('❌ Tables: Check failed');
    return false;
  }
}

async function checkDirectories() {
  const dirs = [
    'uploads/complaints',
    'uploads/avatars', 
    'uploads/documents',
    'views',
    'views/admin',
    'views/partials',
    'public',
    'routes',
    'models',
    'middleware'
  ];
  
  let allGood = true;
  console.log('📁 Directories:');
  
  for (const dir of dirs) {
    const fullPath = path.join(__dirname, dir);
    if (fs.existsSync(fullPath)) {
      console.log(`   ✓ ${dir}`);
    } else {
      console.log(`   ❌ ${dir} - MISSING`);
      allGood = false;
    }
  }
  
  return allGood;
}

async function checkDependencies() {
  const packageJson = require('./package.json');
  const requiredDeps = ['express', 'sequelize', 'pg', 'bcrypt', 'ejs', 'multer'];
  
  console.log('📦 Dependencies:');
  let allInstalled = true;
  
  for (const dep of requiredDeps) {
    try {
      require.resolve(dep);
      console.log(`   ✓ ${dep}`);
    } catch {
      console.log(`   ❌ ${dep} - NOT INSTALLED`);
      allInstalled = false;
    }
  }
  
  return allInstalled;
}

async function checkEnvironment() {
  console.log('🔧 Environment:');
  const required = ['DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASS'];
  let allSet = true;
  
  for (const key of required) {
    if (process.env[key]) {
      console.log(`   ✓ ${key}: Set`);
    } else {
      console.log(`   ❌ ${key}: MISSING`);
      allSet = false;
    }
  }
  
  return allSet;
}

async function main() {
  console.log('🏥 WeEat Health Check');
  console.log('=====================');
  console.log('');
  
  const checks = [
    { name: 'Environment', fn: checkEnvironment },
    { name: 'Database', fn: checkDatabase },
    { name: 'Tables', fn: checkTables },
    { name: 'Directories', fn: checkDirectories },
    { name: 'Dependencies', fn: checkDependencies }
  ];
  
  let allPassed = true;
  
  for (const check of checks) {
    const passed = await check.fn();
    if (!passed) allPassed = false;
    console.log('');
  }
  
  if (allPassed) {
    console.log('✅ All checks passed! System is healthy.');
  } else {
    console.log('⚠️  Some checks failed. Run setup.sh to fix issues.');
  }
  
  process.exit(allPassed ? 0 : 1);
}

main();
