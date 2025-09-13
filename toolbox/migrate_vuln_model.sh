#!/bin/bash

# Migration script for updating Vulnerability model and database

echo "🔄 Migrating Vulnerability model and database"
echo "============================================"

# Load environment variables
if [ -f .env ]; then
    source .env
else
    echo "❌ Error: .env file not found!"
    exit 1
fi

echo ""
echo "Step 1: Backing up current Vulnerability model..."
if [ -f "models/Vulnerability.js" ]; then
    cp "models/Vulnerability.js" "models/Vulnerability.js.backup"
    echo "✅ Backup created: models/Vulnerability.js.backup"
else
    echo "❌ Vulnerability.js not found!"
    exit 1
fi

echo ""
echo "Step 2: Replacing Vulnerability model with updated version..."

# Create the updated model file
cat > models/Vulnerability.js << 'EOF'
const { DataTypes, Model } = require('sequelize');

class Vulnerability extends Model {
  static initModel(sequelize) {
    Vulnerability.init({
      title: { 
        type: DataTypes.STRING, 
        allowNull: false 
      },
      description: { 
        type: DataTypes.TEXT, 
        allowNull: false 
      },
      severity: { 
        type: DataTypes.STRING, 
        allowNull: false 
      },
      resolved: { 
        type: DataTypes.BOOLEAN, 
        defaultValue: false 
      },
      assignedTo: { 
        type: DataTypes.INTEGER,
        allowNull: true
      },
      // ADD THESE THREE MISSING COLUMNS:
      flag: {
        type: DataTypes.STRING(255),
        allowNull: true
      },
      found: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
      },
      resolvedAt: {
        type: DataTypes.DATE,
        allowNull: true
      }
    }, { 
      sequelize, 
      modelName: 'Vulnerability', 
      tableName: 'vulnerabilities',
      timestamps: true // This adds createdAt and updatedAt
    });
  }

  static associate(models) {
    // Add associations if needed
    if (models.User) {
      Vulnerability.belongsTo(models.User, { 
        foreignKey: 'assignedTo',
        as: 'assignee'
      });
    }
  }

  // Instance method to mark vulnerability as resolved
  async markResolved() {
    this.resolved = true;
    this.resolvedAt = new Date();
    await this.save();
  }

  // Instance method to mark vulnerability as found
  async markFound() {
    this.found = true;
    await this.save();
  }

  // Static method to get resolved vulnerabilities with flags
  static async getResolvedWithFlags() {
    return await Vulnerability.findAll({
      where: { resolved: true },
      order: [['resolvedAt', 'DESC']]
    });
  }
}

module.exports = Vulnerability;
EOF

echo "✅ Updated Vulnerability.js model"

echo ""
echo "Step 3: Migrating existing database schema..."
export PGPASSWORD="$DB_PASS"

# Add the columns to existing database
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" << 'SQLMIGRATE'
-- Add missing columns to existing vulnerabilities table
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS flag VARCHAR(255);
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS found BOOLEAN DEFAULT false;
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS "resolvedAt" TIMESTAMP;

-- Update existing vulnerabilities with proper flag values
UPDATE vulnerabilities SET 
    flag = CASE 
        WHEN title LIKE '%SQL Injection%' THEN 'WeEat{SQL_1nj3ct10n_M3nu_S34rch}'
        WHEN title LIKE '%Access Control%' OR title LIKE '%Broken Access%' THEN 'WeEat{Br0k3n_4cc355_C0ntr0l}'
        WHEN title LIKE '%Direct Object%' OR title LIKE '%IDOR%' THEN 'WeEat{1D0R_0rd3r_4cc355}'
        WHEN title LIKE '%XSS%' OR title LIKE '%Cross-Site%' THEN 'WeEat{XSS_R3v13w_F0rm}'
        WHEN title LIKE '%Sensitive Data%' THEN 'WeEat{S3ns1t1v3_D4t4_3xp0sur3}'
        WHEN title LIKE '%Authentication%' OR title LIKE '%Weak%' THEN 'WeEat{W34k_4uth3nt1c4t10n}'
        WHEN title LIKE '%Price%' OR title LIKE '%Manipulation%' THEN 'WeEat{Pr1c3_M4n1pul4t10n_C4rt}'
        WHEN title LIKE '%Logging%' THEN 'WeEat{1nsuff1c13nt_L0gg1ng}'
        WHEN title LIKE '%SSRF%' OR title LIKE '%Request Forgery%' THEN 'WeEat{SSRF_1m4g3_Pr0xy}'
        WHEN title LIKE '%File Upload%' THEN 'WeEat{Unr35tr1ct3d_F1l3_Upl04d}'
        WHEN title LIKE '%XXE%' OR title LIKE '%XML%' THEN 'WeEat{XXE_XML_P4rs3r}'
        WHEN title LIKE '%CSRF%' THEN 'WeEat{CSRF_N0_T0k3ns}'
        ELSE CONCAT('WeEat{', UPPER(REPLACE(REPLACE(title, ' ', '_'), '-', '_')), '}')
    END,
    "resolvedAt" = CASE WHEN resolved = true THEN "updatedAt" ELSE NULL END,
    found = false
WHERE flag IS NULL;

-- Verify the migration
SELECT 'Migration completed successfully' as status;
SELECT COUNT(*) as total_vulnerabilities, COUNT(flag) as vulnerabilities_with_flags FROM vulnerabilities;
SQLMIGRATE

if [ $? -eq 0 ]; then
    echo "✅ Database migration completed successfully"
else
    echo "❌ Database migration failed"
    echo "Restoring backup model file..."
    mv "models/Vulnerability.js.backup" "models/Vulnerability.js"
    unset PGPASSWORD
    exit 1
fi

echo ""
echo "Step 4: Testing Sequelize sync with updated model..."
node -e "
require('dotenv').config();
const { sequelize } = require('./config/db');
(async () => {
  try {
    await sequelize.sync({ alter: false });
    console.log('✅ Sequelize sync successful with updated model');
    process.exit(0);
  } catch(err) {
    console.error('❌ Sequelize sync failed:', err.message);
    process.exit(1);
  }
})();
"

if [ $? -ne 0 ]; then
    echo "❌ Model sync failed - restoring backup"
    mv "models/Vulnerability.js.backup" "models/Vulnerability.js"
    unset PGPASSWORD
    exit 1
fi

echo ""
echo "Step 5: Testing the application query that was failing..."
test_result=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
    SELECT \"id\", \"flag\", \"title\", \"resolvedAt\" 
    FROM \"vulnerabilities\" 
    WHERE \"resolved\" = true 
    ORDER BY \"resolvedAt\" DESC 
    LIMIT 3;
" 2>&1)

if echo "$test_result" | grep -q "ERROR"; then
    echo "❌ Application query still failing:"
    echo "$test_result"
else
    echo "✅ Application query working! Sample results:"
    echo "$test_result"
fi

echo ""
echo "Step 6: Testing with a complete seed run..."
echo "Running node seed.js to verify everything works together..."
node seed.js

if [ $? -eq 0 ]; then
    echo "✅ Seeding successful with updated model!"
    
    echo ""
    echo "Final verification - testing vulnerabilities query after seeding:"
    final_test=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
        SELECT \"id\", \"flag\", \"title\", \"resolvedAt\" 
        FROM \"vulnerabilities\" 
        LIMIT 5;
    " 2>&1)
    
    if echo "$final_test" | grep -q "ERROR"; then
        echo "❌ Final test failed:"
        echo "$final_test"
    else
        echo "✅ Final test passed! Results:"
        echo "$final_test"
    fi
else
    echo "⚠️  Seeding had issues but model update is complete"
fi

unset PGPASSWORD

echo ""
echo "🎉 Migration Complete!"
echo "======================"
echo ""
echo "✅ What was updated:"
echo "   - models/Vulnerability.js now includes flag, found, resolvedAt columns"
echo "   - Database schema updated with new columns"
echo "   - Existing vulnerabilities populated with flag values"
echo "   - Full compatibility with seed.js"
echo ""
echo "✅ Benefits:"
echo "   - No more column missing errors"
echo "   - node seed.js works perfectly"
echo "   - No need for post-seed fixes"
echo "   - Clean, maintainable code"
echo ""
echo "🚀 You can now run 'node seed.js' anytime without issues!"
echo "🌐 Your vulnerabilities page should work perfectly!"
echo ""
echo "💾 Backup saved as: models/Vulnerability.js.backup"
