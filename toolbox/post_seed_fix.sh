#!/bin/bash

# Fix vulnerabilities table columns after seeding

echo "🔧 Adding missing columns to vulnerabilities table after seeding"
echo "============================================================="

# Load environment variables
if [ -f .env ]; then
    source .env
else
    echo "❌ Error: .env file not found!"
    exit 1
fi

export PGPASSWORD="$DB_PASS"

echo "📋 Current vulnerabilities table structure:"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
    SELECT column_name, data_type 
    FROM information_schema.columns 
    WHERE table_name = 'vulnerabilities' 
    ORDER BY ordinal_position;
"

echo ""
echo "➕ Adding missing columns..."

# Add flag column
echo "1. Adding 'flag' column..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
    ALTER TABLE vulnerabilities ADD COLUMN flag VARCHAR(255);
"
if [ $? -eq 0 ]; then
    echo "   ✅ flag column added"
else
    echo "   ⚠️  flag column may already exist"
fi

# Add resolvedAt column
echo "2. Adding 'resolvedAt' column..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
    ALTER TABLE vulnerabilities ADD COLUMN \"resolvedAt\" TIMESTAMP;
"
if [ $? -eq 0 ]; then
    echo "   ✅ resolvedAt column added"
else
    echo "   ⚠️  resolvedAt column may already exist"
fi

# Add found column
echo "3. Adding 'found' column..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
    ALTER TABLE vulnerabilities ADD COLUMN found BOOLEAN DEFAULT false;
"
if [ $? -eq 0 ]; then
    echo "   ✅ found column added"
else
    echo "   ⚠️  found column may already exist"
fi

echo ""
echo "🔄 Updating existing vulnerabilities with proper flag data..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
    UPDATE vulnerabilities SET 
        flag = CASE 
            WHEN title LIKE '%SQL Injection%' THEN 'WeEat{SQL_1nj3ct10n_M3nu_S34rch}'
            WHEN title LIKE '%Access Control%' THEN 'WeEat{Br0k3n_4cc355_C0ntr0l}'
            WHEN title LIKE '%Direct Object%' THEN 'WeEat{1D0R_0rd3r_4cc355}'
            WHEN title LIKE '%XSS%' THEN 'WeEat{XSS_R3v13w_F0rm}'
            WHEN title LIKE '%Sensitive Data%' THEN 'WeEat{S3ns1t1v3_D4t4_3xp0sur3}'
            WHEN title LIKE '%Authentication%' THEN 'WeEat{W34k_4uth3nt1c4t10n}'
            WHEN title LIKE '%Price%' THEN 'WeEat{Pr1c3_M4n1pul4t10n_C4rt}'
            WHEN title LIKE '%Logging%' THEN 'WeEat{1nsuff1c13nt_L0gg1ng}'
            WHEN title LIKE '%SSRF%' THEN 'WeEat{SSRF_1m4g3_Pr0xy}'
            WHEN title LIKE '%File Upload%' THEN 'WeEat{Unr35tr1ct3d_F1l3_Upl04d}'
            WHEN title LIKE '%XXE%' THEN 'WeEat{XXE_XML_P4rs3r}'
            WHEN title LIKE '%CSRF%' THEN 'WeEat{CSRF_N0_T0k3ns}'
            ELSE 'WeEat{G3n3r1c_Vuln3r4b1l1ty}'
        END,
        \"resolvedAt\" = CASE WHEN resolved = true THEN \"updatedAt\" ELSE NULL END
    WHERE flag IS NULL;
"

echo ""
echo "📋 Updated vulnerabilities table structure:"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
    SELECT column_name, data_type 
    FROM information_schema.columns 
    WHERE table_name = 'vulnerabilities' 
    ORDER BY ordinal_position;
"

echo ""
echo "🧪 Testing the application query:"
test_result=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
    SELECT \"id\", \"flag\", \"title\", \"resolvedAt\" 
    FROM \"vulnerabilities\" 
    WHERE \"resolved\" = true 
    ORDER BY \"resolvedAt\" DESC 
    LIMIT 3;
" 2>&1)

if echo "$test_result" | grep -q "ERROR"; then
    echo "❌ Query still failing:"
    echo "$test_result"
else
    echo "✅ Query working! Sample results:"
    echo "$test_result"
fi

echo ""
echo "📊 Vulnerability counts:"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
    SELECT 
        COUNT(*) as total_vulns,
        COUNT(flag) as vulns_with_flags,
        COUNT(CASE WHEN resolved = true THEN 1 END) as resolved_vulns
    FROM vulnerabilities;
"

unset PGPASSWORD

echo ""
echo "🎉 Fix complete! Your vulnerabilities page should now work."
echo ""
echo "💡 Note: After running 'node seed.js', always run this script"
echo "   to add the missing columns that Sequelize doesn't know about."
