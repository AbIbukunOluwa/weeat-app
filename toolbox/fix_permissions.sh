#!/bin/bash

# Fix PostgreSQL permissions for weeatuser

echo "🔧 Fixing PostgreSQL permissions for weeatuser"
echo "=============================================="

# Load environment variables
if [ -f .env ]; then
    source .env
else
    echo "❌ Error: .env file not found!"
    exit 1
fi

echo "Database: ${DB_NAME}"
echo "User: ${DB_USER}"
echo ""

echo "🔑 Connecting as postgres user to fix permissions..."

# Connect as postgres user and grant proper permissions
sudo -u postgres psql << EOF
-- Connect to the target database
\c ${DB_NAME};

-- Grant all privileges on the database
GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};

-- Grant usage and create on schema public
GRANT USAGE, CREATE ON SCHEMA public TO ${DB_USER};

-- Grant all privileges on all tables in public schema
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ${DB_USER};

-- Grant all privileges on all sequences in public schema  
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ${DB_USER};

-- Grant default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO ${DB_USER};
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO ${DB_USER};

-- Make sure the user can create tables
ALTER USER ${DB_USER} CREATEDB;

-- Verify permissions
SELECT 
    grantee, 
    privilege_type 
FROM information_schema.role_table_grants 
WHERE grantee = '${DB_USER}' 
LIMIT 5;

EOF

if [ $? -eq 0 ]; then
    echo "✅ Permissions fixed successfully!"
    echo ""
    echo "🧪 Testing connection as weeatuser..."
    
    # Test connection and permissions
    export PGPASSWORD="$DB_PASS"
    test_result=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
        CREATE TABLE test_permissions (id SERIAL PRIMARY KEY, test VARCHAR(50));
        DROP TABLE test_permissions;
        SELECT 'Permission test successful' as result;
    " 2>&1)
    
    if echo "$test_result" | grep -q "Permission test successful"; then
        echo "✅ Permission test passed!"
        echo ""
        echo "🚀 You can now run: npm start"
    else
        echo "❌ Permission test failed:"
        echo "$test_result"
    fi
    
    unset PGPASSWORD
else
    echo "❌ Failed to fix permissions"
    exit 1
fi
