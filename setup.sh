#!/bin/bash

# WeEat Application Setup Script - COMPLETE WORKING VERSION
# All credentials read from .env file

echo "🍔 WeEat - Vulnerable Web Application Setup"
echo "=========================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }

# Check prerequisites
if ! command -v node &> /dev/null; then
    print_error "Node.js is not installed. Please install Node.js first."
    exit 1
fi

if ! command -v psql &> /dev/null; then
    print_error "PostgreSQL is not installed. Please install PostgreSQL first."
    exit 1
fi

print_success "Prerequisites check passed"
echo ""

# Load environment variables from .env file
if [ -f .env ]; then
    echo "📝 Loading environment variables from .env file..."
    set -a
    source .env
    set +a
    print_success "Environment variables loaded from .env"
    
    # Display loaded configuration (without password)
    echo "   Database configuration:"
    echo "   - Host: ${DB_HOST}"
    echo "   - Port: ${DB_PORT}"
    echo "   - Database: ${DB_NAME}"
    echo "   - User: ${DB_USER}"
    echo "   - Password: [HIDDEN]"
    
    # Validate required variables
    if [[ -z "$DB_NAME" || -z "$DB_USER" || -z "$DB_PASS" || -z "$DB_HOST" || -z "$DB_PORT" ]]; then
        print_error "Missing required database configuration in .env file"
        echo "   Required variables: DB_NAME, DB_USER, DB_PASS, DB_HOST, DB_PORT"
        exit 1
    fi
else
    print_error ".env file not found!"
    echo ""
    
    # Create .env.example if it doesn't exist
    if [ ! -f .env.example ]; then
        echo "Creating .env.example template file..."
        
        cat > .env.example << 'EOF'
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=weeatdb
DB_USER=weeatuser
DB_PASS=CHANGE_THIS_PASSWORD
DB_SSL=false

# Application Settings
NODE_ENV=development
PORT=3000
SESSION_SECRET=CHANGE_THIS_SECRET

# Mail Settings (for Mailhog)
MAIL_HOST=localhost
MAIL_PORT=1025
MAIL_FROM=no-reply@weeat.local

# Security Settings (intentionally weak for testing)
JWT_SECRET=weak-secret-key-2024
FLAG_SALT=vulnerability-testing-salt
EOF
        
        print_success "Created .env.example template"
    fi
    
    echo "👉 To continue, you need to create a .env file:"
    echo ""
    echo "  cp .env.example .env     # Copy the template"
    echo "  nano .env                # Edit with your credentials"
    echo ""
    echo "Then run this script again."
    exit 1
fi

# Parse command line arguments
RESET_DB=false
SKIP_SEED=false
FORCE_RESET=false

for arg in "$@"; do
    case $arg in
        --reset-db)
            RESET_DB=true
            ;;
        --skip-seed)
            SKIP_SEED=true
            ;;
        --force)
            FORCE_RESET=true
            ;;
        --help)
            echo "Usage: ./setup.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --reset-db   Drop and recreate database (DESTRUCTIVE)"
            echo "  --skip-seed  Skip seeding test data"
            echo "  --force      Don't ask for confirmation"
            echo "  --help       Show this help message"
            exit 0
            ;;
    esac
done

# Install dependencies
echo ""
echo "📦 Installing Node.js dependencies..."
npm install
if [ $? -ne 0 ]; then
    print_error "Failed to install dependencies"
    exit 1
fi
print_success "Dependencies installed"

# Create directories
echo ""
echo "📁 Creating directories..."
mkdir -p uploads/{complaints,avatars,documents,profiles,xml,backups,misc,secure,custom,extracted}
mkdir -p public/images
mkdir -p views/{admin,partials}
mkdir -p logs
print_success "Directories created"

# Database setup
echo ""
echo "🗄️  Setting up PostgreSQL database..."

# Start PostgreSQL if not running
sudo systemctl start postgresql 2>/dev/null || true

# Check if database exists (using credentials from .env)
export PGPASSWORD="$DB_PASS"
DB_EXISTS=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -lqt 2>/dev/null | cut -d \| -f 1 | grep -qw "$DB_NAME" && echo "true" || echo "false")

if [ "$DB_EXISTS" = "true" ] && [ "$RESET_DB" = false ] && [ "$FORCE_RESET" = false ]; then
    print_warning "Database '${DB_NAME}' already exists"
    echo ""
    read -p "Do you want to: [U]pdate schema only, [R]eset completely, or [C]ancel? (U/R/C): " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Rr]$ ]]; then
        RESET_DB=true
    elif [[ $REPLY =~ ^[Cc]$ ]]; then
        echo "Setup cancelled."
        exit 0
    fi
    # Default is Update (U)
fi

# Create or reset database (using credentials from .env)
if [ "$RESET_DB" = true ] || [ "$DB_EXISTS" = "false" ]; then
    echo "Setting up database using credentials from .env..."
    
    # Use environment variables from .env file
    sudo -u postgres psql << EOF 2>/dev/null
-- Drop database if resetting
$([ "$RESET_DB" = true ] && echo "DROP DATABASE IF EXISTS ${DB_NAME};")

-- Create database if not exists
CREATE DATABASE ${DB_NAME};

-- Create or update user (using password from .env)
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_user WHERE usename = '${DB_USER}') THEN
        CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';
    ELSE
        ALTER USER ${DB_USER} WITH PASSWORD '${DB_PASS}';
    END IF;
END\$\$;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};
ALTER USER ${DB_USER} CREATEDB;
EOF
    
    if [ $? -eq 0 ]; then
        print_success "Database setup complete using .env credentials"
    else
        print_error "Database setup failed. Check your PostgreSQL permissions."
        echo "You may need to manually create the database and user."
        exit 1
    fi
fi

# Test connection with .env credentials
echo ""
echo "🔗 Testing database connection..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 1;" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    print_success "Database connection successful"
else
    print_error "Database connection failed"
    echo "Connection details from .env:"
    echo "  Host: ${DB_HOST}"
    echo "  Port: ${DB_PORT}"
    echo "  Database: ${DB_NAME}"
    echo "  User: ${DB_USER}"
    unset PGPASSWORD
    exit 1
fi

# ============================================
# FIX POSTGRESQL PERMISSIONS
# ============================================
echo ""
echo "🔑 Setting up proper PostgreSQL permissions..."

sudo -u postgres psql << EOF 2>/dev/null
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
EOF

if [ $? -eq 0 ]; then
    print_success "PostgreSQL permissions configured"
else
    print_warning "Permission setup had issues but continuing..."
fi

# Test permissions
echo "🧪 Testing table creation permissions..."
test_result=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
    CREATE TABLE IF NOT EXISTS test_permissions (id SERIAL PRIMARY KEY);
    DROP TABLE IF EXISTS test_permissions;
    SELECT 'Permission test successful' as result;
" 2>&1)

if echo "$test_result" | grep -q "Permission test successful"; then
    print_success "Permission test passed"
else
    print_error "Permission test failed - you may have issues with table creation"
    echo "Test result: $test_result"
fi

# Create/Update all tables with proper schema
echo ""
echo "📊 Setting up/updating database schema..."

echo "Setting up complete database schema..."
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" << 'SCHEMA'
-- Session table for Express sessions
CREATE TABLE IF NOT EXISTS session (
    sid VARCHAR NOT NULL COLLATE "default",
    sess JSON NOT NULL,
    expire TIMESTAMP(6) NOT NULL,
    CONSTRAINT session_pkey PRIMARY KEY (sid)
) WITH (OIDS=FALSE);
CREATE INDEX IF NOT EXISTS IDX_session_expire ON session(expire);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    "passwordHash" VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'customer',
    avatar VARCHAR(255),
    bio TEXT,
    phone VARCHAR(50),
    active BOOLEAN DEFAULT true,
    "lastLogin" TIMESTAMP,
    "loginCount" INTEGER DEFAULT 0,
    "createdAt" TIMESTAMP DEFAULT NOW(),
    "updatedAt" TIMESTAMP DEFAULT NOW()
);

-- Add UUID column if it doesn't exist (for migration)
ALTER TABLE users ADD COLUMN IF NOT EXISTS uuid UUID DEFAULT gen_random_uuid();

-- Orders table
CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT gen_random_uuid(),
    "orderNumber" VARCHAR(255) UNIQUE,
    "userId" INTEGER REFERENCES users(id) ON DELETE CASCADE,
    items TEXT NOT NULL,
    "totalAmount" FLOAT NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    "discountApplied" BOOLEAN DEFAULT false,
    "cancellationReason" TEXT,
    "cancelledAt" TIMESTAMP,
    "deliveryAddress" TEXT,
    "deliveryInstructions" TEXT,
    "estimatedDelivery" TIMESTAMP,
    "actualDelivery" TIMESTAMP,
    "customerRating" INTEGER,
    "customerComment" TEXT,
    "createdAt" TIMESTAMP DEFAULT NOW(),
    "updatedAt" TIMESTAMP DEFAULT NOW()
);

-- Add UUID column if it doesn't exist
ALTER TABLE orders ADD COLUMN IF NOT EXISTS uuid UUID DEFAULT gen_random_uuid();

-- Complaints table
CREATE TABLE IF NOT EXISTS complaints (
    id SERIAL PRIMARY KEY,
    "userId" INTEGER REFERENCES users(id) ON DELETE CASCADE,
    "orderId" VARCHAR(255),
    details TEXT NOT NULL,
    photo VARCHAR(255),
    category VARCHAR(50) DEFAULT 'other',
    urgent BOOLEAN DEFAULT false,
    "contactMethod" VARCHAR(50) DEFAULT 'email',
    likes INTEGER DEFAULT 0,
    resolved BOOLEAN DEFAULT false,
    "resolvedAt" TIMESTAMP,
    "resolvedBy" INTEGER,
    escalated BOOLEAN DEFAULT false,
    "escalationReason" TEXT,
    "escalatedAt" TIMESTAMP,
    "escalatedBy" INTEGER,
    "createdAt" TIMESTAMP DEFAULT NOW(),
    "updatedAt" TIMESTAMP DEFAULT NOW()
);

-- Foods table
CREATE TABLE IF NOT EXISTS foods (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    image VARCHAR(255) NOT NULL,
    price FLOAT NOT NULL,
    category VARCHAR(50) DEFAULT 'mains',
    description TEXT,
    status VARCHAR(50) DEFAULT 'active',
    cost_price FLOAT,
    supplier_info TEXT,
    internal_notes TEXT,
    "createdAt" TIMESTAMP DEFAULT NOW(),
    "updatedAt" TIMESTAMP DEFAULT NOW()
);

-- Reviews table
CREATE TABLE IF NOT EXISTS reviews (
    id SERIAL PRIMARY KEY,
    "foodId" INTEGER REFERENCES foods(id) ON DELETE CASCADE,
    "userId" INTEGER REFERENCES users(id) ON DELETE CASCADE,
    rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
    title VARCHAR(255) NOT NULL,
    comment TEXT NOT NULL,
    approved BOOLEAN DEFAULT false,
    anonymous BOOLEAN DEFAULT false,
    "createdAt" TIMESTAMP DEFAULT NOW(),
    "updatedAt" TIMESTAMP DEFAULT NOW()
);

-- Vulnerabilities table with ALL required columns (INCLUDING flag, resolvedAt, found)
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(50) DEFAULT 'medium',
    resolved BOOLEAN DEFAULT false,
    "assignedTo" INTEGER,
    flag VARCHAR(255),
    found BOOLEAN DEFAULT false,
    "resolvedAt" TIMESTAMP,
    "createdAt" TIMESTAMP DEFAULT NOW(),
    "updatedAt" TIMESTAMP DEFAULT NOW()
);

-- CartItems table
CREATE TABLE IF NOT EXISTS "CartItems" (
    id SERIAL PRIMARY KEY,
    "userId" INTEGER REFERENCES users(id) ON DELETE CASCADE,
    "foodName" VARCHAR(255) NOT NULL,
    price FLOAT NOT NULL,
    quantity INTEGER DEFAULT 1,
    "createdAt" TIMESTAMP DEFAULT NOW(),
    "updatedAt" TIMESTAMP DEFAULT NOW()
);

-- Contact messages table
CREATE TABLE IF NOT EXISTS contact_messages (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    "createdAt" TIMESTAMP DEFAULT NOW(),
    "updatedAt" TIMESTAMP DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_orders_userid ON orders("userId");
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
CREATE INDEX IF NOT EXISTS idx_complaints_userid ON complaints("userId");
CREATE INDEX IF NOT EXISTS idx_reviews_foodid ON reviews("foodId");
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_resolved ON vulnerabilities(resolved);

SCHEMA

if [ $? -eq 0 ]; then
    print_success "Database schema setup complete"
else
    print_error "Schema setup failed"
    unset PGPASSWORD
    exit 1
fi

# ============================================
# ENSURE VULNERABILITIES TABLE HAS ALL COLUMNS
# ============================================
echo ""
echo "🔧 Ensuring vulnerabilities table has all required columns..."

# Add missing columns if they don't exist (safer approach)
echo "Adding any missing columns to vulnerabilities table..."

psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" << 'VULNFIX'
-- Add flag column if missing
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS flag VARCHAR(255);

-- Add resolvedAt column if missing  
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS "resolvedAt" TIMESTAMP;

-- Add found column if missing
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS found BOOLEAN DEFAULT false;

-- Update existing resolved vulnerabilities with timestamp
UPDATE vulnerabilities 
SET "resolvedAt" = "updatedAt" 
WHERE resolved = true AND "resolvedAt" IS NULL;
VULNFIX

if [ $? -eq 0 ]; then
    print_success "Vulnerabilities table columns ensured"
else
    print_warning "Vulnerabilities table update had issues but continuing..."
fi

# Verify the fix by testing the problematic query
echo "🧪 Testing the application query that was failing..."
test_result=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "
    SELECT \"id\", \"flag\", \"title\", \"resolvedAt\" 
    FROM \"vulnerabilities\" AS \"Vulnerability\" 
    WHERE \"Vulnerability\".\"resolved\" = true 
    ORDER BY \"Vulnerability\".\"resolvedAt\" DESC 
    LIMIT 1;
" 2>&1)

if echo "$test_result" | grep -q "ERROR"; then
    print_error "Vulnerabilities table query still failing"
    echo "Query error: $test_result"
    echo ""
    echo "🔧 Trying manual column addition..."
    
    # Try direct column addition
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "ALTER TABLE vulnerabilities ADD COLUMN flag VARCHAR(255);" 2>/dev/null
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "ALTER TABLE vulnerabilities ADD COLUMN \"resolvedAt\" TIMESTAMP;" 2>/dev/null
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "ALTER TABLE vulnerabilities ADD COLUMN found BOOLEAN DEFAULT false;" 2>/dev/null
    
    print_warning "Manual column addition attempted - try npm start to test"
else
    print_success "Vulnerabilities table query test passed!"
fi

# Clean up password from environment
unset PGPASSWORD

# Sync Sequelize models (but don't alter tables since we manage schema manually)
echo ""
echo "🔄 Syncing Sequelize models..."
node -e "
require('dotenv').config();
const { sequelize } = require('./config/db');
(async () => {
  try {
    await sequelize.sync({ alter: false }); // Don't alter, we handle schema manually
    console.log('✅ Models synced');
    process.exit(0);
  } catch(err) {
    console.error('Sync error:', err.message);
    process.exit(1);
  }
})();
" || print_warning "Model sync had issues but continuing..."

# Seed database
if [ "$SKIP_SEED" = false ]; then
    echo ""
    echo "🌱 Seeding database with test data..."
    node seed.js
    if [ $? -eq 0 ]; then
        print_success "Database seeded successfully"
    else
        print_warning "Seeding failed, but setup can continue"
        echo "You can try seeding later with: node seed.js"
    fi
fi

# Create missing view files
echo ""
echo "🎨 Checking view files..."
if [ ! -f views/error.ejs ]; then
    mkdir -p views
    cat > views/error.ejs << 'EOF'
<%- include('partials/header', { title: 'Error' }) %>
<div class="error-page">
  <h1>❌ <%= error || 'An Error Occurred' %></h1>
  <% if (typeof details !== 'undefined' && details) { %>
    <div class="error-details">
      <p><%= details %></p>
    </div>
  <% } %>
  <div class="error-actions">
    <a href="/" class="btn">Go Home</a>
    <a href="javascript:history.back()" class="btn">Go Back</a>
  </div>
</div>
<%- include('partials/footer') %>
EOF
    print_success "Created error.ejs"
fi

# Run health check
echo ""
echo "🏥 Running health check..."
node health-check.js 2>/dev/null || {
    print_warning "Health check reported some issues (this is normal on first setup)"
}

# Final summary
echo ""
echo "=========================================="
print_success "Setup Complete!"
echo "=========================================="
echo ""
echo "📋 Configuration used from .env:"
echo "  Database: ${DB_NAME} on ${DB_HOST}:${DB_PORT}"
echo "  User: ${DB_USER}"
echo "  App Port: ${PORT:-3000}"
echo ""
echo "🚀 Quick Start:"
echo "  npm start                    # Start the application"
echo ""
echo "🌐 Access:"
echo "  http://localhost:${PORT:-3000}"
echo ""
echo "👤 Test Accounts:"
echo "  Customer: alice@example.com / Alice123!"
echo "  Admin: admin@weeat.com / Admin123!"
echo ""
echo "🛠️ Management Commands:"
echo "  ./setup.sh --reset-db        # Full database reset"
echo "  ./setup.sh --skip-seed       # Setup without test data"
echo "  node seed.js                 # Re-seed test data"
echo "  node reset-full.js           # Reset to pristine state"
echo "  node health-check.js         # Check system health"
echo ""
echo "🔧 If you still have column errors:"
echo "  ./add_missing_columns.sh     # Manual column fix"
echo ""
echo "⚠️  WARNING: This application contains intentional vulnerabilities."
echo "   Only use in isolated testing environments!"
