#!/bin/bash

# WeEat Application Setup Script - SECURE VERSION
# This script reads database credentials from .env file (never hardcoded!)

echo "🍔 WeEat - Vulnerable Web Application Setup"
echo "=========================================="
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js first."
    exit 1
fi

# Check if PostgreSQL is installed
if ! command -v psql &> /dev/null; then
    echo "❌ PostgreSQL is not installed. Please install PostgreSQL first."
    exit 1
fi

echo "✅ Prerequisites check passed"
echo ""

# Load environment variables from .env file SECURELY
if [ -f .env ]; then
    echo "📝 Loading environment variables from .env file..."
    # Source the .env file to load variables into environment
    set -a  # automatically export all variables
    source .env
    set +a  # stop automatically exporting
    echo "   ✓ Environment variables loaded securely"
    
    # Validate required variables exist
    if [[ -z "$DB_NAME" || -z "$DB_USER" || -z "$DB_PASS" || -z "$DB_HOST" || -z "$DB_PORT" ]]; then
        echo "❌ Missing required database configuration in .env file"
        echo "   Required: DB_NAME, DB_USER, DB_PASS, DB_HOST, DB_PORT"
        exit 1
    fi
    
    echo "   Database configuration:"
    echo "   - Host: $DB_HOST:$DB_PORT"
    echo "   - Database: $DB_NAME"
    echo "   - User: $DB_USER"
    echo "   - Password: [HIDDEN for security]"
    
else
    echo "❌ .env file not found. Please create it first with database configuration."
    exit 1
fi

# Install dependencies
echo ""
echo "📦 Installing Node.js dependencies..."
npm install
if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi
echo "   ✓ Dependencies installed"

# Create uploads directory
echo ""
echo "📁 Creating directories..."
mkdir -p uploads/complaints
mkdir -p uploads/profiles
mkdir -p public/images
echo "   ✓ Directories created"

# Database setup using environment variables (SECURE - no hardcoded passwords)
echo ""
echo "🗄️  Setting up PostgreSQL database..."

# Start PostgreSQL if not running
sudo systemctl start postgresql 2>/dev/null || true

# Create database and user using environment variables (SECURE METHOD)
echo "   Creating database and user (credentials from .env file)..."

# Use environment variables in PostgreSQL commands - NO HARDCODED PASSWORDS
sudo -u postgres psql << EOF
-- Create database if it doesn't exist
SELECT 'CREATE DATABASE $DB_NAME' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$DB_NAME')\gexec

-- Create user if it doesn't exist (password from environment variable)
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_user WHERE usename = '$DB_USER') THEN
        EXECUTE 'CREATE USER $DB_USER WITH PASSWORD ''' || '$DB_PASS' || '''';
        RAISE NOTICE 'User $DB_USER created successfully';
    ELSE
        RAISE NOTICE 'User $DB_USER already exists';
    END IF;
END\$\$;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
ALTER USER $DB_USER CREATEDB;

-- Confirm setup
\echo 'Database setup completed successfully'
EOF

if [ $? -eq 0 ]; then
    echo "   ✓ Database setup completed securely"
else
    echo "   ❌ Database setup failed"
    exit 1
fi

# Test database connection using environment variables (SECURE)
echo ""
echo "🔗 Testing database connection..."

# Use PGPASSWORD environment variable (secure method)
export PGPASSWORD="$DB_PASS"
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "SELECT 'Connection successful!' as status;" > /dev/null 2>&1
CONNECTION_RESULT=$?

# Clear password from environment after use (security best practice)
unset PGPASSWORD

if [ $CONNECTION_RESULT -eq 0 ]; then
    echo "   ✓ Database connection successful"
else
    echo "   ❌ Database connection failed."
    echo "   Configuration: Host=$DB_HOST, Port=$DB_PORT, User=$DB_USER, Database=$DB_NAME"
    echo "   Please verify your PostgreSQL setup and .env file settings."
    exit 1
fi

# Seed database
echo ""
echo "🌱 Seeding database with test data and vulnerabilities..."
node seed.js
if [ $? -ne 0 ]; then
    echo "   ❌ Database seeding failed"
    exit 1
fi
echo "   ✓ Database seeded successfully"

# Create missing view files
echo ""
echo "🎨 Creating missing view files..."

# Create error.ejs
mkdir -p views
cat > views/error.ejs << 'EOF'
<%- include('partials/header', { title: 'Error' }) %>

<div class="error-page">
  <h1>❌ <%= error || 'An Error Occurred' %></h1>
  
  <% if (typeof details !== 'undefined' && details) { %>
    <div class="error-details">
      <h3>Error Details:</h3>
      <p><%= details %></p>
    </div>
  <% } %>
  
  <% if (typeof message !== 'undefined' && message) { %>
    <div class="error-message">
      <h3>Message:</h3>
      <p><%= message %></p>
    </div>
  <% } %>
  
  <% if (typeof stack !== 'undefined' && stack) { %>
    <div class="error-stack">
      <details>
        <summary>Stack Trace (Debug Info)</summary>
        <pre><%= stack %></pre>
      </details>
    </div>
  <% } %>
  
  <div class="error-actions">
    <a href="/" class="btn">🏠 Go Home</a>
    <a href="javascript:history.back()" class="btn">⬅️ Go Back</a>
  </div>
</div>

<style>
.error-page { max-width: 800px; margin: 40px auto; padding: 20px; }
.error-details, .error-message, .error-stack { margin: 20px 0; padding: 15px; background: #f8f9fa; border-left: 4px solid #dc3545; border-radius: 4px; }
.btn { display: inline-block; margin: 0 10px; padding: 10px 20px; background: var(--accent-yellow); color: white; text-decoration: none; border-radius: 5px; }
</style>

<%- include('partials/footer') %>
EOF

# Create admin users view
mkdir -p views/admin
cat > views/admin/users.ejs << 'EOF'
<%- include('../partials/header', { title: 'User Management' }) %>

<h1>👤 User Management</h1>

<div class="search-section">
  <form method="GET">
    <input type="text" name="search" placeholder="Search users..." value="<%= search || '' %>">
    <button type="submit">Search</button>
  </form>
</div>

<div class="users-table">
  <table>
    <thead>
      <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Created</th><th>Actions</th></tr>
    </thead>
    <tbody>
      <% users.forEach(user => { %>
        <tr>
          <td><%= user.id %></td>
          <td><%= user.username %></td>
          <td><%= user.email %></td>
          <td><%= user.role %></td>
          <td><%= new Date(user.createdAt).toLocaleDateString() %></td>
          <td>
            <a href="/admin/users/<%= user.id %>">View</a>
            <button onclick="deleteUser(<%= user.id %>)" class="delete-btn">Delete</button>
          </td>
        </tr>
      <% }) %>
    </tbody>
  </table>
</div>

<script>
function deleteUser(userId) {
  if (confirm('Are you sure you want to delete this user?')) {
    fetch(`/admin/users/${userId}`, { method: 'DELETE' })
      .then(response => response.json())
      .then(data => {
        if (data.success) location.reload();
        else alert('Error: ' + data.error);
      });
  }
}
</script>

<%- include('../partials/footer') %>
EOF

echo "   ✓ View files created"

# Final verification using secure method
echo ""
echo "🧪 Running final verification..."
node -e "
require('dotenv').config();
const { sequelize } = require('./config/db');
sequelize.authenticate()
  .then(() => console.log('   ✓ Database connection verified'))
  .catch(err => { console.log('   ❌ Database connection failed:', err.message); process.exit(1); });
" 2>/dev/null

echo ""
echo "🎉 Setup Complete!"
echo ""
echo "🔐 SECURITY NOTES:"
echo "   ✅ Database credentials loaded securely from .env file"
echo "   ✅ No passwords hardcoded in scripts"
echo "   ✅ Environment variables cleared after use"
echo ""
echo "📋 Next Steps:"
echo "1. Start the application:"
echo "   npm start"
echo ""
echo "2. Visit the application:"
echo "   http://localhost:${PORT:-3000}"
echo ""
echo "3. Test accounts:"
echo "   Customer: alice@example.com / alice123"
echo "   Admin: diana@weeat.com / diana123"
echo "   Vulnerable: admin@weeat.com / admin"
echo ""
echo "⚠️  WARNING: This application contains intentional vulnerabilities."
echo "   Only use in isolated testing environments."
echo ""
echo "Happy secure testing! 🕵️‍♂️🔒"
