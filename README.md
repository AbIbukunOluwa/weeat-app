🍔 WeEat - Vulnerable Web Application for Security Testing

 

⚠️ IMPORTANT DISCLAIMER

This application contains INTENTIONAL SECURITY VULNERABILITIES for educational purposes only.

🚫 DO NOT deploy this application to production environments
🚫 DO NOT expose this application to the public internet
✅ ONLY use in isolated, controlled testing environments
✅ ONLY for educational purposes
📋 Overview

WeEat is a deliberately vulnerable food delivery web application designed for:

🎯 Penetration testing practice
📚 Security education and training
🔍 Vulnerability assessment learning
🏆 Capture The Flag (CTF) challenges

The application simulates a real-world food delivery platform with multiple user roles, ordering systems, and various features - all containing carefully crafted security vulnerabilities based on the OWASP Top 10.

🚀 Quick Start
Prerequisites
Node.js (v14 or higher)
PostgreSQL (v12 or higher)
npm (comes with Node.js)
Linux environment (for setup scripts)
Installation
Clone the repository:
git clone https://github.com/AbIbukunOluwa/weeat-app.git
cd weeat-app
Install dependencies:
npm install

   3. Configure your .env file:

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=weeatdb
DB_USER=weeatuser
DB_PASS=your_secure_password_here
DB_SSL=false

# Application Settings
NODE_ENV=development
PORT=3000
SESSION_SECRET=change_this_to_random_string

# Mail Settings (for Mailhog - optional)
MAIL_HOST=localhost
MAIL_PORT=1025
MAIL_FROM=no-reply@weeat.local
Run the setup script:
chmod +x setup.sh
./setup.sh

This will:

Create the PostgreSQL database
Set up all required tables
Create necessary directories
Seed test data
Verify the installation
Start the application:
npm start
Access the application:
http://localhost:3000
👥 Test Accounts
Role	Email	Password	Purpose
Customer	alice@example.com	Alice123!	Regular user testing
Customer	bob@example.com	Bob12345!	Secondary user for IDOR testing
Staff	charlie@weeat.com	Charlie123!	Staff privileges testing
Admin	diana@weeat.com	Diana123!	Full admin access
Admin	admin@weeat.com	Admin123!	Weak credential testing
🏗️ Application Structure
weeat-app/
├── app.js                 # Main application entry point
├── models/               # Sequelize models
│   ├── User.js
│   ├── Order.js
│   ├── Food.js
│   ├── Complaint.js
│   └── ...
├── routes/               # Express routes
│   ├── auth.js          # Authentication endpoints
│   ├── admin.js         # Admin panel
│   ├── menu.js          # Food menu
│   ├── orders.js        # Order management
│   └── ...
├── views/                # EJS templates
│   ├── partials/        # Reusable components
│   ├── admin/           # Admin views
│   └── ...
├── public/               # Static assets
├── uploads/              # User uploads (created on setup)
├── middleware/           # Express middleware
├── utils/                # Utility functions
└── seed.js              # Database seeding script
🎯 Vulnerability Categories

The application includes vulnerabilities from the OWASP Top 10:

SQL Injection - Multiple endpoints with raw SQL queries
Cross-Site Scripting (XSS) - Stored and reflected XSS vulnerabilities
Broken Authentication - Weak passwords, session issues
Insecure Direct Object References (IDOR) - Access control flaws
Security Misconfiguration - Debug info, verbose errors
Sensitive Data Exposure - Information leakage
XML External Entities (XXE) - XML parsing vulnerabilities
Broken Access Control - Privilege escalation paths
Using Components with Known Vulnerabilities - Outdated dependencies
Insufficient Logging & Monitoring - Security event gaps
Additional Vulnerabilities:
CSRF - No token validation on state-changing operations
SSRF - Server-side request forgery in proxy endpoints
Path Traversal - File system access vulnerabilities
File Upload - Unrestricted file upload
Race Conditions - Time-of-check to time-of-use bugs
Business Logic - Price manipulation, workflow bypasses
🔍 Security Testing Challenge
Start at /vulns - the security challenge dashboard
Find and exploit vulnerabilities
Each successful exploit generates a unique flag
Submit flags to track your progress
Try to find all 25+ vulnerabilities!
Flag Format:
WeEat{VULNERABILITY_TYPE_UNIQUE_HASH}
🛠️ Management Commands
Database Management:
# Reset database completely
./setup.sh --reset-db

# Seed fresh test data
node seed.js

# Check system health
node health-check.js

# Sync database schema
node sync.js
🐛 Troubleshooting
Common Issues:

Database connection failed:

Verify PostgreSQL is running: sudo systemctl status postgresql
Check credentials in .env match your PostgreSQL setup
Ensure database exists: psql -U postgres -l

Permission denied errors:

Run: chmod +x setup.sh
Ensure PostgreSQL user has proper privileges

Module not found:

Run: npm install
Delete node_modules and reinstall if needed

Port already in use:

Change port in .env file
Or find and kill the process: lsof -i :3000

Uploads not working:

Ensure upload directories exist: mkdir -p uploads/{avatars,complaints,documents}
Check write permissions: chmod 755 uploads/
🤝 Contributing

This is an educational project. Contributions should:

Add new vulnerability types
Improve existing challenges
Enhance documentation
Fix setup/configuration issues

DO NOT submit fixes for intentional vulnerabilities!

⚖️ Legal Notice

This application is for EDUCATIONAL PURPOSES ONLY.

By using this software, you agree to:

Only use it in authorized, controlled environments
Not deploy it to production or public-facing servers
Take responsibility for any misuse
Follow all applicable laws and regulations

The authors assume no liability for misuse or damage caused by this application.

📝 License

This project is licensed for educational use only. Commercial use is prohibited.

🎮 Game On
Navigate to http://localhost:3000/vulns
Create an account
Start hunting for vulnerabilities!
Each found vulnerability rewards you with a flag
Track your progress on the dashboard

Good luck, and happy hunting! 🎯

Remember: With great power comes great responsibility. Use these skills ethically and always get proper authorization before testing any system you don't own.
