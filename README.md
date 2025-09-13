# 🍔 WeEat - Vulnerable Web Application for Security Testing

[![Node.js](https://img.shields.io/badge/Node.js-v14+-green.svg)](https://nodejs.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-v12+-blue.svg)](https://www.postgresql.org/)
[![License](https://img.shields.io/badge/License-Educational-yellow.svg)](LICENSE)

## ⚠️ IMPORTANT DISCLAIMER

**This application contains INTENTIONAL SECURITY VULNERABILITIES for educational purposes only.**

- 🚫 **DO NOT** deploy this application to production environments
- 🚫 **DO NOT** expose this application to the public internet
- ✅ **ONLY** use in isolated, controlled testing environments
- ✅ **ONLY** for educational purposes

## 📋 Overview

WeEat is a deliberately vulnerable food delivery web application designed for:
- 🎯 Penetration testing practice
- 📚 Security education and training
- 🔍 Vulnerability assessment learning
- 🏆 Capture The Flag (CTF) challenges

The application simulates a real-world food delivery platform with multiple user roles, ordering systems, and various features - all containing carefully crafted security vulnerabilities based on the OWASP Top 10.

## 🚀 Quick Start

### Prerequisites

- **Node.js** (v14 or higher)
- **PostgreSQL** (v12 or higher)
- **npm** (comes with Node.js)
- **Git**
- Linux/macOS/WSL environment (for setup scripts)

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/AbIbukunOluwa/weeat-app.git
cd weeat-app
```

2. **Install dependencies:**
```bash
npm install
```

3. **Configure your `.env` file:**
```env
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

```

5. **Run the setup script:**
```bash
chmod +x setup.sh
./setup.sh
```

This will:
- Create the PostgreSQL database
- Set up all required tables
- Create necessary directories
- Seed test data
- Verify the installation

6. **Start the application:**
```bash
npm start
```

7. **Access the application:**
```
http://localhost:3000
```

## 🏗️ Application Structure

```
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
```

## 🎯 Vulnerability Categories

The application includes vulnerabilities from the OWASP Top 10:

1. **SQL Injection** - Multiple endpoints with raw SQL queries
2. **Cross-Site Scripting (XSS)** - Stored and reflected XSS vulnerabilities
3. **Broken Authentication** - Weak passwords, session issues
4. **Insecure Direct Object References (IDOR)** - Access control flaws
5. **Security Misconfiguration** - Debug info, verbose errors
6. **Sensitive Data Exposure** - Information leakage
7. **XML External Entities (XXE)** - XML parsing vulnerabilities
8. **Broken Access Control** - Privilege escalation paths
9. **Using Components with Known Vulnerabilities** - Outdated dependencies
10. **Insufficient Logging & Monitoring** - Security event gaps

### Additional Vulnerabilities:
- **CSRF** 
- **SSRF** 
- **Path Traversal**
- **File Upload**
- **Race Conditions** 
- **Business Logic**

## 🔍 Security Testing Challenge

1. Start at `/vulns` - the security challenge dashboard
2. Find and exploit vulnerabilities
3. Each successful exploit generates a unique flag
4. Submit flags to track your progress
5. Try to find all 25+ vulnerabilities!

### Flag Format:
```
WeEat{VULNERABILITY_TYPE_UNIQUE_HASH}
```

## 🛠️ Management Commands

### Database Management:
```bash
# Reset database completely
./setup.sh --reset-db

# Seed fresh test data
node seed.js

# Check system health
node health-check.js

# Sync database schema
node sync.js
```

```

## 🐛 Troubleshooting

### Common Issues:

1. **Database connection failed:**
   - Verify PostgreSQL is running: `sudo systemctl status postgresql`
   - Check credentials in `.env` match your PostgreSQL setup
   - Ensure database exists: `psql -U postgres -l`

2. **Permission denied errors:**
   - Run: `chmod +x setup.sh`
   - Ensure PostgreSQL user has proper privileges

3. **Module not found:**
   - Run: `npm install`
   - Delete `node_modules` and reinstall if needed

4. **Port already in use:**
   - Change port in `.env` file
   - Or find and kill the process: `lsof -i :3000`

5. **Uploads not working:**
   - Ensure upload directories exist: `mkdir -p uploads/{avatars,complaints,documents}`
   - Check write permissions: `chmod 755 uploads/`


## 🤝 Contributing

This is an educational project. Contributions should:
- Add new vulnerability types
- Improve existing challenges
- Enhance documentation
- Fix setup/configuration issues

**DO NOT** submit fixes for intentional vulnerabilities!


## ⚖️ Legal Notice

This application is for **EDUCATIONAL PURPOSES ONLY**. 

By using this software, you agree to:
- Only use it in authorized, controlled environments
- Not deploy it to production or public-facing servers
- Take responsibility for any misuse
- Follow all applicable laws and regulations

The authors assume no liability for misuse or damage caused by this application.

## 📝 License

This project is licensed for educational use only. Commercial use is prohibited.

---

## 🎮 Game On


1. Navigate to `http://localhost:3000/vulns`
2. Create an account or login
3. Start hunting for vulnerabilities!
4. Each found vulnerability rewards you with a flag
5. Track your progress on the dashboard

Good luck, and happy hunting! 🎯

---

**Remember:** With great power comes great responsibility. Use these skills ethically and always get proper authorization before testing any system you don't own.
