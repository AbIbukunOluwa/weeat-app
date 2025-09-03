require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');

const sequelize = require('./models');      // Sequelize instance (SQLite)
const User = require('./models/User');      // Ensure models load
const Complaint = require('./models/Complaint');
const Vulnerability = require('./models/Vulnerability');

// Routes
const authRoutes = require('./routes/auth');
const dashboardRoutes = require('./routes/dashboard');
const complaintsRoutes = require('./routes/complaints');
const vulnsRoutes = require('./routes/vulns');
const staffRoutes = require('./routes/staff');

const app = express();

// Views + static
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Sessions (memory store for dev)
app.use(session({
  secret: process.env.SESSION_SECRET || 'supersecret',
  resave: false,
  saveUninitialized: false
}));

// Expose user to views
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// Routes
app.get('/', (_req, res) => res.render('index', { title: 'WeEat', user: _req.session.user }));
app.use('/auth', authRoutes);
app.use('/dashboard', dashboardRoutes);
app.use('/complaints', complaintsRoutes);
app.use('/vulns', vulnsRoutes);
app.use('/staff', staffRoutes);

// DB + start
(async () => {
  await sequelize.sync();
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`WeEat running on http://localhost:${PORT}`));
})();
