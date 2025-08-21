require('dotenv').config();
const path = require('path');
const express = require('express');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);

const { sequelize, pgPool } = require('./config/db');
const { User } = require('./models/User');           

// ROUTES
const authRoutes = require('./routes/auth');
const contactRoutes = require('./routes/contact');
const complaintRoutes = require('./routes/complaint');
const workerRoutes = require('./routes/worker');

const app = express();
const PORT = process.env.PORT || 3000;

// view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// middleware
app.use(morgan('dev'));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// sessions stored in Postgres
app.use(session({
  store: new pgSession({
    pool: pgPool,
    tableName: 'session',
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET || 'dev_secret_change_me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 7 days
}));

// static assets
app.use('/public', express.static(path.join(__dirname, 'public')));

// public pages
app.get('/', (req, res) => res.render('home', { title: 'WeEat — Home' }));
app.get('/about', (req, res) => res.render('about', { title: 'About WeEat' }));
app.get('/menu', (req, res) => res.render('menu', { title: 'Menu' }));

// ROUTE GROUPS
app.use('/auth', authRoutes);         // login, register, logout
app.use('/contact', contactRoutes);   // contact form
app.use('/complaint', complaintRoutes); // file/image upload complaints
app.use('/worker', workerRoutes);     // cooks, delivery drivers portal

// healthcheck
app.get('/health', (_req, res) => res.json({ ok: true }));

// boot
(async () => {
  try {
    await sequelize.authenticate();
    console.log('DB connected');
    app.listen(PORT, () => console.log(`WeEat running on http://localhost:${PORT}`));
  } catch (err) {
    console.error('Failed to start app:', err);
    process.exit(1);
  }
})();
