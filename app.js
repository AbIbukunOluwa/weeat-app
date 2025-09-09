require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const morgan = require('morgan');

const { sequelize, pgPool } = require('./config/db');
const { User, Order, Complaint, Vulnerability } = require('./models');

// Routes
const authRoutes = require('./routes/auth');
const ordersRoutes = require('./routes/orders');
const complaintsRoutes = require('./routes/complaints');
const contactRoutes = require('./routes/contact');
const vulnsRoutes = require('./routes/vulns');
const profileRoutes = require('./routes/profile');
const cartRoutes = require('./routes/cart');

let staffRoutes, dashboardRoutes;
try { staffRoutes = require('./routes/staff'); } catch {}
try { dashboardRoutes = require('./routes/dashboard'); } catch {}

const app = express();

// Views + static
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(morgan('dev'));

// Sessions (Postgres store)
app.use(session({
  store: new pgSession({
    pool: pgPool,
    tableName: 'session'
  }),
  secret: process.env.SESSION_SECRET || 'dev-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 * 8 }
}));

// Expose user to views
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// Routes
app.get('/', (req, res) => res.render('index', { title: 'WeEat' }));
app.use('/auth', authRoutes);
app.use('/orders', ordersRoutes);
app.use('/complaints', complaintsRoutes);
app.use('/contact', contactRoutes);
app.use('/vulns', vulnsRoutes);
app.use('/profile', profileRoutes);
app.use('/cart', cartRoutes);

if (dashboardRoutes) app.use('/dashboard', dashboardRoutes);
if (staffRoutes) app.use('/staff', staffRoutes);

// DB + start
(async () => {
  await sequelize.authenticate();
  await sequelize.sync();
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`WeEat running on http://localhost:${PORT}`));
})();
