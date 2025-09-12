require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const morgan = require('morgan');
const favicon = require('serve-favicon'); 

const { sequelize, pgPool } = require('./config/db');
const { User, Order, Complaint, Vulnerability, Food } = require('./models');

// Routes
const authRoutes = require('./routes/auth');
const ordersRoutes = require('./routes/orders');
const complaintsRoutes = require('./routes/complaints');
const contactRoutes = require('./routes/contact');
const vulnsRoutes = require('./routes/vulns');
const profileRoutes = require('./routes/profile');
const cartRoutes = require('./routes/cart');
const menuRoutes = require('./routes/menu');
const apiRoutes = require('./routes/api');
const aboutRoutes = require('./routes/about');
const uploadRoutes = require('./routes/upload');
const uuidDemoRoutes = require('./routes/uuid-demo');

// Admin and Staff routes
const adminRoutes = require('./routes/admin');
let staffRoutes, dashboardRoutes;
try { staffRoutes = require('./routes/staff'); } catch {}
try { dashboardRoutes = require('./routes/dashboard'); } catch {}

const app = express();

// VULNERABILITY A05: Conditional debug mode (harder to discover)
const isDebugEnabled = (req) => {
  return req.headers['x-weeat-debug'] === 'enable' || 
         req.query.debug_mode === 'on' ||
         req.session?.user?.role === 'admin';
};

if (process.env.NODE_ENV !== 'production') {
  app.set('env', 'development');
  // VULNERABILITY: Only expose pretty printing with specific header
  app.use((req, res, next) => {
    if (req.headers['x-pretty-print'] === 'true') {
      app.locals.pretty = true;
    }
    next();
  });
}

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));

// Views + static
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// VULNERABILITY A09: Conditional verbose logging (requires specific conditions)
app.use(morgan('combined', {
  skip: (req) => {
    // VULNERABILITY: Only log sensitive data with debug header
    return !req.headers['x-verbose-logs'];
  }
}));

// VULNERABILITY A02: Multi-condition sensitive logging
app.use((req, res, next) => {
  if (req.headers['x-weeat-debug'] === 'enable' && req.query.log_level === 'verbose') {
    console.log('🔍 VERBOSE REQUEST LOG:', {
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: req.body,
      sessionID: req.sessionID,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString()
    });
  }
  next();
});

// Sessions with realistic vulnerabilities
app.use(session({
  store: new pgSession({
    pool: pgPool,
    tableName: 'session'
  }),
  secret: process.env.SESSION_SECRET || 'dev-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    httpOnly: true, 
    maxAge: 1000 * 60 * 60 * 8,  // 8 hours
    secure: false  // Set to true in production with HTTPS
  },
  name: 'connect.sid'
}));

// Expose user to views
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.isAuthenticated = !!req.session.user;
  req.user = req.session.user || null;
  
  // Debug info (optional)
  if (req.headers['x-user-debug'] === 'true' && req.session.user) {
    res.locals.userDebug = {
      sessionId: req.sessionID,
      loginTime: req.session.loginTime,
      lastAccess: new Date().toISOString()
    };
  }
  next();
});

// VULNERABILITY A05: Conditional system headers
app.use((req, res, next) => {
  if (req.headers['x-system-info'] === 'show') {
    res.setHeader('X-Node-Version', process.version);
    res.setHeader('X-Platform', process.platform);
    res.setHeader('X-WeEat-Version', '2.1.0');
  }
  
  if (req.headers['x-debug-headers'] === 'on' || isDebugEnabled(req)) {
    res.setHeader('X-Debug-Mode', 'enabled');
    res.setHeader('X-Database-Name', process.env.DB_NAME || 'weeatdb');
    res.setHeader('X-Environment', process.env.NODE_ENV || 'development');
  }
  
  next();
});

// Modern API vulnerabilities
app.use('/api', apiRoutes);

// Routes
app.get('/', async (req, res) => {
  try {
    // Load some food items for the homepage
    const foods = await Food.findAll({ 
      limit: 8,
      where: { status: 'active' },
      order: [['createdAt', 'DESC']]
    });
    
    res.render('index', { 
      title: 'WeEat - Fast Food Delivery',
      user: req.session.user || null,
      foods: foods
    });
  } catch (err) {
    console.error('Homepage error:', err);
    res.render('index', { 
      title: 'WeEat - Fast Food Delivery',
      user: req.session.user || null,
      foods: []
    });
  }
});

// Legal pages
app.get('/privacy', (req, res) => {
  res.render('privacy', {
    title: 'Privacy Policy - WeEat',
    user: req.session.user || null
  });
});

app.get('/terms', (req, res) => {
  res.render('terms', {
    title: 'Terms of Service - WeEat',
    user: req.session.user || null
  });
});

// Placeholder routes for footer links
app.get('/careers', (req, res) => {
  res.render('error', {
    error: 'Careers page coming soon!',
    title: 'Careers - WeEat',
    user: req.session.user || null,
    details: 'Check back later for exciting opportunities to join the WeEat team.'
  });
});

app.get('/franchise', (req, res) => {
  res.render('error', {
    error: 'Franchise opportunities coming soon!',
    title: 'Franchise - WeEat',
    user: req.session.user || null,
    details: 'Interested in opening a WeEat location? Contact us at franchise@weeat.com'
  });
});

app.get('/help', (req, res) => {
  res.redirect('/contact');
});

app.get('/faq', (req, res) => {
  res.redirect('/contact');
});

// Public routes
app.use('/auth', authRoutes);
app.use('/contact', contactRoutes);
app.use('/about', aboutRoutes);
app.use('/profile', profileRoutes);

// Protected routes
app.use('/orders', ordersRoutes);
app.use('/complaints', complaintsRoutes);
app.use('/vulns', vulnsRoutes);
app.use('/profile', profileRoutes);
app.use('/cart', cartRoutes);
app.use('/menu', menuRoutes);
app.use('/uuid-demo', uuidDemoRoutes);

// Advanced vulnerability routes
app.use('/reviews', require('./routes/reviews'));
app.use('/xxe', require('./routes/xxe'));
app.use('/deserialization', require('./routes/deserialization'));  
app.use('/csrf', require('./routes/csrf'));

// Admin routes
app.use('/admin', adminRoutes);

// Optional routes
if (dashboardRoutes) app.use('/dashboard', dashboardRoutes);
if (staffRoutes) app.use('/staff', staffRoutes);

// VULNERABILITY A10: Multi-condition SSRF
app.get('/proxy/image', async (req, res) => {
  try {
    const { url, proxy_auth } = req.query;
    
    if (!url) {
      return res.status(400).json({ error: 'URL parameter required' });
    }

    // VULNERABILITY: Auth bypass for internal URLs
    const isInternal = url.includes('127.0.0.1') || url.includes('localhost') || url.includes('192.168.');
    if (isInternal && proxy_auth !== 'internal-2024') {
      return res.status(403).json({ error: 'Internal URLs require authentication' });
    }

    const fetch = require('node-fetch');
    
    // VULNERABILITY: Additional headers expose more functionality
    const headers = {
      'User-Agent': req.headers['x-custom-ua'] || 'WeEat-ImageProxy/1.0'
    };
    
    if (req.headers['x-forward-auth']) {
      headers['Authorization'] = req.headers['x-forward-auth'];
    }

    const response = await fetch(url, {
      timeout: req.headers['x-timeout'] ? parseInt(req.headers['x-timeout']) : 5000,
      headers
    });

    if (!response.ok) {
      return res.status(response.status).json({ 
        error: 'Failed to fetch image',
        // VULNERABILITY: Expose response details with debug header
        details: req.headers['x-proxy-debug'] === 'true' ? {
          status: response.status,
          statusText: response.statusText,
          headers: Object.fromEntries(response.headers.entries())
        } : undefined
      });
    }

    const buffer = await response.buffer();
    const contentType = response.headers.get('content-type') || 'application/octet-stream';
    
    res.set('Content-Type', contentType);
    
    // VULNERABILITY: Include debug info in response headers
    if (req.headers['x-proxy-debug'] === 'true') {
      res.set('X-Source-URL', url);
      res.set('X-Source-Size', buffer.length.toString());
      res.set('X-Fetch-Time', new Date().toISOString());
    }
    
    res.send(buffer);

  } catch (err) {
    console.error('Image proxy error:', err);
    res.status(500).json({ 
      error: 'Proxy error',
      details: req.headers['x-proxy-debug'] === 'true' ? err.message : undefined,
      url: req.headers['x-proxy-debug'] === 'true' ? req.query.url : undefined
    });
  }
});

app.get('/api/user/:identifier', async (req, res) => {
  try {
    const { identifier } = req.params;
    const user = await User.findByIdentifier(identifier);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // VULNERABILITY: Different response based on identifier type
    const isUuid = identifier.length === 36 && identifier.includes('-');
    
    let response = {
      identifier: identifier,
      identifierType: isUuid ? 'uuid' : 'id',
      username: user.username,
      role: user.role
    };
    
    // VULNERABILITY: More info for UUID-based requests
    if (isUuid) {
      response.uuid = user.uuid;
      response.active = user.active;
      response.lastLogin = user.lastLogin;
    }
    
    res.json(response);
    
  } catch (err) {
    res.status(500).json({ error: 'User lookup failed' });
  }
});

// VULNERABILITY A04: Multi-step password reset
app.post('/auth/reset-password', async (req, res) => {
  try {
    const { email, newPassword, reset_token, bypass_token } = req.body;
    
    // VULNERABILITY: Multiple bypass mechanisms
    const isEmailBypass = req.headers['x-email-verified'] === 'true';
    const isTokenBypass = reset_token === 'emergency-reset-2024';
    const isInternalBypass = bypass_token === 'internal-support' && req.headers['x-support-access'] === 'true';
    
    if (!isEmailBypass && !isTokenBypass && !isInternalBypass) {
      return res.status(400).json({ 
        error: 'Password reset requires verification',
        hint: req.headers['x-debug-hints'] === 'true' ? 'Try different verification methods' : undefined
      });
    }
    
    const user = await User.findOne({ where: { email } });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // VULNERABILITY: Skip rate limiting with bypass header
    if (req.headers['x-skip-ratelimit'] !== 'admin-override') {
      // Simple rate limiting (easily bypassed)
      // In real implementation, this would be more robust
    }

    await user.setPassword(newPassword);
    await user.save();

    // VULNERABILITY: Enhanced logging with debug mode
    if (isDebugEnabled(req)) {
      console.log(`🔐 Password reset details:`, {
        email,
        method: isEmailBypass ? 'email' : isTokenBypass ? 'token' : 'internal',
        timestamp: new Date(),
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
    }

    res.json({ 
      success: true, 
      message: 'Password reset successful',
      // VULNERABILITY: Conditional user data exposure
      user: req.headers['x-return-userdata'] === 'true' ? {
        id: user.id,
        email: user.email,
        role: user.role,
        username: user.username
      } : undefined
    });
  } catch (err) {
    console.error('Password reset error:', err);
    res.status(500).json({ 
      error: err.message,
      stack: isDebugEnabled(req) ? err.stack : undefined
    });
  }
});

// VULNERABILITY A03: Advanced SQL injection with multiple conditions
app.get('/api/search', async (req, res) => {
  const { 
    q: query, 
    table = 'foods', 
    field = 'name', 
    sort = 'id',
    order = 'ASC',
    limit = 10
  } = req.query;
  
  if (!query) {
    return res.status(400).json({ error: 'Query parameter required' });
  }
  
  try {
    // VULNERABILITY: Multiple injection points
    let sqlQuery = `SELECT * FROM ${table} WHERE ${field} ILIKE '%${query}%'`;
    
    // VULNERABILITY: Additional parameters also injectable
    if (req.query.filter) {
      sqlQuery += ` AND ${req.query.filter}`;
    }
    
    sqlQuery += ` ORDER BY ${sort} ${order} LIMIT ${limit}`;
    
    const results = await sequelize.query(sqlQuery, { type: sequelize.QueryTypes.SELECT });
    
    res.json({
      results,
      count: results.length,
      // VULNERABILITY: Query exposure with specific conditions
      debug: (req.headers['x-sql-debug'] === 'true' || isDebugEnabled(req)) ? { 
        query: sqlQuery,
        parameters: req.query,
        execution_time: '12ms'
      } : undefined
    });
  } catch (err) {
    res.status(500).json({ 
      error: 'Search failed',
      details: (req.headers['x-sql-debug'] === 'true' || isDebugEnabled(req)) ? {
        message: err.message,
        code: err.code,
        query: `SELECT * FROM ${req.query.table || 'foods'} WHERE ${req.query.field || 'name'} ILIKE '%${req.query.q}%'`
      } : undefined
    });
  }
});

// VULNERABILITY: Hidden administrative endpoints (requires discovery)
app.get('/api/v1/system/status', (req, res) => {
  // VULNERABILITY: Multi-condition access
  const hasApiKey = req.headers['x-api-key'] === 'weeat-internal-2024';
  const hasUserAgent = req.get('User-Agent')?.includes('WeEat-Monitor');
  const hasValidToken = req.query.token === 'status-check-token';
  
  if (!hasApiKey || !hasUserAgent || !hasValidToken) {
    return res.status(404).json({ error: 'Endpoint not found' });
  }
  
  res.json({
    status: 'operational',
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    database: {
      connected: true,
      // VULNERABILITY: Database info with additional parameter
      details: req.query.include_db_info === 'yes' ? {
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        name: process.env.DB_NAME,
        user: process.env.DB_USER
      } : undefined
    }
  });
});

app.get('/api/order/:identifier', async (req, res) => {
  try {
    const { identifier } = req.params;
    const order = await Order.findByIdentifier(identifier);
    
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    // VULNERABILITY: No authorization check
    res.json(order.getOrderSummary());
    
  } catch (err) {
    res.status(500).json({ error: 'Order lookup failed' });
  }
});

app.get('/api/migration-status', (req, res) => {
  res.json({
    status: 'partial',
    message: 'UUID migration in progress',
    features: {
      uuidSupport: true,
      legacyIdSupport: true,
      mixedMode: true
    },
    endpoints: {
      userLookup: '/uuid-demo/api/user-lookup/:uuid',
      orderDetails: '/uuid-demo/api/order-details/:orderUuid',
      uuidGeneration: '/uuid-demo/api/generate-test-uuid',
      bulkValidation: '/uuid-demo/api/validate-uuids',
      accountRecovery: '/uuid-demo/api/account-recovery',
      statistics: '/uuid-demo/api/uuid-stats'
    },
    vulnerabilities: [
      'UUID enumeration via timing attacks',
      'Predictable UUID generation patterns',
      'Information disclosure via UUID-based lookups',
      'Weak account recovery using UUID patterns',
      'Bulk UUID validation without rate limiting'
    ]
  });
});

app.get('/api/v1/admin/config', async (req, res) => {
  // VULNERABILITY: Complex multi-step authentication
  const auth = req.headers.authorization?.replace('Bearer ', '');
  const signature = req.headers['x-config-signature'];
  const timestamp = req.headers['x-timestamp'];
  
  if (auth !== 'admin-config-token-2024') {
    return res.status(401).json({ error: 'Invalid token' });
  }
  
  if (signature !== 'config-access-signature-v2') {
    return res.status(401).json({ error: 'Invalid signature' });
  }
  
  // VULNERABILITY: Time-based bypass (allows requests within last 5 minutes)
  const now = Date.now();
  const requestTime = parseInt(timestamp);
  if (!timestamp || (now - requestTime > 300000)) { // 5 minutes
    return res.status(401).json({ error: 'Request expired' });
  }
  
  const configSection = req.query.section;
  
  if (configSection === 'database') {
    res.json({
      database: {
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        database: process.env.DB_NAME,
        user: process.env.DB_USER,
        // VULNERABILITY: Password exposed with additional verification
        password: req.query.verify_admin === 'true' && req.headers['x-admin-verify'] === 'confirmed' 
          ? process.env.DB_PASS 
          : '[PROTECTED]'
      }
    });
  } else if (configSection === 'session') {
    res.json({
      session: {
        secret: req.headers['x-show-secrets'] === 'true' ? process.env.SESSION_SECRET : '[PROTECTED]',
        store: 'postgresql',
        maxAge: '8 hours'
      }
    });
  } else {
    res.json({
      available_sections: ['database', 'session'],
      hint: 'Use ?section=database or ?section=session'
    });
  }
});

// VULNERABILITY A05: Conditional error handler (realistic corporate behavior)
app.use((err, req, res, next) => {
  console.error('Global error handler:', err);
  
  // VULNERABILITY: Role-based and condition-based information disclosure
  const isAdmin = req.session?.user?.role === 'admin';
  const isDebugMode = isDebugEnabled(req);
  const isInternalRequest = req.headers['x-internal-request'] === 'true';
  
  let errorResponse = {
    error: 'An internal error occurred',
    timestamp: new Date().toISOString(),
    requestId: Math.random().toString(36).substring(7)
  };

  // VULNERABILITY: Escalating information disclosure
  if (isDebugMode || isInternalRequest) {
    errorResponse.error = err.message;
    errorResponse.url = req.url;
    errorResponse.method = req.method;
  }
  
  if (isAdmin && isDebugMode) {
    errorResponse.stack = err.stack;
    errorResponse.session = req.session;
    errorResponse.headers = req.headers;
    errorResponse.body = req.body;
  }
  
  // VULNERABILITY: Maximum disclosure for specific conditions
  if (isAdmin && req.headers['x-full-debug'] === 'true' && req.query.show_env === '1') {
    errorResponse.env = process.env;
    errorResponse.cwd = process.cwd();
    errorResponse.nodeVersion = process.version;
    errorResponse.platform = process.platform;
  }

  if (req.accepts('json')) {
    res.status(500).json(errorResponse);
  } else {
    res.status(500).render('error', {
      error: errorResponse.error,
      details: isDebugMode ? err.message : null,
      stack: isAdmin && isDebugMode ? err.stack : null,
      title: 'Error - WeEat',
      req: isAdmin && req.headers['x-full-debug'] === 'true' ? req : undefined
    });
  }
});

// Database connection and server start
(async () => {
  try {
    await sequelize.authenticate();
    console.log('✅ Database connected successfully');
    
    await sequelize.sync();
    console.log('📊 Database synced');
    
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`🍔 WeEat running on http://localhost:${PORT}`);
      console.log('🚨 Professional-grade vulnerability testing environment');
      
      if (process.env.NODE_ENV !== 'production') {
        console.log('\n🎯 Advanced Testing Endpoints (require discovery):');
        console.log('   🔍 /api/search - Multi-parameter SQL injection');
        console.log('   🔍 /api/v1/system/status - Hidden admin endpoint');
        console.log('   🔍 /api/v1/admin/config - Complex authentication bypass');
        console.log('   🔍 /proxy/image - Advanced SSRF with conditions');
        
        console.log('\n🔧 Discovery Headers:');
        console.log('   X-WeEat-Debug: enable');
        console.log('   X-System-Info: show');
        console.log('   X-SQL-Debug: true');
        console.log('   X-Proxy-Debug: true');
        
        console.log('\n📋 Professional Test Accounts:');
        console.log('   Customer: alice@example.com / alice123');
        console.log('   Admin: admin@weeat.com / admin');
        
        console.log('\n⚠️  Vulnerabilities now require real penetration testing skills!');
      }
    });
  } catch (err) {
    console.error('❌ Failed to start server:', err);
    process.exit(1);
  }
})();
