// routes/api.js - Modern API vulnerabilities (2024-style attacks)
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { User, Order, Food, sequelize } = require('../models');
const jwt = require('jsonwebtoken');
const flagManager = require('../utils/flags');

// Modern GraphQL-like query injection
router.post('/v2/query', async (req, res) => {
  try {
    const { query, variables = {} } = req.body;
    
    if (!query) {
      return res.status(400).json({ error: 'Query required' });
    }
    
    let processedQuery = query;
    Object.keys(variables).forEach(key => {
      processedQuery = processedQuery.replace(new RegExp(`\\$${key}`, 'g'), variables[key]);
    });
    
    if (processedQuery.includes('SELECT') || processedQuery.includes('select')) {
      const results = await sequelize.query(processedQuery, { 
        type: sequelize.QueryTypes.SELECT 
      });
      res.json({ data: results });
    } else {
      res.json({ error: 'Invalid query type' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Query failed', details: process.env.NODE_ENV === 'development' ? err.message : undefined });
  }
});

// JWT implementation flaws
router.post('/v2/auth/verify', async (req, res) => {
  const { token } = req.body;
  
  if (!token) {
    return res.status(400).json({ error: 'Token required' });
  }
  
  try {
    const decoded = jwt.decode(token, { complete: true });
    
    if (!decoded) {
      return res.status(401).json({ valid: false, error: 'Invalid token format' });
    }
    
    if (decoded.header.alg === 'none' || decoded.header.alg === 'None') {
      req.session.user = decoded.payload;
      return res.json({ 
        valid: true, 
        user: decoded.payload,
        message: 'Token accepted'
      });
    }
    
    if (decoded.header.alg === 'HS256') {
      const publicKey = 'public';
      try {
        const verified = jwt.verify(token, publicKey);
        req.session.user = verified;
        return res.json({ valid: true, user: verified });
      } catch {
        // Try with actual secret
      }
    }
    
    const verified = jwt.verify(token, process.env.JWT_SECRET || 'weak-secret-key-2024');
    req.session.user = verified;
    res.json({ valid: true, user: verified });
    
  } catch (err) {
    res.status(401).json({ valid: false, error: 'Token verification failed' });
  }
});

// Race condition vulnerability
const pendingDiscounts = new Map();

router.post('/v2/discount/apply', async (req, res) => {
  const { orderId, code } = req.body;
  const userId = req.session?.user?.id;
  
  if (!userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const discountKey = `${orderId}-${code}`;
  
  if (pendingDiscounts.has(discountKey)) {
    return res.status(429).json({ error: 'Discount processing, please wait' });
  }
  
  pendingDiscounts.set(discountKey, true);
  
  setTimeout(async () => {
    try {
      const order = await Order.findOne({ where: { id: orderId, userId } });
      
      if (!order) {
        pendingDiscounts.delete(discountKey);
        return res.status(404).json({ error: 'Order not found' });
      }
      
      const discounts = {
        'FLASH20': 0.20,
        'MEGA30': 0.30,
        'ULTIMATE50': 0.50
      };
      
      if (discounts[code]) {
        const discount = order.totalAmount * discounts[code];
        order.totalAmount -= discount;
        order.discountApplied = true;
        await order.save();
        
        pendingDiscounts.delete(discountKey);
        
        res.json({ 
          success: true,
          discount: discount,
          newTotal: order.totalAmount,
          processTime: Date.now()
        });
      } else {
        pendingDiscounts.delete(discountKey);
        res.status(400).json({ error: 'Invalid discount code' });
      }
    } catch (err) {
      pendingDiscounts.delete(discountKey);
      res.status(500).json({ error: 'Processing failed' });
    }
  }, 100);
});

// Prototype pollution endpoint
router.put('/v2/settings/merge', (req, res) => {
  const { settings } = req.body;
  
  if (!settings || typeof settings !== 'object') {
    return res.status(400).json({ error: 'Settings object required' });
  }
  
  function merge(target, source) {
    for (const key in source) {
      if (source.hasOwnProperty(key)) {
        if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
          target[key] = target[key] || {};
          merge(target[key], source[key]);
        } else {
          target[key] = source[key];
        }
      }
    }
    return target;
  }
  
  const userSettings = {};
  merge(userSettings, settings);
  
  const test = {};
  if (test.isAdmin === true || test.role === 'admin') {
    return res.json({ 
      success: true,
      message: 'Settings applied',
      achievement: 'Prototype pollution successful',
      hint: 'Check /v2/admin/panel'
    });
  }
  
  req.session.settings = userSettings;
  res.json({ success: true, settings: userSettings });
});

// SSTI vulnerability
router.post('/v2/template/render', async (req, res) => {
  const { template, data = {} } = req.body;
  
  if (!template) {
    return res.status(400).json({ error: 'Template required' });
  }
  
  if (template.length > 500) {
    return res.status(400).json({ error: 'Template too long' });
  }
  
  try {
    const ejs = require('ejs');
    const defaultData = {
      user: req.session?.user?.username || 'Guest',
      date: new Date().toLocaleDateString(),
      ...data
    };
    
    const rendered = ejs.render(template, defaultData);
    
    res.json({ 
      success: true, 
      output: rendered,
      engine: 'ejs'
    });
  } catch (err) {
    res.status(500).json({ 
      error: 'Render failed',
      message: err.message
    });
  }
});

// NoSQL injection simulation
router.get('/v2/search/advanced', async (req, res) => {
  const { filter } = req.query;
  
  if (!filter) {
    return res.status(400).json({ error: 'Filter required' });
  }
  
  try {
    let parsedFilter;
    if (typeof filter === 'string') {
      parsedFilter = JSON.parse(filter);
    } else {
      parsedFilter = filter;
    }
    
    const query = {};
    if (parsedFilter.name) {
      query.name = parsedFilter.name;
    }
    if (parsedFilter.price) {
      if (parsedFilter.price.$gt !== undefined) {
        query.price = { [Op.gt]: parsedFilter.price.$gt };
      }
      if (parsedFilter.price.$lt !== undefined) {
        query.price = { [Op.lt]: parsedFilter.price.$lt };
      }
    }
    
    const results = await Food.findAll({ where: query });
    res.json({ results, count: results.length });
    
  } catch (err) {
    res.status(500).json({ error: 'Search failed' });
  }
});

// Cache poisoning vulnerability
router.get('/v2/cached/menu/:category', (req, res) => {
  const { category } = req.params;
  const host = req.headers.host || 'localhost';
  const forwarded = req.headers['x-forwarded-host'];
  
  const cacheKey = `menu:${category}:${forwarded || host}`;
  
  res.set('Cache-Control', 'public, max-age=3600');
  res.set('X-Cache-Key', cacheKey);
  
  if (forwarded && forwarded.includes('evil')) {
    res.set('X-Poisoned', 'true');
    return res.json({
      message: 'Cache poisoned',
      redirect: `http://${forwarded}/steal-cookies`
    });
  }
  
  res.json({
    category,
    items: ['item1', 'item2'],
    cached_for: host
  });
});

// CORS misconfiguration
router.use('/v2/*', (req, res, next) => {
  const origin = req.headers.origin;
  
  if (origin) {
    res.set('Access-Control-Allow-Origin', origin);
    res.set('Access-Control-Allow-Credentials', 'true');
  }
  
  if (req.method === 'OPTIONS') {
    res.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.set('Access-Control-Allow-Headers', req.headers['access-control-request-headers']);
    return res.sendStatus(200);
  }
  
  next();
});

// Business logic bypass
const orderStates = {
  'pending': ['confirmed', 'cancelled'],
  'confirmed': ['preparing', 'cancelled'],
  'preparing': ['ready'],
  'ready': ['delivering'],
  'delivering': ['delivered'],
  'delivered': [],
  'cancelled': []
};

router.post('/v2/order/transition', async (req, res) => {
  const { orderId, targetState, bypass } = req.body;
  
  if (!req.session?.user) {
    return res.status(401).json({ error: 'Login required' });
  }
  
  try {
    const order = await Order.findOne({ 
      where: { 
        id: orderId, 
        userId: req.session.user.id 
      } 
    });
    
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    const currentState = order.status || 'pending';
    const allowedTransitions = orderStates[currentState] || [];
    
    if (bypass === 'emergency' && req.headers['x-support-override'] === 'true') {
      order.status = targetState;
      await order.save();
      
      if (targetState === 'delivered' && currentState === 'pending') {
        return res.json({
          success: true,
          message: 'Order delivered without payment',
          achievement: 'Business logic bypassed'
        });
      }
    }
    
    if (!allowedTransitions.includes(targetState)) {
      return res.status(400).json({ 
        error: 'Invalid state transition',
        current: currentState,
        allowed: allowedTransitions
      });
    }
    
    order.status = targetState;
    await order.save();
    
    res.json({ 
      success: true, 
      newState: targetState,
      timestamp: Date.now()
    });
    
  } catch (err) {
    res.status(500).json({ error: 'Transition failed' });
  }
});

// Information disclosure via error messages
router.post('/v2/debug/eval', (req, res) => {
  const { expression, key } = req.body;
  
  const debugKey = crypto.createHash('md5')
    .update('debug-2024')
    .digest('hex');
  
  if (key !== debugKey) {
    return res.status(403).json({ 
      error: 'Invalid debug key',
      hint: 'MD5 of debug-YEAR'
    });
  }
  
  try {
    const result = eval(expression);
    res.json({ result: String(result) });
  } catch (err) {
    res.status(500).json({ 
      error: err.message,
      stack: err.stack
    });
  }
});

// Credential stuffing helper (intentional timing attack)
router.post('/v2/auth/check-email', async (req, res) => {
  const { email } = req.body;
  
  const user = await User.findOne({ where: { email } });
  
  if (user) {
    await new Promise(resolve => setTimeout(resolve, 100));
    res.json({ exists: true });
  } else {
    res.json({ exists: false });
  }
});

// Path traversal in dynamic route loading
router.get('/v2/modules/:module/:action', (req, res) => {
  const { module, action } = req.params;
  
  const allowedModules = ['user', 'food', 'order'];
  
  if (!allowedModules.includes(module)) {
    const modulePath = `../../modules/${module}/${action}`;
    try {
      const moduleFunc = require(modulePath);
      if (typeof moduleFunc === 'function') {
        return moduleFunc(req, res);
      }
    } catch (err) {
      return res.status(404).json({ error: 'Module not found' });
    }
  }
  
  res.json({ module, action, available: true });
});

// JWT vulnerability
router.post('/v2/auth/verify', flagManager.flagMiddleware('JWT_BYPASS'), async (req, res) => {
  const { token } = req.body;
  
  if (!token) {
    return res.status(400).json({ error: 'Token required' });
  }
  
  try {
    const decoded = jwt.decode(token, { complete: true });
    
    if (!decoded) {
      return res.status(401).json({ valid: false });
    }
    
    // Check for algorithm confusion attack
    if (decoded.header.alg === 'none' || decoded.header.alg === 'None') {
      res.locals.jwtBypassed = true;
      res.locals.jwtAlgorithm = 'none';
      res.locals.generateFlag = true;
      
      req.session.user = decoded.payload;
      return res.json({ valid: true, user: decoded.payload });
    }
    
    // Check for weak secret
    if (decoded.header.alg === 'HS256') {
      try {
        // Try with weak secret
        const verified = jwt.verify(token, 'secret');
        res.locals.jwtBypassed = true;
        res.locals.jwtAlgorithm = 'weak_secret';
        res.locals.generateFlag = true;
        
        return res.json({ valid: true, user: verified });
      } catch {
        // Try with actual secret
      }
    }
    
    const verified = jwt.verify(token, process.env.JWT_SECRET || 'weak-secret-key-2024');
    res.json({ valid: true, user: verified });
    
  } catch (err) {
    res.status(401).json({ valid: false });
  }
});

// Race condition in discount application
router.post('/v2/discount/apply', flagManager.flagMiddleware('RACE_CONDITION'), async (req, res) => {
  const { orderId, code } = req.body;
  const userId = req.session?.user?.id;
  
  if (!userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  // Track concurrent requests
  if (!global.discountRequests) {
    global.discountRequests = new Map();
  }
  
  const requestKey = `${orderId}-${code}-${userId}`;
  const now = Date.now();
  
  // Check for race condition (multiple requests within 100ms)
  if (global.discountRequests.has(requestKey)) {
    const lastRequest = global.discountRequests.get(requestKey);
    if (now - lastRequest < 100) {
      res.locals.raceConditionSuccess = true;
      res.locals.raceConditionProof = 'discount_applied_multiple_times';
      res.locals.generateFlag = true;
    }
  }
  
  global.discountRequests.set(requestKey, now);
  
  // Vulnerable to race condition - no locking mechanism
  setTimeout(async () => {
    try {
      const order = await Order.findOne({ where: { id: orderId, userId } });
      
      if (order && !order.discountApplied) {
        order.discountApplied = true;
        order.totalAmount *= 0.8; // 20% discount
        await order.save();
        
        res.json({ success: true, newTotal: order.totalAmount });
      } else {
        res.status(400).json({ error: 'Discount already applied' });
      }
    } catch (err) {
      res.status(500).json({ error: 'Processing failed' });
    }
  }, 50); // Delay creates race condition window
});

// Business logic bypass
router.post('/v2/order/transition', flagManager.flagMiddleware('BUSINESS_LOGIC'), async (req, res) => {
  const { orderId, targetState, bypass } = req.body;
  
  if (!req.session?.user) {
    return res.status(401).json({ error: 'Login required' });
  }
  
  try {
    const order = await Order.findOne({ 
      where: { id: orderId, userId: req.session.user.id } 
    });
    
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    // Check for business logic bypass
    if (bypass === 'emergency' && req.headers['x-support-override'] === 'true') {
      // Skip payment and deliver directly!
      if (order.status === 'pending' && targetState === 'delivered') {
        res.locals.businessLogicBypassed = true;
        res.locals.bypassedLogic = 'payment_skipped';
        res.locals.generateFlag = true;
      }
      
      order.status = targetState;
      await order.save();
      
      return res.json({
        success: true,
        message: 'Order state changed',
        newState: targetState
      });
    }
    
    // Normal state transitions...
    res.json({ success: true, newState: order.status });
    
  } catch (err) {
    res.status(500).json({ error: 'Transition failed' });
  }
});

// Cache poisoning
router.get('/v2/cached/menu/:category', flagManager.flagMiddleware('CACHE_POISONING'), (req, res) => {
  const { category } = req.params;
  const host = req.headers.host || 'localhost';
  const forwarded = req.headers['x-forwarded-host'];
  
  // Check for cache poisoning attempt
  if (forwarded && (forwarded.includes('evil') || forwarded.includes('attacker'))) {
    res.locals.cachePoisoned = true;
    res.locals.poisonedKey = `menu:${category}:${forwarded}`;
    res.locals.generateFlag = true;
  }
  
  const cacheKey = `menu:${category}:${forwarded || host}`;
  
  res.set('Cache-Control', 'public, max-age=3600');
  res.set('X-Cache-Key', cacheKey);
  
  if (forwarded && forwarded.includes('evil')) {
    return res.json({
      message: 'Cache poisoned',
      redirect: `http://${forwarded}/steal-cookies`
    });
  }
  
  res.json({
    category,
    items: ['item1', 'item2'],
    cached_for: forwarded || host
  });
});

module.exports = router;
