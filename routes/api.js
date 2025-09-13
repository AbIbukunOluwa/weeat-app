// routes/api.js - Fixed modern API vulnerabilities
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { User, Order, Food, sequelize } = require('../models');
const { Op } = require('sequelize');
const jwt = require('jsonwebtoken');
const flagManager = require('../utils/flags');

// Modern GraphQL-like query injection
router.post('/v2/query', flagManager.flagMiddleware('SQL_INJECTION'), async (req, res) => {
  try {
    const { query, variables = {} } = req.body;
    
    if (!query) {
      return res.status(400).json({ error: 'Query required' });
    }
    
    let processedQuery = query;
    Object.keys(variables).forEach(key => {
      processedQuery = processedQuery.replace(new RegExp(`\\$${key}`, 'g'), variables[key]);
    });
    
    // Detect SQL injection attempts
    if (processedQuery.includes('UNION') || processedQuery.includes('--') || 
        processedQuery.includes("'") || processedQuery.includes('SELECT')) {
      res.locals.sqlInjectionSuccess = true;
      res.locals.extractedData = 'graphql_injection';
      res.locals.generateFlag = true;
    }
    
    if (processedQuery.includes('SELECT') || processedQuery.includes('select')) {
      const results = await sequelize.query(processedQuery, { 
        type: sequelize.QueryTypes.SELECT 
      });
      res.json({ data: results });
    } else {
      res.json({ error: 'Invalid query type' });
    }
  } catch (err) {
    // SQL errors might indicate successful injection
    if (err.message.includes('syntax') || err.message.includes('relation')) {
      res.locals.sqlInjectionSuccess = true;
      res.locals.extractedData = 'sql_error_graphql';
      res.locals.generateFlag = true;
    }
    
    res.status(500).json({ 
      error: 'Query failed', 
      details: process.env.NODE_ENV === 'development' ? err.message : undefined 
    });
  }
});

// JWT implementation flaws
router.post('/v2/auth/verify', flagManager.flagMiddleware('JWT_BYPASS'), async (req, res) => {
  const { token } = req.body;
  
  if (!token) {
    return res.status(400).json({ error: 'Token required' });
  }
  
  try {
    const decoded = jwt.decode(token, { complete: true });
    
    if (!decoded) {
      return res.status(401).json({ valid: false, error: 'Invalid token format' });
    }
    
    // Check for algorithm confusion attack
    if (decoded.header.alg === 'none' || decoded.header.alg === 'None') {
      res.locals.jwtBypassed = true;
      res.locals.jwtAlgorithm = 'none';
      res.locals.generateFlag = true;
      
      req.session.user = decoded.payload;
      return res.json({ 
        valid: true, 
        user: decoded.payload,
        message: 'Token accepted with none algorithm'
      });
    }
    
    // Check for weak secret
    if (decoded.header.alg === 'HS256') {
      const weakSecrets = ['secret', 'password', 'key', 'jwt', 'test'];
      
      for (const secret of weakSecrets) {
        try {
          const verified = jwt.verify(token, secret);
          res.locals.jwtBypassed = true;
          res.locals.jwtAlgorithm = 'weak_secret';
          res.locals.generateFlag = true;
          
          req.session.user = verified;
          return res.json({ 
            valid: true, 
            user: verified,
            message: 'Token verified with weak secret'
          });
        } catch {
          // Continue to next secret
        }
      }
    }
    
    // Try with actual secret
    const verified = jwt.verify(token, process.env.JWT_SECRET || 'weak-secret-key-2024');
    req.session.user = verified;
    res.json({ valid: true, user: verified });
    
  } catch (err) {
    res.status(401).json({ valid: false, error: 'Token verification failed' });
  }
});

// Race condition vulnerability
const pendingDiscounts = new Map();

router.post('/v2/discount/apply', flagManager.flagMiddleware('RACE_CONDITION'), async (req, res) => {
  const { orderId, code } = req.body;
  const userId = req.session?.user?.id;
  
  if (!userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const discountKey = `${orderId}-${code}-${userId}`;
  const now = Date.now();
  
  // Track concurrent requests for race condition detection
  if (!global.discountRequests) {
    global.discountRequests = new Map();
  }
  
  // Check for race condition (multiple requests within 100ms)
  if (global.discountRequests.has(discountKey)) {
    const lastRequest = global.discountRequests.get(discountKey);
    if (now - lastRequest < 100) {
      res.locals.raceConditionSuccess = true;
      res.locals.raceConditionProof = 'discount_applied_multiple_times';
      res.locals.generateFlag = true;
    }
  }
  
  global.discountRequests.set(discountKey, now);
  
  if (pendingDiscounts.has(discountKey)) {
    return res.status(429).json({ error: 'Discount processing, please wait' });
  }
  
  pendingDiscounts.set(discountKey, true);
  
  // Vulnerable delay creates race condition window
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
router.put('/v2/settings/merge', flagManager.flagMiddleware('PROTOTYPE_POLLUTION'), (req, res) => {
  const { settings } = req.body;
  
  if (!settings || typeof settings !== 'object') {
    return res.status(400).json({ error: 'Settings object required' });
  }
  
  // Check for prototype pollution attempts
  if ('__proto__' in settings || 'constructor' in settings || 'prototype' in settings) {
    res.locals.prototypePolluted = true;
    res.locals.pollutedProperty = Object.keys(settings).join(',');
    res.locals.generateFlag = true;
  }
  
  // Vulnerable merge function
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
  
  // Check if prototype was polluted
  const test = {};
  if (test.isAdmin === true || test.role === 'admin' || test.canExecute === true) {
    res.locals.prototypePolluted = true;
    res.locals.pollutedProperty = 'prototype_chain';
    res.locals.generateFlag = true;
    
    return res.json({ 
      success: true,
      message: 'Settings applied with prototype pollution',
      achievement: 'Prototype pollution successful',
      hint: 'Check /v2/admin/panel'
    });
  }
  
  req.session.settings = userSettings;
  res.json({ success: true, settings: userSettings });
});

// SSTI vulnerability
router.post('/v2/template/render', flagManager.flagMiddleware('RCE'), (req, res) => {
  const { template, data = {} } = req.body;
  
  if (!template) {
    return res.status(400).json({ error: 'Template required' });
  }
  
  if (template.length > 500) {
    return res.status(400).json({ error: 'Template too long' });
  }
  
  // Check for SSTI payloads
  const sstiPatterns = [
    /<%.*?%>/,
    /\{\{.*?\}\}/,
    /\$\{.*?\}/,
    /process\./,
    /require\(/,
    /global\./,
    /constructor/
  ];
  
  if (sstiPatterns.some(pattern => pattern.test(template))) {
    res.locals.rceExecuted = true;
    res.locals.commandOutput = 'ssti_template_injection';
    res.locals.generateFlag = true;
  }
  
  try {
    const ejs = require('ejs');
    const defaultData = {
      user: req.session?.user?.username || 'Guest',
      date: new Date().toLocaleDateString(),
      ...data
    };
    
    // Vulnerable: No sandbox, allows code execution
    const rendered = ejs.render(template, defaultData);
    
    res.json({ 
      success: true, 
      output: rendered,
      engine: 'ejs'
    });
  } catch (err) {
    // Template errors might indicate successful injection
    if (err.message.includes('spawn') || err.message.includes('exec')) {
      res.locals.rceExecuted = true;
      res.locals.commandOutput = 'template_rce_error';
      res.locals.generateFlag = true;
    }
    
    res.status(500).json({ 
      error: 'Render failed',
      message: err.message
    });
  }
});

// NoSQL injection simulation  
router.get('/v2/search/advanced', flagManager.flagMiddleware('SQL_INJECTION'), async (req, res) => {
  const { filter } = req.query;
  
  if (!filter) {
    return res.status(400).json({ error: 'Filter required' });
  }
  
  try {
    let parsedFilter;
    if (typeof filter === 'string') {
      parsedFilter = JSON.parse(filter);
      
      // Check for NoSQL injection patterns
      if (filter.includes('$ne') || filter.includes('$gt') || filter.includes('$regex')) {
        res.locals.sqlInjectionSuccess = true;
        res.locals.extractedData = 'nosql_injection';
        res.locals.generateFlag = true;
      }
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
router.get('/v2/cached/menu/:category', flagManager.flagMiddleware('CACHE_POISONING'), (req, res) => {
  const { category } = req.params;
  const host = req.headers.host || 'localhost';
  const forwarded = req.headers['x-forwarded-host'];
  
  // Check for cache poisoning attempt
  if (forwarded && (forwarded.includes('evil') || forwarded.includes('attacker') || forwarded.includes('malicious'))) {
    res.locals.cachePoisoned = true;
    res.locals.poisonedKey = `menu:${category}:${forwarded}`;
    res.locals.generateFlag = true;
  }
  
  const cacheKey = `menu:${category}:${forwarded || host}`;
  
  res.set('Cache-Control', 'public, max-age=3600');
  res.set('X-Cache-Key', cacheKey);
  
  if (forwarded && forwarded.includes('evil')) {
    return res.json({
      message: 'Cache poisoned successfully',
      redirect: `http://${forwarded}/steal-cookies`,
      poisoned: true
    });
  }
  
  res.json({
    category,
    items: ['item1', 'item2'],
    cached_for: forwarded || host
  });
});

// CORS misconfiguration
router.use('/v2/cors-test', (req, res, next) => {
  const origin = req.headers.origin;
  
  // Vulnerable: Reflects any origin
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

router.get('/v2/cors-test/sensitive', (req, res) => {
  res.json({
    message: 'Sensitive data accessible via CORS',
    user: req.session?.user,
    sessionId: req.sessionID
  });
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

router.post('/v2/order/transition', flagManager.flagMiddleware('BUSINESS_LOGIC'), async (req, res) => {
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
    
    // Check for business logic bypass
    if (bypass === 'emergency' && req.headers['x-support-override'] === 'true') {
      // Skip payment and deliver directly!
      if (currentState === 'pending' && targetState === 'delivered') {
        res.locals.businessLogicBypassed = true;
        res.locals.bypassedLogic = 'payment_skipped';
        res.locals.generateFlag = true;
      }
      
      order.status = targetState;
      await order.save();
      
      return res.json({
        success: true,
        message: 'Order delivered without payment',
        achievement: 'Business logic bypassed',
        newState: targetState
      });
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
router.post('/v2/debug/eval', flagManager.flagMiddleware('RCE'), (req, res) => {
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
  
  // Check for RCE attempts
  if (expression && (expression.includes('require') || expression.includes('process') || 
      expression.includes('fs') || expression.includes('child_process'))) {
    res.locals.rceExecuted = true;
    res.locals.commandOutput = 'eval_rce_attempt';
    res.locals.generateFlag = true;
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

// Credential stuffing helper (timing attack)
router.post('/v2/auth/check-email', async (req, res) => {
  const { email } = req.body;
  
  const user = await User.findOne({ where: { email } });
  
  if (user) {
    // Intentional timing difference
    await new Promise(resolve => setTimeout(resolve, 100));
    res.json({ exists: true });
  } else {
    res.json({ exists: false });
  }
});

// Open redirect vulnerability
router.get('/v2/redirect', flagManager.flagMiddleware('OPEN_REDIRECT'), (req, res) => {
  const { url, target } = req.query;
  const redirectUrl = url || target;
  
  if (!redirectUrl) {
    return res.status(400).json({ error: 'Redirect URL required' });
  }
  
  // Check for open redirect
  if (!redirectUrl.startsWith('/') && (redirectUrl.startsWith('http') || redirectUrl.includes('://'))) {
    res.locals.openRedirectSuccess = true;
    res.locals.redirectUrl = redirectUrl;
    res.locals.generateFlag = true;
  }
  
  // Vulnerable: No validation of redirect URL
  res.redirect(redirectUrl);
});

module.exports = router;
