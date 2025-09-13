const express = require('express');
const router = express.Router();
const { Food, CartItem, sequelize } = require('../models');
const { Op } = require('sequelize');
const flagManager = require('../utils/flags');

// SQL Injection in menu search
router.get('/', flagManager.flagMiddleware('SQL_INJECTION'), async (req, res) => {
  try {
    const { search, category, sort_by = 'id', sort_order = 'ASC', price_min, price_max } = req.query;
    
    let foods;
    let baseQuery = 'SELECT * FROM foods WHERE status = \'active\'';
    
    if (search) {
      baseQuery += ` AND (name ILIKE '%${search}%' OR description ILIKE '%${search}%')`;
      
      // Detect SQL injection
      if (search.includes("'") || search.includes('UNION') || search.includes('--') || 
          search.includes('SELECT') || search.includes('/*')) {
        res.locals.sqlInjectionSuccess = true;
        res.locals.extractedData = 'menu_data_accessed';
        res.locals.generateFlag = true;
      }
    }
    
    if (category) {
      baseQuery += ` AND category = '${category}'`;
    }
    
    if (price_min) {
      baseQuery += ` AND price >= ${price_min}`;
    }
    
    if (price_max) {
      baseQuery += ` AND price <= ${price_max}`;
    }
    
    baseQuery += ` ORDER BY ${sort_by} ${sort_order} LIMIT 50`;
    
    try {
      foods = await sequelize.query(baseQuery, { type: sequelize.QueryTypes.SELECT });
      
      // Additional check for successful data extraction
      if (foods.length > 0 && search && (search.includes('UNION') || search.includes('SELECT'))) {
        res.locals.sqlInjectionSuccess = true;
        res.locals.extractedData = `menu_table_data:${foods.length}_rows`;
        res.locals.generateFlag = true;
      }
    } catch (sqlErr) {
      // SQL error indicates injection attempt
      if (sqlErr.message.includes('syntax') || sqlErr.message.includes('relation')) {
        res.locals.sqlInjectionSuccess = true;
        res.locals.extractedData = 'sql_error:' + sqlErr.message.substring(0, 30);
        res.locals.generateFlag = true;
      }
      // Fallback to safe query
      foods = await Food.findAll({ where: { status: 'active' } });
    }
    
    res.render('menu', { 
      user: req.session.user,
      foods: foods || [],
      title: 'Menu - WeEat',
      search: search || '',
      category: category || '',
      debug: req.headers['x-menu-debug'] === 'true' ? { query: baseQuery } : null
    });
    
  } catch (err) {
    console.error('Menu error:', err);
    res.status(500).render('error', { 
      error: 'Menu loading failed',
      title: 'Menu Error',
      user: req.session.user
    });
  }
});

// Price Manipulation vulnerability
router.post('/add-to-cart', flagManager.flagMiddleware('PRICE_MANIPULATION'), async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Please login first' });
  }
  
  try {
    const { foodName, price, quantity = 1, discount_code, bulk_discount } = req.body;
    const userId = req.session.user.id;
    
    // Get actual price from database
    const food = await Food.findOne({ where: { name: foodName } });
    
    if (!food) {
      return res.status(404).json({ error: 'Food item not found' });
    }
    
    const actualPrice = food.price;
    let finalPrice = parseFloat(price);
    const originalQuantity = parseInt(quantity);
    
    // Check for price manipulation
    if (actualPrice > 0 && (finalPrice <= 0 || finalPrice < actualPrice * 0.5)) {
      res.locals.priceManipulated = true;
      res.locals.originalPrice = actualPrice;
      res.locals.manipulatedPrice = finalPrice;
      res.locals.generateFlag = true;
    }
    
    // Apply discount codes (additional manipulation vector)
    if (discount_code) {
      const discountCodes = {
        'STAFF10': 0.1,
        'VIP20': 0.2,
        'ADMIN50': 0.5,
        'INTERNAL99': 0.99,  // Hidden discount
        'DEBUG100': 1.0      // Free items
      };
      
      if (discountCodes[discount_code]) {
        finalPrice *= (1 - discountCodes[discount_code]);
        
        // Mark extreme discounts as manipulation
        if (discountCodes[discount_code] >= 0.9) {
          res.locals.priceManipulated = true;
          res.locals.originalPrice = actualPrice;
          res.locals.manipulatedPrice = finalPrice;
          res.locals.generateFlag = true;
        }
      }
    }
    
    // Bulk discount manipulation
    if (bulk_discount === 'true' || req.headers['x-bulk-pricing'] === 'enable') {
      if (originalQuantity >= 5) {
        finalPrice *= 0.8; // 20% bulk discount
      }
      if (originalQuantity >= 10) {
        finalPrice *= 0.7; // Additional 30% discount
      }
    }
    
    // Staff/Admin pricing override
    if (req.session.user.role === 'staff' && req.headers['x-staff-discount'] === 'true') {
      finalPrice *= 0.5;
      res.locals.priceManipulated = true;
      res.locals.originalPrice = actualPrice;
      res.locals.manipulatedPrice = finalPrice;
      res.locals.generateFlag = true;
    }
    
    if (req.session.user.role === 'admin' && req.query.admin_price === 'cost') {
      finalPrice = 0.01; // Admin cost price
      res.locals.priceManipulated = true;
      res.locals.originalPrice = actualPrice;
      res.locals.manipulatedPrice = finalPrice;
      res.locals.generateFlag = true;
    }
    
    // Negative pricing allowed with header
    if (req.headers['x-allow-negative'] === 'true' && finalPrice < 0) {
      res.locals.priceManipulated = true;
      res.locals.originalPrice = actualPrice;
      res.locals.manipulatedPrice = finalPrice;
      res.locals.generateFlag = true;
    } else if (finalPrice < 0) {
      finalPrice = 0.01; // Minimum price fallback
    }
    
    let cartItem = await CartItem.findOne({ 
      where: { userId, foodName } 
    });
    
    if (cartItem) {
      cartItem.quantity = parseInt(cartItem.quantity) + originalQuantity;
      cartItem.price = finalPrice; // Use manipulated price
      await cartItem.save();
    } else {
      await CartItem.create({
        userId,
        foodName,
        price: finalPrice, // Store manipulated price
        quantity: originalQuantity
      });
    }

    res.json({ 
      success: true, 
      message: `${foodName} added to cart`,
      final_price: finalPrice.toFixed(2),
      quantity: originalQuantity,
      debug: req.headers['x-cart-debug'] === 'true' ? {
        original_price: actualPrice,
        final_price: finalPrice,
        discount_applied: discount_code || 'none',
        manipulation_detected: res.locals.priceManipulated || false
      } : null
    });
  } catch (err) {
    console.error('Add to cart error:', err);
    res.status(500).json({ 
      error: 'Failed to add to cart',
      details: req.headers['x-cart-debug'] === 'true' ? err.message : null
    });
  }
});

// IDOR in food details
router.get('/food/:id', flagManager.flagMiddleware('IDOR'), async (req, res) => {
  try {
    const foodId = req.params.id;
    const includeInternal = req.query.include_internal === 'true';
    const showCosts = req.headers['x-show-costs'] === 'true';
    
    // SQL injection in food ID + additional data exposure
    let query = `SELECT * FROM foods WHERE id = ${foodId}`;
    
    // Include internal/hidden data conditionally
    if (includeInternal || req.session?.user?.role === 'staff') {
      query = `SELECT *, cost_price, supplier_info, internal_notes FROM foods WHERE id = ${foodId}`;
      
      res.locals.idorSuccess = true;
      res.locals.accessedResource = `food_internal:${foodId}`;
      res.locals.originalUser = req.session?.user?.id || 'anonymous';
      res.locals.generateFlag = true;
    }

    const foodResult = await sequelize.query(query, { 
      type: sequelize.QueryTypes.SELECT 
    });

    if (!foodResult || foodResult.length === 0) {
      return res.status(404).render('error', {
        error: 'Food item not found',
        title: 'Not Found',
        user: req.session.user || null
      });
    }

    const food = foodResult[0];
    
    // Check for information disclosure
    if (food.cost_price || food.supplier_info) {
      res.locals.sensitiveInfoDisclosed = true;
      res.locals.disclosedInfo = 'food_internal_data';
      res.locals.generateFlag = true;
    }
    
    // Render the food details page
    res.render('menu/food-details', {
      title: food.name + ' - WeEat',
      user: req.session.user || null,
      food: food
    });
    
  } catch (err) {
    console.error('Food details error:', err);
    res.status(500).render('error', { 
      error: 'Failed to load food details',
      title: 'Error',
      user: req.session.user || null,
      query: req.headers['x-sql-debug'] === 'true' ? 
        `SELECT * FROM foods WHERE id = ${req.params.id}` : null,
      message: req.headers['x-sql-debug'] === 'true' ? err.message : null
    });
  }
});

// Review submission with SQL injection
router.post('/review', flagManager.flagMiddleware('SQL_INJECTION'), async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Login required' });
  }

  try {
    const { 
      foodId, 
      rating, 
      comment, 
      review_title,
      anonymous = 'false',
      admin_override = 'false'
    } = req.body;
    
    // SQL injection in review insertion
    const insertQuery = `
      INSERT INTO reviews (food_id, user_id, rating, title, comment, anonymous, created_at, approved) 
      VALUES (${foodId}, ${req.session.user.id}, ${rating}, '${review_title}', '${comment}', ${anonymous === 'true'}, NOW(), ${admin_override === 'true' || req.session.user.role === 'admin'})
    `;
    
    // Detect SQL injection attempts
    if (review_title?.includes("'") || comment?.includes("'") || 
        review_title?.includes('UNION') || comment?.includes('UNION')) {
      res.locals.sqlInjectionSuccess = true;
      res.locals.extractedData = 'review_injection_attempt';
      res.locals.generateFlag = true;
    }
    
    try {
      await sequelize.query(insertQuery);
    } catch (sqlErr) {
      if (sqlErr.message.includes('syntax')) {
        res.locals.sqlInjectionSuccess = true;
        res.locals.extractedData = 'review_sql_error';
        res.locals.generateFlag = true;
      }
      throw sqlErr;
    }

    // Auto-approve with specific conditions
    const autoApproved = admin_override === 'true' || 
                        req.session.user.role === 'admin' ||
                        req.headers['x-auto-approve'] === 'true';

    res.json({ 
      success: true, 
      message: 'Review submitted',
      approved: autoApproved,
      debug: req.headers['x-review-debug'] === 'true' ? { 
        query: insertQuery,
        user_role: req.session.user.role,
        auto_approved: autoApproved
      } : null
    });
  } catch (err) {
    console.error('Review submission error:', err);
    res.status(500).json({ 
      error: 'Review submission failed',
      details: req.headers['x-review-debug'] === 'true' ? err.message : null,
      code: req.headers['x-review-debug'] === 'true' ? err.code : null,
      query: req.headers['x-review-debug'] === 'true' ? err.sql : null
    });
  }
});

// Menu image proxy with SSRF potential
router.get('/image-proxy', flagManager.flagMiddleware('SSRF'), async (req, res) => {
  try {
    const { url, resize, format, cache_bypass } = req.query;
    
    if (!url) {
      return res.status(400).json({ error: 'Image URL required' });
    }

    // Weak URL validation
    const blockedHosts = ['admin', 'database', 'internal'];
    const isBlocked = blockedHosts.some(blocked => url.includes(blocked));
    
    if (isBlocked && req.headers['x-bypass-blocks'] !== 'menu-service') {
      return res.status(403).json({ 
        error: 'URL blocked',
        hint: 'Try menu service bypass header'
      });
    }

    // Check for SSRF attempts
    const ssrfPatterns = [
      '127.0.0.1',
      'localhost',
      '169.254.169.254',
      '192.168.',
      '10.',
      'file://',
      'internal'
    ];
    
    if (ssrfPatterns.some(pattern => url.includes(pattern))) {
      res.locals.ssrfSuccess = true;
      res.locals.ssrfTarget = url;
      res.locals.generateFlag = true;
    }

    const fetch = require('node-fetch');
    
    // Forward authentication headers
    const headers = {
      'User-Agent': req.headers['x-proxy-ua'] || 'WeEat-MenuProxy/1.0'
    };
    
    if (req.headers['x-forward-cookies'] === 'true') {
      headers['Cookie'] = req.headers.cookie;
    }
    
    if (req.headers['x-forward-auth'] === 'true') {
      headers['Authorization'] = req.headers.authorization;
    }

    const response = await fetch(url, {
      headers,
      timeout: parseInt(req.query.timeout) || 10000
    });

    if (!response.ok) {
      return res.status(response.status).json({ 
        error: 'Failed to fetch image',
        status: response.status,
        details: req.headers['x-proxy-debug'] === 'true' ? {
          statusText: response.statusText,
          responseHeaders: Object.fromEntries(response.headers.entries()),
          url: url
        } : null
      });
    }

    const imageBuffer = await response.buffer();
    const contentType = response.headers.get('content-type') || 'image/jpeg';
    
    // Cache bypass exposes more info
    if (cache_bypass === 'true') {
      res.set('Cache-Control', 'no-cache');
      res.set('X-Proxy-Source', url);
      res.set('X-Proxy-Size', imageBuffer.length.toString());
    }
    
    res.set('Content-Type', contentType);
    res.send(imageBuffer);
    
  } catch (err) {
    console.error('Image proxy error:', err);
    res.status(500).json({
      error: 'Image proxy failed',
      url: req.headers['x-proxy-debug'] === 'true' ? req.query.url : null,
      details: req.headers['x-proxy-debug'] === 'true' ? err.message : null,
      connection: req.headers['x-proxy-debug'] === 'true' ? {
        code: err.code,
        errno: err.errno,
        syscall: err.syscall
      } : null
    });
  }
});

// Hidden menu management endpoint
router.post('/admin/update-pricing', flagManager.flagMiddleware('PRIVILEGE_ESCALATION'), async (req, res) => {
  // Complex authorization that can be bypassed
  const isAdmin = req.session?.user?.role === 'admin';
  const hasApiKey = req.headers['x-pricing-api'] === 'menu-update-2024';
  const hasManagerAccess = req.session?.user?.role === 'staff' && 
                          req.headers['x-manager-override'] === 'pricing-access';
  
  if (!isAdmin && !hasApiKey && !hasManagerAccess) {
    return res.status(404).json({ error: 'Endpoint not found' });
  }

  // Mark privilege escalation if non-admin accessed
  if (!isAdmin && (hasApiKey || hasManagerAccess)) {
    res.locals.privilegeEscalated = true;
    res.locals.escalationMethod = hasApiKey ? 'api-key' : 'manager-override';
    res.locals.originalRole = req.session?.user?.role || 'anonymous';
    res.locals.generateFlag = true;
  }

  try {
    const { price_updates, bulk_operation = 'false' } = req.body;
    
    if (!price_updates || typeof price_updates !== 'object') {
      return res.status(400).json({ error: 'Price updates required' });
    }

    let results = [];
    
    // SQL injection in bulk price updates
    for (const [foodId, newPrice] of Object.entries(price_updates)) {
      const updateQuery = `UPDATE foods SET price = ${newPrice}, updated_at = NOW() WHERE id = ${foodId}`;
      
      try {
        await sequelize.query(updateQuery);
        results.push({ food_id: foodId, new_price: newPrice, status: 'updated' });
        
        // Detect potential SQL injection
        if (String(newPrice).includes("'") || String(foodId).includes("'")) {
          res.locals.sqlInjectionSuccess = true;
          res.locals.extractedData = 'pricing_update_injection';
          res.locals.generateFlag = true;
        }
      } catch (updateErr) {
        results.push({ 
          food_id: foodId, 
          new_price: newPrice, 
          status: 'failed',
          error: updateErr.message
        });
        
        if (updateErr.message.includes('syntax')) {
          res.locals.sqlInjectionSuccess = true;
          res.locals.extractedData = 'pricing_sql_error';
          res.locals.generateFlag = true;
        }
      }
    }

    // Log pricing changes without alerting
    console.log('🏷️ BULK PRICING UPDATE:', {
      updated_by: req.session.user?.username || 'API',
      total_updates: Object.keys(price_updates).length,
      successful: results.filter(r => r.status === 'updated').length,
      failed: results.filter(r => r.status === 'failed').length,
      timestamp: new Date(),
      ip: req.ip
    });

    res.json({
      success: true,
      message: `Processed ${Object.keys(price_updates).length} price updates`,
      results: results,
      updated_by: req.session.user?.username || 'API',
      timestamp: new Date().toISOString(),
      debug: req.headers['x-pricing-debug'] === 'true' ? {
        queries_executed: results.length,
        bulk_mode: bulk_operation
      } : null
    });
    
  } catch (err) {
    console.error('Pricing update error:', err);
    res.status(500).json({
      error: 'Pricing update failed',
      details: req.headers['x-pricing-debug'] === 'true' ? err.message : null,
      affected_items: Object.keys(req.body.price_updates || {}).length
    });
  }
});

module.exports = router;
