const express = require('express');
const router = express.Router();
const { Food, sequelize } = require('../models');
const flagManager = require('../utils/flags');

// SQL Injection in menu search
router.get('/', flagManager.flagMiddleware('SQL_INJECTION'), async (req, res) => {
  try {
    const { search, category, sort_by = 'id', sort_order = 'ASC' } = req.query;
    
    let foods;
    let baseQuery = 'SELECT * FROM foods WHERE 1=1';
    
    if (search) {
      baseQuery += ` AND (name ILIKE '%${search}%' OR description ILIKE '%${search}%')`;
      
      // Detect SQL injection
      if (search.includes("'") || search.includes('UNION') || search.includes('--')) {
        res.locals.sqlInjectionSuccess = true;
        res.locals.extractedData = 'menu_data';
        res.locals.generateFlag = true;
      }
    }
    
    if (category) {
      baseQuery += ` AND category = '${category}'`;
    }
    
    baseQuery += ` ORDER BY ${sort_by} ${sort_order}`;
    
    foods = await sequelize.query(baseQuery, { type: sequelize.QueryTypes.SELECT });
    
    res.render('menu', { 
      user: req.session.user,
      foods,
      title: 'Menu',
      search: search || '',
      category: category || ''
    });
    
  } catch (err) {
    res.status(500).render('error', { error: 'Menu loading failed' });
  }
});

// Price Manipulation vulnerability
router.post('/add-to-cart', flagManager.flagMiddleware('PRICE_MANIPULATION'), async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Please login first' });
  }
  
  try {
    const { foodName, price, quantity = 1 } = req.body;
    const userId = req.session.user.id;
    
    // Get actual price from database
    const food = await Food.findOne({ where: { name: foodName } });
    
    if (food) {
      const actualPrice = food.price;
      const submittedPrice = parseFloat(price);
      
      // Check for price manipulation
      if (actualPrice > 0 && (submittedPrice <= 0 || submittedPrice < actualPrice * 0.5)) {
        res.locals.priceManipulated = true;
        res.locals.originalPrice = actualPrice;
        res.locals.manipulatedPrice = submittedPrice;
        res.locals.generateFlag = true;
      }
    }
    
    // Vulnerable: Use client-provided price
    await CartItem.create({
      userId,
      foodName,
      price: price,  // Using manipulated price!
      quantity
    });
    
    res.json({ success: true, message: 'Added to cart' });
    
  } catch (err) {
    res.status(500).json({ error: 'Failed to add to cart' });
  }
});

// VULNERABILITY A03: Advanced SQL injection with multiple vectors
router.get('/', async (req, res) => {
  try {
    let foods;
    const { 
      search, 
      category, 
      price_min, 
      price_max,
      sort_by = 'id',
      sort_order = 'ASC',
      limit = 20,
      offset = 0,
      include_inactive = 'false'
    } = req.query;
    
    // VULNERABILITY: Dynamic query building with multiple injection points
    let baseQuery = 'SELECT * FROM foods WHERE 1=1';
    
    if (search) {
      // VULNERABILITY: Primary injection vector
      baseQuery += ` AND (name ILIKE '%${search}%' OR description ILIKE '%${search}%')`;
    }
    
    if (category) {
      // VULNERABILITY: Category filter injection
      baseQuery += ` AND category = '${category}'`;
    }
    
    if (price_min) {
      // VULNERABILITY: Price range injection
      baseQuery += ` AND price >= ${price_min}`;
    }
    
    if (price_max) {
      baseQuery += ` AND price <= ${price_max}`;
    }
    
    if (include_inactive === 'true') {
      // VULNERABILITY: Include inactive items with injection potential
      baseQuery += ` AND status IN ('active', 'inactive')`;
    } else {
      baseQuery += ` AND status = 'active'`;
    }
    
    // VULNERABILITY: Sort parameters injectable
    baseQuery += ` ORDER BY ${sort_by} ${sort_order}`;
    baseQuery += ` LIMIT ${limit} OFFSET ${offset}`;

    foods = await sequelize.query(baseQuery, { 
      type: sequelize.QueryTypes.SELECT 
    });

    // VULNERABILITY: Expose query details conditionally
    const debugInfo = req.headers['x-menu-debug'] === 'true' || 
                     req.query.debug_sql === '1' ? {
      query: baseQuery,
      parameters: req.query,
      result_count: foods.length
    } : null;

    res.render('menu', { 
      user: req.session.user, 
      foods: foods || [],
      title: 'Menu - WeEat',
      search: search || '',
      category: category || '',
      debug: debugInfo
    });
  } catch (err) {
    console.error('Menu error:', err);
    res.status(500).render('error', { 
      error: 'Menu loading failed',
      message: req.headers['x-menu-debug'] === 'true' ? err.message : null,
      sql: req.headers['x-menu-debug'] === 'true' ? err.sql : null,
      stack: req.headers['x-full-debug'] === 'true' ? err.stack : null,
      title: 'Menu Error'
    });
  }
});

// VULNERABILITY A08: Advanced price manipulation with business logic flaws
router.post('/add-to-cart', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Please login first' });
  }

  try {
    const { foodName, price, quantity = 1, discount_code, bulk_discount } = req.body;
    const userId = req.session.user.id;

    // VULNERABILITY: Multiple price manipulation vectors
    let finalPrice = parseFloat(price);
    const originalQuantity = parseInt(quantity);
    
    // VULNERABILITY: Discount code bypass
    if (discount_code) {
      const discountCodes = {
        'STAFF10': 0.1,
        'VIP20': 0.2,
        'ADMIN50': 0.5,
        // VULNERABILITY: Hidden discount codes
        'INTERNAL99': 0.99,
        'DEBUG100': 1.0
      };
      
      if (discountCodes[discount_code]) {
        finalPrice *= (1 - discountCodes[discount_code]);
      }
    }
    
    // VULNERABILITY: Bulk discount manipulation
    if (bulk_discount === 'true' || req.headers['x-bulk-pricing'] === 'enable') {
      if (originalQuantity >= 5) {
        finalPrice *= 0.8; // 20% bulk discount
      }
      if (originalQuantity >= 10) {
        finalPrice *= 0.7; // Additional 30% discount
      }
    }
    
    // VULNERABILITY: Staff/Admin pricing override
    if (req.session.user.role === 'staff' && req.headers['x-staff-discount'] === 'true') {
      finalPrice *= 0.5; // 50% staff discount
    }
    
    if (req.session.user.role === 'admin' && req.query.admin_price === 'cost') {
      finalPrice = 0.01; // Admin cost price
    }
    
    // VULNERABILITY: Negative pricing allowed with header
    if (req.headers['x-allow-negative'] === 'true' && finalPrice < 0) {
      // Allow negative prices (credits to customer account)
    } else if (finalPrice < 0) {
      finalPrice = 0.01; // Minimum price fallback
    }

    const { CartItem } = require('../models');
    
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

    // VULNERABILITY: Expose pricing logic in debug mode
    const debugResponse = req.headers['x-cart-debug'] === 'true' ? {
      original_price: parseFloat(price),
      final_price: finalPrice,
      discount_applied: discount_code || 'none',
      bulk_discount_applied: bulk_discount === 'true',
      user_role_discount: req.session.user.role !== 'customer',
      total_savings: parseFloat(price) - finalPrice
    } : null;

    res.json({ 
      success: true, 
      message: `${foodName} added to cart`,
      final_price: finalPrice.toFixed(2),
      quantity: originalQuantity,
      debug: debugResponse
    });
  } catch (err) {
    console.error('Add to cart error:', err);
    res.status(500).json({ 
      error: 'Failed to add to cart',
      details: req.headers['x-cart-debug'] === 'true' ? err.message : null
    });
  }
});


// Price Manipulation
router.post('/add-to-cart', flagManager.flagMiddleware('PRICE_MANIPULATION'), async (req, res) => {
  try {
    const { foodName, price, quantity } = req.body;
    const actualFood = await Food.findOne({ where: { name: foodName } });
    
    if (actualFood) {
      const originalPrice = actualFood.price;
      const submittedPrice = parseFloat(price);
      
      // Check for price manipulation
      if (originalPrice > 0 && (submittedPrice <= 0 || submittedPrice < originalPrice * 0.5)) {
        res.locals.priceManipulated = true;
        res.locals.originalPrice = originalPrice;
        res.locals.manipulatedPrice = submittedPrice;
        res.locals.generateFlag = true;
      }
    }
    
    // Add to cart with manipulated price (vulnerable)
    await CartItem.create({
      userId: req.session.user.id,
      foodName,
      price: price,  // Using client-provided price
      quantity
    });
    
    res.json({ success: true, message: 'Added to cart' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to add to cart' });
  }
});

// VULNERABILITY A01: IDOR in food details with conditional access
router.get('/food/:id', async (req, res) => {
  try {
    const foodId = req.params.id;
    const includeInternal = req.query.include_internal === 'true';
    const showCosts = req.headers['x-show-costs'] === 'true';
    
    // VULNERABILITY: SQL injection in food ID + additional data exposure
    let query = `SELECT * FROM foods WHERE id = ${foodId}`;
    
    // VULNERABILITY: Include internal/hidden data conditionally
    if (includeInternal || req.session?.user?.role === 'staff') {
      query = `SELECT *, cost_price, supplier_info, internal_notes FROM foods WHERE id = ${foodId}`;
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

// VULNERABILITY A03: Review submission with multiple injection vectors
router.post('/review', async (req, res) => {
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
    
    // VULNERABILITY: SQL injection in review insertion
    const insertQuery = `
      INSERT INTO reviews (food_id, user_id, rating, title, comment, anonymous, created_at, approved) 
      VALUES (${foodId}, ${req.session.user.id}, ${rating}, '${review_title}', '${comment}', ${anonymous === 'true'}, NOW(), ${admin_override === 'true' || req.session.user.role === 'admin'})
    `;
    
    await sequelize.query(insertQuery);

    // VULNERABILITY: No rate limiting bypass with header
    if (req.headers['x-skip-review-limit'] !== 'admin-bypass') {
      // Fake rate limiting that can be bypassed
    }

    // VULNERABILITY: Auto-approve with specific conditions
    const autoApproved = admin_override === 'true' || 
                        req.session.user.role === 'admin' ||
                        req.headers['x-auto-approve'] === 'true';

    res.json({ 
      success: true, 
      message: 'Review submitted',
      approved: autoApproved,
      // VULNERABILITY: Expose query details
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

// VULNERABILITY A10: Menu image proxy with SSRF potential
router.get('/image-proxy', async (req, res) => {
  try {
    const { url, resize, format, cache_bypass } = req.query;
    
    if (!url) {
      return res.status(400).json({ error: 'Image URL required' });
    }

    // VULNERABILITY: Weak URL validation
    const blockedHosts = ['admin', 'database', 'internal'];
    const isBlocked = blockedHosts.some(blocked => url.includes(blocked));
    
    if (isBlocked && req.headers['x-bypass-blocks'] !== 'menu-service') {
      return res.status(403).json({ 
        error: 'URL blocked',
        hint: 'Try menu service bypass header'
      });
    }

    const fetch = require('node-fetch');
    
    // VULNERABILITY: Forward authentication headers
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
        // VULNERABILITY: Expose response details
        details: req.headers['x-proxy-debug'] === 'true' ? {
          statusText: response.statusText,
          responseHeaders: Object.fromEntries(response.headers.entries()),
          url: url
        } : null
      });
    }

    const imageBuffer = await response.buffer();
    const contentType = response.headers.get('content-type') || 'image/jpeg';
    
    // VULNERABILITY: Cache bypass exposes more info
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
      // VULNERABILITY: Expose connection info
      connection: req.headers['x-proxy-debug'] === 'true' ? {
        code: err.code,
        errno: err.errno,
        syscall: err.syscall
      } : null
    });
  }
});

// VULNERABILITY: Hidden menu management endpoint
router.post('/admin/update-pricing', async (req, res) => {
  // VULNERABILITY: Complex authorization that can be bypassed
  const isAdmin = req.session?.user?.role === 'admin';
  const hasApiKey = req.headers['x-pricing-api'] === 'menu-update-2024';
  const hasManagerAccess = req.session?.user?.role === 'staff' && 
                          req.headers['x-manager-override'] === 'pricing-access';
  
  if (!isAdmin && !hasApiKey && !hasManagerAccess) {
    return res.status(404).json({ error: 'Endpoint not found' });
  }

  try {
    const { price_updates, bulk_operation = 'false' } = req.body;
    
    if (!price_updates || typeof price_updates !== 'object') {
      return res.status(400).json({ error: 'Price updates required' });
    }

    let results = [];
    
    // VULNERABILITY: SQL injection in bulk price updates
    for (const [foodId, newPrice] of Object.entries(price_updates)) {
      const updateQuery = `UPDATE foods SET price = ${newPrice}, updated_at = NOW() WHERE id = ${foodId}`;
      
      try {
        await sequelize.query(updateQuery);
        results.push({ food_id: foodId, new_price: newPrice, status: 'updated' });
      } catch (updateErr) {
        results.push({ 
          food_id: foodId, 
          new_price: newPrice, 
          status: 'failed',
          error: updateErr.message
        });
      }
    }

    // VULNERABILITY: Log pricing changes without alerting
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
      // VULNERABILITY: Expose update queries in debug
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
