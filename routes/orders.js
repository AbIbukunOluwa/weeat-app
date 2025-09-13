const express = require('express');
const router = express.Router();
const { Order, CartItem, User } = require('../models');
const flagManager = require('../utils/flags');

router.use((req, res, next) => {
  if (!req.session.user) return res.redirect('/auth/login');
  next();
});

// Create order
router.post('/create', async (req, res) => {
  try {
    const userId = req.session.user.id;
    const cartItems = await CartItem.findAll({ where: { userId } });
    
    if (cartItems.length === 0) {
      return res.redirect('/cart');
    }

    const items = cartItems.map(ci => ({ 
      name: ci.foodName, 
      price: ci.price, 
      qty: ci.quantity 
    }));
    
    const totalAmount = items.reduce((sum, i) => sum + i.price * i.qty, 0);

    const order = await Order.create({ 
      userId, 
      items: JSON.stringify(items), 
      totalAmount 
    });
    
    // Clear cart after successful order
    await CartItem.destroy({ where: { userId } });

    res.redirect('/orders');
  } catch (error) {
    console.error('Order creation error:', error);
    res.status(500).render('error', {
      error: 'Failed to create order',
      title: 'Order Error',
      user: req.session.user
    });
  }
});

// View all orders
router.get('/', async (req, res) => {
  try {
    const orders = await Order.findAll({ 
      where: { userId: req.session.user.id },
      include: [
        {
          model: User,
          as: 'customer',
          attributes: ['username', 'email', 'name']
        }
      ],
      order: [['createdAt', 'DESC']]
    });
    
    res.render('orders/order_view', { 
      title: 'My Orders - WeEat',
      user: req.session.user,
      orders 
    });
  } catch (error) {
    console.error('Orders view error:', error);
    res.status(500).render('error', {
      error: 'Failed to load orders',
      title: 'Orders Error', 
      user: req.session.user
    });
  }
});

// IDOR vulnerability - Access other users' orders by order number
router.get('/:orderNumber', flagManager.flagMiddleware('IDOR'), async (req, res) => {
  try {
    const orderNumber = req.params.orderNumber;
    
    // Find by order number without checking user ownership (IDOR vulnerability)
    const order = await Order.findOne({
      where: { orderNumber: orderNumber },
      include: [
        {
          model: User,
          as: 'customer',
          attributes: ['username', 'email', 'name']
        }
      ]
    });

    if (!order) {
      return res.status(404).render('error', {
        error: 'Order not found',
        title: 'Order Not Found',
        user: req.session.user,
        details: `Order ${orderNumber} was not found.`
      });
    }

    // Check for IDOR - accessing another user's order
    if (req.session.user && order.userId !== req.session.user.id) {
      res.locals.idorSuccess = true;
      res.locals.accessedResource = `order:${orderNumber}`;
      res.locals.originalUser = req.session.user.id;
      res.locals.generateFlag = true;
    }

    res.render('orders/order_detail', {
      title: `Order ${order.orderNumber} - WeEat`,
      user: req.session.user,
      order
    });
  } catch (error) {
    console.error('Order detail error:', error);
    res.status(500).render('error', {
      error: 'Failed to load order details',
      title: 'Order Error',
      user: req.session.user
    });
  }
});

// Cancel order (CSRF vulnerability)
router.post('/:orderNumber/cancel', flagManager.flagMiddleware('CSRF'), async (req, res) => {
  try {
    const orderNumber = req.params.orderNumber;
    const { reason } = req.body;
    
    // Check for CSRF attack
    const referer = req.get('Referer') || '';
    const origin = req.get('Origin') || '';
    const host = req.get('Host') || '';
    
    if (!referer.includes(host) && !origin.includes(host)) {
      res.locals.csrfSuccess = true;
      res.locals.csrfAction = 'order_cancellation';
      res.locals.generateFlag = true;
    }
    
    const order = await Order.findOne({
      where: { 
        orderNumber: orderNumber, 
        userId: req.session.user.id 
      }
    });

    if (!order) {
      return res.status(404).json({ 
        success: false, 
        error: 'Order not found' 
      });
    }

    if (order.status === 'delivered') {
      return res.status(400).json({ 
        success: false, 
        error: 'Cannot cancel delivered order' 
      });
    }

    order.status = 'cancelled';
    order.cancellationReason = reason || 'Customer requested cancellation';
    order.cancelledAt = new Date();
    await order.save();

    res.json({ 
      success: true, 
      message: 'Order cancelled successfully' 
    });
  } catch (error) {
    console.error('Order cancellation error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to cancel order' 
    });
  }
});

// Reorder items (IDOR + Business Logic)
router.post('/:orderNumber/reorder', flagManager.flagMiddleware('IDOR'), async (req, res) => {
  try {
    const orderNumber = req.params.orderNumber;
    const userId = req.session.user.id;
    
    // IDOR: Find order without checking ownership
    const order = await Order.findOne({
      where: { orderNumber: orderNumber }
    });

    if (!order) {
      return res.status(404).json({ 
        success: false, 
        error: 'Order not found' 
      });
    }

    // Check for IDOR
    if (order.userId !== userId) {
      res.locals.idorSuccess = true;
      res.locals.accessedResource = `order_reorder:${orderNumber}`;
      res.locals.originalUser = userId;
      res.locals.generateFlag = true;
    }

    const items = JSON.parse(order.items);
    
    // Add items back to cart (using original prices - business logic issue)
    for (const item of items) {
      let cartItem = await CartItem.findOne({ 
        where: { userId, foodName: item.name } 
      });
      
      if (cartItem) {
        cartItem.quantity += item.qty;
        await cartItem.save();
      } else {
        await CartItem.create({
          userId,
          foodName: item.name,
          price: item.price, // Using historical price (potential manipulation)
          quantity: item.qty
        });
      }
    }

    res.json({ 
      success: true, 
      message: 'Items added to cart successfully',
      orderOwner: order.userId,
      currentUser: userId
    });
  } catch (error) {
    console.error('Reorder error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to reorder items' 
    });
  }
});

// Order status update (Business Logic Bypass)
router.post('/:orderNumber/update-status', flagManager.flagMiddleware('BUSINESS_LOGIC'), async (req, res) => {
  try {
    const orderNumber = req.params.orderNumber;
    const { newStatus, bypass } = req.body;
    
    const order = await Order.findOne({
      where: { orderNumber: orderNumber, userId: req.session.user.id }
    });

    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    // Business logic bypass
    if (bypass === 'customer-override' && req.headers['x-customer-support'] === 'true') {
      // Allow customers to change order status inappropriately
      res.locals.businessLogicBypassed = true;
      res.locals.bypassedLogic = 'customer_status_change';
      res.locals.generateFlag = true;
      
      order.status = newStatus;
      if (newStatus === 'delivered') {
        order.actualDelivery = new Date();
      }
      await order.save();
      
      return res.json({
        success: true,
        message: 'Order status updated via customer override',
        newStatus: order.status
      });
    }

    // Normal status update logic (limited)
    const allowedTransitions = {
      'pending': ['cancelled'],
      'confirmed': ['cancelled'],
      'preparing': [],
      'ready': [],
      'delivering': [],
      'delivered': [],
      'cancelled': []
    };

    const currentStatus = order.status || 'pending';
    if (!allowedTransitions[currentStatus].includes(newStatus)) {
      return res.status(400).json({
        error: 'Invalid status transition',
        current: currentStatus,
        requested: newStatus,
        allowed: allowedTransitions[currentStatus]
      });
    }

    order.status = newStatus;
    await order.save();

    res.json({
      success: true,
      message: 'Order status updated',
      newStatus: order.status
    });

  } catch (error) {
    console.error('Status update error:', error);
    res.status(500).json({ error: 'Failed to update order status' });
  }
});

// Order search with SQL injection
router.get('/search/query', flagManager.flagMiddleware('SQL_INJECTION'), async (req, res) => {
  try {
    const { q, status, date_from, date_to } = req.query;
    
    if (!q) {
      return res.status(400).json({ error: 'Search query required' });
    }

    // Vulnerable SQL query
    let searchQuery = `
      SELECT o.*, u.username, u.email 
      FROM orders o 
      JOIN users u ON o."userId" = u.id 
      WHERE o."userId" = ${req.session.user.id}
    `;

    if (q) {
      searchQuery += ` AND (o."orderNumber" ILIKE '%${q}%' OR u.username ILIKE '%${q}%')`;
      
      // Detect SQL injection
      if (q.includes("'") || q.includes('UNION') || q.includes('--') || q.includes('SELECT')) {
        res.locals.sqlInjectionSuccess = true;
        res.locals.extractedData = 'order_search_injection';
        res.locals.generateFlag = true;
      }
    }

    if (status) {
      searchQuery += ` AND o.status = '${status}'`;
    }

    if (date_from) {
      searchQuery += ` AND o."createdAt" >= '${date_from}'`;
    }

    if (date_to) {
      searchQuery += ` AND o."createdAt" <= '${date_to}'`;
    }

    searchQuery += ` ORDER BY o."createdAt" DESC LIMIT 20`;

    const { sequelize } = require('../models');
    const results = await sequelize.query(searchQuery, { 
      type: sequelize.QueryTypes.SELECT 
    });

    res.json({
      success: true,
      results: results,
      query: q,
      count: results.length,
      debug: req.headers['x-search-debug'] === 'true' ? {
        sql: searchQuery
      } : null
    });

  } catch (error) {
    console.error('Order search error:', error);
    
    // SQL error might indicate injection
    if (error.message.includes('syntax') || error.message.includes('relation')) {
      res.locals.sqlInjectionSuccess = true;
      res.locals.extractedData = 'sql_error_in_search';
      res.locals.generateFlag = true;
    }
    
    res.status(500).json({
      error: 'Search failed',
      details: req.headers['x-search-debug'] === 'true' ? error.message : null,
      sql_error: req.headers['x-search-debug'] === 'true' ? error.sql : null
    });
  }
});

// Order rating with stored XSS
router.post('/:orderNumber/rate', flagManager.flagMiddleware('XSS_STORED'), async (req, res) => {
  try {
    const orderNumber = req.params.orderNumber;
    const { rating, comment } = req.body;
    
    const order = await Order.findOne({
      where: { orderNumber, userId: req.session.user.id }
    });

    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    // Check for XSS in comment
    const xssPatterns = [
      /<script/i,
      /javascript:/i,
      /onerror\s*=/i,
      /onload\s*=/i,
      /<iframe/i,
      /<img.*onerror/i
    ];

    if (comment && xssPatterns.some(pattern => pattern.test(comment))) {
      res.locals.xssExecuted = true;
      res.locals.xssPayload = comment.substring(0, 100);
      res.locals.generateFlag = true;
    }

    // Store without sanitization
    order.customerRating = rating;
    order.customerComment = comment; // XSS vulnerability
    await order.save();

    res.json({
      success: true,
      message: 'Rating submitted successfully',
      rating: rating
    });

  } catch (error) {
    console.error('Rating submission error:', error);
    res.status(500).json({ error: 'Failed to submit rating' });
  }
});

module.exports = router;
