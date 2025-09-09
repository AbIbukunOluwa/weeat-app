const express = require('express');
const router = express.Router();
const { Food } = require('../models');

// Authentication middleware
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/auth/login');
  }
  next();
}

// Dashboard route with intentional vulnerabilities
router.get('/', requireAuth, async (req, res) => {
  try {
    // VULNERABILITY A03: SQL Injection in search
    let foods;
    const search = req.query.search;
    
    if (search) {
      // INTENTIONAL VULNERABILITY: Raw SQL injection
      const query = `SELECT * FROM foods WHERE name LIKE '%${search}%'`;
      const results = await sequelize.query(query, { type: sequelize.QueryTypes.SELECT });
      foods = results;
    } else {
      foods = await Food.findAll();
    }

    // VULNERABILITY A02: Sensitive data exposure in logs
    console.log('Dashboard access:', {
      userId: req.session.user.id,
      userAgent: req.get('User-Agent'),
      ip: req.ip,
      sessionId: req.sessionID
    });

    res.render('dashboard', { 
      user: req.session.user, 
      foods: foods || [],
      title: 'Dashboard'
    });
  } catch (err) {
    // VULNERABILITY A05: Verbose error messages
    console.error('Dashboard error details:', err);
    res.status(500).render('error', { 
      error: 'Dashboard Error',
      details: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : null
    });
  }
});

// Add to cart with vulnerabilities
router.post('/add-to-cart', requireAuth, async (req, res) => {
  try {
    const { foodId, price } = req.body;
    const userId = req.session.user.id;

    // VULNERABILITY A08: Client-side data integrity failure
    // No server-side price verification - trust client price
    const food = await Food.findByPk(foodId);
    
    if (!food) {
      return res.status(404).json({ error: 'Food not found' });
    }

    // VULNERABILITY: Use client-provided price instead of database price
    const { CartItem } = require('../models');
    let cartItem = await CartItem.findOne({ where: { userId, foodName: food.name } });
    
    if (cartItem) {
      cartItem.quantity += 1;
      cartItem.price = price; // Trust client price
      await cartItem.save();
    } else {
      await CartItem.create({
        userId,
        foodName: food.name,
        price: parseFloat(price), // Trust client price
        quantity: 1
      });
    }

    res.json({ success: true, message: 'Added to cart' });
  } catch (err) {
    console.error('Add to cart error:', err);
    res.status(500).json({ error: 'Failed to add to cart' });
  }
});

module.exports = router;
