// FIXED routes/cart.js - Addressing cart persistence issues

const express = require('express');
const router = express.Router();
const { CartItem } = require('../models');

// Middleware to ensure user is authenticated
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/auth/login');
  }
  next();
}

// Add item to cart - FIXED: Better error handling and user feedback
router.post('/add', requireAuth, async (req, res) => {
  try {
    const { foodName, price } = req.body;
    const userId = req.session.user.id;

    if (!foodName || !price) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing food name or price' 
      });
    }

    // Validate price is a number
    const validPrice = parseFloat(price);
    if (isNaN(validPrice) || validPrice <= 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid price' 
      });
    }

    // Check if item already exists in cart
    let item = await CartItem.findOne({ 
      where: { userId, foodName } 
    });

    if (item) {
      // Update existing item
      item.quantity += 1;
      await item.save();
    } else {
      // Create new cart item
      item = await CartItem.create({ 
        userId, 
        foodName, 
        price: validPrice, 
        quantity: 1 
      });
    }

    // Return success response for AJAX calls
    if (req.headers['content-type'] === 'application/json' || req.xhr) {
      return res.json({
        success: true,
        message: `${foodName} added to cart`,
        cartItem: {
          id: item.id,
          foodName: item.foodName,
          price: item.price,
          quantity: item.quantity
        }
      });
    }

    // Redirect for form submissions
    res.redirect('/cart');
  } catch (error) {
    console.error('Add to cart error:', error);
    
    if (req.headers['content-type'] === 'application/json' || req.xhr) {
      return res.status(500).json({
        success: false,
        error: 'Failed to add item to cart'
      });
    }
    
    res.status(500).render('error', {
      error: 'Failed to add item to cart',
      title: 'Cart Error',
      user: req.session.user
    });
  }
});

// Show cart - FIXED: Better error handling and data validation
router.get('/', requireAuth, async (req, res) => {
  try {
    const cartItems = await CartItem.findAll({ 
      where: { userId: req.session.user.id },
      order: [['createdAt', 'ASC']] // Show items in order they were added
    });

    // Calculate total with proper error handling
    let total = 0;
    const validCartItems = cartItems.filter(item => {
      const price = parseFloat(item.price);
      const quantity = parseInt(item.quantity);
      
      if (isNaN(price) || isNaN(quantity) || price < 0 || quantity < 1) {
        console.warn(`Invalid cart item detected: ${item.id}`);
        return false;
      }
      
      total += price * quantity;
      return true;
    });

    res.render('cart', { 
      title: 'My Cart - WeEat',
      user: req.session.user,
      cartItems: validCartItems, 
      total: total,
      itemCount: validCartItems.length
    });
  } catch (error) {
    console.error('Cart view error:', error);
    res.status(500).render('error', {
      error: 'Failed to load cart',
      title: 'Cart Error',
      user: req.session.user
    });
  }
});

// Remove item - FIXED: Better validation and response handling
router.post('/remove', requireAuth, async (req, res) => {
  try {
    const { id } = req.body;
    
    if (!id) {
      return res.status(400).json({
        success: false,
        error: 'Item ID required'
      });
    }

    const deletedCount = await CartItem.destroy({ 
      where: { 
        id: parseInt(id), 
        userId: req.session.user.id 
      } 
    });

    if (deletedCount === 0) {
      return res.status(404).json({
        success: false,
        error: 'Item not found in cart'
      });
    }

    // Return JSON for AJAX requests
    if (req.headers['content-type'] === 'application/json' || req.xhr) {
      return res.json({
        success: true,
        message: 'Item removed from cart'
      });
    }

    // Redirect for form submissions
    res.redirect('/cart');
  } catch (error) {
    console.error('Remove from cart error:', error);
    
    if (req.headers['content-type'] === 'application/json' || req.xhr) {
      return res.status(500).json({
        success: false,
        error: 'Failed to remove item'
      });
    }
    
    res.redirect('/cart');
  }
});

// Update quantity - FIXED: Better validation and persistence
router.post('/update', requireAuth, async (req, res) => {
  try {
    const { id, quantity } = req.body;
    
    if (!id || !quantity) {
      return res.status(400).json({
        success: false,
        error: 'Item ID and quantity required'
      });
    }

    const newQuantity = parseInt(quantity);
    
    if (isNaN(newQuantity) || newQuantity < 1) {
      return res.status(400).json({
        success: false,
        error: 'Invalid quantity'
      });
    }

    const item = await CartItem.findOne({ 
      where: { 
        id: parseInt(id), 
        userId: req.session.user.id 
      } 
    });

    if (!item) {
      return res.status(404).json({
        success: false,
        error: 'Item not found in cart'
      });
    }

    // Update quantity
    item.quantity = newQuantity;
    await item.save();

    // Return JSON for AJAX requests
    if (req.headers['content-type'] === 'application/json' || req.xhr) {
      return res.json({
        success: true,
        message: 'Quantity updated',
        item: {
          id: item.id,
          foodName: item.foodName,
          price: item.price,
          quantity: item.quantity,
          subtotal: (item.price * item.quantity).toFixed(2)
        }
      });
    }

    // Redirect for form submissions
    res.redirect('/cart');
  } catch (error) {
    console.error('Update cart error:', error);
    
    if (req.headers['content-type'] === 'application/json' || req.xhr) {
      return res.status(500).json({
        success: false,
        error: 'Failed to update quantity'
      });
    }
    
    res.redirect('/cart');
  }
});

// Clear entire cart - NEW: Added for better cart management
router.post('/clear', requireAuth, async (req, res) => {
  try {
    await CartItem.destroy({ 
      where: { userId: req.session.user.id } 
    });

    if (req.headers['content-type'] === 'application/json' || req.xhr) {
      return res.json({
        success: true,
        message: 'Cart cleared'
      });
    }

    res.redirect('/cart');
  } catch (error) {
    console.error('Clear cart error:', error);
    
    if (req.headers['content-type'] === 'application/json' || req.xhr) {
      return res.status(500).json({
        success: false,
        error: 'Failed to clear cart'
      });
    }
    
    res.redirect('/cart');
  }
});

// Get cart count - NEW: For header cart indicator
router.get('/count', requireAuth, async (req, res) => {
  try {
    const count = await CartItem.count({ 
      where: { userId: req.session.user.id } 
    });
    
    res.json({ count });
  } catch (error) {
    console.error('Cart count error:', error);
    res.json({ count: 0 });
  }
});

// Cart summary - NEW: For quick cart overview
router.get('/summary', requireAuth, async (req, res) => {
  try {
    const cartItems = await CartItem.findAll({ 
      where: { userId: req.session.user.id } 
    });

    const summary = {
      itemCount: cartItems.length,
      total: cartItems.reduce((sum, item) => sum + (item.price * item.quantity), 0),
      items: cartItems.map(item => ({
        id: item.id,
        foodName: item.foodName,
        quantity: item.quantity,
        price: item.price
      }))
    };

    res.json(summary);
  } catch (error) {
    console.error('Cart summary error:', error);
    res.status(500).json({
      error: 'Failed to get cart summary'
    });
  }
});

module.exports = router;
