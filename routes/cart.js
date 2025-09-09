const express = require('express');
const router = express.Router();
const cartController = require('../controllers/cartController');
const { authenticate } = require('../middleware/auth'); // assumes you have auth middleware

// All routes require authentication
router.use(authenticate);

// Get current user's cart
router.get('/', cartController.getCart);

// Add product to cart
router.post('/add', cartController.addToCart);

// Update cart item quantity
router.put('/update', cartController.updateCartItem);

// Remove item from cart
router.delete('/remove/:itemId', cartController.removeCartItem);

module.exports = router;
