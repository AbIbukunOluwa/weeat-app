const express = require('express');
const router = express.Router();
const { CartItem } = require('../models');

// Add item to cart
router.post('/add', async (req, res) => {
  if (!req.user) return res.redirect('/auth/login');

  const { foodName, price } = req.body;
  const userId = req.user.id;

  // Check if item already exists in cart
  let item = await CartItem.findOne({ where: { userId, foodName } });
  if (item) {
    item.quantity += 1;
    await item.save();
  } else {
    await CartItem.create({ userId, foodName, price, quantity: 1 });
  }

  res.redirect('/cart');
});

// Show cart - FIXED: Added title and proper user passing
router.get('/', async (req, res) => {
  if (!req.user) return res.redirect('/auth/login');

  const cartItems = await CartItem.findAll({ where: { userId: req.user.id } });
  const total = cartItems.reduce((sum, i) => sum + i.price * i.quantity, 0);

  res.render('cart', { 
    title: 'My Cart - WeEat',  // FIXED: Added title
    user: req.user,            // Pass user for header
    cartItems, 
    total 
  });
});

// Remove item
router.post('/remove', async (req, res) => {
  if (!req.user) return res.redirect('/auth/login');

  const { id } = req.body;
  await CartItem.destroy({ where: { id, userId: req.user.id } });
  res.redirect('/cart');
});

// Update quantity
router.post('/update', async (req, res) => {
  if (!req.user) return res.redirect('/auth/login');

  const { id, quantity } = req.body;
  const item = await CartItem.findOne({ where: { id, userId: req.user.id } });
  if (item) {
    item.quantity = parseInt(quantity) || 1;
    await item.save();
  }

  res.redirect('/cart');
});

module.exports = router;
