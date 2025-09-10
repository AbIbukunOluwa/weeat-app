const express = require('express');
const router = express.Router();
const { Order, CartItem } = require('../models');

router.use((req, res, next) => {
  if (!req.session.user) return res.redirect('/auth/login');
  next();
});

router.post('/create', async (req, res) => {
  const userId = req.session.user.id;
  const cartItems = await CartItem.findAll({ where: { userId } });
  if (cartItems.length === 0) return res.redirect('/cart');

  const items = cartItems.map(ci => ({ name: ci.foodName, price: ci.price, qty: ci.quantity }));
  const totalAmount = items.reduce((sum, i) => sum + i.price * i.qty, 0);

  await Order.create({ userId, items: JSON.stringify(items), totalAmount });
  await CartItem.destroy({ where: { userId } });

  res.redirect('/orders');
});

router.get('/', async (req, res) => {
  const orders = await Order.findAll({ where: { userId: req.session.user.id } });
  res.render('orders/view', { 
    title: 'My Orders - WeEat',  // FIXED: Added title
    user: req.session.user,      // Pass user for header
    orders 
  });
});

module.exports = router;
