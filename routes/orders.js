const express = require('express');
const router = express.Router();
const { Order } = require('../models');

router.get('/', async (req, res) => {
  const orders = await Order.findAll();
  res.render('orders/order_view', { title: 'Orders', orders });
});

router.get('/:id', async (req, res) => {
  const order = await Order.findByPk(req.params.id);
  if (!order) return res.status(404).send('Order not found');
  res.render('orders/order_detail', { title: 'Order Detail', order });
});

module.exports = router;
