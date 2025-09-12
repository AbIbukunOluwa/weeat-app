const express = require('express');
const router = express.Router();
const { Order, CartItem, User } = require('../models');

router.use((req, res, next) => {
  if (!req.session.user) return res.redirect('/auth/login');
  next();
});

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

// UPDATED: Individual order view by order number
router.get('/:orderNumber', async (req, res) => {
  try {
    const orderNumber = req.params.orderNumber;
    
    // Find by order number instead of ID
    const order = await Order.findOne({
      where: { 
        orderNumber: orderNumber, 
        userId: req.session.user.id 
      },
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
        details: `Order ${orderNumber} was not found or doesn't belong to you.`
      });
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

// UPDATED: Cancel order by order number
router.post('/:orderNumber/cancel', async (req, res) => {
  try {
    const orderNumber = req.params.orderNumber;
    const { reason } = req.body;
    
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

// UPDATED: Reorder items by order number
router.post('/:orderNumber/reorder', async (req, res) => {
  try {
    const orderNumber = req.params.orderNumber;
    const userId = req.session.user.id;
    
    const order = await Order.findOne({
      where: { 
        orderNumber: orderNumber, 
        userId: userId 
      }
    });

    if (!order) {
      return res.status(404).json({ 
        success: false, 
        error: 'Order not found' 
      });
    }

    const items = JSON.parse(order.items);
    
    // Add items back to cart
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
          price: item.price,
          quantity: item.qty
        });
      }
    }

    res.json({ 
      success: true, 
      message: 'Items added to cart successfully' 
    });
  } catch (error) {
    console.error('Reorder error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to reorder items' 
    });
  }
});

module.exports = router;
