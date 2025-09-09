const express = require('express');
const router = express.Router();
const { Order } = require('../models');

// Require login middleware
function isLoggedIn(req, res, next) {
    if (!req.session.user) return res.redirect('/auth/login');
    next();
}

router.get('/', isLoggedIn, async (req, res) => {
    const userOrders = await Order.findAll({ where: { userId: req.session.user.id } });
    res.render('profile', { title: 'My Profile', orders: userOrders });
});

module.exports = router;
