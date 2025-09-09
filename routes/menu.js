const express = require('express');
const router = express.Router();
const { Food } = require('../models');

// GET /menu
router.get('/', async (req, res) => {
  try {
    const foods = await Food.findAll();
    res.render('menu', { user: req.user, foods, title: 'Menu' });
  } catch (err) {
    console.error(err);
    res.status(500).send('Something went wrong fetching the menu.');
  }
});

module.exports = router;
