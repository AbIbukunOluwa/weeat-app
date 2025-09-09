const { CartItem } = require('../models');

exports.addToCart = async (req, res) => {
  const userId = req.session.user.id;
  const { foodName, price } = req.body;

  if (!foodName || !price) return res.status(400).send('Missing data');

  // Check if already in cart
  let item = await CartItem.findOne({ where: { userId, foodName } });
  if (item) {
    item.quantity += 1;
    await item.save();
  } else {
    await CartItem.create({ userId, foodName, price, quantity: 1 });
  }

  res.redirect('/menu');
};

exports.viewCart = async (req, res) => {
  const userId = req.session.user.id;
  const items = await CartItem.findAll({ where: { userId } });
  const total = items.reduce((sum, i) => sum + i.price * i.quantity, 0);
  res.render('cart/view', { items, total });
};

exports.removeFromCart = async (req, res) => {
  const userId = req.session.user.id;
  const { id } = req.params;
  await CartItem.destroy({ where: { id, userId } });
  res.redirect('/cart');
};
