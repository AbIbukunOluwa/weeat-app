const { Cart, CartItem, Product } = require('../models');

// Get current user's cart
async function getCart(req, res) {
  try {
    const userId = req.user.id; // assuming req.user is set after auth
    let cart = await Cart.findOne({ 
      where: { userId },
      include: { model: CartItem, include: Product }
    });

    if (!cart) {
      cart = await Cart.create({ userId });
    }

    res.json(cart);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Failed to fetch cart' });
  }
}

// Add product to cart
async function addToCart(req, res) {
  try {
    const userId = req.user.id;
    const { productId, quantity } = req.body;

    let cart = await Cart.findOne({ where: { userId } });
    if (!cart) cart = await Cart.create({ userId });

    let item = await CartItem.findOne({ where: { cartId: cart.id, productId } });
    if (item) {
      item.quantity += quantity || 1;
      await item.save();
    } else {
      item = await CartItem.create({
        cartId: cart.id,
        productId,
        quantity: quantity || 1
      });
    }

    const updatedCart = await Cart.findOne({
      where: { id: cart.id },
      include: { model: CartItem, include: Product }
    });

    res.json(updatedCart);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Failed to add to cart' });
  }
}

// Update quantity of a cart item
async function updateCartItem(req, res) {
  try {
    const userId = req.user.id;
    const { itemId, quantity } = req.body;

    const cart = await Cart.findOne({ where: { userId } });
    if (!cart) return res.status(404).json({ message: 'Cart not found' });

    const item = await CartItem.findOne({ where: { id: itemId, cartId: cart.id } });
    if (!item) return res.status(404).json({ message: 'Item not found' });

    item.quantity = quantity;
    await item.save();

    const updatedCart = await Cart.findOne({
      where: { id: cart.id },
      include: { model: CartItem, include: Product }
    });

    res.json(updatedCart);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Failed to update cart item' });
  }
}

// Remove item from cart
async function removeCartItem(req, res) {
  try {
    const userId = req.user.id;
    const { itemId } = req.params;

    const cart = await Cart.findOne({ where: { userId } });
    if (!cart) return res.status(404).json({ message: 'Cart not found' });

    const item = await CartItem.findOne({ where: { id: itemId, cartId: cart.id } });
    if (!item) return res.status(404).json({ message: 'Item not found' });

    await item.destroy();

    const updatedCart = await Cart.findOne({
      where: { id: cart.id },
      include: { model: CartItem, include: Product }
    });

    res.json(updatedCart);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Failed to remove cart item' });
  }
}

module.exports = {
  getCart,
  addToCart,
  updateCartItem,
  removeCartItem
};
