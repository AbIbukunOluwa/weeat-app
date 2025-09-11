// routes/reviews.js - Fixed reviews route

const express = require('express');
const router = express.Router();
const { Review, Food, User } = require('../models');

// Main reviews page - handles both /reviews and /reviews?order=X
router.get('/', async (req, res) => {
  try {
    const orderId = req.query.order;
    
    // If coming from an order, could pre-select food items from that order
    // For now, just show the reviews page
    const foods = await Food.findAll({
      where: { status: 'active' },
      order: [['name', 'ASC']]
    });
    
    const reviews = await Review.findAll({
      include: [
        { model: User, attributes: ['username'] },
        { model: Food, attributes: ['name', 'image', 'price'] }
      ],
      order: [['createdAt', 'DESC']],
      limit: 20
    });
    
    res.render('reviews/index', {
      title: 'Food Reviews - WeEat',
      user: req.session.user,
      foods: foods,
      reviews: reviews,
      orderId: orderId
    });
  } catch (err) {
    console.error('Reviews page error:', err);
    res.status(500).render('error', {
      error: 'Failed to load reviews',
      title: 'Error',
      user: req.session.user
    });
  }
});

// Submit review with STORED XSS vulnerability
router.post('/submit', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const { foodId, rating, title, comment } = req.body;
    
    // VULNERABILITY: No CSRF token validation
    // VULNERABILITY: No input sanitization - allows stored XSS
    const review = await Review.create({
      foodId: parseInt(foodId),
      userId: req.session.user.id,
      rating: parseInt(rating),
      title: title, // XSS VULNERABILITY - stored without sanitization
      comment: comment, // XSS VULNERABILITY - stored without sanitization
      approved: true // Auto-approve for faster testing
    });

    // VULNERABILITY: Reflect user input in response
    res.json({ 
      success: true, 
      message: `Review "${title}" submitted successfully!`,
      reviewId: review.id,
      // VULNERABILITY: Information disclosure
      debug: {
        userId: req.session.user.id,
        sessionId: req.sessionID,
        timestamp: new Date().toISOString()
      }
    });
  } catch (err) {
    console.error('Review submission error:', err);
    res.status(500).json({ 
      error: 'Failed to submit review',
      details: err.message 
    });
  }
});

// Display reviews for specific food with XSS vulnerability (no escaping)
router.get('/food/:foodId', async (req, res) => {
  try {
    const foodId = req.params.foodId;
    
    // VULNERABILITY: SQL injection in foodId parameter
    const reviews = await Review.findAll({
      where: { foodId: foodId, approved: true },
      include: [{ model: User, attributes: ['username'] }],
      order: [['createdAt', 'DESC']]
    });

    const food = await Food.findByPk(foodId);

    res.render('reviews/food-reviews', { 
      foodId, 
      food,
      reviews, 
      title: `Reviews for ${food ? food.name : 'Food Item'}`,
      user: req.session.user
    });
  } catch (err) {
    console.error('Reviews fetch error:', err);
    res.status(500).render('error', { 
      error: 'Failed to load reviews',
      details: err.message,
      stack: err.stack,
      title: 'Error',
      user: req.session.user
    });
  }
});

// Like a review
router.post('/:id/like', (req, res) => {
  // VULNERABILITY: No authentication check
  // VULNERABILITY: No CSRF protection
  res.json({ success: true, message: 'Review liked' });
});

// Report a review
router.post('/:id/report', (req, res) => {
  const { reason } = req.body;
  // VULNERABILITY: No validation of report reason
  res.json({ success: true, message: 'Review reported' });
});

// Admin review management with CSRF vulnerability
router.post('/admin/approve/:id', (req, res) => {
  // VULNERABILITY: No CSRF protection on admin actions
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const reviewId = req.params.id;
  
  Review.findByPk(reviewId)
    .then(review => {
      if (!review) {
        return res.status(404).json({ error: 'Review not found' });
      }
      
      review.approved = true;
      return review.save();
    })
    .then(() => {
      res.json({ success: true, message: 'Review approved' });
    })
    .catch(err => {
      res.status(500).json({ error: 'Approval failed', details: err.message });
    });
});

// Delete review with CSRF vulnerability  
router.post('/admin/delete/:id', (req, res) => {
  // VULNERABILITY: No CSRF protection
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const reviewId = req.params.id;
  
  Review.destroy({ where: { id: reviewId } })
    .then(deleted => {
      if (deleted) {
        res.json({ success: true, message: 'Review deleted' });
      } else {
        res.status(404).json({ error: 'Review not found' });
      }
    })
    .catch(err => {
      res.status(500).json({ error: 'Deletion failed', details: err.message });
    });
});

// Edit review
router.post('/admin/edit/:id', async (req, res) => {
  // VULNERABILITY: No CSRF protection
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    const reviewId = req.params.id;
    const { title, comment } = req.body;
    
    const review = await Review.findByPk(reviewId);
    if (!review) {
      return res.status(404).json({ error: 'Review not found' });
    }
    
    // VULNERABILITY: No sanitization on update
    review.title = title;
    review.comment = comment;
    await review.save();
    
    res.json({ success: true, message: 'Review updated' });
  } catch (err) {
    res.status(500).json({ error: 'Update failed', details: err.message });
  }
});

module.exports = router;
