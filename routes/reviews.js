const express = require('express');
const router = express.Router();
const { Review, Food, User } = require('../models');
const flagManager = require('../utils/flags');

// Main reviews page
router.get('/', async (req, res) => {
  try {
    const orderId = req.query.order;
    
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
router.post('/submit', flagManager.flagMiddleware('XSS_STORED'), async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const { foodId, rating, title, comment } = req.body;
    
    // Check for XSS payloads
    const xssPatterns = [
      /<script/i,
      /javascript:/i,
      /onerror\s*=/i,
      /onload\s*=/i,
      /onclick\s*=/i,
      /<iframe/i,
      /<img.*?onerror/i,
      /<svg.*?onload/i,
      /alert\s*\(/i,
      /prompt\s*\(/i,
      /confirm\s*\(/i,
      /document\.cookie/i,
      /<object/i,
      /<embed/i
    ];
    
    const hasXSS = xssPatterns.some(pattern => 
      pattern.test(title) || pattern.test(comment)
    );
    
    if (hasXSS) {
      res.locals.xssExecuted = true;
      res.locals.xssPayload = (title + ' ' + comment).substring(0, 100);
      res.locals.generateFlag = true;
    }
    
    // Store review WITHOUT sanitization (vulnerable!)
    const review = await Review.create({
      foodId: parseInt(foodId),
      userId: req.session.user.id,
      rating: parseInt(rating),
      title: title,    // XSS vulnerability - stored without sanitization
      comment: comment, // XSS vulnerability - stored without sanitization
      approved: true // Auto-approve for faster testing
    });

    res.json({ 
      success: true, 
      message: `Review "${title}" submitted successfully!`,
      reviewId: review.id,
      // Information disclosure
      debug: req.headers['x-review-debug'] === 'true' ? {
        userId: req.session.user.id,
        sessionId: req.sessionID,
        timestamp: new Date().toISOString()
      } : null
    });
  } catch (err) {
    console.error('Review submission error:', err);
    res.status(500).json({ 
      error: 'Failed to submit review',
      details: req.headers['x-review-debug'] === 'true' ? err.message : null
    });
  }
});

// Display reviews for specific food (vulnerable to XSS when displaying)
router.get('/food/:foodId', async (req, res) => {
  try {
    const foodId = req.params.foodId;
    
    const reviews = await Review.findAll({
      where: { foodId: foodId, approved: true },
      include: [{ model: User, attributes: ['username'] }],
      order: [['createdAt', 'DESC']]
    });

    const food = await Food.findByPk(foodId);

    // The XSS vulnerability is in the view template - reviews are displayed without escaping
    res.render('reviews/food-reviews', { 
      foodId, 
      food,
      reviews, // Reviews contain unescaped HTML/JS from user input
      title: `Reviews for ${food ? food.name : 'Food Item'}`,
      user: req.session.user
    });
  } catch (err) {
    console.error('Reviews fetch error:', err);
    res.status(500).render('error', { 
      error: 'Failed to load reviews',
      details: req.headers['x-review-debug'] === 'true' ? err.message : null,
      title: 'Error',
      user: req.session.user
    });
  }
});

// Like a review (CSRF vulnerability)
router.post('/:id/like', flagManager.flagMiddleware('CSRF'), (req, res) => {
  // Check for CSRF attack
  const referer = req.get('Referer') || '';
  const origin = req.get('Origin') || '';
  const host = req.get('Host') || '';
  
  if (!referer.includes(host) && !origin.includes(host)) {
    res.locals.csrfSuccess = true;
    res.locals.csrfAction = 'review_like';
    res.locals.generateFlag = true;
  }
  
  // No authentication check - another vulnerability
  // No CSRF protection
  res.json({ success: true, message: 'Review liked' });
});

// Report a review (input validation bypass)
router.post('/:id/report', flagManager.flagMiddleware('XSS_REFLECTED'), (req, res) => {
  const { reason } = req.body;
  
  // Check for reflected XSS in reason
  const xssPatterns = [
    /<script/i,
    /javascript:/i,
    /onerror\s*=/i,
    /onload\s*=/i
  ];
  
  if (reason && xssPatterns.some(pattern => pattern.test(reason))) {
    res.locals.reflectedXss = true;
    res.locals.xssPayload = reason.substring(0, 50);
    res.locals.generateFlag = true;
  }
  
  // Echo back user input without sanitization (reflected XSS)
  res.json({ 
    success: true, 
    message: `Review reported for: ${reason}`, // Vulnerable: reflects user input
    timestamp: new Date().toISOString()
  });
});

// Admin review management with CSRF vulnerability
router.post('/admin/approve/:id', flagManager.flagMiddleware('CSRF'), (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  // Check for CSRF
  const referer = req.get('Referer') || '';
  const origin = req.get('Origin') || '';
  const host = req.get('Host') || '';
  
  if (!referer.includes(host) && !origin.includes(host)) {
    res.locals.csrfSuccess = true;
    res.locals.csrfAction = 'admin_approve_review';
    res.locals.generateFlag = true;
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
router.post('/admin/delete/:id', flagManager.flagMiddleware('CSRF'), (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  // Check for CSRF
  const referer = req.get('Referer') || '';
  const origin = req.get('Origin') || '';
  const host = req.get('Host') || '';
  
  if (!referer.includes(host) && !origin.includes(host)) {
    res.locals.csrfSuccess = true;
    res.locals.csrfAction = 'admin_delete_review';
    res.locals.generateFlag = true;
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

// Edit review (Stored XSS on update)
router.post('/admin/edit/:id', flagManager.flagMiddleware('XSS_STORED'), async (req, res) => {
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
    
    // Check for XSS in updated content
    const xssPatterns = [
      /<script/i,
      /javascript:/i,
      /onerror\s*=/i,
      /onload\s*=/i,
      /onclick\s*=/i
    ];
    
    if (xssPatterns.some(pattern => pattern.test(title) || pattern.test(comment))) {
      res.locals.xssExecuted = true;
      res.locals.xssPayload = (title + ' ' + comment).substring(0, 100);
      res.locals.generateFlag = true;
    }
    
    // No sanitization on update
    review.title = title;
    review.comment = comment;
    await review.save();
    
    res.json({ success: true, message: 'Review updated' });
  } catch (err) {
    res.status(500).json({ error: 'Update failed', details: err.message });
  }
});

// Bulk review operations (CSRF + Privilege escalation)
router.post('/admin/bulk-action', flagManager.flagMiddleware('CSRF'), (req, res) => {
  if (!req.session.user || (req.session.user.role !== 'admin' && req.session.user.role !== 'staff')) {
    return res.status(403).json({ error: 'Admin or staff access required' });
  }

  // Check for CSRF
  const referer = req.get('Referer') || '';
  if (!referer.includes(req.get('Host'))) {
    res.locals.csrfSuccess = true;
    res.locals.csrfAction = 'bulk_review_action';
    res.locals.generateFlag = true;
  }

  const { action, reviewIds } = req.body;
  
  if (!action || !Array.isArray(reviewIds)) {
    return res.status(400).json({ error: 'Action and review IDs required' });
  }

  let updateData = {};
  switch (action) {
    case 'approve':
      updateData = { approved: true };
      break;
    case 'reject':
      updateData = { approved: false };
      break;
    case 'delete':
      Review.destroy({ where: { id: reviewIds } })
        .then(() => {
          res.json({ success: true, message: `${reviewIds.length} reviews deleted` });
        })
        .catch(err => {
          res.status(500).json({ error: 'Bulk delete failed' });
        });
      return;
    default:
      return res.status(400).json({ error: 'Invalid action' });
  }

  Review.update(updateData, { where: { id: reviewIds } })
    .then(() => {
      res.json({ 
        success: true, 
        message: `${reviewIds.length} reviews ${action}d`,
        action: action,
        count: reviewIds.length
      });
    })
    .catch(err => {
      res.status(500).json({ error: `Bulk ${action} failed` });
    });
});

module.exports = router;
