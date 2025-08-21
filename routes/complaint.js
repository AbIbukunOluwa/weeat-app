const express = require('express');
const router = express.Router();

// GET /complaint → show complaint form
router.get('/', (req, res) => {
  res.render('complaint', { title: 'Submit a Complaint' });
});

// POST /complaint → handle submission
router.post('/', (req, res) => {
  const { orderId, description, photo } = req.body;

  // For now, log complaints
  console.log('Complaint submitted:', { orderId, description, photo });

  res.render('complaint-success', { title: 'Complaint Submitted', orderId });
});

module.exports = router;
