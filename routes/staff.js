const express = require('express');
const { ensureRole } = require('../middleware/auth');
const Complaint = require('../models/Complaint');
const User = require('../models/User');

const router = express.Router();

// staff portal home: list all complaints (newest first)
router.get('/', ensureRole('staff'), async (_req, res) => {
  const complaints = await Complaint.findAll({
    include: [{ model: User, attributes: ['username'] }],
    order: [['createdAt', 'DESC']]
  });
  res.render('staff/index', { title: 'Staff Portal', user: _req.session.user, complaints });
});

module.exports = router;
