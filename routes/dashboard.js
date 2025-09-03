const express = require('express');
const { ensureAuth } = require('../middleware/auth');
const Complaint = require('../models/Complaint');
const router = express.Router();

router.get('/', ensureAuth, async (req, res) => {
  const myComplaints = await Complaint.findAll({
    where: { userId: req.session.user.id },
    order: [['createdAt', 'DESC']]
  });
  res.render('dashboard', { title: 'Dashboard', user: req.session.user, complaints: myComplaints });
});

module.exports = router;
