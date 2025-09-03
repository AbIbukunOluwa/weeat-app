const express = require('express');
const { ContactMessage } = require('../models/ContactMessage');
const { Complaint } = require('../models/Complaint');

const router = express.Router();

// Simple middleware for auth placeholder (replace later with real auth)
router.use((req, res, next) => {
  // TODO: Replace with real admin auth check
  next();
});

// Admin Home
router.get('/', (req, res) => {
  res.render('admin', { title: 'Admin Dashboard' });
});

// View Contact Messages
router.get('/contacts', async (req, res) => {
  const messages = await ContactMessage.findAll({ order: [['createdAt', 'DESC']] });
  res.render('admin_contacts', { title: 'Contact Messages', messages });
});

// View Complaints
router.get('/complaints', async (req, res) => {
  const complaints = await Complaint.findAll({ order: [['createdAt', 'DESC']] });
  res.render('admin_complaints', { title: 'Complaints', complaints });
});

module.exports = router;
