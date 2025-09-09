const express = require('express');
const router = express.Router();
const { Complaint, User } = require('../models');
const multer = require('multer');
const path = require('path');

const upload = multer({ dest: path.join(__dirname, '../uploads/') });

// List complaints & submit
router.get('/', async (req, res) => {
  const complaints = await Complaint.findAll({ include: User, order: [['createdAt', 'DESC']] });
  res.render('complaints', { title: 'Complaints', complaints, user: req.session.user });
});

router.post('/', upload.single('image'), async (req, res) => {
  if (!req.session.user) return res.redirect('/auth/login');
  const { text } = req.body;
  let imagePath = req.file ? `uploads/${req.file.filename}` : null;
  try {
    await Complaint.create({ text, imagePath, userId: req.session.user.id });
    res.redirect('/complaints');
  } catch (err) {
    console.error(err);
    res.send('Error submitting complaint');
  }
});

module.exports = router;
