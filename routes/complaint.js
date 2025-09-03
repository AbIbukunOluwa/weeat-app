const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { ensureAuth } = require('../middleware/auth');
const Complaint = require('../models/Complaint');

const router = express.Router();

// ensure uploads path
const uploadDir = path.join(__dirname, '..', 'uploads', 'complaints');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// multer
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});
const upload = multer({ storage });

// GET list + form
router.get('/', ensureAuth, async (req, res) => {
  const myComplaints = await Complaint.findAll({
    where: { userId: req.session.user.id },
    order: [['createdAt', 'DESC']]
  });
  res.render('complaints', { title: 'Complaints', user: req.session.user, complaints: myComplaints });
});

// POST new complaint
router.post('/', ensureAuth, upload.single('image'), async (req, res) => {
  const imagePath = req.file ? path.join('uploads', 'complaints', req.file.filename) : null;
  await Complaint.create({
    text: req.body.text,
    imagePath,
    userId: req.session.user.id
  });
  res.redirect('/complaints');
});

module.exports = router;
