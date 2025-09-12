
// routes/complaints.js - FIXED VERSION
const express = require('express');
const router = express.Router();
const { Complaint, User } = require('../models');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Ensure upload directory exists
const uploadDir = path.join(__dirname, '../uploads/complaints');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'complaint-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    // VULNERABILITY: Weak file type validation (intentional)
    const allowedTypes = /jpeg|jpg|png|gif|pdf|svg/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Invalid file type'));
    }
  }
});

// Middleware to ensure user is authenticated
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/auth/login');
  }
  next();
}

// List complaints & display submission form
router.get('/', requireAuth, async (req, res) => {
  try {
    const complaints = await Complaint.findAll({ 
      include: User, 
      order: [['createdAt', 'DESC']] 
    });
    
    res.render('complaints', { 
      title: 'Complaints & Feedback', 
      complaints, 
      user: req.session.user 
    });
  } catch (error) {
    console.error('Error loading complaints:', error);
    res.status(500).render('error', {
      error: 'Failed to load complaints',
      title: 'Error',
      user: req.session.user
    });
  }
});

// Submit complaint with file upload - FIXED VERSION
router.post('/', requireAuth, upload.single('photo'), async (req, res) => {
  try {
    // FIXED: Get form data with proper field names
    const { orderId, details, category, urgent, contactMethod } = req.body;
    
    // FIXED: Enhanced validation and debugging
    console.log('Complaint submission data:', {
      orderId: orderId,
      details: details,
      category: category,
      urgent: urgent,
      contactMethod: contactMethod,
      hasFile: !!req.file,
      userId: req.session.user.id
    });
    
    // FIXED: Validate required fields with better error messages
    if (!details || details.trim() === '') {
      if (req.file) {
        // Clean up uploaded file if validation fails
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).render('error', {
        error: 'Complaint details are required. Please describe your issue.',
        title: 'Validation Error',
        user: req.session.user
      });
    }
    
    // FIXED: Prepare complaint data with proper field mapping
    const complaintData = {
      userId: req.session.user.id,
      orderId: orderId && orderId.trim() !== '' ? orderId.trim() : null, // FIXED: Handle empty orderId properly
      details: details.trim(), // FIXED: Ensure details is not null or empty
      category: category || 'other',
      urgent: urgent === 'true' || urgent === true,
      contactMethod: contactMethod || 'email',
      photo: req.file ? req.file.filename : null
    };
    
    // FIXED: Additional validation before database save
    if (!complaintData.details) {
      throw new Error('Details cannot be empty after processing');
    }
    
    console.log('Final complaint data before save:', complaintData);
    
    // Create complaint in database
    const newComplaint = await Complaint.create(complaintData);
    
    console.log('Complaint created successfully with ID:', newComplaint.id);
    
    // Redirect back to complaints page with success
    res.redirect('/complaints?success=true');
    
  } catch (error) {
    console.error('Complaint submission error:', error);
    
    // Clean up uploaded file if there was an error
    if (req.file && fs.existsSync(req.file.path)) {
      try {
        fs.unlinkSync(req.file.path);
      } catch (cleanupError) {
        console.error('File cleanup error:', cleanupError);
      }
    }
    
    // FIXED: Better error handling with specific error messages
    let errorMessage = 'Failed to submit complaint. Please try again.';
    
    if (error.name === 'SequelizeValidationError') {
      const validationErrors = error.errors.map(err => err.message);
      errorMessage = `Validation error: ${validationErrors.join(', ')}`;
    } else if (error.message.includes('orderId')) {
      errorMessage = 'Order ID validation failed. Please check the order ID format.';
    } else if (error.message.includes('details')) {
      errorMessage = 'Complaint details are required and cannot be empty.';
    }
    
    res.status(500).render('error', {
      error: errorMessage,
      title: 'Submission Error',
      user: req.session.user,
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// View uploaded complaint image/file (VULNERABILITY: Path traversal possible)
router.get('/view/:filename', requireAuth, (req, res) => {
  const filename = req.params.filename;
  
  // VULNERABILITY: Basic validation can be bypassed with encoded characters
  if (filename.includes('../')) {
    return res.status(400).send('Invalid filename');
  }
  
  const filePath = path.join(uploadDir, filename);
  
  // Check if file exists
  if (!fs.existsSync(filePath)) {
    return res.status(404).send('File not found');
  }
  
  // Send file
  res.sendFile(filePath);
});

// Like complaint (VULNERABILITY: No CSRF protection)
router.post('/:id/like', requireAuth, async (req, res) => {
  try {
    const complaintId = req.params.id;
    const { action } = req.body;
    
    // Simple like tracking (in production, track per user)
    const complaint = await Complaint.findByPk(complaintId);
    if (!complaint) {
      return res.status(404).json({ success: false, error: 'Complaint not found' });
    }
    
    // Update likes count
    if (action === 'unlike') {
      complaint.likes = Math.max(0, (complaint.likes || 0) - 1);
    } else {
      complaint.likes = (complaint.likes || 0) + 1;
    }
    
    await complaint.save();
    
    res.json({ 
      success: true, 
      likes: complaint.likes 
    });
  } catch (error) {
    console.error('Like error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to update like' 
    });
  }
});

// Add comment to complaint (VULNERABILITY: Stored XSS)
router.post('/:id/comment', requireAuth, async (req, res) => {
  try {
    const complaintId = req.params.id;
    const { comment } = req.body;
    
    if (!comment || comment.trim() === '') {
      return res.status(400).json({ 
        success: false, 
        error: 'Comment cannot be empty' 
      });
    }
    
    // In a real app, store comments in a separate table
    // For demo, we'll just return success
    res.json({ 
      success: true,
      comment: comment, // VULNERABILITY: No sanitization
      user: req.session.user.username,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Comment error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to add comment' 
    });
  }
});

// Admin/Staff actions
router.post('/:id/resolve', requireAuth, async (req, res) => {
  // Check if user is admin or staff
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'staff') {
    return res.status(403).json({ 
      success: false, 
      error: 'Unauthorized' 
    });
  }
  
  try {
    const complaint = await Complaint.findByPk(req.params.id);
    if (!complaint) {
      return res.status(404).json({ 
        success: false, 
        error: 'Complaint not found' 
      });
    }
    
    complaint.resolved = true;
    complaint.resolvedAt = new Date();
    complaint.resolvedBy = req.session.user.id;
    await complaint.save();
    
    res.json({ 
      success: true, 
      message: 'Complaint marked as resolved' 
    });
  } catch (error) {
    console.error('Resolve error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to resolve complaint' 
    });
  }
});

router.post('/:id/escalate', requireAuth, async (req, res) => {
  // Check if user is admin or staff
  if (req.session.user.role !== 'admin' && req.session.user.role !== 'staff') {
    return res.status(403).json({ 
      success: false, 
      error: 'Unauthorized' 
    });
  }
  
  try {
    const { reason } = req.body;
    const complaint = await Complaint.findByPk(req.params.id);
    
    if (!complaint) {
      return res.status(404).json({ 
        success: false, 
        error: 'Complaint not found' 
      });
    }
    
    complaint.escalated = true;
    complaint.escalationReason = reason;
    complaint.escalatedAt = new Date();
    complaint.escalatedBy = req.session.user.id;
    await complaint.save();
    
    res.json({ 
      success: true, 
      message: 'Complaint escalated to management' 
    });
  } catch (error) {
    console.error('Escalate error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to escalate complaint' 
    });
  }
});

module.exports = router;
