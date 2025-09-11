// In routes/profile.js, ensure the upload directory exists and fix the upload handler

const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { User, Order } = require('../models');

// Ensure upload directories exist
const uploadDir = path.join(__dirname, '..', 'uploads', 'avatars');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// ENHANCED: Additional file upload validation middleware - MOVED TO TOP
const validateFileUpload = (req, res, next) => {
  // Additional server-side validation
  if (req.file) {
    const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    const maxSize = 5 * 1024 * 1024; // 5MB
    
    if (!allowedMimeTypes.includes(req.file.mimetype)) {
      // Clean up invalid file
      if (fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({
        success: false,
        error: 'Invalid file type. Only JPEG, PNG, GIF, and WebP images are allowed.'
      });
    }
    
    if (req.file.size > maxSize) {
      // Clean up oversized file
      if (fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({
        success: false,
        error: 'File too large. Maximum size is 5MB.'
      });
    }
  }
  
  next();
};

// Multer configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const userId = req.session.user?.id || 'anonymous';
    const timestamp = Date.now();
    const ext = path.extname(file.originalname);
    const filename = `${userId}_${timestamp}${ext}`;
    cb(null, filename);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
  
  const fileExtension = path.extname(file.originalname).toLowerCase();
  const mimeType = file.mimetype;
  
  if (allowedTypes.includes(mimeType) || allowedExtensions.includes(fileExtension)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only JPEG, PNG, GIF, and WebP are allowed.'), false);
  }
};

const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  }
});

// Middleware to check if user is logged in
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/auth/login');
  }
  next();
}

// Profile page route
router.get('/', requireAuth, async (req, res) => {
  try {
    const user = await User.findByPk(req.session.user.id);
    
    if (!user) {
      req.session.destroy();
      return res.redirect('/auth/login');
    }
    
    const orders = await Order.findAll({
      where: { userId: user.id },
      order: [['createdAt', 'DESC']],
      limit: 5
    });
    
    res.render('profile', {
      title: 'My Profile',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        name: user.name,
        role: user.role,
        avatar: user.avatar || null,
        bio: user.bio || null,
        phone: user.phone || null
      },
      orders: orders
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).render('error', {
      error: 'Failed to load profile',
      title: 'Error',
      user: req.session.user
    });
  }
});

// Avatar upload route - FIXED
router.post('/upload-avatar', requireAuth, upload.single('avatar'), validateFileUpload, async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ 
        success: false,
        error: 'No file uploaded. Please select an image file.' 
      });
    }
    
    // Enhanced file validation
    const allowedMimeTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
    const maxFileSize = 5 * 1024 * 1024; // 5MB
    
    const fileExtension = path.extname(req.file.originalname).toLowerCase();
    const mimeType = req.file.mimetype;
    
    // Validate file type
    if (!allowedMimeTypes.includes(mimeType) && !allowedExtensions.includes(fileExtension)) {
      // Delete uploaded file
      if (fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({ 
        success: false,
        error: 'Invalid file type. Please upload a JPEG, PNG, GIF, or WebP image.' 
      });
    }
    
    // Validate file size
    if (req.file.size > maxFileSize) {
      // Delete uploaded file
      if (fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({ 
        success: false,
        error: 'File too large. Please upload an image smaller than 5MB.' 
      });
    }

    // Generate unique filename to prevent conflicts
    const userId = req.session.user.id;
    const timestamp = Date.now();
    const uniqueFileName = `${userId}_${timestamp}${fileExtension}`;
    const finalPath = path.join(uploadDir, uniqueFileName);
    
    // Move file to final location with unique name
    fs.renameSync(req.file.path, finalPath);
    
    // Build the avatar URL
    const avatarUrl = `/uploads/avatars/${uniqueFileName}`;
    
    // Update user avatar in database
    const user = await User.findByPk(req.session.user.id);
    if (!user) {
      // Clean up uploaded file if user not found
      if (fs.existsSync(finalPath)) {
        fs.unlinkSync(finalPath);
      }
      return res.status(404).json({ 
        success: false,
        error: 'User account not found. Please log in again.' 
      });
    }

    // Delete old avatar if it exists and is different
    if (user.avatar && user.avatar !== avatarUrl) {
      const oldAvatarPath = path.join(__dirname, '..', user.avatar.replace(/^\//, ''));
      if (fs.existsSync(oldAvatarPath)) {
        try {
          fs.unlinkSync(oldAvatarPath);
        } catch (deleteError) {
          console.warn('Could not delete old avatar:', deleteError.message);
          // Don't fail the upload for this
        }
      }
    }

    // Update user avatar in database
    await user.update({ avatar: avatarUrl });
    
    // Update session data
    req.session.user.avatar = avatarUrl;
    
    // Force session save and wait for it
    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) {
          console.error('Session save error:', err);
          reject(err);
        } else {
          resolve();
        }
      });
    });
    
    res.json({
      success: true,
      message: 'Avatar uploaded successfully!',
      avatar_url: avatarUrl,
      file_info: {
        name: uniqueFileName,
        originalName: req.file.originalname,
        size: req.file.size,
        type: req.file.mimetype
      }
    });
    
  } catch (error) {
    console.error('Avatar upload error:', error);
    
    // Clean up uploaded file on any error
    if (req.file?.path && fs.existsSync(req.file.path)) {
      try {
        fs.unlinkSync(req.file.path);
      } catch (cleanupError) {
        console.error('Error cleaning up file:', cleanupError);
      }
    }
    
    res.status(500).json({
      success: false,
      error: 'Avatar upload failed. Please try again.',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Also fix the delete avatar route:

router.delete('/avatar', requireAuth, async (req, res) => {
  try {
    const user = await User.findByPk(req.session.user.id);
    
    if (!user) {
      return res.status(404).json({ 
        success: false,
        error: 'User account not found. Please log in again.' 
      });
    }
    
    if (!user.avatar) {
      return res.status(400).json({ 
        success: false,
        error: 'No avatar to delete' 
      });
    }
    
    // Delete avatar file from filesystem
    const avatarPath = path.join(__dirname, '..', user.avatar.replace(/^\//, ''));
    if (fs.existsSync(avatarPath)) {
      try {
        fs.unlinkSync(avatarPath);
      } catch (deleteError) {
        console.warn('Could not delete avatar file:', deleteError.message);
      }
    }
    
    // Update database
    await user.update({ avatar: null });
    
    // CRITICAL FIX: Update session immediately
    req.session.user.avatar = null;
    
    // Force session save
    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) {
          console.error('Session save error:', err);
          reject(err);
        } else {
          resolve();
        }
      });
    });
    
    res.json({
      success: true,
      message: 'Avatar deleted successfully'
    });
    
  } catch (error) {
    console.error('Avatar deletion error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete avatar. Please try again.',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Profile update route
router.post('/update', requireAuth, async (req, res) => {
  try {
    const { name, email, bio, phone } = req.body;
    
    if (!name || !email) {
      return res.status(400).json({ 
        success: false,
        error: 'Name and email are required' 
      });
    }
    
    const user = await User.findByPk(req.session.user.id);
    if (!user) {
      return res.status(404).json({ 
        success: false,
        error: 'User not found' 
      });
    }
    
    user.name = name;
    user.email = email;
    user.bio = bio || null;
    user.phone = phone || null;
    
    await user.save();
    
    // Update session
    req.session.user.name = name;
    req.session.user.email = email;
    
    res.json({
      success: true,
      message: 'Profile updated successfully'
    });
    
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({
      success: false,
      error: 'Profile update failed: ' + error.message
    });
  }
});

module.exports = router;
