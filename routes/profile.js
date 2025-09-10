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
router.post('/upload-avatar', requireAuth, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ 
        success: false,
        error: 'No file uploaded' 
      });
    }

    // Build the avatar URL
    const avatarUrl = `/uploads/avatars/${req.file.filename}`;
    
    // Update user avatar in database
    const user = await User.findByPk(req.session.user.id);
    if (!user) {
      // Delete uploaded file if user not found
      fs.unlinkSync(req.file.path);
      return res.status(404).json({ 
        success: false,
        error: 'User not found' 
      });
    }

    // Delete old avatar if it exists
    if (user.avatar) {
      const oldAvatarPath = path.join(__dirname, '..', user.avatar.replace(/^\//, ''));
      if (fs.existsSync(oldAvatarPath)) {
        fs.unlinkSync(oldAvatarPath);
      }
    }

    // Update user avatar
    user.avatar = avatarUrl;
    await user.save();
    
    // Update session
    req.session.user.avatar = avatarUrl;
    
    res.json({
      success: true,
      message: 'Avatar uploaded successfully',
      avatar_url: avatarUrl,
      file_info: {
        name: req.file.filename,
        size: req.file.size,
        type: req.file.mimetype
      }
    });
    
  } catch (error) {
    console.error('Avatar upload error:', error);
    
    // Clean up uploaded file on error
    if (req.file?.path && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    
    res.status(500).json({
      success: false,
      error: 'Avatar upload failed: ' + error.message
    });
  }
});

// Avatar deletion route
router.delete('/avatar', requireAuth, async (req, res) => {
  try {
    const user = await User.findByPk(req.session.user.id);
    
    if (!user || !user.avatar) {
      return res.status(400).json({ 
        success: false,
        error: 'No avatar to delete' 
      });
    }
    
    // Delete avatar file
    const avatarPath = path.join(__dirname, '..', user.avatar.replace(/^\//, ''));
    if (fs.existsSync(avatarPath)) {
      fs.unlinkSync(avatarPath);
    }
    
    // Update database
    user.avatar = null;
    await user.save();
    
    // Update session
    req.session.user.avatar = null;
    
    res.json({
      success: true,
      message: 'Avatar deleted successfully'
    });
    
  } catch (error) {
    console.error('Avatar deletion error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to delete avatar: ' + error.message
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
