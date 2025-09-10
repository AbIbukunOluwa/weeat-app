// routes/profile.js - Enhanced with profile picture upload vulnerabilities
const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const sharp = require('sharp');
const { User, Order } = require('../models');

// Require login middleware
function isLoggedIn(req, res, next) {
    if (!req.session.user) return res.redirect('/auth/login');
    next();
}

// VULNERABILITY: Weak file upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/avatars/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // VULNERABILITY: Predictable filename generation
    const userId = req.session.user?.id || 'anonymous';
    const timestamp = Date.now();
    const originalName = file.originalname;
    
    // VULNERABILITY: Insufficient sanitization - only removes ../ but not other path traversal
    const sanitized = originalName.replace(/\.\./g, '').replace(/\//g, '');
    
    // VULNERABILITY: Double extension bypass possible (file.jpg.php)
    const filename = `${userId}_${timestamp}_${sanitized}`;
    cb(null, filename);
  }
});

// VULNERABILITY: Bypassable file filter
const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
  
  const fileExtension = path.extname(file.originalname).toLowerCase();
  const mimeType = file.mimetype;
  
  // VULNERABILITY: Admin bypass header
  if (req.headers['x-admin-upload'] === 'true' && req.session.user?.role === 'admin') {
    return cb(null, true);
  }
  
  // VULNERABILITY: Staff bypass with specific user agent
  if (req.session.user?.role === 'staff' && 
      req.get('User-Agent')?.includes('StaffUploader')) {
    return cb(null, true);
  }
  
  // VULNERABILITY: Double extension check bypass
  if (file.originalname.includes('.jpg.') || file.originalname.includes('.png.')) {
    // Check if it "looks" like an image file
    if (allowedExtensions.some(ext => file.originalname.toLowerCase().includes(ext))) {
      return cb(null, true);
    }
  }
  
  // VULNERABILITY: MIME type can be spoofed
  if (allowedTypes.includes(mimeType) || allowedExtensions.includes(fileExtension)) {
    cb(null, true);
  } else {
    // VULNERABILITY: Expose allowed types in error
    cb(new Error(`File type not allowed. Allowed: ${allowedTypes.join(', ')}`), false);
  }
};

const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB base limit
    files: 1
  }
});

// Override limits with headers (VULNERABILITY: Size limit bypass)
const dynamicUpload = (req, res, next) => {
  const customLimit = req.headers['x-upload-limit'];
  if (customLimit && req.session.user?.role === 'admin') {
    upload.limits.fileSize = parseInt(customLimit) * 1024 * 1024;
  }
  
  // VULNERABILITY: Staff can upload larger files with special header
  if (req.headers['x-staff-override'] === 'large-files' && req.session.user?.role === 'staff') {
    upload.limits.fileSize = 50 * 1024 * 1024; // 50MB
  }
  
  upload.single('avatar')(req, res, next);
};

// Profile view
router.get('/', isLoggedIn, async (req, res) => {
  try {
    const userOrders = await Order.findAll({ 
      where: { userId: req.session.user.id },
      order: [['createdAt', 'DESC']],
      limit: 10
    });
    
    // Get user details including avatar
    const user = await User.findByPk(req.session.user.id, {
      attributes: ['id', 'username', 'email', 'name', 'role', 'avatar', 'createdAt']
    });
    
    res.render('profile/index', { 
      title: 'My Profile', 
      orders: userOrders,
      profileUser: user
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).render('error', {
      error: 'Failed to load profile',
      details: req.headers['x-debug-profile'] === 'true' ? error.message : null
    });
  }
});

// Profile picture upload with multiple vulnerabilities
router.post('/upload-avatar', isLoggedIn, dynamicUpload, async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ 
        error: 'No file uploaded',
        accepted_types: ['JPEG', 'PNG', 'GIF', 'WebP']
      });
    }

    const filePath = req.file.path;
    const fileExtension = path.extname(req.file.originalname).toLowerCase();
    const mimeType = req.file.mimetype;
    
    console.log(`📸 Avatar upload: ${req.session.user.username} uploaded ${req.file.filename}`);
    
    let processedImagePath = filePath;
    
    // VULNERABILITY: Image processing with potential ImageTragick-style attacks
    if (['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(fileExtension)) {
      try {
        // VULNERABILITY: Process uploaded image without proper validation
        const metadata = await sharp(filePath)
          .metadata();
        
        // VULNERABILITY: EXIF data might contain malicious payloads
        if (metadata.exif && req.query.preserve_exif === 'true') {
          // Keep EXIF data (including potential XSS payloads)
          req.session.imageMetadata = metadata.exif;
        }
        
        // Resize image but keep original if header is set
        if (req.headers['x-keep-original'] !== 'true') {
          const resizedPath = filePath.replace(fileExtension, '_thumb' + fileExtension);
          
          await sharp(filePath)
            .resize(300, 300, { 
              fit: 'cover',
              position: 'center'
            })
            .jpeg({ quality: 80 })
            .toFile(resizedPath);
          
          processedImagePath = resizedPath;
        }
        
      } catch (imageError) {
        console.error('Image processing error:', imageError);
        // Continue with original file even if processing fails
      }
    }
    
    // VULNERABILITY: File path stored without proper validation
    const avatarUrl = `/uploads/avatars/${req.file.filename}`;
    
    // Update user avatar in database
    await User.update(
      { avatar: avatarUrl },
      { where: { id: req.session.user.id } }
    );
    
    // Update session data
    req.session.user.avatar = avatarUrl;
    
    // VULNERABILITY: Expose file system information
    const debugInfo = req.headers['x-upload-debug'] === 'true' ? {
      original_filename: req.file.originalname,
      stored_filename: req.file.filename,
      file_path: filePath,
      file_size: req.file.size,
      mime_type: mimeType,
      upload_directory: path.dirname(filePath),
      server_path: path.resolve(filePath),
      metadata: req.session.imageMetadata || null
    } : null;
    
    res.json({
      success: true,
      message: 'Avatar uploaded successfully',
      avatar_url: avatarUrl,
      file_info: {
        name: req.file.filename,
        size: req.file.size,
        type: mimeType
      },
      debug: debugInfo
    });
    
  } catch (error) {
    console.error('Avatar upload error:', error);
    
    // Clean up uploaded file on error
    if (req.file?.path && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    
    res.status(500).json({
      error: 'Avatar upload failed',
      details: req.headers['x-upload-debug'] === 'true' ? error.message : 'Please try again',
      stack: req.headers['x-full-debug'] === 'true' ? error.stack : null
    });
  }
});

// VULNERABILITY: Avatar file serving without proper access controls
router.get('/avatar/:filename', (req, res) => {
  const filename = req.params.filename;
  
  // VULNERABILITY: Insufficient path traversal protection
  if (filename.includes('../') || filename.includes('..\\')) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  // VULNERABILITY: No authentication check - anyone can access any avatar
  const filePath = path.join(__dirname, '..', 'uploads', 'avatars', filename);
  
  // VULNERABILITY: File existence check exposes file system structure
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ 
      error: 'Avatar not found',
      searched_path: req.headers['x-debug-paths'] === 'true' ? filePath : null
    });
  }
  
  // VULNERABILITY: Serve file without content type validation
  const stat = fs.statSync(filePath);
  const fileExtension = path.extname(filename).toLowerCase();
  
  // Set content type based on extension (can be bypassed)
  const contentTypes = {
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg', 
    '.png': 'image/png',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
    '.svg': 'image/svg+xml', // VULNERABILITY: SVG can contain XSS
    '.html': 'text/html',    // VULNERABILITY: HTML execution
    '.js': 'application/javascript' // VULNERABILITY: JavaScript execution
  };
  
  const contentType = contentTypes[fileExtension] || 'application/octet-stream';
  res.set('Content-Type', contentType);
  
  // VULNERABILITY: Expose file metadata
  if (req.query.include_metadata === 'true') {
    res.set('X-File-Size', stat.size.toString());
    res.set('X-File-Modified', stat.mtime.toISOString());
    res.set('X-File-Path', req.headers['x-debug-paths'] === 'true' ? filePath : null);
  }
  
  // VULNERABILITY: Allow execution of SVG/HTML files in browser context
  res.sendFile(filePath);
});

// VULNERABILITY: Batch avatar upload for "testing"
router.post('/upload-batch-avatars', isLoggedIn, (req, res) => {
  // VULNERABILITY: Only basic role check
  if (req.session.user.role !== 'admin' && 
      req.headers['x-batch-override'] !== 'testing-mode') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  
  const batchUpload = multer({ 
    dest: 'uploads/avatars/batch/',
    limits: { 
      files: 10,
      fileSize: 10 * 1024 * 1024 // 10MB per file
    }
  }).array('avatars', 10);
  
  batchUpload(req, res, async (err) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'No files uploaded' });
    }
    
    const results = [];
    
    for (const file of req.files) {
      try {
        const avatarUrl = `/uploads/avatars/batch/${file.filename}`;
        results.push({
          filename: file.originalname,
          stored_as: file.filename,
          url: avatarUrl,
          size: file.size,
          status: 'success'
        });
      } catch (error) {
        results.push({
          filename: file.originalname,
          status: 'error',
          error: error.message
        });
      }
    }
    
    res.json({
      success: true,
      message: `Uploaded ${results.filter(r => r.status === 'success').length} files`,
      results: results,
      upload_directory: req.headers['x-show-paths'] === 'true' ? 'uploads/avatars/batch/' : null
    });
  });
});

// Profile update endpoint
router.post('/update', isLoggedIn, async (req, res) => {
  try {
    const { name, email, bio, phone } = req.body;
    const userId = req.session.user.id;
    
    // Basic validation
    if (!name || !email) {
      return res.status(400).json({ error: 'Name and email are required' });
    }
    
    // VULNERABILITY: No email uniqueness check when updating
    const updateData = {
      name: name,
      email: email,
      bio: bio || null,
      phone: phone || null
    };
    
    await User.update(updateData, { where: { id: userId } });
    
    // Update session data
    req.session.user.name = name;
    req.session.user.email = email;
    
    res.json({
      success: true,
      message: 'Profile updated successfully',
      updated_fields: Object.keys(updateData)
    });
    
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({
      error: 'Profile update failed',
      details: req.headers['x-debug-profile'] === 'true' ? error.message : null
    });
  }
});

// VULNERABILITY: Delete profile picture without proper authorization
router.delete('/avatar', isLoggedIn, async (req, res) => {
  try {
    const user = await User.findByPk(req.session.user.id);
    
    if (!user.avatar) {
      return res.status(400).json({ error: 'No avatar to delete' });
    }
    
    // VULNERABILITY: File deletion without proper path validation
    const filename = path.basename(user.avatar);
    const filePath = path.join(__dirname, '..', 'uploads', 'avatars', filename);
    
    // Delete file if it exists
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      
      // Also delete thumbnail if it exists
      const thumbPath = filePath.replace(path.extname(filename), '_thumb' + path.extname(filename));
      if (fs.existsSync(thumbPath)) {
        fs.unlinkSync(thumbPath);
      }
    }
    
    // Update database
    await User.update(
      { avatar: null },
      { where: { id: req.session.user.id } }
    );
    
    // Update session
    req.session.user.avatar = null;
    
    res.json({
      success: true,
      message: 'Avatar deleted successfully'
    });
    
  } catch (error) {
    console.error('Avatar deletion error:', error);
    res.status(500).json({
      error: 'Failed to delete avatar',
      details: req.headers['x-debug-profile'] === 'true' ? error.message : null
    });
  }
});

module.exports = router;
