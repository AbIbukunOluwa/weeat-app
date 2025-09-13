// routes/upload.js - Advanced file upload vulnerabilities
const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const sharp = require('sharp'); // For image processing
const unzipper = require('unzipper'); // For zip file handling
const flagManager = require('../utils/flags');

// Storage configuration with multiple vulnerabilities
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Different upload directories based on file type
    let uploadPath = 'uploads/';
    
    if (file.fieldname === 'avatar') {
      uploadPath += 'avatars/';
    } else if (file.fieldname === 'document') {
      uploadPath += 'documents/';
    } else if (file.fieldname === 'backup') {
      uploadPath += 'backups/';
    } else {
      uploadPath += 'misc/';
    }
    
    // Create directory if doesn't exist
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    // Weak filename sanitization
    let filename = file.originalname;
    
    // Only basic sanitization - can be bypassed
    filename = filename.replace(/\.\./g, '');
    
    // Add timestamp to prevent collisions (but predictable)
    const timestamp = Date.now();
    const name = `${timestamp}_${filename}`;
    
    cb(null, name);
  }
});

// File filter with bypassable checks
const fileFilter = (req, file, cb) => {
  // Check file extension (case sensitive - bypass with .PHP, .Php, etc)
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt'];
  const ext = path.extname(file.originalname).toLowerCase();
  
  // MIME type check (can be spoofed)
  const allowedMimeTypes = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf',
    'text/plain'
  ];
  
  // Bypass with double extensions like file.jpg.php
  if (req.headers['x-bypass-filter'] === 'true' || req.query.admin === 'true') {
    return cb(null, true);
  }
  
  // Weak validation
  if (allowedExtensions.includes(ext) || allowedMimeTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('File type not allowed'), false);
  }
};

const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB - but can be bypassed
    files: 5
  }
});

// Profile picture upload with multiple vulnerabilities
router.post('/profile/avatar', upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const filePath = req.file.path;
    const fileExt = path.extname(req.file.originalname);
    
    // Image processing vulnerability (ImageTragick-style)
    if (fileExt.match(/\.(jpg|jpeg|png|gif)$/i)) {
      try {
        // Using sharp for image processing (can be exploited with crafted images)
        const metadata = await sharp(filePath).metadata();
        
        // Resize image (but process EXIF data which might contain payloads)
        await sharp(filePath)
          .resize(200, 200)
          .toFile(filePath.replace(fileExt, '_thumb' + fileExt));
        
        // Store EXIF data (might contain XSS payloads)
        if (metadata.exif) {
          req.session.imageMetadata = metadata.exif;
        }
      } catch (imgError) {
        console.log('Image processing error:', imgError);
      }
    }
    
    // Update user profile with avatar path
    if (req.session.user) {
      const { User } = require('../models');
      await User.update(
        { avatar: `/uploads/avatars/${req.file.filename}` },
        { where: { id: req.session.user.id } }
      );
    }
    
    res.json({
      success: true,
      file: {
        filename: req.file.filename,
        originalName: req.file.originalname,
        path: `/uploads/avatars/${req.file.filename}`,
        size: req.file.size,
        mimetype: req.file.mimetype
      }
    });
    
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Polyglot file upload (file that's valid as multiple formats)
router.post('/document/upload', upload.single('document'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  const filePath = req.file.path;
  const fileContent = fs.readFileSync(filePath);
  
  // Check if file is a polyglot (e.g., GIFAR - GIF + JAR)
  const gifHeader = Buffer.from([0x47, 0x49, 0x46, 0x38]); // GIF8
  const pdfHeader = Buffer.from([0x25, 0x50, 0x44, 0x46]); // %PDF
  const zipHeader = Buffer.from([0x50, 0x4B, 0x03, 0x04]); // PK..
  
  const isGif = fileContent.slice(0, 4).equals(gifHeader);
  const isPdf = fileContent.slice(0, 4).equals(pdfHeader);
  const hasZip = fileContent.indexOf(zipHeader) !== -1;
  
  if ((isGif || isPdf) && hasZip) {
    // Potential polyglot file detected
    res.json({
      success: true,
      warning: 'Interesting file structure detected',
      polyglot: true,
      types: {
        gif: isGif,
        pdf: isPdf,
        zip: hasZip
      }
    });
  } else {
    res.json({
      success: true,
      file: req.file.filename,
      path: `/uploads/documents/${req.file.filename}`
    });
  }
});

// ZIP file extraction vulnerability (path traversal via zip)
router.post('/backup/restore', upload.single('backup'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No backup file uploaded' });
  }
  
  const zipPath = req.file.path;
  const extractPath = path.join('uploads', 'extracted', Date.now().toString());
  
  try {
    // Create extraction directory
    fs.mkdirSync(extractPath, { recursive: true });
    
    // Extract ZIP file (vulnerable to zip slip attack)
    await fs.createReadStream(zipPath)
      .pipe(unzipper.Extract({ path: extractPath }))
      .promise();
    
    // List extracted files
    const extractedFiles = fs.readdirSync(extractPath);
    
    res.json({
      success: true,
      message: 'Backup restored',
      extracted: extractedFiles,
      path: extractPath
    });
    
  } catch (err) {
    res.status(500).json({ 
      error: 'Extraction failed',
      details: err.message 
    });
  }
});

// File inclusion vulnerability
router.get('/view/:type/:filename', (req, res) => {
  const { type, filename } = req.params;
  
  // Basic path traversal protection (can be bypassed)
  if (filename.includes('../')) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  // But doesn't check for URL encoding: ..%2F, double encoding: %252e%252e%252f
  const decodedFilename = decodeURIComponent(filename);
  
  const basePath = path.join(__dirname, '..', 'uploads', type);
  const filePath = path.join(basePath, decodedFilename);
  
  // Check file exists
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found' });
  }
  
  // Determine content type (but trusts file extension)
  const ext = path.extname(filePath).toLowerCase();
  const contentTypes = {
    '.html': 'text/html',
    '.js': 'application/javascript',
    '.php': 'application/x-httpd-php',
    '.jsp': 'application/x-jsp',
    '.svg': 'image/svg+xml'
  };
  
  if (contentTypes[ext]) {
    res.set('Content-Type', contentTypes[ext]);
  }
  
  // Send file (executes HTML/JS/SVG in browser context)
  res.sendFile(filePath);
});

// EXIF data extraction (can contain XSS payloads)
router.post('/image/analyze', upload.single('image'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No image uploaded' });
  }
  
  try {
    const exifParser = require('exif-parser');
    const buffer = fs.readFileSync(req.file.path);
    const parser = exifParser.create(buffer);
    const exifData = parser.parse();
    
    // Return raw EXIF data (might contain malicious payloads)
    res.json({
      success: true,
      filename: req.file.filename,
      exif: exifData.tags,
      // Include GPS data if present
      gps: exifData.tags.GPSLatitude ? {
        lat: exifData.tags.GPSLatitude,
        lon: exifData.tags.GPSLongitude
      } : null
    });
    
  } catch (err) {
    res.status(500).json({ 
      error: 'EXIF extraction failed',
      details: err.message
    });
  }
});

// Unrestricted file upload
router.post('/profile/avatar', upload.single('avatar'), flagManager.flagMiddleware('FILE_UPLOAD'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const fileExt = path.extname(req.file.originalname).toLowerCase();
    
    // Check for malicious file types
    const dangerousExtensions = [
      '.php', '.jsp', '.asp', '.aspx', 
      '.js', '.py', '.rb', '.sh', '.bat',
      '.exe', '.dll', '.so'
    ];
    
    if (dangerousExtensions.includes(fileExt)) {
      res.locals.maliciousFileUploaded = true;
      res.locals.uploadedFileType = fileExt;
      res.locals.generateFlag = true;
    }
    
    // Check for double extensions (bypass attempt)
    if (req.file.originalname.match(/\.(jpg|png|gif)\.(php|asp|jsp)/i)) {
      res.locals.maliciousFileUploaded = true;
      res.locals.uploadedFileType = 'double_extension';
      res.locals.generateFlag = true;
    }
    
    res.json({
      success: true,
      file: {
        filename: req.file.filename,
        path: `/uploads/${req.file.filename}`
      }
    });
    
  } catch (err) {
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Path traversal vulnerability
router.get('/view/:filename', flagManager.flagMiddleware('PATH_TRAVERSAL'), (req, res) => {
  const filename = req.params.filename;
  
  // Check for path traversal attempts
  if (filename.includes('../') || filename.includes('..\\')) {
    res.locals.pathTraversalSuccess = true;
    res.locals.accessedPath = filename;
    res.locals.generateFlag = true;
  }
  
  // Vulnerable: No proper sanitization
  const filePath = path.join(__dirname, '../uploads', filename);
  
  if (fs.existsSync(filePath)) {
    res.sendFile(filePath);
  } else {
    res.status(404).send('File not found');
  }
});

// SVG upload with XSS
router.post('/logo/upload', upload.single('logo'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No logo uploaded' });
  }
  
  const filePath = req.file.path;
  const fileContent = fs.readFileSync(filePath, 'utf8');
  
  // Check if SVG (but doesn't sanitize)
  if (req.file.mimetype === 'image/svg+xml' || filePath.endsWith('.svg')) {
    // SVG files can contain JavaScript
    if (fileContent.includes('<script') || fileContent.includes('onload=')) {
      res.json({
        success: true,
        warning: 'Active content detected in SVG',
        path: `/uploads/misc/${req.file.filename}`,
        render: true // Will be rendered in browser!
      });
    } else {
      res.json({
        success: true,
        path: `/uploads/misc/${req.file.filename}`
      });
    }
  } else {
    res.json({
      success: true,
      path: `/uploads/misc/${req.file.filename}`
    });
  }
});

// Race condition in file upload
router.post('/temp/upload', upload.single('tempfile'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  const tempPath = req.file.path;
  const finalPath = tempPath.replace('misc', 'permanent');
  
  // Async file validation (creates race condition window)
  setTimeout(() => {
    // Check file content after delay
    const content = fs.readFileSync(tempPath, 'utf8');
    if (content.includes('<?php') || content.includes('<%')) {
      // Try to delete malicious file (but might be too late)
      fs.unlinkSync(tempPath);
      return;
    }
    
    // Move to permanent location
    fs.renameSync(tempPath, finalPath);
  }, 1000); // 1 second window to replace file
  
  res.json({
    success: true,
    tempPath: tempPath,
    message: 'File uploaded, validation in progress...'
  });
});

// Filename injection
router.post('/custom/upload', upload.single('custom'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  // Use user-provided filename (dangerous!)
  const customName = req.body.filename || req.file.originalname;
  const newPath = path.join('uploads', 'custom', customName);
  
  // Create custom directory
  if (!fs.existsSync(path.dirname(newPath))) {
    fs.mkdirSync(path.dirname(newPath), { recursive: true });
  }
  
  // Move file to new location with custom name
  fs.renameSync(req.file.path, newPath);
  
  res.json({
    success: true,
    message: `File saved as ${customName}`,
    path: `/uploads/custom/${customName}`,
    // Log injection possible through filename
    log: `User ${req.session?.user?.username || 'anonymous'} uploaded ${customName}`
  });
});

module.exports = router;
