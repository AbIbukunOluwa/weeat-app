// routes/upload.js - Fixed file upload vulnerabilities with proper detection
const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
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
    // Weak filename sanitization (can be bypassed)
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
  
  // Bypass with special headers
  if (req.headers['x-bypass-filter'] === 'true' || req.query.admin === 'true') {
    return cb(null, true);
  }
  
  // Weak validation that can be bypassed
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
    fileSize: 10 * 1024 * 1024, // 10MB - but can be bypassed with headers
    files: 5
  }
});

// Profile picture upload with multiple vulnerabilities
router.post('/profile/avatar', upload.single('avatar'), flagManager.flagMiddleware('FILE_UPLOAD'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const filePath = req.file.path;
    const fileExt = path.extname(req.file.originalname).toLowerCase();
    
    // Check for dangerous file types
    const dangerousExtensions = [
      '.php', '.jsp', '.asp', '.aspx', 
      '.js', '.py', '.rb', '.sh', '.bat',
      '.exe', '.dll', '.so', '.jar'
    ];
    
    if (dangerousExtensions.includes(fileExt)) {
      res.locals.maliciousFileUploaded = true;
      res.locals.uploadedFileType = fileExt;
      res.locals.generateFlag = true;
    }
    
    // Check for double extensions (bypass attempt)
    if (req.file.originalname.match(/\.(jpg|png|gif)\.(php|asp|jsp|js)/i)) {
      res.locals.maliciousFileUploaded = true;
      res.locals.uploadedFileType = 'double_extension';
      res.locals.generateFlag = true;
    }
    
    // Check for null byte injection
    if (req.file.originalname.includes('\x00')) {
      res.locals.maliciousFileUploaded = true;
      res.locals.uploadedFileType = 'null_byte_injection';
      res.locals.generateFlag = true;
    }
    
    // Image processing with potential vulnerabilities
    if (fileExt.match(/\.(jpg|jpeg|png|gif)$/i)) {
      try {
        // Check if sharp is available
        const sharp = require('sharp');
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

// Document upload with polyglot detection
router.post('/document/upload', upload.single('document'), flagManager.flagMiddleware('FILE_UPLOAD'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  const filePath = req.file.path;
  const fileExt = path.extname(req.file.originalname).toLowerCase();
  
  try {
    const fileContent = fs.readFileSync(filePath);
    
    // Check if file is a polyglot (e.g., GIFAR - GIF + JAR)
    const gifHeader = Buffer.from([0x47, 0x49, 0x46, 0x38]); // GIF8
    const pdfHeader = Buffer.from([0x25, 0x50, 0x44, 0x46]); // %PDF
    const zipHeader = Buffer.from([0x50, 0x4B, 0x03, 0x04]); // PK..
    const phpHeader = Buffer.from('<?php');
    
    const isGif = fileContent.slice(0, 4).equals(gifHeader);
    const isPdf = fileContent.slice(0, 4).equals(pdfHeader);
    const hasZip = fileContent.indexOf(zipHeader) !== -1;
    const hasPhp = fileContent.indexOf(phpHeader) !== -1;
    
    // Detect malicious file uploads
    if (hasPhp || fileExt === '.php') {
      res.locals.maliciousFileUploaded = true;
      res.locals.uploadedFileType = 'php_file';
      res.locals.generateFlag = true;
    }
    
    if ((isGif || isPdf) && hasZip) {
      // Potential polyglot file detected
      res.locals.maliciousFileUploaded = true;
      res.locals.uploadedFileType = 'polyglot_file';
      res.locals.generateFlag = true;
      
      res.json({
        success: true,
        warning: 'Polyglot file structure detected',
        polyglot: true,
        types: {
          gif: isGif,
          pdf: isPdf,
          zip: hasZip,
          php: hasPhp
        }
      });
    } else {
      res.json({
        success: true,
        file: req.file.filename,
        path: `/uploads/documents/${req.file.filename}`
      });
    }
  } catch (err) {
    res.status(500).json({ error: 'File processing failed' });
  }
});

// ZIP file extraction vulnerability (path traversal via zip)
router.post('/backup/restore', upload.single('backup'), flagManager.flagMiddleware('PATH_TRAVERSAL'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No backup file uploaded' });
  }
  
  const zipPath = req.file.path;
  const extractPath = path.join('uploads', 'extracted', Date.now().toString());
  
  try {
    // Create extraction directory
    fs.mkdirSync(extractPath, { recursive: true });
    
    // Check if it's actually a zip file
    const fileBuffer = fs.readFileSync(zipPath);
    if (!fileBuffer.slice(0, 2).equals(Buffer.from([0x50, 0x4b]))) {
      return res.status(400).json({ error: 'Invalid ZIP file' });
    }
    
    // Extract ZIP file (vulnerable to zip slip attack)
    const unzipper = require('unzipper');
    await fs.createReadStream(zipPath)
      .pipe(unzipper.Extract({ path: extractPath }))
      .promise();
    
    // List extracted files (might show path traversal attempts)
    const extractedFiles = fs.readdirSync(extractPath);
    
    // Check for path traversal in extracted files
    if (extractedFiles.some(file => file.includes('../') || file.includes('..\\'))) {
      res.locals.pathTraversalSuccess = true;
      res.locals.accessedPath = 'zip_extraction_traversal';
      res.locals.generateFlag = true;
    }
    
    res.json({
      success: true,
      message: 'Backup restored',
      extracted: extractedFiles,
      path: extractPath
    });
    
  } catch (err) {
    // Extraction errors might indicate path traversal attempts
    if (err.message.includes('ENOENT') || err.message.includes('outside')) {
      res.locals.pathTraversalSuccess = true;
      res.locals.accessedPath = 'zip_traversal_error';
      res.locals.generateFlag = true;
    }
    
    res.status(500).json({ 
      error: 'Extraction failed',
      details: err.message 
    });
  }
});

// File viewing with path traversal vulnerability
router.get('/view/:type/:filename', flagManager.flagMiddleware('PATH_TRAVERSAL'), (req, res) => {
  const { type, filename } = req.params;
  
  // Basic path traversal protection (can be bypassed)
  if (filename.includes('../')) {
    res.locals.pathTraversalSuccess = true;
    res.locals.accessedPath = filename;
    res.locals.generateFlag = true;
  }
  
  // URL encoding bypass detection
  const decodedFilename = decodeURIComponent(filename);
  if (decodedFilename.includes('../') || decodedFilename.includes('..\\')) {
    res.locals.pathTraversalSuccess = true;
    res.locals.accessedPath = decodedFilename;
    res.locals.generateFlag = true;
  }
  
  // Double encoding bypass
  const doubleDecoded = decodeURIComponent(decodedFilename);
  if (doubleDecoded.includes('../')) {
    res.locals.pathTraversalSuccess = true;
    res.locals.accessedPath = 'double_encoded_traversal';
    res.locals.generateFlag = true;
  }
  
  const basePath = path.join(__dirname, '..', 'uploads', type);
  const filePath = path.join(basePath, doubleDecoded);
  
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
    '.svg': 'image/svg+xml',
    '.xml': 'application/xml'
  };
  
  if (contentTypes[ext]) {
    res.set('Content-Type', contentTypes[ext]);
  }
  
  // Send file (executes HTML/JS/SVG in browser context)
  res.sendFile(path.resolve(filePath));
});

// SVG upload with XSS potential
router.post('/logo/upload', upload.single('logo'), flagManager.flagMiddleware('XSS_STORED'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No logo uploaded' });
  }
  
  const filePath = req.file.path;
  const fileContent = fs.readFileSync(filePath, 'utf8');
  
  // Check if SVG contains XSS
  if (req.file.mimetype === 'image/svg+xml' || filePath.endsWith('.svg')) {
    const xssPatterns = [
      /<script/i,
      /javascript:/i,
      /onload\s*=/i,
      /onerror\s*=/i,
      /onclick\s*=/i,
      /onmouseover\s*=/i,
      /<iframe/i
    ];
    
    if (xssPatterns.some(pattern => pattern.test(fileContent))) {
      res.locals.xssExecuted = true;
      res.locals.xssPayload = 'svg_xss_payload';
      res.locals.generateFlag = true;
      
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
router.post('/temp/upload', upload.single('tempfile'), flagManager.flagMiddleware('RACE_CONDITION'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  const tempPath = req.file.path;
  const finalPath = tempPath.replace('misc', 'permanent');
  
  // Track race condition attempts
  const uploadKey = `${req.ip}-${Date.now()}`;
  if (!global.uploadRaceTracker) {
    global.uploadRaceTracker = new Map();
  }
  
  // Check for concurrent uploads (race condition indicator)
  const now = Date.now();
  const recentUploads = Array.from(global.uploadRaceTracker.entries())
    .filter(([key, time]) => now - time < 1000); // Within 1 second
  
  if (recentUploads.length > 0) {
    res.locals.raceConditionSuccess = true;
    res.locals.raceConditionProof = 'concurrent_file_uploads';
    res.locals.generateFlag = true;
  }
  
  global.uploadRaceTracker.set(uploadKey, now);
  
  // Async file validation (creates race condition window)
  setTimeout(() => {
    try {
      // Check file content after delay
      const content = fs.readFileSync(tempPath, 'utf8');
      if (content.includes('<?php') || content.includes('<%')) {
        // Try to delete malicious file (but might be too late)
        if (fs.existsSync(tempPath)) {
          fs.unlinkSync(tempPath);
        }
        return;
      }
      
      // Move to permanent location
      if (fs.existsSync(tempPath)) {
        fs.renameSync(tempPath, finalPath);
      }
    } catch (err) {
      console.log('Race condition file processing error:', err);
    }
  }, 1000); // 1 second window to replace file
  
  res.json({
    success: true,
    tempPath: tempPath,
    message: 'File uploaded, validation in progress...'
  });
});

// Filename injection
router.post('/custom/upload', upload.single('custom'), flagManager.flagMiddleware('PATH_TRAVERSAL'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  // Use user-provided filename (dangerous!)
  const customName = req.body.filename || req.file.originalname;
  
  // Check for path traversal in custom filename
  if (customName.includes('../') || customName.includes('..\\')) {
    res.locals.pathTraversalSuccess = true;
    res.locals.accessedPath = customName;
    res.locals.generateFlag = true;
  }
  
  const newPath = path.join('uploads', 'custom', customName);
  
  // Create custom directory
  const dirPath = path.dirname(newPath);
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
  
  try {
    // Move file to new location with custom name
    fs.renameSync(req.file.path, newPath);
    
    res.json({
      success: true,
      message: `File saved as ${customName}`,
      path: `/uploads/custom/${customName}`,
      // Log injection possible through filename
      log: `User ${req.session?.user?.username || 'anonymous'} uploaded ${customName}`
    });
  } catch (err) {
    res.status(500).json({ 
      error: 'File save failed',
      details: err.message 
    });
  }
});

// EXIF data extraction (can contain XSS payloads)
router.post('/image/analyze', upload.single('image'), flagManager.flagMiddleware('XSS_STORED'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No image uploaded' });
  }
  
  try {
    const exifParser = require('exif-parser');
    const buffer = fs.readFileSync(req.file.path);
    const parser = exifParser.create(buffer);
    const exifData = parser.parse();
    
    // Check EXIF data for XSS payloads
    const exifString = JSON.stringify(exifData);
    const xssPatterns = [
      /<script/i,
      /javascript:/i,
      /onerror\s*=/i,
      /onload\s*=/i
    ];
    
    if (xssPatterns.some(pattern => pattern.test(exifString))) {
      res.locals.xssExecuted = true;
      res.locals.xssPayload = 'exif_xss_data';
      res.locals.generateFlag = true;
    }
    
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

module.exports = router;
