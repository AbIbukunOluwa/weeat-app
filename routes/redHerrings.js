// routes/redHerrings.js - Endpoints that look vulnerable but aren't
const express = require('express');
const router = express.Router();
const { User, sequelize } = require('../models');

// RED HERRING: Looks like SQL injection but is actually parameterized
router.get('/api/users/search', async (req, res) => {
  const { q, role, limit = 10 } = req.query;
  
  try {
    // This LOOKS vulnerable but uses proper parameterization
    const query = `
      SELECT id, username, email, role, created_at 
      FROM users 
      WHERE username ILIKE $1 
      AND ($2::text IS NULL OR role = $2)
      ORDER BY created_at DESC 
      LIMIT $3
    `;
    
    const results = await sequelize.query(query, {
      bind: [`%${q || ''}%`, role || null, parseInt(limit)],
      type: sequelize.QueryTypes.SELECT
    });
    
    res.json({ 
      results,
      count: results.length,
      // Make it look like there might be debug info
      query_info: 'Parameterized query executed safely'
    });
  } catch (err) {
    res.status(500).json({ 
      error: 'Search failed',
      // No stack trace or sensitive info leaked
      message: 'Please try a different search term'
    });
  }
});

// RED HERRING: Looks like file upload vulnerability but has proper validation
router.post('/api/secure-upload', require('multer')({ 
  dest: 'uploads/secure/',
  limits: { fileSize: 1024 * 1024 } // 1MB
}).single('file'), async (req, res) => {
  
  if (!req.file) {
    return res.status(400).json({ error: 'No file provided' });
  }
  
  const fs = require('fs');
  const path = require('path');
  
  // SECURE: Proper file validation
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif'];
  
  const fileExt = path.extname(req.file.originalname).toLowerCase();
  
  // Actually secure validation
  if (!allowedTypes.includes(req.file.mimetype) || 
      !allowedExtensions.includes(fileExt)) {
    fs.unlinkSync(req.file.path); // Clean up
    return res.status(400).json({ 
      error: 'Invalid file type',
      allowed: allowedExtensions
    });
  }
  
  // Check file signature (magic bytes)
  const buffer = fs.readFileSync(req.file.path, { start: 0, end: 10 });
  const isValidImage = 
    buffer.toString('hex', 0, 4) === 'ffd8ffe0' || // JPEG
    buffer.toString('hex', 0, 8) === '89504e470d0a1a0a' || // PNG
    buffer.toString('ascii', 0, 6) === 'GIF89a'; // GIF
  
  if (!isValidImage) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'File signature validation failed' });
  }
  
  res.json({
    success: true,
    message: 'File uploaded securely',
    filename: req.file.filename,
    // Looks like it might expose paths but doesn't
    path: '/secure/' + req.file.filename
  });
});

// RED HERRING: Looks like command injection but input is properly sanitized
router.post('/api/system/ping', (req, res) => {
  const { host } = req.body;
  
  if (!host) {
    return res.status(400).json({ error: 'Host required' });
  }
  
  // SECURE: Proper input validation
  const validHostRegex = /^[a-zA-Z0-9.-]+$/;
  if (!validHostRegex.test(host) || host.length > 253) {
    return res.status(400).json({ 
      error: 'Invalid host format',
      hint: 'Only alphanumeric characters, dots, and hyphens allowed'
    });
  }
  
  const { exec } = require('child_process');
  
  // SECURE: Uses shell escaping and limits
  const escapedHost = host.replace(/[^a-zA-Z0-9.-]/g, '');
  const command = `ping -c 4 "${escapedHost}"`;
  
  exec(command, { timeout: 10000 }, (error, stdout, stderr) => {
    if (error) {
      return res.status(500).json({ 
        error: 'Ping failed',
        // No sensitive error info
        message: 'Host unreachable or invalid'
      });
    }
    
    res.json({
      success: true,
      result: stdout,
      // Misleading comment that suggests vulnerability
      note: 'Ping executed safely with input validation'
    });
  });
});

// RED HERRING: Looks like authentication bypass but actually secure
router.post('/api/admin/secure-action', async (req, res) => {
  // Multiple apparent bypass opportunities that don't work
  const authHeader = req.headers.authorization;
  const apiKey = req.headers['x-api-key'];
  const userRole = req.session?.user?.role;
  const bypassHeader = req.headers['x-admin-bypass'];
  
  // SECURE: Proper authentication check
  if (userRole !== 'admin') {
    return res.status(403).json({ 
      error: 'Admin access required',
      // Misleading hint
      hint: 'Valid admin session required'
    });
  }
  
  // SECURE: Actually validates the session properly
  try {
    const user = await User.findByPk(req.session.user.id);
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Invalid admin session' });
    }
    
    res.json({
      success: true,
      message: 'Admin action completed securely',
      user: user.username,
      // Make it look like there might be more to exploit
      system_info: 'Secure admin endpoint'
    });
    
  } catch (err) {
    res.status(500).json({ error: 'Authentication verification failed' });
  }
});

// RED HERRING: Looks like SQL injection in WHERE clause but uses safe methods
router.get('/api/orders/report', async (req, res) => {
  const { status, start_date, end_date, user_id } = req.query;
  
  try {
    // SECURE: Uses Sequelize ORM properly
    const whereClause = {};
    
    if (status) {
      whereClause.status = status;
    }
    
    if (start_date) {
      whereClause.createdAt = { [sequelize.Op.gte]: new Date(start_date) };
    }
    
    if (end_date) {
      if (whereClause.createdAt) {
        whereClause.createdAt[sequelize.Op.lte] = new Date(end_date);
      } else {
        whereClause.createdAt = { [sequelize.Op.lte]: new Date(end_date) };
      }
    }
    
    if (user_id) {
      whereClause.userId = parseInt(user_id);
    }
    
    const { Order } = require('../models');
    const orders = await Order.findAll({
      where: whereClause,
      limit: 100,
      order: [['createdAt', 'DESC']]
    });
    
    res.json({
      orders,
      count: orders.length,
      // Looks like it might expose query details
      filters_applied: Object.keys(whereClause),
      note: 'Report generated with secure parameterized queries'
    });
    
  } catch (err) {
    res.status(500).json({ 
      error: 'Report generation failed',
      // No stack trace
      message: 'Invalid filter parameters'
    });
  }
});

// RED HERRING: Template injection that's actually safe
router.post('/api/render-safe', (req, res) => {
  const { template, data } = req.body;
  
  if (!template) {
    return res.status(400).json({ error: 'Template required' });
  }
  
  // SECURE: Uses safe template rendering
  const allowedTemplates = {
    'user_welcome': 'Welcome {{username}}! Your account was created on {{date}}.',
    'order_confirm': 'Order #{{orderId}} confirmed. Total: ${{total}}.',
    'password_reset': 'Password reset requested for {{email}} at {{timestamp}}.'
  };
  
  if (!allowedTemplates[template]) {
    return res.status(400).json({ 
      error: 'Invalid template',
      available: Object.keys(allowedTemplates)
    });
  }
  
  // SECURE: Simple string replacement, not eval
  let rendered = allowedTemplates[template];
  
  if (data && typeof data === 'object') {
    Object.keys(data).forEach(key => {
      // SECURE: Only allows alphanumeric keys
      if (/^[a-zA-Z0-9_]+$/.test(key)) {
        const value = String(data[key]).replace(/[<>&"']/g, ''); // Basic sanitization
        rendered = rendered.replace(new RegExp(`{{${key}}}`, 'g'), value);
      }
    });
  }
  
  res.json({
    success: true,
    rendered: rendered,
    template_used: template,
    note: 'Template rendered safely with input sanitization'
  });
});

// RED HERRING: SSRF that looks vulnerable but has proper validation  
router.get('/api/fetch-safe', async (req, res) => {
  const { url } = req.query;
  
  if (!url) {
    return res.status(400).json({ error: 'URL required' });
  }
  
  // SECURE: Proper URL validation
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (err) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }
  
  // SECURE: Whitelist approach
  const allowedHosts = [
    'api.weather.com',
    'httpbin.org', 
    'jsonplaceholder.typicode.com'
  ];
  
  if (!allowedHosts.includes(parsedUrl.hostname)) {
    return res.status(403).json({ 
      error: 'Host not allowed',
      allowed_hosts: allowedHosts
    });
  }
  
  // SECURE: No private IP ranges
  const fetch = require('node-fetch');
  
  try {
    const response = await fetch(url, {
      timeout: 5000,
      headers: {
        'User-Agent': 'WeEat-Safe-Fetcher/1.0'
      }
    });
    
    const data = await response.text();
    
    res.json({
      success: true,
      data: data.substring(0, 1000), // Limit response size
      status: response.status,
      note: 'URL fetched safely from whitelisted host'
    });
    
  } catch (err) {
    res.status(500).json({ 
      error: 'Fetch failed',
      message: 'Could not retrieve URL'
    });
  }
});

module.exports = router;
