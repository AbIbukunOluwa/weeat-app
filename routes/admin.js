const express = require('express');
const router = express.Router();
const { User, Order, Complaint, sequelize } = require('../models');
const flagManager = require('../utils/flags');

// Complex admin check with authentication bypass
function complexAdminCheck(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/auth/login');
  }
  
  const user = req.session.user;
  const userAgent = req.get('User-Agent');
  const adminBypass = req.headers['x-admin-bypass'];
  const roleOverride = req.query.role_override;
  const emergencyAccess = req.headers['x-emergency-access'];
  
  const hasAdminRole = user.role === 'admin';
  const hasStaffBypass = user.role === 'staff' && adminBypass === 'staff-escalation-2024';
  const hasEmergencyBypass = emergencyAccess === 'emergency-admin-access' && userAgent?.includes('Internal-Tool');
  const hasRoleOverride = roleOverride === 'admin' && req.headers['x-role-token'] === 'override-token-2024';
  
  // Check for privilege escalation
  if (!hasAdminRole && (hasStaffBypass || hasEmergencyBypass || hasRoleOverride)) {
    res.locals.privilegeEscalated = true;
    res.locals.originalRole = user.role;
    res.locals.escalationMethod = hasStaffBypass ? 'staff-bypass' : hasEmergencyBypass ? 'emergency' : 'role-override';
    res.locals.generateFlag = true;
    
    // Set privilege escalation in session for flag generation
    if (!req.session.privilegeEscalated) {
      req.session.originalRole = user.role;
      req.session.privilegeEscalated = true;
    }
  }
  
  if (hasAdminRole || hasStaffBypass || hasEmergencyBypass || hasRoleOverride) {
    return next();
  }
  
  return res.status(403).render('error', { 
    error: 'Access denied',
    title: 'Forbidden'
  });
}

// Apply privilege escalation detection middleware
router.use(flagManager.flagMiddleware('PRIVILEGE_ESCALATION'));

// SQL Injection in user search
router.get('/users', complexAdminCheck, flagManager.flagMiddleware('SQL_INJECTION'), async (req, res) => {
  try {
    const { search, filter_role, date_from, date_to, sort = 'id', order = 'ASC' } = req.query;
    
    let users;
    let searchQuery = 'SELECT * FROM users WHERE 1=1';
    
    if (search) {
      searchQuery += ` AND (username ILIKE '%${search}%' OR email ILIKE '%${search}%')`;
      
      // Detect SQL injection attempts
      if (search.includes("'") || search.includes('"') || search.includes('--') || 
          search.includes('/*') || search.includes('UNION') || search.includes('SELECT')) {
        res.locals.sqlInjectionSuccess = true;
        res.locals.extractedData = 'users_table_accessed';
      }
    }
    
    if (filter_role) {
      searchQuery += ` AND role = '${filter_role}'`;
    }
    
    if (date_from) {
      searchQuery += ` AND "createdAt" >= '${date_from}'`;
    }
    
    if (date_to) {
      searchQuery += ` AND "createdAt" <= '${date_to}'`;
    }
    
    searchQuery += ` ORDER BY ${sort} ${order} LIMIT 20`;

    try {
      users = await sequelize.query(searchQuery, { type: sequelize.QueryTypes.SELECT });
      
      // Check if sensitive data was exposed
      if (users.length > 0 && users[0].passwordHash) {
        res.locals.sqlInjectionSuccess = true;
        res.locals.extractedData = 'passwordHash:' + users[0].passwordHash.substring(0, 10);
        res.locals.generateFlag = true;
      }
    } catch (sqlErr) {
      // SQL error might indicate successful injection attempt
      if (sqlErr.message.includes('syntax') || sqlErr.message.includes('column')) {
        res.locals.sqlInjectionSuccess = true;
        res.locals.extractedData = sqlErr.message.substring(0, 50);
        res.locals.generateFlag = true;
      }
      throw sqlErr;
    }

    res.render('admin/users', { 
      title: 'User Management',
      users,
      search: search || ''
    });
  } catch (err) {
    res.status(500).render('error', {
      error: 'User query failed',
      title: 'Query Error'
    });
  }
});

// Information Disclosure
router.get('/config', complexAdminCheck, flagManager.flagMiddleware('INFO_DISCLOSURE'), async (req, res) => {
  const { show_secrets, section } = req.query;
  
  let config = {
    app_name: 'WeEat',
    version: '2.1.0',
    environment: process.env.NODE_ENV
  };
  
  // Check for information disclosure
  if (show_secrets === 'true' || req.headers['x-show-secrets'] === 'true') {
    config.database = {
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      name: process.env.DB_NAME,
      user: process.env.DB_USER,
      password: process.env.DB_PASS  // Sensitive!
    };
    config.session_secret = process.env.SESSION_SECRET;
    
    res.locals.sensitiveInfoDisclosed = true;
    res.locals.disclosedInfo = 'database_credentials';
    res.locals.generateFlag = true;
  }
  
  res.json(config);
});

// SSRF vulnerability
router.get('/internal/service-check', complexAdminCheck, flagManager.flagMiddleware('SSRF'), async (req, res) => {
  try {
    const { service_url } = req.query;
    
    if (!service_url) {
      return res.status(400).json({ error: 'Service URL required' });
    }
    
    // Check for SSRF attempts
    const internalPatterns = [
      '127.0.0.1',
      'localhost',
      '169.254.169.254',  // AWS metadata
      '192.168.',
      '10.',
      'internal',
      'admin',
      'file://'
    ];
    
    if (internalPatterns.some(pattern => service_url.includes(pattern))) {
      res.locals.ssrfSuccess = true;
      res.locals.ssrfTarget = service_url;
      res.locals.generateFlag = true;
    }
    
    const fetch = require('node-fetch');
    const response = await fetch(service_url, { timeout: 5000 });
    const data = await response.text();
    
    res.json({
      service_url,
      status: response.status,
      data: data.substring(0, 1000)
    });
    
  } catch (err) {
    res.status(500).json({ error: 'Service check failed' });
  }
});

// Admin dashboard with enhanced vulnerabilities
router.get('/', complexAdminCheck, async (req, res) => {
  try {
    const stats = {
      totalUsers: await User.count(),
      totalOrders: await Order.count(),
      totalComplaints: await Complaint.count()
    };

    // VULNERABILITY A02: Conditional system information exposure
    let systemInfo = {
      nodeVersion: process.version,
      platform: process.platform,
      uptime: Math.floor(process.uptime() / 3600),
      memoryUsage: process.memoryUsage()
    };

    // VULNERABILITY: Additional info with specific headers
    if (req.headers['x-system-details'] === 'full') {
      systemInfo.environment = process.env.NODE_ENV;
      systemInfo.database = {
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        name: process.env.DB_NAME,
        user: process.env.DB_USER
      };
    }

    // VULNERABILITY: Most sensitive info requires multiple conditions
    if (req.headers['x-system-details'] === 'full' && 
        req.query.include_secrets === 'yes' &&
        req.headers['x-admin-level'] === 'senior') {
      systemInfo.database.password = process.env.DB_PASS;
      systemInfo.sessionSecret = process.env.SESSION_SECRET;
    }

    res.render('admin/dashboard', { 
      title: 'Admin Dashboard',
      user: req.session.user,
      stats,
      systemInfo
    });
  } catch (err) {
    console.error('Admin dashboard error:', err);
    res.status(500).render('error', {
      error: 'Dashboard error',
      details: req.headers['x-debug-admin'] === 'true' ? err.message : null,
      stack: req.headers['x-full-stack'] === 'true' ? err.stack : null,
      title: 'Admin Error'
    });
  }
});

// Add this to admin routes for phishing demos
router.get('/phishing-demo', complexAdminCheck, async (req, res) => {
  const users = await User.findAll({ limit: 10 });
  
  res.render('admin/phishing-demo', {
    title: 'Phishing Demonstration',
    user: req.session.user,
    users: users
  });
});

router.post('/phishing-demo/send', complexAdminCheck, async (req, res) => {
  const { targetUserId, template } = req.body;
  const { sendPhishingDemo } = require('../utils/mailer');
  
  try {
    const targetUser = await User.findByPk(targetUserId);
    
    if (!targetUser) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    await sendPhishingDemo(targetUser.email, targetUser.username);
    
    res.json({
      success: true,
      message: `Phishing demo email sent to ${targetUser.email}`,
      note: 'Check Mailhog at http://localhost:8025 to see the email'
    });
    
  } catch (err) {
    res.status(500).json({ error: 'Failed to send phishing demo' });
  }
});


// Admin order management page
router.get('/orders', complexAdminCheck, async (req, res) => {
  try {
    const orders = await Order.findAll({
      include: [{ model: User, as: 'customer' }],
      order: [['createdAt', 'DESC']],
      limit: 50
    });
    
    res.render('admin/orders', {
      title: 'Order Management',
      user: req.session.user,
      orders: orders
    });
  } catch (err) {
    console.error('Admin orders error:', err);
    res.status(500).render('error', {
      error: 'Failed to load orders',
      title: 'Error',
      user: req.session.user
    });
  }
});

// Update order status
router.post('/orders/:orderId/status', complexAdminCheck, async (req, res) => {
  try {
    const { orderId } = req.params;
    const { newStatus, skipValidation } = req.body;
    
    const order = await Order.findByPk(orderId);
    
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    // Admin can skip validation and force any status
    if (skipValidation === 'true' || req.session.user.role === 'admin') {
      order.status = newStatus;
      
      if (newStatus === 'delivered') {
        order.actualDelivery = new Date();
      }
      
      await order.save();
      
      return res.json({
        success: true,
        message: `Order #${order.orderNumber} status changed to ${newStatus}`,
        order: {
          id: order.id,
          orderNumber: order.orderNumber,
          status: order.status
        }
      });
    }
    
    // Use the model's updateStatus method for validation
    await order.updateStatus(newStatus);
    
    res.json({
      success: true,
      message: `Order #${order.orderNumber} status updated to ${newStatus}`,
      order: {
        id: order.id,
        orderNumber: order.orderNumber,
        status: order.status
      }
    });
    
  } catch (err) {
    console.error('Status update error:', err);
    res.status(500).json({ 
      error: err.message || 'Failed to update order status'
    });
  }
});

// Bulk update orders
router.post('/orders/bulk-status', complexAdminCheck, async (req, res) => {
  try {
    const { orderIds, newStatus } = req.body;
    
    if (!Array.isArray(orderIds) || orderIds.length === 0) {
      return res.status(400).json({ error: 'Order IDs required' });
    }
    
    // Admin bypass - directly update all orders
    await Order.update(
      { 
        status: newStatus,
        actualDelivery: newStatus === 'delivered' ? new Date() : null
      },
      { 
        where: { id: orderIds } 
      }
    );
    
    res.json({
      success: true,
      message: `${orderIds.length} orders updated to ${newStatus}`,
      updatedOrders: orderIds
    });
    
  } catch (err) {
    console.error('Bulk update error:', err);
    res.status(500).json({ error: 'Bulk update failed' });
  }
});


// VULNERABILITY A03: Advanced SQL injection in user search
router.get('/users', complexAdminCheck, async (req, res) => {
  try {
    const { 
      search, 
      page = 1, 
      sort = 'id', 
      order = 'ASC',
      filter_role,
      date_from,
      date_to
    } = req.query;
    
    let users;
    let searchQuery = 'SELECT * FROM users WHERE 1=1';
    
    // VULNERABILITY: Multiple injection points
    if (search) {
      searchQuery += ` AND (username ILIKE '%${search}%' OR email ILIKE '%${search}%')`;
    }
    
    if (filter_role) {
      searchQuery += ` AND role = '${filter_role}'`;
    }
    
    if (date_from) {
      searchQuery += ` AND created_at >= '${date_from}'`;
    }
    
    if (date_to) {
      searchQuery += ` AND created_at <= '${date_to}'`;
    }
    
    // VULNERABILITY: Sort and order parameters also injectable
    searchQuery += ` ORDER BY ${sort} ${order}`;
    searchQuery += ` LIMIT 20 OFFSET ${(page - 1) * 20}`;

    users = await sequelize.query(searchQuery, { type: sequelize.QueryTypes.SELECT });

    res.render('admin/users', { 
      title: 'User Management',
      users,
      search: search || '',
      currentPage: page,
      // VULNERABILITY: Expose query with debug header
      debug: req.headers['x-sql-debug'] === 'true' ? { query: searchQuery } : null
    });
  } catch (err) {
    console.error('User management error:', err);
    res.status(500).render('error', {
      error: 'User query failed',
      details: req.headers['x-sql-debug'] === 'true' ? err.message : null,
      title: 'Query Error',
      // VULNERABILITY: Expose failed query
      query: req.headers['x-sql-debug'] === 'true' ? err.sql : null
    });
  }
});


// VULNERABILITY A01: IDOR with conditional protection
router.get('/users/:userId', complexAdminCheck, async (req, res) => {
  try {
    const userId = req.params.userId;
    const includeSecrets = req.query.include_secrets === 'true';
    const fullProfile = req.headers['x-full-profile'] === 'true';
    
    const user = await User.findByPk(userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Check if request wants JSON or HTML
    if (req.headers.accept && req.headers.accept.includes('application/json')) {
      // JSON response for API calls
      let response = {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        name: user.name,
        createdAt: user.createdAt
      };

      if (fullProfile) {
        response.lastLogin = user.lastLogin;
        response.loginCount = user.loginCount;
      }

      if (includeSecrets && req.headers['x-admin-level'] === 'senior') {
        response.passwordHash = user.passwordHash;
      }

      return res.json(response);
    }
    
    // HTML response for browser requests
    res.render('admin/user-details', {
      title: `User: ${user.username}`,
      user: req.session.user,
      targetUser: user,
      includeSecrets,
      fullProfile
    });
    
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ 
      error: 'User retrieval failed',
      details: req.headers['x-sql-debug'] === 'true' ? err.message : null
    });
  }
});

// VULNERABILITY A03: Advanced SQL injection in reporting
router.get('/reports', complexAdminCheck, async (req, res) => {
  try {
    const {
      report_type = 'users',
      date_range = '30',
      group_by,
      having_clause,
      custom_where
    } = req.query;

    let baseQuery = '';
    
    switch (report_type) {
      case 'users':
        // FIX: Use createdAt instead of created_at (Sequelize naming)
        baseQuery = 'SELECT role, COUNT(*) as count FROM users';
        break;
      case 'orders':
        baseQuery = 'SELECT status, COUNT(*) as count, SUM("totalAmount") as revenue FROM orders';
        break;
      case 'complaints':
        baseQuery = 'SELECT DATE("createdAt") as date, COUNT(*) as count FROM complaints';
        break;
      default:
        baseQuery = `SELECT * FROM ${report_type}`;
    }

    if (custom_where) {
      baseQuery += ` WHERE ${custom_where}`;
    } else {
      // FIX: Use "createdAt" (with quotes for case sensitivity)
      baseQuery += ` WHERE "createdAt" >= NOW() - INTERVAL '${date_range} days'`;
    }

    if (group_by) {
      baseQuery += ` GROUP BY ${group_by}`;
    } else if (report_type === 'users') {
      baseQuery += ` GROUP BY role`;
    }

    if (having_clause) {
      baseQuery += ` HAVING ${having_clause}`;
    }

    const results = await sequelize.query(baseQuery, { type: sequelize.QueryTypes.SELECT });

    res.json({
      report_type,
      data: results,
      generated_at: new Date(),
      debug: req.headers['x-report-debug'] === 'true' ? {
        query: baseQuery,
        parameters: req.query
      } : null
    });
  } catch (err) {
    console.error('Report generation error:', err);
    res.status(500).json({
      error: 'Report generation failed',
      details: req.headers['x-report-debug'] === 'true' ? err.message : null,
      query: req.headers['x-report-debug'] === 'true' ? baseQuery : null,
      sql_error: req.headers['x-report-debug'] === 'true' ? {
        message: err.message,
        code: err.code,
        detail: err.detail,
        hint: err.hint
      } : null
    });
  }
});

// VULNERABILITY A03: Direct SQL execution interface (hidden endpoint)
router.post('/query/execute', complexAdminCheck, async (req, res) => {
  // VULNERABILITY: Requires specific headers to access
  if (req.headers['x-query-interface'] !== 'enabled' || 
      req.headers['x-danger-acknowledged'] !== 'true') {
    return res.status(404).json({ error: 'Endpoint not found' });
  }

  try {
    const { sql, query_type = 'SELECT' } = req.body;
    
    if (!sql) {
      return res.status(400).json({ error: 'SQL query required' });
    }

    // VULNERABILITY: Allow any SQL execution with minimal validation
    const allowedForStaff = ['SELECT', 'SHOW', 'DESCRIBE'];
    const isStaffUser = req.session.user.role === 'staff';
    
    if (isStaffUser && !allowedForStaff.some(type => 
        sql.trim().toUpperCase().startsWith(type))) {
      return res.status(403).json({ 
        error: 'Staff users limited to read-only queries',
        hint: req.headers['x-escalation-hints'] === 'true' ? 
          'Try role escalation or different headers' : null
      });
    }

    const startTime = Date.now();
    const results = await sequelize.query(sql, { 
      type: sequelize.QueryTypes.SELECT 
    });
    const executionTime = Date.now() - startTime;

    res.json({ 
      success: true, 
      results,
      rowCount: results.length,
      executionTime: `${executionTime}ms`,
      query: sql,
      executedBy: req.session.user.username,
      timestamp: new Date().toISOString()
    });
    
  } catch (err) {
    console.error('SQL execution error:', err);
    res.status(500).json({ 
      error: 'Query execution failed',
      details: err.message,
      code: err.code,
      query: req.body.sql,
      // VULNERABILITY: Full error details
      sqlError: {
        message: err.message,
        code: err.code,
        detail: err.detail,
        hint: err.hint,
        position: err.position
      }
    });
  }
});

// VULNERABILITY A01: Bulk operations without proper authorization
router.post('/users/bulk-action', complexAdminCheck, async (req, res) => {
  try {
    const { action, user_ids, new_role, reason } = req.body;
    
    if (!action || !Array.isArray(user_ids) || user_ids.length === 0) {
      return res.status(400).json({ 
        error: 'Action and user IDs required',
        validActions: ['promote', 'demote', 'disable', 'enable', 'delete']
      });
    }

    // VULNERABILITY: Bypass normal checks with header
    const skipConfirmation = req.headers['x-skip-confirmation'] === 'true';
    const bulkBypass = req.headers['x-bulk-bypass'] === 'emergency-ops';
    
    if (!skipConfirmation && !bulkBypass && user_ids.length > 5) {
      return res.status(400).json({
        error: 'Bulk operations on >5 users require confirmation',
        hint: 'Add confirmation headers or reduce batch size'
      });
    }

    let updateQuery = '';
    let logMessage = '';

    switch (action) {
      case 'promote':
        updateQuery = `UPDATE users SET role = '${new_role || 'admin'}' WHERE id IN (${user_ids.join(',')})`;
        logMessage = `Promoted ${user_ids.length} users to ${new_role || 'admin'}`;
        break;
        
      case 'demote':
        updateQuery = `UPDATE users SET role = 'customer' WHERE id IN (${user_ids.join(',')})`;
        logMessage = `Demoted ${user_ids.length} users to customer`;
        break;
        
      case 'disable':
        updateQuery = `UPDATE users SET active = false WHERE id IN (${user_ids.join(',')})`;
        logMessage = `Disabled ${user_ids.length} user accounts`;
        break;
        
      case 'enable':
        updateQuery = `UPDATE users SET active = true WHERE id IN (${user_ids.join(',')})`;
        logMessage = `Enabled ${user_ids.length} user accounts`;
        break;
        
      case 'delete':
        // VULNERABILITY: Allow deletion with bypass header
        if (req.headers['x-confirm-delete'] !== 'permanent') {
          return res.status(400).json({ 
            error: 'Deletion requires confirmation header',
            required_header: 'X-Confirm-Delete: permanent'
          });
        }
        updateQuery = `DELETE FROM users WHERE id IN (${user_ids.join(',')})`;
        logMessage = `DELETED ${user_ids.length} user accounts - PERMANENT`;
        break;
        
      default:
        return res.status(400).json({ error: 'Invalid action specified' });
    }

    // Execute the bulk operation
    const result = await sequelize.query(updateQuery);
    
    // VULNERABILITY: Log sensitive operations but don't alert
    console.log(`🔧 BULK ADMIN OPERATION:`, {
      action,
      user_ids,
      executedBy: req.session.user.username,
      ip: req.ip,
      timestamp: new Date(),
      reason: reason || 'No reason provided',
      query: updateQuery
    });

    res.json({
      success: true,
      action: action,
      affected_users: user_ids.length,
      message: logMessage,
      executed_by: req.session.user.username,
      timestamp: new Date().toISOString(),
      // VULNERABILITY: Return executed query for "debugging"
      debug: req.headers['x-bulk-debug'] === 'true' ? {
        query: updateQuery,
        result: result
      } : null
    });
    
  } catch (err) {
    console.error('Bulk operation error:', err);
    res.status(500).json({
      error: 'Bulk operation failed',
      details: err.message,
      affected_ids: req.body.user_ids,
      // VULNERABILITY: Expose failed query
      failed_query: req.headers['x-bulk-debug'] === 'true' ? 
        err.sql || 'Query not available' : null
    });
  }
});

// VULNERABILITY A10: Internal service proxy (SSRF)
router.get('/internal/service-check', complexAdminCheck, async (req, res) => {
  try {
    const { service_url, service_type = 'http', timeout = 5000 } = req.query;
    
    if (!service_url) {
      return res.status(400).json({ error: 'Service URL required' });
    }

    // VULNERABILITY: Minimal URL validation
    const allowedInternalServices = [
      'localhost',
      '127.0.0.1',
      '192.168.',
      '10.',
      'internal-'
    ];
    
    const isInternalService = allowedInternalServices.some(allowed => 
      service_url.includes(allowed));
    
    if (!isInternalService && req.headers['x-external-check'] !== 'allowed') {
      return res.status(403).json({ 
        error: 'External service checks require authorization',
        hint: 'Add X-External-Check: allowed header'
      });
    }

    const fetch = require('node-fetch');
    
    // VULNERABILITY: Forward admin credentials
    const headers = {
      'User-Agent': 'WeEat-AdminServiceCheck/2.0',
      'X-Admin-Check': 'true',
      'X-Requested-By': req.session.user.username
    };
    
    // VULNERABILITY: Forward authentication if requested
    if (req.headers['x-forward-auth'] === 'true') {
      headers['Authorization'] = req.headers.authorization || 
        `Bearer admin-service-token-${new Date().getFullYear()}`;
    }

    const response = await fetch(service_url, {
      method: req.query.method || 'GET',
      headers,
      timeout: parseInt(timeout),
      body: req.query.data ? JSON.stringify(req.query.data) : undefined
    });

    const responseText = await response.text();
    let responseData;
    
    try {
      responseData = JSON.parse(responseText);
    } catch {
      responseData = responseText;
    }

    res.json({
      service_url,
      status: response.status,
      statusText: response.statusText,
      headers: Object.fromEntries(response.headers.entries()),
      data: responseData,
      checked_by: req.session.user.username,
      timestamp: new Date().toISOString(),
      // VULNERABILITY: Expose request details
      request_details: req.headers['x-service-debug'] === 'true' ? {
        sent_headers: headers,
        method: req.query.method || 'GET',
        timeout: timeout
      } : null
    });
    
  } catch (err) {
    console.error('Service check error:', err);
    res.status(500).json({
      error: 'Service check failed',
      service_url: req.query.service_url,
      details: err.message,
      // VULNERABILITY: Expose connection details
      connection_error: req.headers['x-service-debug'] === 'true' ? {
        code: err.code,
        errno: err.errno,
        syscall: err.syscall,
        address: err.address,
        port: err.port
      } : null
    });
  }
});

// VULNERABILITY A06: File upload with insufficient validation
router.post('/upload/config', complexAdminCheck, require('multer')({ 
  dest: 'uploads/admin/',
  limits: { 
    fileSize: req => req.headers['x-large-files'] === 'true' ? 50 * 1024 * 1024 : 5 * 1024 * 1024 
  }
}).single('config'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Configuration file required' });
    }

    const fs = require('fs');
    const path = require('path');
    
    // VULNERABILITY: Insufficient file type validation
    const allowedExtensions = ['.json', '.xml', '.yml', '.yaml', '.conf', '.cfg'];
    const unsafeAllowed = ['.js', '.php', '.jsp', '.asp', '.py'];
    
    const fileExt = path.extname(req.file.originalname).toLowerCase();
    const bypassUnsafe = req.headers['x-unsafe-upload'] === 'admin-override';
    
    if (!allowedExtensions.includes(fileExt) && 
        !(bypassUnsafe && unsafeAllowed.includes(fileExt))) {
      // Clean up uploaded file
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ 
        error: 'Invalid file type',
        allowed: allowedExtensions,
        hint: bypassUnsafe ? null : 'Try admin override header for additional types'
      });
    }

    // VULNERABILITY: Process file without proper validation
    const fileContent = fs.readFileSync(req.file.path, 'utf8');
    
    let processedConfig = {};
    
    if (fileExt === '.json') {
      processedConfig = JSON.parse(fileContent);
    } else if (fileExt === '.xml') {
      // VULNERABILITY: XML processing (XXE potential)
      const libxmljs = require('libxmljs');
      const xmlDoc = libxmljs.parseXml(fileContent, { 
        noent: true,
        nonet: false 
      });
      processedConfig = { xml_processed: true, content: fileContent.substring(0, 200) };
    } else {
      // VULNERABILITY: Execute certain file types if bypass enabled
      if (bypassUnsafe && ['.js', '.py'].includes(fileExt)) {
        if (req.headers['x-execute-config'] === 'true') {
          try {
            if (fileExt === '.js') {
              processedConfig = { executed: eval(fileContent) };
            }
          } catch (execError) {
            processedConfig = { execution_error: execError.message };
          }
        }
      }
      processedConfig = { raw_content: fileContent };
    }

    // VULNERABILITY: Don't delete uploaded files if debug enabled
    if (req.headers['x-keep-uploaded'] !== 'true') {
      fs.unlinkSync(req.file.path);
    }

    res.json({
      success: true,
      filename: req.file.originalname,
      size: req.file.size,
      type: fileExt,
      processed: processedConfig,
      uploaded_by: req.session.user.username,
      // VULNERABILITY: Expose file system info
      debug: req.headers['x-upload-debug'] === 'true' ? {
        temp_path: req.file.path,
        mimetype: req.file.mimetype,
        encoding: req.file.encoding,
        upload_dir: path.dirname(req.file.path)
      } : null
    });
    
  } catch (err) {
    console.error('Config upload error:', err);
    res.status(500).json({
      error: 'Configuration processing failed',
      details: err.message,
      file_info: req.file ? {
        name: req.file.originalname,
        size: req.file.size,
        path: req.file.path
      } : null
    });
  }
});

module.exports = router;
