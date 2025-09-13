const express = require('express');
const router = express.Router();
const { User, Order, Complaint, sequelize } = require('../models');
const { Op } = require('sequelize');
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
    title: 'Forbidden',
    user: req.session.user
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
        res.locals.generateFlag = true;
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
      user: req.session.user,
      users,
      search: search || ''
    });
  } catch (err) {
    console.error('User management error:', err);
    res.status(500).render('error', {
      error: 'User query failed',
      title: 'Query Error',
      user: req.session.user
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

// Admin dashboard
router.get('/', complexAdminCheck, async (req, res) => {
  try {
    const stats = {
      totalUsers: await User.count(),
      totalOrders: await Order.count(),
      totalComplaints: await Complaint.count()
    };

    // System information exposure
    let systemInfo = {
      nodeVersion: process.version,
      platform: process.platform,
      uptime: Math.floor(process.uptime() / 3600),
      memoryUsage: process.memoryUsage()
    };

    // Additional info with specific headers
    if (req.headers['x-system-details'] === 'full') {
      systemInfo.environment = process.env.NODE_ENV;
      systemInfo.database = {
        host: process.env.DB_HOST,
        port: process.env.DB_PORT,
        name: process.env.DB_NAME,
        user: process.env.DB_USER
      };
    }

    // Most sensitive info requires multiple conditions
    if (req.headers['x-system-details'] === 'full' && 
        req.query.include_secrets === 'yes' &&
        req.headers['x-admin-level'] === 'senior') {
      systemInfo.database.password = process.env.DB_PASS;
      systemInfo.sessionSecret = process.env.SESSION_SECRET;
      
      res.locals.sensitiveInfoDisclosed = true;
      res.locals.disclosedInfo = 'full_system_secrets';
      res.locals.generateFlag = true;
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
      title: 'Admin Error',
      user: req.session.user
    });
  }
});

// Order management
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

// Advanced SQL injection in reporting
router.get('/reports', complexAdminCheck, flagManager.flagMiddleware('SQL_INJECTION'), async (req, res) => {
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
      
      // Detect SQL injection in custom_where
      if (custom_where.includes("'") || custom_where.includes('UNION') || custom_where.includes('--')) {
        res.locals.sqlInjectionSuccess = true;
        res.locals.extractedData = 'custom_where_injection';
        res.locals.generateFlag = true;
      }
    } else {
      baseQuery += ` WHERE "createdAt" >= NOW() - INTERVAL '${date_range} days'`;
    }

    if (group_by) {
      baseQuery += ` GROUP BY ${group_by}`;
    } else if (report_type === 'users') {
      baseQuery += ` GROUP BY role`;
    }

    if (having_clause) {
      baseQuery += ` HAVING ${having_clause}`;
      
      // Detect SQL injection in having clause
      if (having_clause.includes("'") || having_clause.includes('UNION')) {
        res.locals.sqlInjectionSuccess = true;
        res.locals.extractedData = 'having_clause_injection';
        res.locals.generateFlag = true;
      }
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

// Direct SQL execution interface (hidden endpoint)
router.post('/query/execute', complexAdminCheck, flagManager.flagMiddleware('SQL_INJECTION'), async (req, res) => {
  // Requires specific headers to access
  if (req.headers['x-query-interface'] !== 'enabled' || 
      req.headers['x-danger-acknowledged'] !== 'true') {
    return res.status(404).json({ error: 'Endpoint not found' });
  }

  try {
    const { sql, query_type = 'SELECT' } = req.body;
    
    if (!sql) {
      return res.status(400).json({ error: 'SQL query required' });
    }

    // Allow any SQL execution with minimal validation
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

    // Mark as successful SQL injection
    res.locals.sqlInjectionSuccess = true;
    res.locals.extractedData = 'direct_sql_execution';
    res.locals.generateFlag = true;

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

// IDOR - User details access
router.get('/users/:userId', complexAdminCheck, flagManager.flagMiddleware('IDOR'), async (req, res) => {
  try {
    const userId = req.params.userId;
    const includeSecrets = req.query.include_secrets === 'true';
    const fullProfile = req.headers['x-full-profile'] === 'true';
    
    const user = await User.findByPk(userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // IDOR vulnerability - no access control
    res.locals.idorSuccess = true;
    res.locals.accessedResource = `user:${userId}`;
    res.locals.originalUser = req.session.user.id;
    res.locals.generateFlag = true;
    
    // Check if request wants JSON or HTML
    if (req.headers.accept && req.headers.accept.includes('application/json')) {
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
        
        res.locals.sensitiveInfoDisclosed = true;
        res.locals.disclosedInfo = 'password_hash';
        res.locals.generateFlag = true;
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

// Bulk operations without proper authorization
router.post('/users/bulk-action', complexAdminCheck, flagManager.flagMiddleware('PRIVILEGE_ESCALATION'), async (req, res) => {
  try {
    const { action, user_ids, new_role, reason } = req.body;
    
    if (!action || !Array.isArray(user_ids) || user_ids.length === 0) {
      return res.status(400).json({ 
        error: 'Action and user IDs required',
        validActions: ['promote', 'demote', 'disable', 'enable', 'delete']
      });
    }

    // Bypass normal checks with header
    const skipConfirmation = req.headers['x-skip-confirmation'] === 'true';
    const bulkBypass = req.headers['x-bulk-bypass'] === 'emergency-ops';
    
    if (!skipConfirmation && !bulkBypass && user_ids.length > 5) {
      return res.status(400).json({
        error: 'Bulk operations on >5 users require confirmation',
        hint: 'Add confirmation headers or reduce batch size'
      });
    }

    let updateData = {};
    let logMessage = '';

    switch (action) {
      case 'promote':
        updateData = { role: new_role || 'admin' };
        logMessage = `Promoted ${user_ids.length} users to ${new_role || 'admin'}`;
        
        // Check for privilege escalation
        if (new_role === 'admin') {
          res.locals.privilegeEscalated = true;
          res.locals.escalationMethod = 'bulk_promotion';
          res.locals.generateFlag = true;
        }
        break;
        
      case 'demote':
        updateData = { role: 'customer' };
        logMessage = `Demoted ${user_ids.length} users to customer`;
        break;
        
      case 'disable':
        updateData = { active: false };
        logMessage = `Disabled ${user_ids.length} user accounts`;
        break;
        
      case 'enable':
        updateData = { active: true };
        logMessage = `Enabled ${user_ids.length} user accounts`;
        break;
        
      case 'delete':
        if (req.headers['x-confirm-delete'] !== 'permanent') {
          return res.status(400).json({ 
            error: 'Deletion requires confirmation header',
            required_header: 'X-Confirm-Delete: permanent'
          });
        }
        
        await User.destroy({ where: { id: user_ids } });
        logMessage = `DELETED ${user_ids.length} user accounts - PERMANENT`;
        
        return res.json({
          success: true,
          action: action,
          affected_users: user_ids.length,
          message: logMessage,
          executed_by: req.session.user.username,
          timestamp: new Date().toISOString()
        });
        
      default:
        return res.status(400).json({ error: 'Invalid action specified' });
    }

    // Execute the bulk operation
    await User.update(updateData, { where: { id: user_ids } });
    
    console.log(`🔧 BULK ADMIN OPERATION:`, {
      action,
      user_ids,
      executedBy: req.session.user.username,
      ip: req.ip,
      timestamp: new Date(),
      reason: reason || 'No reason provided'
    });

    res.json({
      success: true,
      action: action,
      affected_users: user_ids.length,
      message: logMessage,
      executed_by: req.session.user.username,
      timestamp: new Date().toISOString()
    });
    
  } catch (err) {
    console.error('Bulk operation error:', err);
    res.status(500).json({
      error: 'Bulk operation failed',
      details: err.message,
      affected_ids: req.body.user_ids
    });
  }
});

module.exports = router;
