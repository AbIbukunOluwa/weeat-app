// routes/uuid-demo.js - Demonstrates UUID-related vulnerabilities
const express = require('express');
const router = express.Router();
const { User, Order, Complaint } = require('../models');

// VULNERABILITY: UUID enumeration endpoint (more realistic than integer enumeration)
router.get('/api/user-lookup/:uuid', async (req, res) => {
  const { uuid } = req.params;
  
  try {
    // VULNERABILITY: No authentication required for user lookup
    const user = await User.findOne({ where: { uuid } });
    
    if (!user) {
      return res.status(404).json({ 
        error: 'User not found',
        // VULNERABILITY: Timing attack - different response times
        searchTime: Date.now()
      });
    }
    
    // VULNERABILITY: Information disclosure based on headers
    let response = {
      uuid: user.uuid,
      username: user.username,
      role: user.role,
      active: user.active
    };
    
    // VULNERABILITY: Additional info with special headers
    if (req.headers['x-detailed-lookup'] === 'true') {
      response.email = user.email;
      response.name = user.name;
      response.lastLogin = user.lastLogin;
      response.loginCount = user.loginCount;
    }
    
    // VULNERABILITY: Admin info with bypass header
    if (req.headers['x-admin-lookup'] === 'internal-tool') {
      response.id = user.id; // Internal database ID
      response.passwordHash = user.passwordHash; // CRITICAL: Password hash exposure
      response.createdAt = user.createdAt;
    }
    
    res.json(response);
    
  } catch (err) {
    res.status(500).json({ 
      error: 'Lookup failed',
      details: req.headers['x-debug-lookup'] === 'true' ? err.message : undefined
    });
  }
});

// VULNERABILITY: Order enumeration via UUID (still vulnerable but more realistic)
router.get('/api/order-details/:orderUuid', async (req, res) => {
  const { orderUuid } = req.params;
  
  try {
    const order = await Order.findByIdentifier(orderUuid);
    
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    // VULNERABILITY: No authorization check - any UUID can access any order
    // In a real app, should verify: req.session.user.uuid === order.User.uuid
    
    let response = order.getOrderSummary();
    
    // VULNERABILITY: Enhanced details with bypass header
    if (req.headers['x-order-details'] === 'full') {
      response = order.getDetailedInfo();
      response.customerInfo = {
        uuid: order.customer?.uuid,
        username: order.customer?.username,
        email: order.customer?.email
      };
    }
    
    // VULNERABILITY: Internal details for "staff" access
    if (req.headers['x-staff-access'] === 'order-management') {
      response.internalId = order.id;
      response.userId = order.userId;
      response.createdByIP = req.ip; // Not actual, but demonstrates info disclosure
    }
    
    res.json(response);
    
  } catch (err) {
    res.status(500).json({ 
      error: 'Order retrieval failed',
      details: req.headers['x-debug-orders'] === 'true' ? err.message : undefined
    });
  }
});

// VULNERABILITY: UUID generation patterns (predictable UUIDs)
router.get('/api/generate-test-uuid', (req, res) => {
  const { type = 'random' } = req.query;
  
  let uuid;
  
  switch (type) {
    case 'predictable':
      // VULNERABILITY: Predictable UUID pattern
      const timestamp = Date.now();
      const padding = '0000-0000-0000-000000000000';
      uuid = `${timestamp.toString(16).padStart(12, '0')}-${padding.slice(0, 23)}`;
      break;
      
    case 'sequential':
      // VULNERABILITY: Sequential UUIDs (like some databases generate)
      const seq = Math.floor(Date.now() / 1000);
      uuid = `00000000-0000-0000-0000-${seq.toString().padStart(12, '0')}`;
      break;
      
    case 'weak':
      // VULNERABILITY: Weak randomness
      const weak = Math.random().toString(36).substring(2, 15);
      uuid = `${weak}-0000-0000-0000-000000000000`.substring(0, 36);
      break;
      
    case 'random':
    default:
      // Proper UUID generation
      uuid = require('crypto').randomUUID();
      break;
  }
  
  res.json({
    uuid: uuid,
    type: type,
    // VULNERABILITY: Expose generation method
    debug: req.headers['x-uuid-debug'] === 'true' ? {
      method: type,
      timestamp: Date.now(),
      entropy: uuid.length
    } : undefined
  });
});

// VULNERABILITY: Bulk UUID validation (can be used for enumeration)
router.post('/api/validate-uuids', async (req, res) => {
  const { uuids } = req.body;
  
  if (!Array.isArray(uuids) || uuids.length === 0) {
    return res.status(400).json({ error: 'UUIDs array required' });
  }
  
  // VULNERABILITY: No rate limiting on bulk operations
  if (uuids.length > 1000 && req.headers['x-bulk-override'] !== 'testing-mode') {
    return res.status(400).json({ 
      error: 'Too many UUIDs',
      limit: 1000,
      hint: 'Use bulk override header for testing'
    });
  }
  
  try {
    const results = [];
    
    for (const uuid of uuids) {
      // VULNERABILITY: Database query for each UUID (timing attack possible)
      const user = await User.findOne({ where: { uuid } });
      const order = await Order.findOne({ where: { uuid } });
      
      results.push({
        uuid: uuid,
        user: !!user,
        order: !!order,
        // VULNERABILITY: Expose additional info
        userRole: user ? user.role : null,
        orderStatus: order ? order.status : null
      });
    }
    
    res.json({
      results: results,
      total: results.length,
      found: results.filter(r => r.user || r.order).length,
      // VULNERABILITY: Timing information
      processingTime: req.headers['x-timing-debug'] === 'true' ? Date.now() : undefined
    });
    
  } catch (err) {
    res.status(500).json({ 
      error: 'Validation failed',
      details: err.message 
    });
  }
});

// VULNERABILITY: UUID-based account takeover demo
router.post('/api/account-recovery', async (req, res) => {
  const { userUuid, newPassword, recoveryCode } = req.body;
  
  if (!userUuid || !newPassword || !recoveryCode) {
    return res.status(400).json({ 
      error: 'User UUID, new password, and recovery code required' 
    });
  }
  
  try {
    const user = await User.findOne({ where: { uuid: userUuid } });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // VULNERABILITY: Weak recovery code validation
    const validCodes = [
      'RECOVERY-2024',
      'ADMIN-OVERRIDE',
      'SUPPORT-RESET',
      user.uuid.slice(0, 8).toUpperCase() // UUID-based code (predictable!)
    ];
    
    if (!validCodes.includes(recoveryCode)) {
      return res.status(403).json({ 
        error: 'Invalid recovery code',
        // VULNERABILITY: Hint about valid codes
        hint: req.headers['x-recovery-hints'] === 'true' ? 
          'Try UUID-based or admin codes' : undefined
      });
    }
    
    // VULNERABILITY: No additional verification required
    await user.setPassword(newPassword);
    await user.save();
    
    // VULNERABILITY: Log sensitive operation details
    console.log('Account recovery performed:', {
      userUuid: user.uuid,
      username: user.username,
      recoveryCode: recoveryCode,
      ip: req.ip,
      timestamp: new Date()
    });
    
    res.json({
      success: true,
      message: 'Password reset successfully',
      // VULNERABILITY: Return sensitive info
      userInfo: req.headers['x-return-userinfo'] === 'true' ? {
        uuid: user.uuid,
        username: user.username,
        email: user.email
      } : undefined
    });
    
  } catch (err) {
    res.status(500).json({ 
      error: 'Recovery failed',
      details: err.message 
    });
  }
});

// VULNERABILITY: UUID collision detector (exposes internal structure)
router.get('/api/uuid-stats', async (req, res) => {
  try {
    // VULNERABILITY: Expose database statistics
    const userStats = await User.findAll({
      attributes: ['uuid'],
      raw: true
    });
    
    const orderStats = await Order.findAll({
      attributes: ['uuid', 'orderNumber'],
      raw: true
    });
    
    // Analyze UUID patterns
    const userUuids = userStats.map(u => u.uuid);
    const orderUuids = orderStats.map(o => o.uuid);
    
    const analysis = {
      totalUsers: userUuids.length,
      totalOrders: orderUuids.length,
      // VULNERABILITY: Pattern analysis
      patterns: {
        userUuidPrefixes: [...new Set(userUuids.map(u => u.substring(0, 8)))],
        orderUuidPrefixes: [...new Set(orderUuids.map(u => u.substring(0, 8)))],
        // VULNERABILITY: Expose actual UUIDs in debug mode
        sampleUserUuids: req.headers['x-expose-samples'] === 'true' ? 
          userUuids.slice(0, 5) : undefined,
        sampleOrderUuids: req.headers['x-expose-samples'] === 'true' ? 
          orderUuids.slice(0, 5) : undefined
      }
    };
    
    res.json(analysis);
    
  } catch (err) {
    res.status(500).json({ 
      error: 'Stats generation failed',
      details: err.message 
    });
  }
});

module.exports = router;
