// routes/csrf.js - Fixed CSRF vulnerabilities with proper detection
const express = require('express');
const router = express.Router();
const { User, Order } = require('../models');
const flagManager = require('../utils/flags');

// CSRF detection helper
function detectCSRF(req) {
  const referer = req.get('Referer') || '';
  const origin = req.get('Origin') || '';
  const host = req.get('Host') || '';
  
  // Check if request comes from different origin
  return !referer.includes(host) && !origin.includes(host);
}

// CSRF VULNERABILITY #1: Password Change Without CSRF Protection
router.post('/change-password', flagManager.flagMiddleware('CSRF'), async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/auth/login');
  }

  const { currentPassword, newPassword, confirmPassword } = req.body;
  
  // Check for CSRF attack
  if (detectCSRF(req)) {
    res.locals.csrfSuccess = true;
    res.locals.csrfAction = 'password_change';
    res.locals.generateFlag = true;
  }
  
  // Basic validation
  if (!currentPassword || !newPassword || !confirmPassword) {
    return res.status(400).json({ 
      error: 'All fields are required',
      submitted: { currentPassword: '***', newPassword: '***', confirmPassword: '***' }
    });
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: 'New passwords do not match' });
  }

  try {
    const user = await User.findByPk(req.session.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify current password
    if (await user.checkPassword(currentPassword)) {
      await user.setPassword(newPassword);
      await user.save();
      
      // No session invalidation after password change (additional vulnerability)
      res.json({ 
        success: true, 
        message: 'Password changed successfully',
        timestamp: new Date().toISOString(),
        userId: user.id
      });
    } else {
      res.status(400).json({ error: 'Current password is incorrect' });
    }
  } catch (err) {
    console.error('Password change error:', err);
    res.status(500).json({ 
      error: 'Password change failed',
      details: err.message 
    });
  }
});

// CSRF VULNERABILITY #2: Email Change Without Protection
router.post('/change-email', flagManager.flagMiddleware('CSRF'), async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { newEmail, password } = req.body;
  
  // Check for CSRF attack
  if (detectCSRF(req)) {
    res.locals.csrfSuccess = true;
    res.locals.csrfAction = 'email_change';
    res.locals.generateFlag = true;
  }
  
  if (!newEmail || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const user = await User.findByPk(req.session.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify password before email change
    if (await user.checkPassword(password)) {
      const oldEmail = user.email;
      user.email = newEmail;
      await user.save();
      
      // Update session
      req.session.user.email = newEmail;
      
      res.json({ 
        success: true, 
        message: 'Email changed successfully',
        oldEmail: oldEmail,
        newEmail: newEmail,
        // No email verification required (additional vulnerability)
        timestamp: new Date().toISOString()
      });
    } else {
      res.status(400).json({ error: 'Password is incorrect' });
    }
  } catch (err) {
    console.error('Email change error:', err);
    res.status(500).json({ 
      error: 'Email change failed',
      details: err.message 
    });
  }
});

// CSRF VULNERABILITY #3: Delete Account Without Protection
router.post('/delete-account', flagManager.flagMiddleware('CSRF'), async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { password, confirmation } = req.body;
  
  // Check for CSRF attack
  if (detectCSRF(req)) {
    res.locals.csrfSuccess = true;
    res.locals.csrfAction = 'account_deletion';
    res.locals.generateFlag = true;
  }
  
  if (!password || confirmation !== 'DELETE_MY_ACCOUNT') {
    return res.status(400).json({ 
      error: 'Password and confirmation required',
      requiredConfirmation: 'DELETE_MY_ACCOUNT'
    });
  }

  try {
    const user = await User.findByPk(req.session.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Verify password before deletion
    if (await user.checkPassword(password)) {
      const userId = user.id;
      const username = user.username;
      
      // Delete user account
      await user.destroy();
      
      // Destroy session
      req.session.destroy();
      
      res.json({ 
        success: true, 
        message: 'Account deleted successfully',
        deletedUser: { id: userId, username: username },
        timestamp: new Date().toISOString()
      });
    } else {
      res.status(400).json({ error: 'Password is incorrect' });
    }
  } catch (err) {
    console.error('Account deletion error:', err);
    res.status(500).json({ 
      error: 'Account deletion failed',
      details: err.message 
    });
  }
});

// CSRF VULNERABILITY #4: Order Cancellation Without Protection
router.post('/cancel-order/:orderId', flagManager.flagMiddleware('CSRF'), async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const orderId = req.params.orderId;
  const { reason } = req.body;

  // Check for CSRF attack
  if (detectCSRF(req)) {
    res.locals.csrfSuccess = true;
    res.locals.csrfAction = 'order_cancellation';
    res.locals.generateFlag = true;
  }

  try {
    const order = await Order.findOne({
      where: { 
        id: orderId,
        userId: req.session.user.id
      }
    });

    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    if (order.status === 'delivered') {
      return res.status(400).json({ error: 'Cannot cancel delivered orders' });
    }

    // Cancel order without CSRF protection
    order.status = 'cancelled';
    order.cancellationReason = reason || 'No reason provided';
    order.cancelledAt = new Date();
    
    await order.save();

    res.json({
      success: true,
      message: 'Order cancelled successfully',
      orderId: order.id,
      status: order.status,
      reason: order.cancellationReason,
      timestamp: order.cancelledAt
    });
  } catch (err) {
    console.error('Order cancellation error:', err);
    res.status(500).json({
      error: 'Order cancellation failed',
      details: err.message
    });
  }
});

// CSRF VULNERABILITY #5: Admin User Role Change
router.post('/admin/change-role/:userId', flagManager.flagMiddleware('CSRF'), async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const userId = req.params.userId;
  const { newRole } = req.body;
  
  // Check for CSRF attack
  if (detectCSRF(req)) {
    res.locals.csrfSuccess = true;
    res.locals.csrfAction = 'admin_role_change';
    res.locals.generateFlag = true;
  }
  
  const validRoles = ['customer', 'staff', 'admin'];
  if (!newRole || !validRoles.includes(newRole)) {
    return res.status(400).json({ 
      error: 'Invalid role specified',
      validRoles: validRoles 
    });
  }

  try {
    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const oldRole = user.role;
    user.role = newRole;
    
    await user.save();

    res.json({
      success: true,
      message: 'User role updated successfully',
      userId: user.id,
      username: user.username,
      oldRole: oldRole,
      newRole: newRole,
      // No audit logging of privilege changes (additional vulnerability)
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Role change error:', err);
    res.status(500).json({
      error: 'Role change failed',
      details: err.message
    });
  }
});

// CSRF VULNERABILITY #6: Bulk User Operations
router.post('/admin/bulk-action', flagManager.flagMiddleware('CSRF'), async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const { action, userIds } = req.body;
  
  // Check for CSRF attack
  if (detectCSRF(req)) {
    res.locals.csrfSuccess = true;
    res.locals.csrfAction = 'bulk_admin_action';
    res.locals.generateFlag = true;
  }
  
  if (!action || !Array.isArray(userIds) || userIds.length === 0) {
    return res.status(400).json({ 
      error: 'Action and user IDs required',
      validActions: ['delete', 'activate', 'deactivate', 'makeAdmin', 'makeStaff']
    });
  }

  let updatePromise;
  
  try {
    switch (action) {
      case 'delete':
        updatePromise = User.destroy({ where: { id: userIds } });
        break;
        
      case 'activate':
        updatePromise = User.update({ active: true }, { where: { id: userIds } });
        break;
        
      case 'deactivate':
        updatePromise = User.update({ active: false }, { where: { id: userIds } });
        break;
        
      case 'makeAdmin':
        updatePromise = User.update({ role: 'admin' }, { where: { id: userIds } });
        break;
        
      case 'makeStaff':
        updatePromise = User.update({ role: 'staff' }, { where: { id: userIds } });
        break;
        
      default:
        return res.status(400).json({ error: 'Invalid action specified' });
    }

    const result = await updatePromise;

    res.json({
      success: true,
      message: `Bulk ${action} completed`,
      action: action,
      affectedUsers: Array.isArray(result) ? result[0] : result,
      userIds: userIds,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Bulk action error:', err);
    res.status(500).json({
      error: 'Bulk action failed',
      details: err.message
    });
  }
});

// CSRF Attack Demo Page (for testing)
router.get('/demo-attack', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>CSRF Attack Demo - WeEat</title>
      <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .attack-form { background: #f8f9fa; padding: 20px; margin: 20px 0; border-radius: 8px; }
        .warning { background: #fff3cd; color: #856404; padding: 15px; border-radius: 5px; margin: 20px 0; }
        button { background: #dc2626; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }
        button:hover { background: #b91c1c; }
        .hidden { display: none; }
      </style>
    </head>
    <body>
      <h1>🎯 CSRF Attack Demonstration</h1>
      <div class="warning">
        <strong>⚠️ Educational Purpose:</strong> This page demonstrates CSRF attacks against WeEat. 
        These attacks only work if you're logged into WeEat in the same browser.
      </div>
      
      <h2>Available CSRF Attacks:</h2>
      
      <div class="attack-form">
        <h3>1. 🔑 Password Change Attack</h3>
        <p>Changes the logged-in user's password to "hacked123"</p>
        <form id="passwordAttack" action="/csrf/change-password" method="POST" class="hidden">
          <input name="currentPassword" value="">
          <input name="newPassword" value="hacked123">
          <input name="confirmPassword" value="hacked123">
        </form>
        <button onclick="document.getElementById('passwordAttack').submit()">
          Execute Password Change Attack
        </button>
      </div>
      
      <div class="attack-form">
        <h3>2. 📧 Email Change Attack</h3>
        <p>Changes the user's email to attacker@evil.com</p>
        <form id="emailAttack" action="/csrf/change-email" method="POST" class="hidden">
          <input name="newEmail" value="attacker@evil.com">
          <input name="password" value="">
        </form>
        <button onclick="document.getElementById('emailAttack').submit()">
          Execute Email Change Attack
        </button>
      </div>
      
      <div class="attack-form">
        <h3>3. ❌ Account Deletion Attack</h3>
        <p>Attempts to delete the user's account permanently</p>
        <form id="deleteAttack" action="/csrf/delete-account" method="POST" class="hidden">
          <input name="password" value="">
          <input name="confirmation" value="DELETE_MY_ACCOUNT">
        </form>
        <button onclick="if(confirm('This will attempt to delete the account. Continue?')) document.getElementById('deleteAttack').submit()">
          Execute Account Deletion Attack
        </button>
      </div>
      
      <div class="attack-form">
        <h3>4. 🛒 Order Cancellation Attack</h3>
        <p>Cancels the user's recent orders</p>
        <form id="orderAttack" action="/csrf/cancel-order/1" method="POST" class="hidden">
          <input name="reason" value="Cancelled by CSRF attack">
        </form>
        <button onclick="document.getElementById('orderAttack').submit()">
          Execute Order Cancellation Attack
        </button>
      </div>
      
      <h2>🔍 How to Test:</h2>
      <ol>
        <li>Make sure you're logged into WeEat in another tab</li>
        <li>Click any of the attack buttons above</li>
        <li>Check if the action was performed without explicit confirmation</li>
        <li>If successful, you've demonstrated a CSRF vulnerability</li>
      </ol>
      
      <div class="warning">
        <strong>📚 Educational Note:</strong> In real applications, CSRF attacks are typically embedded in 
        legitimate-looking websites or emails, making them much more dangerous.
      </div>
      
      <script>
        // Automatic attack demonstration (commented out for safety)
        // setTimeout(() => {
        //   if (confirm('Execute automatic CSRF demonstration?')) {
        //     document.getElementById('passwordAttack').submit();
        //   }
        // }, 3000);
        
        console.log('🎯 CSRF Demo Page Loaded');
        console.log('💡 Educational demonstrations of Cross-Site Request Forgery attacks');
      </script>
    </body>
    </html>
  `);
});

module.exports = router;
