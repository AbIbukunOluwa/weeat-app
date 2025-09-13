const express = require('express');
const router = express.Router();
const { Vulnerability } = require('../models');
const flagManager = require('../utils/flags');

// Main vulnerabilities page - pure black box, no hints
router.get('/', async (req, res) => {
  try {
    // Get statistics from flag manager
    const stats = flagManager.getStats();
    
    // Get all found vulnerabilities from database
    const foundVulns = await Vulnerability.findAll({
      where: { resolved: true },
      attributes: ['id', 'flag', 'title', 'resolvedAt'],
      order: [['resolvedAt', 'DESC']]
    });
    
    res.render('vulns', { 
      title: 'Security Testing Challenge',
      totalVulns: stats.total,
      foundCount: stats.found,
      remainingCount: stats.remaining,
      progress: stats.progress,
      foundVulnerabilities: foundVulns,
      message: req.query.message || null,
      error: req.query.error || null,
      user: req.session.user
    });
  } catch (err) {
    console.error('Vulns page error:', err);
    res.status(500).render('error', {
      error: 'Failed to load challenge page',
      title: 'Error',
      user: req.session.user
    });
  }
});

// Submit flag endpoint
router.post('/submit', async (req, res) => {
  const { code } = req.body;
  
  if (!code || code.trim() === '') {
    return res.redirect('/vulns?error=Please enter a flag');
  }
  
  try {
    // Validate the flag
    const validation = flagManager.validateFlag(code.trim());
    
    if (validation.valid) {
      // Check if already submitted
      const existing = await Vulnerability.findOne({
        where: { flag: code.trim() }
      });
      
      if (existing) {
        return res.redirect('/vulns?message=Flag already submitted! Good job finding it again.');
      }
      
      // Save to database
      await Vulnerability.create({
        title: validation.type || 'Unknown Vulnerability',
        description: `Successfully exploited ${validation.type}`,
        severity: 'High',
        resolved: true,
        resolvedAt: new Date(),
        flag: code.trim()
      });
      
      return res.redirect(`/vulns?message=🎉 Excellent! ${validation.type} vulnerability found! Keep hunting for more.`);
    } else {
      return res.redirect(`/vulns?error=${validation.message}`);
    }
  } catch (err) {
    console.error('Flag submission error:', err);
    return res.redirect('/vulns?error=Error processing flag submission. Please try again.');
  }
});

// Get progress statistics (API endpoint)
router.get('/api/stats', (req, res) => {
  try {
    const stats = flagManager.getStats();
    res.json(stats);
  } catch (err) {
    console.error('Stats API error:', err);
    res.status(500).json({ error: 'Failed to get statistics' });
  }
});

// Leaderboard endpoint (if multiple users)
router.get('/api/leaderboard', async (req, res) => {
  try {
    const leaderboard = await Vulnerability.findAll({
      attributes: [
        'resolvedBy',
        [sequelize.fn('COUNT', sequelize.col('id')), 'count'],
        [sequelize.fn('MAX', sequelize.col('resolvedAt')), 'lastFlag']
      ],
      where: { resolved: true },
      group: ['resolvedBy'],
      order: [[sequelize.fn('COUNT', sequelize.col('id')), 'DESC']],
      limit: 10
    });
    
    res.json(leaderboard);
  } catch (err) {
    console.error('Leaderboard error:', err);
    res.status(500).json({ error: 'Failed to get leaderboard' });
  }
});

// Reset progress (admin only)
router.post('/reset', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized - Admin access required' });
  }
  
  try {
    // Clear database
    await Vulnerability.destroy({ where: {} });
    
    // Reset flag manager
    flagManager.reset();
    
    console.log(`[ADMIN ACTION] Progress reset by ${req.session.user.username} from IP ${req.ip}`);
    
    res.redirect('/vulns?message=✅ Progress reset successfully. All flags cleared.');
  } catch (err) {
    console.error('Reset error:', err);
    res.redirect('/vulns?error=Failed to reset progress. Please try again.');
  }
});

// Hint system (optional - can be disabled for pure black box)
router.get('/api/hint/:category', (req, res) => {
  const category = req.params.category;
  
  // Only provide hints if explicitly enabled
  if (req.headers['x-hints-enabled'] !== 'true') {
    return res.status(404).json({ error: 'Hints are disabled for this challenge' });
  }
  
  const hints = {
    'web': [
      'Check for input validation issues in forms',
      'Look for authentication and authorization flaws',
      'Test file upload functionality carefully',
      'Examine how user input is processed and displayed'
    ],
    'api': [
      'Test API endpoints for injection vulnerabilities',
      'Check authentication mechanisms',
      'Look for business logic flaws',
      'Test different HTTP methods'
    ],
    'auth': [
      'Test login mechanisms thoroughly',
      'Look for privilege escalation opportunities',
      'Check session management',
      'Test password reset functionality'
    ]
  };
  
  if (hints[category]) {
    res.json({
      category: category,
      hints: hints[category],
      disclaimer: 'These are general hints. Specific vulnerabilities require discovery.'
    });
  } else {
    res.status(404).json({ error: 'Category not found' });
  }
});

// Flag validation endpoint (for frontend AJAX)
router.post('/api/validate', (req, res) => {
  const { flag } = req.body;
  
  if (!flag) {
    return res.status(400).json({ error: 'Flag required' });
  }
  
  const validation = flagManager.validateFlag(flag.trim());
  res.json(validation);
});

// Export challenge results (admin only)
router.get('/api/export', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  
  try {
    const vulnerabilities = await Vulnerability.findAll({
      where: { resolved: true },
      order: [['resolvedAt', 'ASC']]
    });
    
    const stats = flagManager.getStats();
    
    const exportData = {
      timestamp: new Date().toISOString(),
      statistics: stats,
      vulnerabilities: vulnerabilities.map(v => ({
        title: v.title,
        flag: v.flag,
        resolvedAt: v.resolvedAt,
        description: v.description
      })),
      summary: {
        totalFound: vulnerabilities.length,
        totalPossible: stats.total,
        completionRate: `${stats.progress}%`
      }
    };
    
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename=weeat-challenge-results.json');
    res.json(exportData);
    
  } catch (err) {
    console.error('Export error:', err);
    res.status(500).json({ error: 'Export failed' });
  }
});

module.exports = router;
