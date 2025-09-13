const express = require('express');
const router = express.Router();
const { Vulnerability } = require('../models');
const flagManager = require('../utils/flags');

// Main vulnerabilities page - pure black box, no hints
router.get('/', async (req, res) => {
  try {
    const totalVulns = 45; // Total number of vulnerabilities in the system
    
    // Get all found vulnerabilities from database
    const foundVulns = await Vulnerability.findAll({
      where: { resolved: true },
      attributes: ['id', 'flag', 'resolvedAt'],
      order: [['resolvedAt', 'DESC']]
    });
    
    res.render('vulns', { 
      title: 'Security Testing Challenge',
      totalVulns,
      foundCount: foundVulns.length,
      remainingCount: totalVulns - foundVulns.length,
      progress: Math.round((foundVulns.length / totalVulns) * 100),
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
        return res.redirect('/vulns?message=Flag already submitted');
      }
      
      // Save to database
      await Vulnerability.create({
        title: validation.type || 'Unknown Vulnerability',
        description: 'Successfully exploited',
        severity: 'Unknown',
        resolved: true,
        resolvedAt: new Date(),
        flag: code.trim()
      });
      
      return res.redirect(`/vulns?message=🎉 Correct! ${validation.type} vulnerability found!`);
    } else {
      return res.redirect(`/vulns?error=${validation.message}`);
    }
  } catch (err) {
    console.error('Flag submission error:', err);
    return res.redirect('/vulns?error=Error processing flag submission');
  }
});

// Reset progress (admin only)
router.post('/reset', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  
  try {
    await Vulnerability.destroy({ where: {} });
    flagManager.validatedFlags.clear();
    res.redirect('/vulns?message=Progress reset successfully');
  } catch (err) {
    console.error('Reset error:', err);
    res.redirect('/vulns?error=Failed to reset progress');
  }
});

module.exports = router;
