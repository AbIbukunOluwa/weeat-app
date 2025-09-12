const express = require('express');
const router = express.Router();
const { Vulnerability } = require('../models');
const { Op } = require('sequelize');

// Comprehensive vulnerability list - all 40+ vulnerabilities
const VULNERABILITIES = [
  // SQL Injection (7 vulnerabilities)
  { 
    code: 'SQLI_001', 
    title: 'SQL Injection in User Search', 
    severity: 'Critical',
    description: 'User search functionality contains SQL injection vulnerability'
  },
  { 
    code: 'SQLI_002', 
    title: 'SQL Injection in Report Generation', 
    severity: 'Critical',
    description: 'Report generation allows arbitrary SQL execution'
  },
  { 
    code: 'SQLI_003', 
    title: 'SQL Injection in API Search', 
    severity: 'Critical',
    description: 'API search endpoint vulnerable to SQL injection'
  },
  { 
    code: 'SQLI_004', 
    title: 'SQL Injection in Menu Filtering', 
    severity: 'Critical',
    description: 'Menu search and filtering contains SQL injection'
  },
  { 
    code: 'SQLI_005', 
    title: 'SQL Injection in Direct Query Execution', 
    severity: 'Critical',
    description: 'Hidden endpoint allows direct SQL execution'
  },
  { 
    code: 'SQLI_006', 
    title: 'SQL Injection in GraphQL-like API', 
    severity: 'Critical',
    description: 'Modern API endpoint contains injection vulnerability'
  },
  { 
    code: 'SQLI_007', 
    title: 'SQL Injection in Order Lookup', 
    severity: 'High',
    description: 'Order lookup functionality vulnerable to injection'
  },

  // Cross-Site Scripting (6 vulnerabilities)
  { 
    code: 'XSS_001', 
    title: 'Stored XSS in Review System', 
    severity: 'High',
    description: 'Food reviews allow persistent XSS attacks'
  },
  { 
    code: 'XSS_002', 
    title: 'XSS via SVG File Upload', 
    severity: 'High',
    description: 'SVG file upload allows JavaScript execution'
  },
  { 
    code: 'XSS_003', 
    title: 'XSS in EXIF Data Display', 
    severity: 'Medium',
    description: 'Image metadata displayed without sanitization'
  },
  { 
    code: 'XSS_004', 
    title: 'Reflected XSS in Error Messages', 
    severity: 'Medium',
    description: 'Error pages reflect user input without encoding'
  },
  { 
    code: 'XSS_005', 
    title: 'DOM XSS in Client-Side Scripts', 
    severity: 'Medium',
    description: 'Client-side JavaScript contains DOM XSS'
  },
  { 
    code: 'XSS_006', 
    title: 'XSS in Complaint Comments', 
    severity: 'High',
    description: 'Complaint system vulnerable to stored XSS'
  },

  // Authentication & Authorization (8 vulnerabilities)
  { 
    code: 'AUTH_001', 
    title: 'Admin Panel Authentication Bypass', 
    severity: 'Critical',
    description: 'Administrative functions can be accessed without proper authentication'
  },
  { 
    code: 'AUTH_002', 
    title: 'Password Reset Bypass', 
    severity: 'Critical',
    description: 'Password reset mechanism can be bypassed'
  },
  { 
    code: 'AUTH_003', 
    title: 'User Enumeration via Timing Attack', 
    severity: 'Medium',
    description: 'User existence can be determined through timing differences'
  },
  { 
    code: 'AUTH_004', 
    title: 'JWT Algorithm Confusion', 
    severity: 'High',
    description: 'JWT implementation accepts weak algorithms'
  },
  { 
    code: 'AUTH_005', 
    title: 'Session Fixation', 
    severity: 'Medium',
    description: 'Session management vulnerable to fixation attacks'
  },
  { 
    code: 'AUTH_006', 
    title: 'Privilege Escalation via Role Manipulation', 
    severity: 'Critical',
    description: 'User roles can be manipulated to gain admin access'
  },
  { 
    code: 'AUTH_007', 
    title: 'UUID Enumeration and Prediction', 
    severity: 'Medium',
    description: 'UUID implementation allows enumeration'
  },
  { 
    code: 'AUTH_008', 
    title: 'Weak Password Recovery', 
    severity: 'High',
    description: 'Account recovery uses predictable tokens'
  },

  // CSRF (5 vulnerabilities)
  { 
    code: 'CSRF_001', 
    title: 'CSRF in Password Change', 
    severity: 'High',
    description: 'Password change lacks CSRF protection'
  },
  { 
    code: 'CSRF_002', 
    title: 'CSRF in Account Deletion', 
    severity: 'Critical',
    description: 'Account deletion vulnerable to CSRF'
  },
  { 
    code: 'CSRF_003', 
    title: 'CSRF in Email Change', 
    severity: 'High',
    description: 'Email modification lacks token validation'
  },
  { 
    code: 'CSRF_004', 
    title: 'CSRF in Order Cancellation', 
    severity: 'Medium',
    description: 'Order operations vulnerable to CSRF'
  },
  { 
    code: 'CSRF_005', 
    title: 'CSRF in Admin Role Changes', 
    severity: 'Critical',
    description: 'Administrative actions lack CSRF protection'
  },

  // IDOR (4 vulnerabilities)
  { 
    code: 'IDOR_001', 
    title: 'Direct Order Access', 
    severity: 'High',
    description: 'Orders accessible without authorization'
  },
  { 
    code: 'IDOR_002', 
    title: 'User Profile Information Disclosure', 
    severity: 'High',
    description: 'User profiles accessible via direct reference'
  },
  { 
    code: 'IDOR_003', 
    title: 'Complaint File Access', 
    severity: 'Medium',
    description: 'Uploaded files accessible without authorization'
  },
  { 
    code: 'IDOR_004', 
    title: 'Admin User Details Access', 
    severity: 'High',
    description: 'Administrative user details exposed'
  },

  // SSRF (3 vulnerabilities)
  { 
    code: 'SSRF_001', 
    title: 'Image Proxy SSRF', 
    severity: 'High',
    description: 'Image proxy can access internal resources'
  },
  { 
    code: 'SSRF_002', 
    title: 'Admin Service Scanner', 
    severity: 'Critical',
    description: 'Internal service enumeration possible'
  },
  { 
    code: 'SSRF_003', 
    title: 'Menu Image Fetcher SSRF', 
    severity: 'Medium',
    description: 'Menu system can fetch arbitrary URLs'
  },

  // File Upload (5 vulnerabilities)
  { 
    code: 'FILE_001', 
    title: 'Unrestricted File Upload', 
    severity: 'High',
    description: 'File upload restrictions can be bypassed'
  },
  { 
    code: 'FILE_002', 
    title: 'Path Traversal via ZIP', 
    severity: 'Critical',
    description: 'ZIP extraction vulnerable to path traversal'
  },
  { 
    code: 'FILE_003', 
    title: 'Polyglot File Upload', 
    severity: 'Medium',
    description: 'System accepts files valid as multiple formats'
  },
  { 
    code: 'FILE_004', 
    title: 'Race Condition in Upload', 
    severity: 'Medium',
    description: 'File validation contains race condition'
  },
  { 
    code: 'FILE_005', 
    title: 'Filename Injection', 
    severity: 'Medium',
    description: 'Uploaded filenames not properly sanitized'
  },

  // XXE (2 vulnerabilities)
  { 
    code: 'XXE_001', 
    title: 'XXE in Menu Import', 
    severity: 'Critical',
    description: 'XML menu import vulnerable to external entity injection'
  },
  { 
    code: 'XXE_002', 
    title: 'XXE in Configuration Upload', 
    severity: 'Critical',
    description: 'Configuration processing allows XXE attacks'
  },

  // Deserialization (3 vulnerabilities)
  { 
    code: 'DESER_001', 
    title: 'Remote Code Execution via Deserialization', 
    severity: 'Critical',
    description: 'Unsafe deserialization leads to RCE'
  },
  { 
    code: 'DESER_002', 
    title: 'Prototype Pollution', 
    severity: 'High',
    description: 'Object prototype can be polluted'
  },
  { 
    code: 'DESER_003', 
    title: 'Session Import Vulnerability', 
    severity: 'Critical',
    description: 'Session import uses dangerous functions'
  },

  // Business Logic (4 vulnerabilities)
  { 
    code: 'LOGIC_001', 
    title: 'Price Manipulation', 
    severity: 'High',
    description: 'Product prices can be manipulated'
  },
  { 
    code: 'LOGIC_002', 
    title: 'Race Condition in Discounts', 
    severity: 'Medium',
    description: 'Discount system vulnerable to race conditions'
  },
  { 
    code: 'LOGIC_003', 
    title: 'Negative Price Vulnerability', 
    severity: 'High',
    description: 'System accepts negative prices'
  },
  { 
    code: 'LOGIC_004', 
    title: 'Order State Machine Bypass', 
    severity: 'Medium',
    description: 'Order workflow can be bypassed'
  },

  // Information Disclosure (4 vulnerabilities)
  { 
    code: 'INFO_001', 
    title: 'Debug Information Exposure', 
    severity: 'Medium',
    description: 'Sensitive debug information exposed'
  },
  { 
    code: 'INFO_002', 
    title: 'Database Credentials Disclosure', 
    severity: 'Critical',
    description: 'Database credentials can be extracted'
  },
  { 
    code: 'INFO_003', 
    title: 'Stack Trace Information Leak', 
    severity: 'Low',
    description: 'Error messages expose stack traces'
  },
  { 
    code: 'INFO_004', 
    title: 'User Password Hash Exposure', 
    severity: 'Critical',
    description: 'Password hashes can be retrieved'
  },

  // Other (3 vulnerabilities)
  { 
    code: 'MISC_001', 
    title: 'Rate Limiting Bypass', 
    severity: 'Medium',
    description: 'Rate limiting can be circumvented'
  },
  { 
    code: 'MISC_002', 
    title: 'Server-Side Template Injection', 
    severity: 'Critical',
    description: 'Template engine vulnerable to injection'
  },
  { 
    code: 'MISC_003', 
    title: 'Cache Poisoning', 
    severity: 'Medium',
    description: 'Cache can be poisoned with malicious content'
  }
];

// Initialize/update vulnerabilities in database
router.get('/init', async (req, res) => {
  try {
    // Clear existing vulnerabilities
    await Vulnerability.destroy({ where: {} });
    
    // Add all vulnerabilities
    for (const vuln of VULNERABILITIES) {
      await Vulnerability.create({
        title: vuln.title,
        description: vuln.description,
        severity: vuln.severity,
        resolved: false,
        flag: vuln.code // Store the code as the flag
      });
    }
    
    res.redirect('/vulns?message=Initialized ' + VULNERABILITIES.length + ' vulnerabilities');
  } catch (err) {
    console.error('Init error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Main vulnerabilities page (black-box style)
router.get('/', async (req, res) => {
  try {
    const vulns = await Vulnerability.findAll({ 
      order: [
        ['severity', 'DESC'], 
        ['resolved', 'ASC'],
        ['createdAt', 'DESC']
      ] 
    });
    
    res.render('vulns', { 
      title: 'Vulnerability Tracker - WeEat Security Testing',
      vulns,
      message: req.query.message || null,
      error: req.query.error || null,
      user: req.session.user
    });
  } catch (err) {
    console.error('Vulns page error:', err);
    res.status(500).render('error', {
      error: 'Failed to load vulnerabilities',
      title: 'Error',
      user: req.session.user
    });
  }
});

// Submit flag
router.post('/submit', async (req, res) => {
  const { code } = req.body;
  
  if (!code) {
    return res.redirect('/vulns?error=Please enter a flag code');
  }
  
  try {
    // Search for vulnerability by flag code or title
    const vuln = await Vulnerability.findOne({ 
      where: { 
        [Op.or]: [
          { flag: code.toUpperCase() },
          { flag: code },
          { title: { [Op.iLike]: `%${code}%` } }
        ]
      }
    });
    
    if (!vuln) {
      return res.redirect('/vulns?error=Invalid flag code');
    }
    
    if (!vuln.resolved) {
      vuln.resolved = true;
      vuln.resolvedAt = new Date();
      await vuln.save();
      return res.redirect('/vulns?message=🎉 Vulnerability found! ' + vuln.title);
    }
    
    res.redirect('/vulns?message=This vulnerability was already found');
  } catch (err) {
    console.error('Flag submission error:', err);
    res.redirect('/vulns?error=Error submitting flag');
  }
});

module.exports = router;
