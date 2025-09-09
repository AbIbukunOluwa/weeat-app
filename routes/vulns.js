const express = require('express');
const router = express.Router();
const { Vulnerability } = require('../models');

// Vulnerability tracker
router.get('/', async (req, res) => {
  const vulns = await Vulnerability.findAll({ order: [['createdAt', 'DESC']] });
  res.render('vulns', { title: 'Vulnerability Tracker', vulns, message: null, error: null, user: req.session.user });
});

router.post('/submit', async (req, res) => {
  const { code } = req.body;
  try {
    const vuln = await Vulnerability.findOne({ where: { flag: code } });
    if (!vuln) {
      return res.render('vulns', { title: 'Vulnerability Tracker', vulns: await Vulnerability.findAll(), message: null, error: 'Invalid code', user: req.session.user });
    }
    if (!vuln.found) {
      vuln.found = true;
      vuln.foundAt = new Date();
      await vuln.save();
    }
    res.render('vulns', { title: 'Vulnerability Tracker', vulns: await Vulnerability.findAll(), message: 'Flag accepted!', error: null, user: req.session.user });
  } catch (err) {
    console.error(err);
    res.render('vulns', { title: 'Vulnerability Tracker', vulns: await Vulnerability.findAll(), message: null, error: 'Error submitting flag', user: req.session.user });
  }
});

module.exports = router;
