const express = require('express');
const { ensureAuth } = require('../middleware/auth');
const Vulnerability = require('../models/Vulnerability');

const router = express.Router();

// GET: list all vulns + found status
router.get('/', ensureAuth, async (req, res) => {
  const vulns = await Vulnerability.findAll({ order: [['id', 'ASC']] });
  res.render('vulns', { title: 'WeEat Vulnerability Tracker', user: req.session.user, vulns, message: null, error: null });
});

// POST: submit a flag/code to mark a vuln as found
router.post('/submit', ensureAuth, async (req, res) => {
  const { code } = req.body;
  const v = await Vulnerability.findOne({ where: { code } });
  if (!v) {
    const vulns = await Vulnerability.findAll({ order: [['id','ASC']] });
    return res.status(400).render('vulns', { title: 'WeEat Vulnerability Tracker', user: req.session.user, vulns, message: null, error: 'Invalid flag.' });
  }
  if (!v.found) {
    v.found = true;
    v.foundAt = new Date();
    v.foundByUserId = req.session.user.id;
    await v.save();
  }
  const vulns = await Vulnerability.findAll({ order: [['id','ASC']] });
  return res.render('vulns', { title: 'WeEat Vulnerability Tracker', user: req.session.user, vulns, message: 'Flag accepted. Marked as found.', error: null });
});

module.exports = router;
