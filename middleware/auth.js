function ensureAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.redirect('/auth/login');
}

function ensureRole(role) {
  return (req, res, next) => {
    if (!req.session || !req.session.user) return res.redirect('/auth/login');
    const u = req.session.user;
    if (u.role === role || u.role === 'admin') return next();
    return res.status(403).send('Forbidden');
  };
}

module.exports = { ensureAuth, ensureRole };
