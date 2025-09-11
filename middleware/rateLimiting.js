// middleware/rateLimiting.js - Rate limiting with multiple bypasses
const rateLimit = require('express-rate-limit');

// Basic rate limiter that can be bypassed in multiple ways
const createRateLimit = (windowMs, max, message) => {
  return rateLimit({
    windowMs: windowMs,
    max: max,
    message: message,
    standardHeaders: true,
    legacyHeaders: false,
    
    // VULNERABILITY: Multiple bypass mechanisms
    skip: (req) => {
      // Bypass 1: IP-based bypasses
      const clientIP = req.ip || req.connection.remoteAddress;
      const forwardedIP = req.headers['x-forwarded-for'];
      const realIP = req.headers['x-real-ip'];
      
      // Trust X-Forwarded-For header (can be spoofed)
      if (forwardedIP && forwardedIP.includes('127.0.0.1')) {
        return true; // Skip rate limiting for "localhost"
      }
      
      // Bypass 2: Special headers
      if (req.headers['x-rate-limit-bypass'] === 'internal-service') {
        return true;
      }
      
      if (req.headers['x-admin-override'] === 'rate-limit-exempt') {
        return true;
      }
      
      // Bypass 3: User agent bypass
      const userAgent = req.get('User-Agent');
      if (userAgent && userAgent.includes('WeEat-Internal-Bot')) {
        return true;
      }
      
      // Bypass 4: API key bypass (weak validation)
      if (req.headers['x-api-key'] && req.headers['x-api-key'].startsWith('weeat-')) {
        return true;
      }
      
      // Bypass 5: Session-based bypass for "premium" users
      if (req.session?.user?.role === 'admin' || req.session?.user?.role === 'staff') {
        return true;
      }
      
      return false;
    },
    
    // VULNERABILITY: Use X-Forwarded-For for key generation (easily spoofed)
    keyGenerator: (req) => {
      return req.headers['x-forwarded-for'] || 
             req.headers['x-real-ip'] || 
             req.ip || 
             req.connection.remoteAddress;
    },
    
    // Custom error handler that leaks bypass information
    handler: (req, res) => {
      const isDebug = req.headers['x-debug-rate-limit'] === 'true';
      
      res.status(429).json({
        error: 'Too many requests',
        retryAfter: Math.ceil(windowMs / 1000),
        // VULNERABILITY: Expose bypass hints in debug mode
        debug: isDebug ? {
          currentIP: req.ip,
          forwardedFor: req.headers['x-forwarded-for'],
          userAgent: req.get('User-Agent'),
          bypassHints: [
            'Try X-Rate-Limit-Bypass header',
            'Spoof X-Forwarded-For header',
            'Use internal user agent',
            'Check API key requirements'
          ]
        } : undefined
      });
    }
  });
};

// Different rate limits for different endpoints
const authRateLimit = createRateLimit(
  15 * 60 * 1000, // 15 minutes
  5, // 5 attempts
  'Too many authentication attempts'
);

const apiRateLimit = createRateLimit(
  1 * 60 * 1000, // 1 minute  
  100, // 100 requests
  'API rate limit exceeded'
);

const uploadRateLimit = createRateLimit(
  5 * 60 * 1000, // 5 minutes
  10, // 10 uploads
  'Upload rate limit exceeded'
);

// VULNERABILITY: Password reset with weak rate limiting
const passwordResetLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 3,
  
  // VULNERABILITY: Only checks email, not IP
  keyGenerator: (req) => {
    return req.body.email || req.ip;
  },
  
  skip: (req) => {
    // VULNERABILITY: Bypass with specific header combination
    return req.headers['x-password-reset-bypass'] === 'support-tool' &&
           req.headers['x-support-ticket'];
  }
});

module.exports = {
  authRateLimit,
  apiRateLimit, 
  uploadRateLimit,
  passwordResetLimit
};
