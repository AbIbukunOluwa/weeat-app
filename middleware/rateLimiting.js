// middleware/rateLimiting.js - Fixed rate limiting with bypass vulnerabilities
const rateLimit = require('express-rate-limit');
const flagManager = require('../utils/flags');

// Basic rate limiter that can be bypassed in multiple ways
const createRateLimit = (windowMs, max, message) => {
  return rateLimit({
    windowMs: windowMs,
    max: max,
    message: { error: message },
    standardHeaders: true,
    legacyHeaders: false,
    
    // Rate limit bypass detection and flag generation
    skip: (req, res) => {
      // Check for bypass attempts
      const bypassHeaders = [
        'x-forwarded-for',
        'x-real-ip',
        'x-rate-limit-bypass',
        'x-admin-override'
      ];
      
      const bypassDetected = bypassHeaders.some(header => {
        const value = req.headers[header];
        return value && (value.includes('127.0.0.1') || value === 'internal-service' || value === 'rate-limit-exempt');
      });
      
      // Check for user agent bypass
      const userAgent = req.get('User-Agent');
      const hasUserAgentBypass = userAgent && userAgent.includes('WeEat-Internal-Bot');
      
      // Check for API key bypass (weak validation)
      const hasApiKeyBypass = req.headers['x-api-key'] && req.headers['x-api-key'].startsWith('weeat-');
      
      // Check for session-based bypass
      const hasSessionBypass = req.session?.user?.role === 'admin' || req.session?.user?.role === 'staff';
      
      if (bypassDetected || hasUserAgentBypass || hasApiKeyBypass || hasSessionBypass) {
        // Set flag generation markers
        res.locals.rateLimitBypassed = true;
        res.locals.bypassMethod = bypassDetected ? 'headers' : 
                                 hasUserAgentBypass ? 'user-agent' :
                                 hasApiKeyBypass ? 'api-key' : 'session';
        res.locals.generateFlag = true;
        
        // Override response methods to inject flag
        if (!req.rateLimitFlagSet) {
          req.rateLimitFlagSet = true;
          
          const originalSend = res.send;
          const originalJson = res.json;
          
          res.send = function(data) {
            const flag = flagManager.checkExploitation('RATE_LIMIT_BYPASS', req, this);
            if (flag && typeof data === 'string') {
              data = data.replace('</body>', `<!-- FLAG: ${flag} --></body>`);
            }
            return originalSend.call(this, data);
          };
          
          res.json = function(data) {
            const flag = flagManager.checkExploitation('RATE_LIMIT_BYPASS', req, this);
            if (flag && data && typeof data === 'object') {
              data._flag = flag;
            }
            return originalJson.call(this, data);
          };
        }
        
        return true; // Skip rate limiting
      }
      
      return false; // Apply rate limiting
    },
    
    // Use spoofable headers for key generation (vulnerability)
    keyGenerator: (req) => {
      // Prioritize spoofable headers
      return req.headers['x-forwarded-for'] || 
             req.headers['x-real-ip'] || 
             req.ip || 
             req.connection.remoteAddress ||
             'unknown';
    },
    
    // Custom error handler that leaks bypass information
    handler: (req, res) => {
      const isDebug = req.headers['x-debug-rate-limit'] === 'true';
      
      res.status(429).json({
        error: 'Too many requests',
        retryAfter: Math.ceil(windowMs / 1000),
        message: message,
        // Expose bypass hints in debug mode
        debug: isDebug ? {
          currentIP: req.ip,
          forwardedFor: req.headers['x-forwarded-for'],
          realIP: req.headers['x-real-ip'],
          userAgent: req.get('User-Agent'),
          bypassHints: [
            'Try X-Rate-Limit-Bypass: internal-service',
            'Try X-Admin-Override: rate-limit-exempt', 
            'Spoof X-Forwarded-For: 127.0.0.1',
            'Use WeEat-Internal-Bot user agent',
            'Try X-API-Key: weeat-bypass-token'
          ]
        } : undefined,
        timestamp: new Date().toISOString()
      });
    }
  });
};

// Different rate limits for different endpoints
const authRateLimit = createRateLimit(
  15 * 60 * 1000, // 15 minutes
  5, // 5 attempts
  'Too many authentication attempts. Please try again later.'
);

const apiRateLimit = createRateLimit(
  1 * 60 * 1000, // 1 minute  
  100, // 100 requests
  'API rate limit exceeded. Please slow down.'
);

const uploadRateLimit = createRateLimit(
  5 * 60 * 1000, // 5 minutes
  10, // 10 uploads
  'Upload rate limit exceeded. Please wait before uploading again.'
);

// Password reset with weak rate limiting
const passwordResetLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 3,
  message: { error: 'Too many password reset attempts' },
  
  // Only checks email, not IP (vulnerability)
  keyGenerator: (req) => {
    return req.body.email || req.ip;
  },
  
  skip: (req, res) => {
    // Bypass with specific header combination
    const hasBypass = req.headers['x-password-reset-bypass'] === 'support-tool' &&
                     req.headers['x-support-ticket'];
    
    if (hasBypass) {
      res.locals.rateLimitBypassed = true;
      res.locals.bypassMethod = 'support-bypass';
      res.locals.generateFlag = true;
    }
    
    return hasBypass;
  }
});

// Comment rate limiting (easily bypassed)
const commentRateLimit = createRateLimit(
  5 * 60 * 1000, // 5 minutes
  20, // 20 comments
  'Comment rate limit exceeded. Please slow down.'
);

// Admin action rate limiting (bypassable)
const adminRateLimit = createRateLimit(
  1 * 60 * 1000, // 1 minute
  50, // 50 admin actions
  'Admin action rate limit exceeded.'
);

module.exports = {
  authRateLimit,
  apiRateLimit,
  uploadRateLimit,
  passwordResetLimit,
  commentRateLimit,
  adminRateLimit,
  createRateLimit
};
