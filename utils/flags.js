// utils/flags.js - Fixed and enhanced flag generation system
const crypto = require('crypto');

class FlagManager {
  constructor() {
    // Use environment variable or generate a random salt on startup
    this.salt = process.env.FLAG_SALT || crypto.randomBytes(32).toString('hex');
    
    // Store validated flags in memory (in production, use database)
    this.validatedFlags = new Set();
    
    // Track exploitation attempts
    this.exploitAttempts = new Map();
    
    // Track which vulnerabilities have been found
    this.foundVulnerabilities = new Map();
  }

  // Generate a unique flag based on vulnerability exploitation
  generateFlag(vulnType, proofOfExploit) {
    const timestamp = Date.now();
    const data = `${vulnType}:${proofOfExploit}:${this.salt}:${timestamp}`;
    const hash = crypto.createHash('sha256').update(data).digest('hex');
    
    // Create a flag that looks legitimate but is unique
    const flagPrefix = vulnType.substring(0, 4).toUpperCase();
    const flagSuffix = hash.substring(0, 8).toUpperCase();
    const flagMiddle = hash.substring(8, 16).toUpperCase();
    
    return `WeEat{${flagPrefix}_${flagMiddle}_${flagSuffix}}`;
  }

  // Check if exploitation was successful and generate flag
  checkExploitation(type, req, res) {
    const userKey = req.ip || req.sessionID || 'unknown';
    
    // Rate limiting per IP
    if (this.exploitAttempts.has(userKey)) {
      const attempts = this.exploitAttempts.get(userKey);
      if (attempts.count > 100 && (Date.now() - attempts.lastAttempt) < 60000) {
        return null; // Too many attempts
      }
    }
    
    // Track attempt
    this.exploitAttempts.set(userKey, {
      count: (this.exploitAttempts.get(userKey)?.count || 0) + 1,
      lastAttempt: Date.now()
    });

    let flag = null;
    let proof = null;

    switch(type) {
      case 'SQL_INJECTION':
        if (res.locals?.sqlInjectionSuccess) {
          proof = res.locals.extractedData || 'sqli_success';
          flag = this.generateFlag('SQLI', proof.substring(0, 30));
        }
        break;

      case 'XSS_STORED':
        if (res.locals?.xssExecuted) {
          proof = res.locals.xssPayload || 'xss_payload';
          flag = this.generateFlag('XSS', proof.substring(0, 30));
        }
        break;

      case 'XSS_REFLECTED':
        if (res.locals?.reflectedXss) {
          proof = res.locals.xssPayload || 'reflected_xss';
          flag = this.generateFlag('RXSS', proof.substring(0, 30));
        }
        break;

      case 'IDOR':
        if (res.locals?.idorSuccess) {
          proof = `${res.locals.accessedResource}:${res.locals.originalUser}`;
          flag = this.generateFlag('IDOR', proof);
        }
        break;

      case 'PRIVILEGE_ESCALATION':
        if (res.locals?.privilegeEscalated) {
          const method = res.locals.escalationMethod || 'unknown';
          const originalRole = res.locals.originalRole || 'customer';
          proof = `${originalRole}->${method}`;
          flag = this.generateFlag('PRIVESC', proof);
        }
        break;

      case 'AUTH_BYPASS':
        if (res.locals?.authBypassed) {
          proof = res.locals.bypassMethod || 'auth_bypass';
          flag = this.generateFlag('AUTH', proof);
        }
        break;

      case 'RCE':
        if (res.locals?.rceExecuted) {
          proof = res.locals.commandOutput || 'code_execution';
          flag = this.generateFlag('RCE', proof.substring(0, 30));
        }
        break;

      case 'SSRF':
        if (res.locals?.ssrfSuccess) {
          const target = res.locals.ssrfTarget;
          if (target && (target.includes('169.254') || target.includes('localhost') || target.includes('127.0.0.1') || target.includes('internal'))) {
            proof = target;
            flag = this.generateFlag('SSRF', proof.substring(0, 30));
          }
        }
        break;

      case 'XXE':
        if (res.locals?.xxeSuccess) {
          proof = res.locals.xxeData || 'xxe_exploit';
          flag = this.generateFlag('XXE', proof.substring(0, 30));
        }
        break;

      case 'DESERIALIZATION':
        if (res.locals?.deserializationSuccess) {
          proof = res.locals.deserializedPayload || 'deser_exploit';
          flag = this.generateFlag('DESER', proof.substring(0, 30));
        }
        break;

      case 'PROTOTYPE_POLLUTION':
        if (res.locals?.prototypePolluted) {
          proof = res.locals.pollutedProperty || 'proto_pollution';
          flag = this.generateFlag('PROTO', proof);
        }
        break;

      case 'PATH_TRAVERSAL':
        if (res.locals?.pathTraversalSuccess) {
          const accessedPath = res.locals.accessedPath;
          if (accessedPath && (accessedPath.includes('../') || accessedPath.includes('etc'))) {
            proof = accessedPath;
            flag = this.generateFlag('PATH', proof.substring(0, 30));
          }
        }
        break;

      case 'CSRF':
        if (res.locals?.csrfSuccess) {
          proof = res.locals.csrfAction || 'csrf_attack';
          flag = this.generateFlag('CSRF', proof);
        }
        break;

      case 'PRICE_MANIPULATION':
        if (res.locals?.priceManipulated) {
          const originalPrice = res.locals.originalPrice || 0;
          const manipulatedPrice = res.locals.manipulatedPrice || 0;
          if (originalPrice > 0 && (manipulatedPrice <= 0 || manipulatedPrice < originalPrice * 0.5)) {
            proof = `${originalPrice}->${manipulatedPrice}`;
            flag = this.generateFlag('PRICE', proof);
          }
        }
        break;

      case 'FILE_UPLOAD':
        if (res.locals?.maliciousFileUploaded) {
          proof = res.locals.uploadedFileType || 'malicious_upload';
          flag = this.generateFlag('UPLOAD', proof);
        }
        break;

      case 'RACE_CONDITION':
        if (res.locals?.raceConditionSuccess) {
          proof = res.locals.raceConditionProof || 'race_condition';
          flag = this.generateFlag('RACE', proof);
        }
        break;

      case 'JWT_BYPASS':
        if (res.locals?.jwtBypassed) {
          proof = res.locals.jwtAlgorithm || 'jwt_bypass';
          flag = this.generateFlag('JWT', proof);
        }
        break;

      case 'CACHE_POISONING':
        if (res.locals?.cachePoisoned) {
          proof = res.locals.poisonedKey || 'cache_poison';
          flag = this.generateFlag('CACHE', proof.substring(0, 30));
        }
        break;

      case 'BUSINESS_LOGIC':
        if (res.locals?.businessLogicBypassed) {
          proof = res.locals.bypassedLogic || 'logic_bypass';
          flag = this.generateFlag('LOGIC', proof);
        }
        break;

      case 'INFO_DISCLOSURE':
        if (res.locals?.sensitiveInfoDisclosed) {
          proof = res.locals.disclosedInfo || 'info_leak';
          flag = this.generateFlag('INFO', proof.substring(0, 30));
        }
        break;

      case 'RATE_LIMIT_BYPASS':
        if (res.locals?.rateLimitBypassed) {
          proof = res.locals.bypassMethod || 'rate_bypass';
          flag = this.generateFlag('RATE', proof);
        }
        break;

      case 'OPEN_REDIRECT':
        if (res.locals?.openRedirectSuccess) {
          proof = res.locals.redirectUrl || 'open_redirect';
          flag = this.generateFlag('REDIR', proof.substring(0, 30));
        }
        break;

      case 'SESSION_FIXATION':
        if (res.locals?.sessionFixed) {
          proof = res.locals.sessionId || 'session_fixation';
          flag = this.generateFlag('SESSFIX', proof.substring(0, 20));
        }
        break;
    }

    if (flag) {
      // Store the flag for validation
      this.validatedFlags.add(flag);
      
      // Track the vulnerability as found
      this.foundVulnerabilities.set(type, {
        flag: flag,
        timestamp: Date.now(),
        proof: proof
      });
      
      // Log successful exploitation (for scoring)
      console.log(`[FLAG GENERATED] Type: ${type}, Flag: ${flag.substring(0, 15)}...`);
    }

    return flag;
  }

  // Validate a submitted flag
  validateFlag(submittedFlag) {
    // Check if flag matches our pattern
    const flagPattern = /^WeEat\{[A-Z0-9_]+\}$/;
    if (!flagPattern.test(submittedFlag)) {
      return { valid: false, message: 'Invalid flag format. Use: WeEat{LETTERS_NUMBERS}' };
    }

    // Check if flag was previously generated
    if (this.validatedFlags.has(submittedFlag)) {
      return { 
        valid: true, 
        message: 'Congratulations! Valid flag submitted.',
        type: this.extractFlagType(submittedFlag)
      };
    }

    return { valid: false, message: 'Flag not recognized. Make sure you exploited the vulnerability successfully.' };
  }

  // Extract vulnerability type from flag
  extractFlagType(flag) {
    const match = flag.match(/WeEat\{([A-Z]+)_/);
    if (match) {
      const typeMap = {
        'SQLI': 'SQL Injection',
        'XSS': 'Stored Cross-Site Scripting',
        'RXSS': 'Reflected Cross-Site Scripting',
        'IDOR': 'Insecure Direct Object Reference',
        'PRIV': 'Privilege Escalation',
        'AUTH': 'Authentication Bypass',
        'RCE': 'Remote Code Execution',
        'SSRF': 'Server-Side Request Forgery',
        'XXE': 'XML External Entity',
        'DESE': 'Unsafe Deserialization',
        'PROT': 'Prototype Pollution',
        'PATH': 'Path Traversal',
        'CSRF': 'Cross-Site Request Forgery',
        'PRIC': 'Price Manipulation',
        'UPLO': 'Malicious File Upload',
        'RACE': 'Race Condition',
        'JWT': 'JWT Vulnerability',
        'CACH': 'Cache Poisoning',
        'LOGI': 'Business Logic Bypass',
        'INFO': 'Information Disclosure',
        'RATE': 'Rate Limit Bypass',
        'REDI': 'Open Redirect',
        'SESS': 'Session Management'
      };
      return typeMap[match[1]] || 'Unknown Vulnerability';
    }
    return 'Unknown Vulnerability';
  }

  // Get statistics about found vulnerabilities
  getStats() {
    const totalVulns = 25; // Update this based on actual vulnerability count
    const foundCount = this.foundVulnerabilities.size;
    
    return {
      total: totalVulns,
      found: foundCount,
      remaining: totalVulns - foundCount,
      progress: Math.round((foundCount / totalVulns) * 100),
      vulnerabilities: Array.from(this.foundVulnerabilities.entries()).map(([type, data]) => ({
        type: this.extractFlagType(data.flag),
        timestamp: data.timestamp,
        flag: data.flag.substring(0, 15) + '...'
      }))
    };
  }

  // Middleware to inject flag checking
  flagMiddleware(vulnType) {
    return (req, res, next) => {
      // Store original res.send/json/render
      const originalSend = res.send;
      const originalJson = res.json;
      const originalRender = res.render;
      
      // Override to check for exploitation after response
      res.send = function(data) {
        const flag = this.locals?.generateFlag ? 
          flagManager.checkExploitation(vulnType, req, res) : null;
        
        if (flag && typeof data === 'string') {
          // Inject flag into HTML response if exploitation successful
          if (data.includes('</body>')) {
            data = data.replace('</body>', `<!-- FLAG: ${flag} --></body>`);
          } else if (data.includes('</html>')) {
            data = data.replace('</html>', `<!-- FLAG: ${flag} --></html>`);
          }
        }
        
        return originalSend.call(this, data);
      };
      
      res.json = function(data) {
        const flag = this.locals?.generateFlag ? 
          flagManager.checkExploitation(vulnType, req, res) : null;
        
        if (flag && data && typeof data === 'object') {
          // Add flag to JSON response if exploitation successful
          data._flag = flag;
        }
        
        return originalJson.call(this, data);
      };

      res.render = function(view, locals, callback) {
        // Check for flag after render
        const flag = this.locals?.generateFlag ? 
          flagManager.checkExploitation(vulnType, req, res) : null;
        
        if (flag && locals && typeof locals === 'object') {
          locals._flag = flag;
        }
        
        return originalRender.call(this, view, locals, callback);
      };
      
      next();
    };
  }

  // Clear all flags (admin function)
  reset() {
    this.validatedFlags.clear();
    this.foundVulnerabilities.clear();
    this.exploitAttempts.clear();
    console.log('[FLAG MANAGER] All progress reset');
  }
}

// Create singleton instance
const flagManager = new FlagManager();

module.exports = flagManager;
