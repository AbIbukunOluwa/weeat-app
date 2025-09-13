// utils/flags.js - Dynamic flag generation system
const crypto = require('crypto');

class FlagManager {
  constructor() {
    // Use environment variable or generate a random salt on startup
    this.salt = process.env.FLAG_SALT || crypto.randomBytes(32).toString('hex');
    
    // Store validated flags in memory (in production, use database)
    this.validatedFlags = new Set();
    
    // Track exploitation attempts
    this.exploitAttempts = new Map();
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
    const userKey = req.ip || req.sessionID;
    
    // Rate limiting
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
        // Check for successful SQL injection
        if (res.locals?.sqlInjectionSuccess) {
          proof = res.locals.extractedData;
          if (proof && proof.includes('passwordHash')) {
            flag = this.generateFlag('SQLI', proof.substring(0, 20));
          }
        }
        break;

      case 'XSS_STORED':
        // Check for stored XSS execution
        if (res.locals?.xssExecuted) {
          proof = res.locals.xssPayload;
          flag = this.generateFlag('XSS', proof.substring(0, 20));
        }
        break;

      case 'IDOR':
        // Check for unauthorized access
        if (res.locals?.idorSuccess) {
          proof = `${res.locals.accessedResource}:${res.locals.originalUser}`;
          flag = this.generateFlag('IDOR', proof);
        }
        break;

      case 'PRIVILEGE_ESCALATION':
        // Check for privilege escalation
        if (req.session?.privilegeEscalated) {
          const originalRole = req.session.originalRole || 'customer';
          const currentRole = req.session.user?.role;
          if (originalRole !== 'admin' && currentRole === 'admin') {
            proof = `${originalRole}->${currentRole}`;
            flag = this.generateFlag('PRIVESC', proof);
          }
        }
        break;

      case 'RCE':
        // Check for remote code execution
        if (res.locals?.rceExecuted) {
          proof = res.locals.commandOutput;
          if (proof && (proof.includes('uid=') || proof.includes('root'))) {
            flag = this.generateFlag('RCE', proof.substring(0, 30));
          }
        }
        break;

      case 'SSRF':
        // Check for SSRF success
        if (res.locals?.ssrfSuccess) {
          const target = res.locals.ssrfTarget;
          if (target && (target.includes('169.254') || target.includes('localhost:') || target.includes('127.0.0.1:'))) {
            proof = target;
            flag = this.generateFlag('SSRF', proof);
          }
        }
        break;

      case 'XXE':
        // Check for XXE exploitation
        if (res.locals?.xxeSuccess) {
          proof = res.locals.xxeData;
          if (proof && (proof.includes('/etc/passwd') || proof.includes('root:x:0'))) {
            flag = this.generateFlag('XXE', proof.substring(0, 30));
          }
        }
        break;

      case 'DESERIALIZATION':
        // Check for unsafe deserialization
        if (res.locals?.deserializationSuccess) {
          proof = res.locals.deserializedPayload;
          flag = this.generateFlag('DESER', proof.substring(0, 30));
        }
        break;

      case 'PATH_TRAVERSAL':
        // Check for path traversal
        if (res.locals?.pathTraversalSuccess) {
          const accessedPath = res.locals.accessedPath;
          if (accessedPath && (accessedPath.includes('../') || accessedPath.includes('etc'))) {
            proof = accessedPath;
            flag = this.generateFlag('PATH', proof);
          }
        }
        break;

      case 'CSRF':
        // Check for CSRF success
        if (res.locals?.csrfSuccess) {
          proof = res.locals.csrfAction;
          flag = this.generateFlag('CSRF', proof);
        }
        break;

      case 'AUTH_BYPASS':
        // Check for authentication bypass
        if (res.locals?.authBypassed) {
          proof = res.locals.bypassMethod;
          flag = this.generateFlag('AUTH', proof);
        }
        break;

      case 'PRICE_MANIPULATION':
        // Check for price manipulation
        if (res.locals?.priceManipulated) {
          const originalPrice = res.locals.originalPrice;
          const manipulatedPrice = res.locals.manipulatedPrice;
          if (originalPrice > 0 && manipulatedPrice <= 0) {
            proof = `${originalPrice}->${manipulatedPrice}`;
            flag = this.generateFlag('PRICE', proof);
          }
        }
        break;

      case 'FILE_UPLOAD':
        // Check for malicious file upload
        if (res.locals?.maliciousFileUploaded) {
          proof = res.locals.uploadedFileType;
          flag = this.generateFlag('UPLOAD', proof);
        }
        break;

      case 'RACE_CONDITION':
        // Check for race condition exploitation
        if (res.locals?.raceConditionSuccess) {
          proof = res.locals.raceConditionProof;
          flag = this.generateFlag('RACE', proof);
        }
        break;

      case 'JWT_BYPASS':
        // Check for JWT vulnerabilities
        if (res.locals?.jwtBypassed) {
          proof = res.locals.jwtAlgorithm;
          flag = this.generateFlag('JWT', proof);
        }
        break;

      case 'CACHE_POISONING':
        // Check for cache poisoning
        if (res.locals?.cachePoisoned) {
          proof = res.locals.poisonedKey;
          flag = this.generateFlag('CACHE', proof);
        }
        break;

      case 'PROTOTYPE_POLLUTION':
        // Check for prototype pollution
        if (res.locals?.prototypePolluted) {
          proof = res.locals.pollutedProperty;
          flag = this.generateFlag('PROTO', proof);
        }
        break;

      case 'BUSINESS_LOGIC':
        // Check for business logic bypass
        if (res.locals?.businessLogicBypassed) {
          proof = res.locals.bypassedLogic;
          flag = this.generateFlag('LOGIC', proof);
        }
        break;

      case 'INFO_DISCLOSURE':
        // Check for information disclosure
        if (res.locals?.sensitiveInfoDisclosed) {
          proof = res.locals.disclosedInfo;
          flag = this.generateFlag('INFO', proof.substring(0, 30));
        }
        break;

      case 'RATE_LIMIT_BYPASS':
        // Check for rate limit bypass
        if (res.locals?.rateLimitBypassed) {
          proof = res.locals.bypassMethod;
          flag = this.generateFlag('RATE', proof);
        }
        break;
    }

    if (flag) {
      // Store the flag for validation
      this.validatedFlags.add(flag);
      
      // Log successful exploitation (for scoring)
      console.log(`[FLAG GENERATED] Type: ${type}, Flag: ${flag.substring(0, 10)}...`);
    }

    return flag;
  }

  // Validate a submitted flag
  validateFlag(submittedFlag) {
    // Check if flag matches our pattern
    const flagPattern = /^WeEat\{[A-Z0-9_]+\}$/;
    if (!flagPattern.test(submittedFlag)) {
      return { valid: false, message: 'Invalid flag format' };
    }

    // Check if flag was previously generated
    if (this.validatedFlags.has(submittedFlag)) {
      return { 
        valid: true, 
        message: 'Congratulations! Valid flag submitted.',
        type: this.extractFlagType(submittedFlag)
      };
    }

    return { valid: false, message: 'Unknown or invalid flag' };
  }

  // Extract vulnerability type from flag
  extractFlagType(flag) {
    const match = flag.match(/WeEat\{([A-Z]+)_/);
    if (match) {
      const typeMap = {
        'SQLI': 'SQL Injection',
        'XSS': 'Cross-Site Scripting',
        'IDOR': 'Insecure Direct Object Reference',
        'PRIV': 'Privilege Escalation',
        'RCE': 'Remote Code Execution',
        'SSRF': 'Server-Side Request Forgery',
        'XXE': 'XML External Entity',
        'DESE': 'Deserialization',
        'PATH': 'Path Traversal',
        'CSRF': 'Cross-Site Request Forgery',
        'AUTH': 'Authentication Bypass',
        'PRIC': 'Price Manipulation',
        'UPLO': 'File Upload',
        'RACE': 'Race Condition',
        'JWT': 'JWT Vulnerability',
        'CACH': 'Cache Poisoning',
        'PROT': 'Prototype Pollution',
        'LOGI': 'Business Logic',
        'INFO': 'Information Disclosure',
        'RATE': 'Rate Limit Bypass'
      };
      return typeMap[match[1]] || 'Unknown';
    }
    return 'Unknown';
  }

  // Middleware to inject flag checking
  flagMiddleware(vulnType) {
    return (req, res, next) => {
      // Store original res.send/json
      const originalSend = res.send;
      const originalJson = res.json;
      
      // Override to check for exploitation
      res.send = function(data) {
        const flag = this.locals?.generateFlag ? 
          flagManager.checkExploitation(vulnType, req, res) : null;
        
        if (flag && typeof data === 'string') {
          // Inject flag into response if exploitation successful
          data = data.replace('</body>', `<!-- FLAG: ${flag} --></body>`);
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
      
      next();
    };
  }
}

// Create singleton instance
const flagManager = new FlagManager();

module.exports = flagManager;
