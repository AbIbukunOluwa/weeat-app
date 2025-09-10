// utils/flags.js - Dynamic flag generation system
const crypto = require('crypto');

class FlagManager {
  constructor() {
    // Flags are generated based on exploitation, not stored plaintext
    this.salt = process.env.FLAG_SALT || 'W3E4t_S3cur1ty_2024';
  }

  generateFlag(vulnerability, proof) {
    // Flag is only generated when proper exploitation occurs
    const hash = crypto.createHash('sha256')
      .update(`${vulnerability}:${proof}:${this.salt}`)
      .digest('hex');
    
    return `WeEat{${hash.substring(0, 8)}_${vulnerability}_${hash.substring(8, 16)}}`;
  }

  // Flags are only revealed when specific conditions are met
  checkExploit(type, request, response) {
    switch(type) {
      case 'SQL_INJECTION':
        // Must successfully extract admin password hash
        if (response.includes('admin') && response.includes('$2b$')) {
          return this.generateFlag('SQLi', response.substring(0, 10));
        }
        break;
        
      case 'PRIVILEGE_ESCALATION':
        // Must actually become admin from regular user
        if (request.session?.originalRole === 'customer' && 
            request.session?.user?.role === 'admin') {
          return this.generateFlag('PrivEsc', request.session.user.id);
        }
        break;
        
      case 'RCE':
        // Must execute actual command
        if (response.includes('uid=') && response.includes('gid=')) {
          return this.generateFlag('RCE', 'SystemCompromised');
        }
        break;
        
      case 'SSRF':
        // Must access internal service
        if (request.url?.includes('169.254.169.254') || 
            request.url?.includes('internal')) {
          return this.generateFlag('SSRF', 'InternalAccess');
        }
        break;
        
      case 'XXE':
        // Must successfully read /etc/passwd or similar
        if (response.includes('root:x:0:0')) {
          return this.generateFlag('XXE', 'FileRead');
        }
        break;
    }
    
    return null;
  }

  // Validate submitted flag
  validateFlag(submittedFlag, expectedType) {
    // Complex validation to prevent brute force
    const parts = submittedFlag.match(/WeEat\{([a-f0-9]{8})_(.+)_([a-f0-9]{8})\}/);
    if (!parts) return false;
    
    // Regenerate and compare
    const validFlags = [
      this.generateFlag('SQLi', 'admin'),
      this.generateFlag('PrivEsc', '1'),
      this.generateFlag('RCE', 'SystemCompromised'),
      this.generateFlag('SSRF', 'InternalAccess'),
      this.generateFlag('XXE', 'FileRead')
    ];
    
    return validFlags.includes(submittedFlag);
  }
}

module.exports = new FlagManager();
