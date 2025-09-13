// routes/xxe.js - NEW FILE FOR XXE VULNERABILITIES

const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const flagManager = require('../utils/flags');

// Configure multer for file uploads
const upload = multer({ dest: path.join(__dirname, '../uploads/xml/') });

// XXE Vulnerability #1: Menu Import via XML
router.post('/import-menu', (req, res) => {
  try {
    const xmlData = req.body.xml || req.body;
    
    if (!xmlData) {
      return res.status(400).json({ error: 'XML data required' });
    }

    // VULNERABILITY: Unsafe XML parsing with external entity resolution
    const libxmljs = require('libxmljs');
    const xmlDoc = libxmljs.parseXml(xmlData, { 
      noent: true,    // VULNERABILITY: Enable entity processing
      nonet: false,   // VULNERABILITY: Allow network access
      recover: true   // Continue parsing despite errors
    });

    // Process XML menu data
    const menuItems = [];
    try {
      const items = xmlDoc.find('//item');
      
      items.forEach(item => {
        const nameNode = item.get('name') || item.get('n');
        const priceNode = item.get('price') || item.get('p');
        const descNode = item.get('description') || item.get('desc');
        
        menuItems.push({
          name: nameNode ? nameNode.text() : 'Unknown',
          price: priceNode ? priceNode.text() : '0.00',
          description: descNode ? descNode.text() : 'No description'
        });
      });
    } catch (parseErr) {
      // Still return success to not reveal parsing errors
      console.log('XML parsing error (hidden from user):', parseErr);
    }

    res.json({ 
      success: true, 
      message: 'Menu import processed',
      imported: menuItems.length,
      items: menuItems,
      // VULNERABILITY: Expose XML parsing details
      debug: {
        xmlLength: xmlData.length,
        timestamp: new Date().toISOString(),
        parser: 'libxmljs'
      }
    });
    
  } catch (err) {
    console.error('XXE processing error:', err);
    res.status(500).json({ 
      error: 'XML processing failed', 
      details: err.message,
      // VULNERABILITY: Expose stack trace
      stack: err.stack
    });
  }
});

// XXE Vulnerability #2: Configuration File Upload
router.post('/import-config', upload.single('config'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Configuration file required' });
  }

  try {
    const fs = require('fs');
    const xmlContent = fs.readFileSync(req.file.path, 'utf8');
    
    // VULNERABILITY: Parse uploaded XML with external entity resolution
    const libxmljs = require('libxmljs');
    const xmlDoc = libxmljs.parseXml(xmlContent, { 
      noent: true,    // VULNERABILITY: Process external entities
      nonet: false,   // VULNERABILITY: Allow network requests
      recover: true,
      huge: true      // VULNERABILITY: Allow huge documents
    });

    // Extract configuration settings
    const config = {};
    try {
      const settings = xmlDoc.find('//setting');
      
      settings.forEach(setting => {
        const nameAttr = setting.attr('name');
        const name = nameAttr ? nameAttr.value() : null;
        const value = setting.text();
        
        if (name) {
          config[name] = value;
        }
      });
    } catch (parseErr) {
      console.log('Config parsing error:', parseErr);
    }

    // Clean up uploaded file
    fs.unlinkSync(req.file.path);

    res.json({ 
      success: true, 
      message: 'Configuration imported successfully',
      settings: Object.keys(config).length,
      config: config,
      // VULNERABILITY: Information disclosure
      debug: {
        filename: req.file.originalname,
        size: req.file.size,
        uploadPath: req.file.path,
        mimetype: req.file.mimetype
      }
    });

  } catch (err) {
    console.error('Config import error:', err);
    res.status(500).json({ 
      error: 'Configuration import failed', 
      details: err.message,
      stack: err.stack
    });
  }
});

router.post('/import-menu', flagManager.flagMiddleware('XXE'), (req, res) => {
  try {
    const xmlData = req.body.xml || req.body;
    
    if (!xmlData) {
      return res.status(400).json({ error: 'XML data required' });
    }
    
    // Check for XXE payloads
    const xxePatterns = [
      /<!DOCTYPE/i,
      /<!ENTITY/i,
      /SYSTEM/i,
      /file:\/\//i,
      /\/etc\/passwd/i,
      /C:\\Windows/i
    ];
    
    if (xxePatterns.some(pattern => pattern.test(xmlData))) {
      res.locals.xxeSuccess = true;
      res.locals.xxeData = xmlData.substring(0, 100);
      res.locals.generateFlag = true;
    }
    
    // Vulnerable XML parsing
    const libxmljs = require('libxmljs');
    const xmlDoc = libxmljs.parseXml(xmlData, { 
      noent: true,    // VULNERABILITY: Enable entity processing
      nonet: false    // VULNERABILITY: Allow network access
    });
    
    res.json({ 
      success: true, 
      message: 'Menu import processed'
    });
    
  } catch (err) {
    res.status(500).json({ error: 'XML processing failed' });
  }
});

// XXE Vulnerability #3: API Endpoint for XML Processing
router.post('/process-xml', (req, res) => {
  try {
    const { xmlContent, operation = 'parse' } = req.body;
    
    if (!xmlContent) {
      return res.status(400).json({ error: 'XML content required' });
    }

    const libxmljs = require('libxmljs');
    
    // VULNERABILITY: Different XML processing options, all vulnerable
    let parseOptions = {
      noent: true,
      nonet: false,
      recover: true
    };

    if (operation === 'validate') {
      parseOptions.dtdvalid = true;  // VULNERABILITY: DTD validation with external entities
    }

    const xmlDoc = libxmljs.parseXml(xmlContent, parseOptions);
    
    let result = {};
    
    switch (operation) {
      case 'parse':
        result = {
          root: xmlDoc.root() ? xmlDoc.root().name() : null,
          children: xmlDoc.root() ? xmlDoc.root().childNodes().length : 0
        };
        break;
        
      case 'extract':
        const textNodes = xmlDoc.find('//text()');
        result = {
          textContent: textNodes.map(node => node.text()).join(' ')
        };
        break;
        
      case 'validate':
        result = {
          valid: xmlDoc.validate() ? true : false,
          errors: xmlDoc.validationErrors
        };
        break;
        
      default:
        result = { message: 'Unknown operation' };
    }

    res.json({
      success: true,
      operation: operation,
      result: result,
      // VULNERABILITY: Echo back potentially malicious content
      originalXml: xmlContent.substring(0, 200) + '...'
    });

  } catch (err) {
    console.error('XML processing error:', err);
    res.status(500).json({
      error: 'XML processing failed',
      details: err.message,
      // VULNERABILITY: Full error disclosure
      fullError: {
        message: err.message,
        stack: err.stack,
        code: err.code
      }
    });
  }
});

module.exports = router;
