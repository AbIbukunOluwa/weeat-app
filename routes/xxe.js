// routes/xxe.js - Fixed XXE vulnerabilities with proper detection
const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const flagManager = require('../utils/flags');

// Configure multer for file uploads
const upload = multer({ dest: path.join(__dirname, '../uploads/xml/') });

// XXE Vulnerability #1: Menu Import via XML
router.post('/import-menu', flagManager.flagMiddleware('XXE'), (req, res) => {
  try {
    const xmlData = req.body.xml || req.body;
    
    if (!xmlData) {
      return res.status(400).json({ error: 'XML data required' });
    }

    // Check for XXE attack patterns
    const xxePatterns = [
      /<!DOCTYPE/i,
      /<!ENTITY/i,
      /SYSTEM\s+["'][^"']*["']/i,
      /file:\/\//i,
      /\/etc\/passwd/i,
      /C:\\Windows/i,
      /http:\/\/.*\/.*$/i,
      /ftp:\/\//i,
      /gopher:\/\//i,
      /expect:\/\//i
    ];
    
    if (xxePatterns.some(pattern => pattern.test(xmlData))) {
      res.locals.xxeSuccess = true;
      res.locals.xxeData = xmlData.substring(0, 100);
      res.locals.generateFlag = true;
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
      debug: {
        xmlLength: xmlData.length,
        timestamp: new Date().toISOString(),
        parser: 'libxmljs'
      }
    });
    
  } catch (err) {
    console.error('XXE processing error:', err);
    
    // Check if error indicates successful XXE
    if (err.message.includes('No such file') || err.message.includes('Permission denied') || 
        err.message.includes('Connection refused')) {
      res.locals.xxeSuccess = true;
      res.locals.xxeData = err.message.substring(0, 50);
      res.locals.generateFlag = true;
    }
    
    res.status(500).json({ 
      error: 'XML processing failed', 
      details: err.message,
      stack: err.stack
    });
  }
});

// XXE Vulnerability #2: Configuration File Upload
router.post('/import-config', upload.single('config'), flagManager.flagMiddleware('XXE'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Configuration file required' });
  }

  try {
    const xmlContent = fs.readFileSync(req.file.path, 'utf8');
    
    // Check for XXE attack patterns in uploaded file
    const xxePatterns = [
      /<!DOCTYPE/i,
      /<!ENTITY/i,
      /SYSTEM/i,
      /file:\/\//i,
      /\/etc\/passwd/i,
      /\/proc\/self/i,
      /C:\\Windows\\System32/i
    ];
    
    if (xxePatterns.some(pattern => pattern.test(xmlContent))) {
      res.locals.xxeSuccess = true;
      res.locals.xxeData = xmlContent.substring(0, 100);
      res.locals.generateFlag = true;
    }
    
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
      debug: {
        filename: req.file.originalname,
        size: req.file.size,
        uploadPath: req.file.path,
        mimetype: req.file.mimetype
      }
    });

  } catch (err) {
    console.error('Config import error:', err);
    
    // XXE errors might reveal successful exploitation
    if (err.message.includes('ENOENT') || err.message.includes('EACCES')) {
      res.locals.xxeSuccess = true;
      res.locals.xxeData = 'file_access_attempt';
      res.locals.generateFlag = true;
    }
    
    res.status(500).json({ 
      error: 'Configuration import failed', 
      details: err.message,
      stack: err.stack
    });
  }
});

// XXE Vulnerability #3: API Endpoint for XML Processing
router.post('/process-xml', flagManager.flagMiddleware('XXE'), (req, res) => {
  try {
    const { xmlContent, operation = 'parse' } = req.body;
    
    if (!xmlContent) {
      return res.status(400).json({ error: 'XML content required' });
    }

    // Check for XXE attack patterns
    const xxePatterns = [
      /<!DOCTYPE[^>]*>/i,
      /<!ENTITY[^>]*>/i,
      /SYSTEM\s*["'][^"']*["']/i,
      /PUBLIC\s*["'][^"']*["']/i,
      /file:\/\/[^\s"'<>]+/i,
      /http:\/\/[^\s"'<>]+/i,
      /ftp:\/\/[^\s"'<>]+/i,
      /\/etc\/passwd/i,
      /\/proc\/version/i,
      /C:\\Windows\\win\.ini/i
    ];
    
    if (xxePatterns.some(pattern => pattern.test(xmlContent))) {
      res.locals.xxeSuccess = true;
      res.locals.xxeData = xmlContent.substring(0, 100);
      res.locals.generateFlag = true;
    }

    const libxmljs = require('libxmljs');
    
    // Different XML processing options, all vulnerable
    let parseOptions = {
      noent: true,    // VULNERABILITY: Enable entity processing
      nonet: false,   // VULNERABILITY: Allow network access
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
      // Echo back potentially malicious content
      originalXml: xmlContent.substring(0, 200) + '...'
    });

  } catch (err) {
    console.error('XML processing error:', err);
    
    // Check for XXE-related errors
    if (err.message.includes('No such file') || err.message.includes('Permission denied') ||
        err.message.includes('Connection refused') || err.message.includes('network unreachable')) {
      res.locals.xxeSuccess = true;
      res.locals.xxeData = 'xxe_network_or_file_access';
      res.locals.generateFlag = true;
    }
    
    res.status(500).json({
      error: 'XML processing failed',
      details: err.message,
      fullError: {
        message: err.message,
        stack: err.stack,
        code: err.code
      }
    });
  }
});

// XXE Vulnerability #4: SOAP-like XML Processing
router.post('/soap/process', flagManager.flagMiddleware('XXE'), (req, res) => {
  try {
    const { soapXml } = req.body;
    
    if (!soapXml) {
      return res.status(400).json({ error: 'SOAP XML required' });
    }

    // Check for XXE in SOAP envelope
    if (soapXml.includes('<!ENTITY') || soapXml.includes('<!DOCTYPE') || 
        soapXml.includes('SYSTEM') || soapXml.includes('file://')) {
      res.locals.xxeSuccess = true;
      res.locals.xxeData = 'soap_xxe_attempt';
      res.locals.generateFlag = true;
    }

    const libxmljs = require('libxmljs');
    
    // Parse SOAP XML with vulnerable settings
    const soapDoc = libxmljs.parseXml(soapXml, {
      noent: true,     // Process entities
      nonet: false,    // Allow network access
      dtdload: true,   // Load DTD
      dtdattr: true,   // Load DTD attributes
      dtdvalid: true   // Validate against DTD
    });

    // Extract SOAP body
    const soapBody = soapDoc.find('//soap:Body/*', {
      soap: 'http://schemas.xmlsoap.org/soap/envelope/'
    });

    res.json({
      success: true,
      message: 'SOAP message processed',
      bodyElements: soapBody.length,
      processed: true
    });

  } catch (err) {
    // SOAP processing errors might indicate XXE
    if (err.message.includes('entity') || err.message.includes('external')) {
      res.locals.xxeSuccess = true;
      res.locals.xxeData = 'soap_entity_processing';
      res.locals.generateFlag = true;
    }
    
    res.status(500).json({
      error: 'SOAP processing failed',
      details: err.message
    });
  }
});

// XXE Vulnerability #5: XML-RPC Style Processing
router.post('/xmlrpc', flagManager.flagMiddleware('XXE'), (req, res) => {
  try {
    const { method, params, xmlData } = req.body;
    
    let xmlContent = xmlData;
    
    // If no direct XML, construct XML-RPC from method and params
    if (!xmlContent && method) {
      xmlContent = `<?xml version="1.0"?>
        <methodCall>
          <methodName>${method}</methodName>
          <params>
            <param><value><string>${params || ''}</string></value></param>
          </params>
        </methodCall>`;
    }
    
    if (!xmlContent) {
      return res.status(400).json({ error: 'XML-RPC data required' });
    }

    // Check for XXE patterns in XML-RPC
    const xxePatterns = [
      /<!DOCTYPE[^>]*SYSTEM/i,
      /<!ENTITY[^>]*>/i,
      /&[a-zA-Z][a-zA-Z0-9]*;/,
      /file:\/\//i,
      /http:\/\/169\.254\.169\.254/i
    ];
    
    if (xxePatterns.some(pattern => pattern.test(xmlContent))) {
      res.locals.xxeSuccess = true;
      res.locals.xxeData = 'xmlrpc_xxe';
      res.locals.generateFlag = true;
    }

    const libxmljs = require('libxmljs');
    
    // Vulnerable XML-RPC parsing
    const xmlrpcDoc = libxmljs.parseXml(xmlContent, {
      noent: true,      // Enable entity resolution
      nonet: false,     // Allow network access
      recover: true,
      huge: true        // Allow large documents
    });

    // Extract method name and parameters
    const methodName = xmlrpcDoc.get('//methodName');
    const paramValues = xmlrpcDoc.find('//param/value');

    const response = {
      success: true,
      method: methodName ? methodName.text() : 'unknown',
      paramCount: paramValues.length,
      timestamp: new Date().toISOString()
    };

    // Simulate method execution
    if (methodName && methodName.text() === 'system.listMethods') {
      response.result = ['system.listMethods', 'system.methodHelp', 'getUserInfo'];
    }

    res.json(response);

  } catch (err) {
    console.error('XML-RPC processing error:', err);
    
    // Check for entity-related errors
    if (err.message.includes('entity') || err.message.includes('Attempt to load network entity')) {
      res.locals.xxeSuccess = true;
      res.locals.xxeData = 'xmlrpc_entity_error';
      res.locals.generateFlag = true;
    }
    
    res.status(500).json({
      error: 'XML-RPC processing failed',
      details: err.message
    });
  }
});

// XXE Vulnerability #6: Document Processing
router.post('/document/process', upload.single('document'), flagManager.flagMiddleware('XXE'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Document file required' });
  }

  try {
    const documentContent = fs.readFileSync(req.file.path, 'utf8');
    
    // Check file extension and content
    const fileExt = path.extname(req.file.originalname).toLowerCase();
    const supportedFormats = ['.xml', '.svg', '.xhtml', '.docx', '.xlsx'];
    
    if (!supportedFormats.includes(fileExt)) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ 
        error: 'Unsupported file format',
        supported: supportedFormats 
      });
    }

    // Detect XXE patterns in document
    if (documentContent.includes('<!ENTITY') || documentContent.includes('<!DOCTYPE') ||
        documentContent.includes('SYSTEM') || documentContent.includes('file://')) {
      res.locals.xxeSuccess = true;
      res.locals.xxeData = `document_xxe_${fileExt}`;
      res.locals.generateFlag = true;
    }

    const libxmljs = require('libxmljs');
    let processedDoc;
    
    try {
      // Process different document types
      if (fileExt === '.svg') {
        // SVG files can contain XXE
        processedDoc = libxmljs.parseXml(documentContent, {
          noent: true,    // Process entities in SVG
          nonet: false,   // Allow network access for external entities
          recover: true
        });
      } else if (fileExt === '.xml' || fileExt === '.xhtml') {
        // Direct XML processing
        processedDoc = libxmljs.parseXml(documentContent, {
          noent: true,
          nonet: false,
          dtdload: true,
          dtdvalid: true
        });
      } else {
        // For other formats, try to parse as XML anyway
        processedDoc = libxmljs.parseXml(documentContent, {
          noent: true,
          nonet: false,
          recover: true
        });
      }
    } catch (parseError) {
      // Parse errors might indicate successful XXE attempts
      if (parseError.message.includes('Attempt to load network entity') ||
          parseError.message.includes('failed to load external entity')) {
        res.locals.xxeSuccess = true;
        res.locals.xxeData = 'document_entity_load';
        res.locals.generateFlag = true;
      }
      throw parseError;
    }

    // Clean up uploaded file
    fs.unlinkSync(req.file.path);

    res.json({
      success: true,
      message: 'Document processed successfully',
      format: fileExt,
      size: req.file.size,
      hasRoot: processedDoc && processedDoc.root() ? true : false,
      elements: processedDoc && processedDoc.root() ? processedDoc.root().childNodes().length : 0
    });

  } catch (err) {
    console.error('Document processing error:', err);
    
    // Clean up file on error
    if (fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    
    // Check for XXE-related errors
    if (err.message.includes('No such file or directory') ||
        err.message.includes('Permission denied') ||
        err.message.includes('network unreachable')) {
      res.locals.xxeSuccess = true;
      res.locals.xxeData = 'document_file_access';
      res.locals.generateFlag = true;
    }
    
    res.status(500).json({
      error: 'Document processing failed',
      details: err.message,
      filename: req.file.originalname
    });
  }
});

module.exports = router;
