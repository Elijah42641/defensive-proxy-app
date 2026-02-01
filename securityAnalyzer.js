// ============================================================================
// HTTP Request Vulnerability Analyzer & Path Security Recommendations
// ============================================================================
// This module provides security analysis for HTTP requests and path-based
// security advice for endpoints that require server-side security measures
// ============================================================================

// --- Path-Based Advice Only Recommendations ---
// For keywords that require server-side security (cannot be blocked by proxy rules)
// These will show security advice instead of proxy rules
const pathAdviceOnly = {
  '2fa': {
    name: 'Two-Factor Authentication Endpoint',
    severity: 'high',
    advice: 'Rate limiting on 2FA endpoints to prevent brute force attacks. Create a new valid cookie when 2fa is verified. Use time-based OTPs with short expiration. Device fingerprinting for trusted devices. Log all 2FA attempts and failures.'
  },
  'mfa': {
    name: 'Multi-Factor Authentication Endpoint',
    severity: 'high',
    advice: 'Strict rate limiting on MFA endpoints. Hardware tokens or authenticator apps with TOTP. Re-verification for sensitive operations. Monitor unusual MFA activity.'
  },
  'totp': {
    name: 'TOTP (Time-based OTP) Endpoint',
    severity: 'high',
    advice: 'Cryptographically secure random secrets. Short OTP expiration windows. Account lockout after failed attempts. Hardware tokens for high-security scenarios.'
  },
  'otp': {
    name: 'One-Time Password Endpoint',
    severity: 'high',
    advice: 'Cryptographically secure OTP generation. Short expiration times (5-10 minutes). SMS/email OTP rate limiting. Never send OTPs to same device multiple times.'
  },
  'one-time-pass': {
    name: 'One-Time Password Endpoint',
    severity: 'high',
    advice: 'Cryptographically secure OTP generation. Short expiration times. Rate limiting per phone number/email. Log all OTP requests for monitoring.'
  },
  'authenticator': {
    name: 'Authenticator App Endpoint',
    severity: 'high',
    advice: 'TOTP standard (RFC 6238) for authenticator apps. 6-digit codes with 30-second windows. Backup codes with single-use restriction.'
  },
  'checkout': {
    name: 'Checkout/Payment Endpoint',
    severity: 'high',
    advice: 'Never trust client-provided prices - calculate on server. PCI-compliant payment processors. Idempotency keys to prevent duplicate charges. Log all transaction attempts.'
  },
  'payment': {
    name: 'Payment Processing Endpoint',
    severity: 'high',
    advice: 'PCI-compliant payment gateways. Never store card numbers - use tokenization. Fraud detection. Webhooks for payment confirmation. Log all payment events.'
  },
  'pay': {
    name: 'Payment Endpoint',
    severity: 'high',
    advice: 'Validate all payment amounts server-side. Secure payment processors. Proper error handling. HTTPS exclusively for payment pages.'
  },
  'billing': {
    name: 'Billing Endpoint',
    severity: 'high',
    advice: 'Validate subscription plans server-side. Never trust client-provided prices. Proper invoice generation and storage. Webhooks for subscription events.'
  },
  'subscription': {
    name: 'Subscription Endpoint',
    severity: 'high',
    advice: 'Validate subscription status server-side on every request. Proper proration logic. Webhooks for subscription lifecycle events. Grace periods for failed payments.'
  },
  'invoice': {
    name: 'Invoice Endpoint',
    severity: 'high',
    advice: 'Invoice numbers sequentially with gaps to prevent enumeration. Validate amounts server-side. Proper PDF generation with access controls.'
  },
  'transaction': {
    name: 'Transaction Endpoint',
    severity: 'high',
    advice: 'Transaction IDs to prevent double-submission. Proper rollback for failed transactions. Log all transaction details securely. Idempotency keys for API transactions.'
  },
  'password': {
    name: 'Password Endpoint',
    severity: 'high',
    advice: 'Never log passwords. Use bcrypt/Argon2 for hashing. Minimum complexity requirements. Password change notifications. Consider 2FA for password changes.'
  },
  'reset': {
    name: 'Password Reset Endpoint',
    severity: 'high',
    advice: 'Cryptographically secure random tokens for reset links. Short expiration times (15-30 minutes). Invalidate tokens after use. Email notifications. CAPTCHA to prevent abuse.'
  },
  'forgot': {
    name: 'Password Recovery Endpoint',
    severity: 'high',
    advice: 'Rate limiting to prevent email enumeration. Secure tokens with short expiration. Never reveal whether an email exists in the system. Confirmation emails for all reset requests.'
  },
  'recover': {
    name: 'Account Recovery Endpoint',
    severity: 'high',
    advice: 'Secure recovery codes with single-use restriction. Verify identity through multiple factors. Log all recovery attempts. Security questions with hashed answers.'
  },
  'change-password': {
    name: 'Password Change Endpoint',
    severity: 'high',
    advice: 'Require current password for changes. Validate new password strength. Email/SMS notifications for password changes. Invalidate all existing sessions.'
  }
};

// Keywords that only get security advice (no proxy rules)
const adviceOnlyKeywords = ['2fa', 'mfa', 'totp', 'otp', 'one-time-pass', 'authenticator', 'checkout', 'payment', 'pay', 'billing', 'subscription', 'invoice', 'transaction', 'password', 'reset', 'forgot', 'recover', 'change-password'];

// ============================================================================
// Field Name Vulnerability Detection
// ============================================================================

const sqlInjectionFieldNames = ['username', 'user', 'email', 'search', 'query', 'filter', 'id', 'uid', 'pid', 'category', 'sort', 'order', 'where', 'lookup', 'keyword', 'term', 's', 'q'];
const xssFieldNames = ['content', 'body', 'text', 'message', 'comment', 'description', 'bio', 'about', 'title', 'name', 'firstName', 'lastName', 'display', 'input', 'value', 'html', 'richtext', 'summernote', 'ckeditor', 'tinymce'];
const nosqlInjectionFieldNames = ['query', 'filter', 'criteria', 'conditions', 'match', 'where', 'find', 'search'];
const pathTraversalFieldNames = ['file', 'path', 'filename', 'filepath', 'dir', 'directory', 'folder', 'location', 'url', 'uri', 'src', 'dest', 'destination', 'target', 'resource'];
const commandInjectionFieldNames = ['command', 'cmd', 'exec', 'execute', 'shell', 'bash', 'system', 'eval', 'code', 'script', 'function', 'callback'];
const authFieldNames = ['password', 'passwd', 'pwd', 'secret', 'token', 'apikey', 'api_key', 'authorization', 'auth', 'credential', 'session', 'jwt', 'oauth', 'access', 'key', 'private', 'crypt'];
const fileUploadFieldNames = ['file', 'upload', 'image', 'photo', 'avatar', 'document', 'attachment', 'media', 'video', 'audio', 'pdf', 'doc', 'blob', 'data'];
const identifierFieldNames = ['user_id', 'uid', 'userid', 'account_id', 'accountid', 'profile_id', 'profileid', 'order_id', 'orderid', 'transaction_id', 'transactionid', 'id', 'pid', 'cid', 'customer_id', 'customerid', 'member_id', 'memberid', 'post_id', 'postid', 'item_id', 'itemid', 'product_id', 'productid', 'resource_id', 'resourceid', 'object_id', 'objectid', 'entity_id', 'entityid', 'record_id', 'recordid'];
const businessLogicFieldNames = ['price', 'cost', 'amount', 'quantity', 'qty', 'discount', 'tax', 'total', 'subtotal', 'balance', 'credit', 'debit', 'points', 'credits', 'status', 'role', 'level', 'tier', 'plan', 'subscription', 'permission', 'access_level', 'admin', 'is_admin', 'is_root', 'is_superuser', 'privilege'];

// ============================================================================
// Vulnerability Patterns Definition
// ============================================================================

const vulnerabilityPatterns = {
  sqlInjectionFields: {
    names: sqlInjectionFieldNames,
    severity: 'high',
    name: 'SQL Injection Risk',
    check: (fieldNames) => fieldNames.some(f => sqlInjectionFieldNames.includes(f.toLowerCase())),
    recommendation: 'User input fields detected - add SQL injection blocking rules',
    suggestedRule: { key: '', keyRuleType: 'value', value: '(SELECT|UNION|INSERT|DROP|DELETE|UPDATE|EXEC|--|#|/\\*|\\*/|\\$\\{)', ruleType: 'regex', listType: 'blacklist', notes: 'Block SQL injection patterns in user input fields' }
  },
  xssFields: {
    names: xssFieldNames,
    severity: 'high',
    name: 'XSS (Cross-Site Scripting) Risk',
    check: (fieldNames) => fieldNames.some(f => xssFieldNames.includes(f.toLowerCase())),
    recommendation: 'User content fields detected - add XSS blocking rules',
    suggestedRule: { key: '', keyRuleType: 'value', value: '<script|<iframe|<object|<embed|javascript:|vbscript:|on\\w+\\s*=', ruleType: 'regex', listType: 'blacklist', notes: 'Block XSS patterns in user content' }
  },
  nosqlInjectionFields: {
    names: nosqlInjectionFieldNames,
    severity: 'high',
    name: 'NoSQL Injection Risk',
    check: (fieldNames) => fieldNames.some(f => nosqlInjectionFieldNames.includes(f.toLowerCase())),
    recommendation: 'Query/filter fields detected - add NoSQL injection blocking rules',
    suggestedRule: { key: '', keyRuleType: 'value', value: '\\$where|\\$ne|\\$gt|\\$lt|\\$regex|\\$in|\\$or', ruleType: 'regex', listType: 'blacklist', notes: 'Block NoSQL injection operators' }
  },
  pathTraversalFields: {
    names: pathTraversalFieldNames,
    severity: 'high',
    name: 'Path Traversal Risk',
    check: (fieldNames) => fieldNames.some(f => pathTraversalFieldNames.includes(f.toLowerCase())),
    recommendation: 'File/path fields detected - add path traversal blocking rules',
    suggestedRule: { key: '', keyRuleType: 'value', value: '\\.\\.\\/|\\.\\.\\\\|%2e%2e|etc/passwd|windows/system', ruleType: 'regex', listType: 'blacklist', notes: 'Block path traversal attempts' }
  },
  commandInjectionFields: {
    names: commandInjectionFieldNames,
    severity: 'high',
    name: 'Command Injection Risk',
    check: (fieldNames) => fieldNames.some(f => commandInjectionFieldNames.includes(f.toLowerCase())),
    recommendation: 'Command/execution fields detected - add command injection blocking rules',
    suggestedRule: { key: '', keyRuleType: 'value', value: '(;|\\||&&|`|\\$\\(|\\$\\{).*(rm|cat|ls|wget|curl|nc|bash|sh)', ruleType: 'regex', listType: 'blacklist', notes: 'Block command injection patterns' }
  },
  authFields: {
    names: authFieldNames,
    severity: 'medium',
    name: 'Sensitive Data Handling',
    check: (fieldNames) => fieldNames.some(f => authFieldNames.includes(f.toLowerCase())),
    recommendation: 'Authentication/secret fields detected - ensure proper logging/masking',
    suggestedRule: { key: '', keyRuleType: 'value', value: '(password|secret|token|apikey|auth).*', ruleType: 'regex', listType: 'blacklist', notes: 'Flag sensitive data for logging' }
  },
  fileUploadFields: {
    names: fileUploadFieldNames,
    severity: 'medium',
    name: 'File Upload Risk',
    check: (fieldNames) => fieldNames.some(f => fileUploadFieldNames.includes(f.toLowerCase())),
    recommendation: 'File upload fields detected - add file type validation rules',
    suggestedRule: { key: 'Content-Type', keyRuleType: 'value', value: '(image/|application/pdf|text/|audio/|video/)', ruleType: 'regex', listType: 'whitelist', notes: 'Allow only safe file types for uploads' }
  },
  http11Indicators: {
    check: (headers) => {
      const headerKeys = Object.keys(headers).map(h => h.toLowerCase());
      return {
        hasHost: headerKeys.includes('host'),
        hasUserAgent: headerKeys.includes('user-agent'),
        hasContentType: headerKeys.includes('content-type'),
        hasAuthorization: headerKeys.includes('authorization'),
        hasCookie: headerKeys.includes('cookie'),
        hasOrigin: headerKeys.includes('origin'),
        hasXForwarded: headerKeys.some(h => h.startsWith('x-forwarded')),
        hasCustom: headerKeys.filter(h => !['host', 'user-agent', 'content-type', 'authorization', 'cookie', 'origin', 'accept', 'accept-language', 'accept-encoding', 'connection', 'content-length', 'cache-control', 'referer'].includes(h))
      };
    }
  },
  idorFields: {
    names: identifierFieldNames,
    severity: 'medium',
    name: 'IDOR Risk (Insecure Direct Object Reference)',
    check: (fieldNames) => fieldNames.some(f => identifierFieldNames.includes(f.toLowerCase())),
    recommendation: 'Identifier fields detected - ensure proper authorization checks',
    suggestedRule: null,
    advice: 'Implement proper authorization checks. Verify user permission to access/modify resources. Use indirect references (mapping IDs to internal IDs).'
  },
  businessLogicFields: {
    names: businessLogicFieldNames,
    severity: 'high',
    name: 'Business Logic Manipulation Risk',
    check: (fieldNames) => fieldNames.some(f => businessLogicFieldNames.includes(f.toLowerCase())),
    recommendation: 'Business-critical fields detected - ensure proper server-side validation',
    suggestedRule: null,
    advice: 'Never trust client-provided values for price, quantity, or access levels. Validate all business logic server-side. Server-side calculations for totals.'
  },
  endpointPathAdvice: {
    check: (endpointPath) => {
      if (!endpointPath) return null;
      const path = endpointPath.toLowerCase();
      
      const endpointAdvice = [
        { patterns: ['2fa', 'mfa', 'totp', 'authenticator', 'otp', 'one-time-pass'], name: 'Two-Factor Authentication Endpoint', severity: 'high', advice: 'Rate limiting, using a new cookie after validating OTP, time-based OTPs, device fingerprinting, logging.' },
        { patterns: ['password', 'reset', 'forgot', 'recover', 'change-password'], name: 'Password Management Endpoint', severity: 'high', advice: 'Strict rate limiting, secure tokens, email notifications, 2FA.' },
        { patterns: ['register', 'signup', 'create-account', 'join'], name: 'User Registration Endpoint', severity: 'medium', advice: 'Email uniqueness, rate limiting, email verification, logging.' },
        { patterns: ['login', 'signin', 'auth', 'oauth', 'authorize'], name: 'Authentication Endpoint', severity: 'high', advice: 'Rate limiting, account lockout, secure sessions, CAPTCHA, logging.' },
        { patterns: ['admin', 'root', 'superuser', 'administrator', 'management', 'dashboard'], name: 'Administrative Endpoint', severity: 'high', advice: 'Strict access controls, IP restrictions, MFA, comprehensive logging.' },
        { patterns: ['api', 'v1', 'v2', 'v3', 'graphql', 'rest'], name: 'API Endpoint', severity: 'medium', advice: 'API authentication, rate limiting, Content-Type validation.' },
        { patterns: ['payment', 'billing', 'checkout', 'subscribe', 'invoice', 'transaction'], name: 'Payment/Financial Endpoint', severity: 'high', advice: 'Server-side pricing, PCI compliance, idempotency keys, logging.' },
        { patterns: ['upload', 'file', 'document', 'image', 'photo', 'avatar'], name: 'File Upload Endpoint', severity: 'high', advice: 'Content-based validation, size limits, malware scanning, random filenames.' },
        { patterns: ['webhook', 'callback', 'hook', 'event', 'notify'], name: 'Webhook/Callback Endpoint', severity: 'medium', advice: 'Signature validation, source authenticity, idempotency, logging.' },
        { patterns: ['token', 'refresh', 'session', 'jwt', 'access'], name: 'Token/Session Endpoint', severity: 'high', advice: 'Short-lived tokens, token rotation, secure storage, revocation.' },
        { patterns: ['profile', 'settings', 'account', 'user', 'me'], name: 'User Data Endpoint', severity: 'medium', advice: 'Authorization checks, no sensitive data exposure, input validation.' },
        { patterns: ['search', 'query', 'filter', 'find'], name: 'Search Endpoint', severity: 'low', advice: 'Rate limiting, query complexity limits, caching, sanitization.' }
      ];
      
      for (const advice of endpointAdvice) {
        if (advice.patterns.some(pattern => path.includes(pattern))) {
          return { name: advice.name, severity: advice.severity, advice: advice.advice };
        }
      }
      
      return null;
    }
  }
};

// ============================================================================
// Helper Functions
// ============================================================================

function detectPathAdvice(endpointPath) {
  const detected = [];
  const pathLower = endpointPath.toLowerCase();

  adviceOnlyKeywords.forEach(keyword => {
    if (pathLower.includes(keyword) && pathAdviceOnly[keyword]) {
      detected.push(keyword);
    }
  });

  return detected;
}

function parseBodyFieldNames(body) {
  let fieldNames = [];
  if (body && body.trim()) {
    try {
      const parsed = JSON.parse(body);
      fieldNames = Object.keys(parsed);
    } catch (e) {
      const matches = body.match(/"([^"]+)"\s*:/g);
      if (matches) {
        fieldNames = matches.map(m => m.replace(/["\s:]/g, ''));
      }
    }
  }
  return fieldNames;
}

// ============================================================================
// Main Analysis Function
// ============================================================================

function analyzeRequestVulnerabilities(headers, body, endpointPath) {
  const issues = [];
  const fieldNames = parseBodyFieldNames(body);
  const headerKeys = headers ? Object.keys(headers) : [];

  const patterns = ['sqlInjectionFields', 'xssFields', 'nosqlInjectionFields', 'pathTraversalFields', 'commandInjectionFields', 'authFields', 'fileUploadFields', 'idorFields', 'businessLogicFields'];

  patterns.forEach(patternKey => {
    const pattern = vulnerabilityPatterns[patternKey];
    if (pattern.check && pattern.check(fieldNames)) {
      issues.push({
        type: patternKey,
        name: pattern.name,
        severity: pattern.severity,
        recommendation: pattern.recommendation,
        suggestedRule: pattern.suggestedRule,
        advice: pattern.advice || null,
        location: fieldNames.length > 0 ? 'body' : 'unknown'
      });
    }
  });

  const endpointAdvice = vulnerabilityPatterns.endpointPathAdvice.check(endpointPath);
  if (endpointAdvice) {
    const severityEmoji = endpointAdvice.severity === 'high' ? '🔴' : endpointAdvice.severity === 'medium' ? '🟠' : '🟡';
    issues.push({
      type: 'endpointPathAdvice',
      name: endpointAdvice.name,
      severity: endpointAdvice.severity,
      recommendation: `${severityEmoji} ${endpointAdvice.name}`,
      suggestedRule: null,
      advice: endpointAdvice.advice,
      location: 'endpoint path'
    });
  }

  if (headers) {
    const headerAnalysis = vulnerabilityPatterns.http11Indicators.check(headers);

    if (!headerAnalysis.hasAuthorization && !headerAnalysis.hasCookie) {
      issues.push({
        type: 'missingAuth',
        name: 'No Authentication Headers',
        severity: 'info',
        recommendation: 'Consider requiring Authorization or Cookie headers for sensitive endpoints',
        suggestedRule: { key: 'Authorization', keyRuleType: 'value', value: 'Bearer .+', ruleType: 'regex', listType: 'whitelist', notes: 'Require Bearer token' },
        location: 'headers'
      });
    }

    if (!headerAnalysis.hasContentType && fieldNames.length > 0) {
      issues.push({
        type: 'missingContentType',
        name: 'No Content-Type Header',
        severity: 'info',
        recommendation: 'Add Content-Type header validation for API endpoints',
        suggestedRule: { key: 'Content-Type', keyRuleType: 'value', value: 'application/json', ruleType: 'value', listType: 'whitelist', notes: 'Require JSON content type' },
        location: 'headers'
      });
    }

    if (headerAnalysis.hasCustom.length > 0) {
      issues.push({
        type: 'customHeaders',
        name: `Custom Headers Detected (${headerAnalysis.hasCustom.length})`,
        severity: 'low',
        recommendation: `${headerAnalysis.hasCustom.join(', ')} - Review these custom headers`,
        suggestedRule: null,
        location: 'headers'
      });
    }

    if (headerAnalysis.hasXForwarded.length > 0) {
      issues.push({
        type: 'xForwardedHeaders',
        name: 'X-Forwarded Headers Present',
        severity: 'low',
        recommendation: 'X-Forwarded headers can be spoofed - validate client IP from trusted source',
        suggestedRule: { key: '', keyRuleType: 'value', value: 'X-Forwarded-For:\\s*\\d+\\.\\d+\\.\\d+\\.\\d+', ruleType: 'regex', listType: 'blacklist', notes: 'Block suspicious X-Forwarded patterns' },
        location: 'headers'
      });
    }
  }

  const highSeverityCount = issues.filter(i => i.severity === 'high').length;
  const mediumSeverityCount = issues.filter(i => i.severity === 'medium').length;

  if (highSeverityCount >= 2) {
    issues.unshift({
      type: 'riskAssessment',
      name: '🔴 High Overall Risk',
      severity: 'high',
      recommendation: `This endpoint has ${highSeverityCount} high-severity vulnerability opportunities. Strong security rules recommended.`,
      suggestedRule: null,
      location: endpointPath || 'endpoint'
    });
  } else if (highSeverityCount >= 1 || mediumSeverityCount >= 2) {
    issues.unshift({
      type: 'riskAssessment',
      name: '🟠 Medium Overall Risk',
      severity: 'medium',
      recommendation: 'This endpoint has some vulnerability opportunities. Standard security rules recommended.',
      suggestedRule: null,
      location: endpointPath || 'endpoint'
    });
  } else if (issues.length > 0) {
    issues.unshift({
      type: 'riskAssessment',
      name: '🟡 Low Overall Risk',
      severity: 'low',
      recommendation: 'Minor vulnerability opportunities detected. Basic security rules should suffice.',
      suggestedRule: null,
      location: endpointPath || 'endpoint'
    });
  }

  return issues;
}

// ============================================================================
// Export Functions and Data
// ============================================================================

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    pathAdviceOnly,
    adviceOnlyKeywords,
    sqlInjectionFieldNames,
    xssFieldNames,
    nosqlInjectionFieldNames,
    pathTraversalFieldNames,
    commandInjectionFieldNames,
    authFieldNames,
    fileUploadFieldNames,
    identifierFieldNames,
    businessLogicFieldNames,
    vulnerabilityPatterns,
    detectPathAdvice,
    parseBodyFieldNames,
    analyzeRequestVulnerabilities
  };
}

// ============================================================================
// Keyword-Based Rule Recommendations
// ============================================================================

const ruleRecommendations = {
  // Authentication endpoints
  'auth': {
    name: 'Authentication Endpoint',
    description: 'Authentication endpoints require strong protection against brute force and injection attacks.',
    keywords: ['auth', 'login', 'signin', 'register', 'signup', 'password', 'credential', 'oauth', 'token'],
    rules: {
      request: {
        body: [
          { key: '', keyRuleType: 'value', value: '(SELECT|UNION|INSERT|DROP|DELETE|UPDATE|EXEC|--|#|/\\*|\\*/)', ruleType: 'regex', listType: 'blacklist', notes: 'Block SQL injection patterns in authentication forms' },
          { key: '', keyRuleType: 'value', value: '<script|javascript:|vbscript:|on(load|click|mouse|error|submit)=', ruleType: 'regex', listType: 'blacklist', notes: 'Block XSS attempts in credentials' },
          { key: 'Content-Type', keyRuleType: 'value', value: 'application/json', ruleType: 'value', listType: 'whitelist', notes: 'Only allow JSON content type for auth endpoints' }
        ],
        headers: [
          { key: '', keyRuleType: 'value', value: '(curl|wget|python-requests|bot|crawler|scraper)', ruleType: 'regex', listType: 'blacklist', notes: 'Block automated tools from authentication endpoints' }
        ]
      }
    }
  },

  // File upload endpoints
  'file': {
    name: 'File Upload Endpoint',
    description: 'File upload endpoints need protection against malicious file types and path traversal attacks.',
    keywords: ['file', 'upload', 'image', 'document', 'media', 'attachment', 'photo', 'video'],
    rules: {
      request: {
        headers: [
          { key: 'Content-Type', keyRuleType: 'value', value: 'multipart/form-data', ruleType: 'value', listType: 'whitelist', notes: 'Only allow multipart form data for uploads' }
        ],
        body: [
          { key: '', keyRuleType: 'value', value: '\\.\\.\\/|\\.\\.\\\\', ruleType: 'regex', listType: 'blacklist', notes: 'Block path traversal attempts' },
          { key: '', keyRuleType: 'value', value: '\\.(exe|bat|cmd|sh|php|pl|cgi|asp|jsp|jar|war)', ruleType: 'regex', listType: 'blacklist', notes: 'Block executable file extensions' },
          { key: '', keyRuleType: 'value', value: '<script|<?php|<%|\\$\\{', ruleType: 'regex', listType: 'blacklist', notes: 'Block embedded script patterns in files' }
        ]
      }
    }
  },

  // API endpoints
  'api': {
    name: 'API Endpoint',
    description: 'API endpoints should have proper content-type validation and rate limiting considerations.',
    keywords: ['api', 'v1', 'v2', 'rest', 'graphql', 'endpoint', 'service'],
    rules: {
      request: {
        headers: [
          { key: 'Content-Type', keyRuleType: 'value', value: '(application/json|application/xml)', ruleType: 'regex', listType: 'whitelist', notes: 'Only allow proper API content types' },
          { key: 'Authorization', keyRuleType: 'value', value: 'Bearer .+', ruleType: 'regex', listType: 'whitelist', notes: 'Require Bearer token authorization' }
        ],
        body: [
          { key: '', keyRuleType: 'value', value: '\\$where|\\$ne|\\$gt|\\$lt|\\$regex', ruleType: 'regex', listType: 'blacklist', notes: 'Block NoSQL injection operators' }
        ]
      }
    }
  },

  // Payment/sensitive data endpoints
  'payment': {
    name: 'Payment/Sensitive Data Endpoint',
    description: 'Payment endpoints require strict validation and logging for PCI compliance.',
    keywords: ['payment', 'pay', 'billing', 'credit', 'card', 'subscription', 'invoice', 'transaction', 'money', 'checkout'],
    rules: {
      request: {
        headers: [
          { key: '', keyRuleType: 'value', value: '(curl|wget|python|bot|scraper)', ruleType: 'regex', listType: 'blacklist', notes: 'Block automated access to payment endpoints' },
          { key: 'Content-Type', keyRuleType: 'value', value: 'application/json', ruleType: 'value', listType: 'whitelist', notes: 'Require JSON content type' }
        ],
        body: [
          { key: '', keyRuleType: 'value', value: '\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}', ruleType: 'regex', listType: 'blacklist', notes: 'Flag raw credit card numbers for logging' }
        ]
      }
    }
  },

  // Search endpoints
  'search': {
    name: 'Search Endpoint',
    description: 'Search endpoints need protection against injection attacks in query parameters.',
    keywords: ['search', 'query', 'find', 'filter', 'list', 'results'],
    rules: {
      request: {
        body: [
          { key: '', keyRuleType: 'value', value: '(SELECT|UNION|INSERT|DROP|DELETE|UPDATE|--|#|/\\*)', ruleType: 'regex', listType: 'blacklist', notes: 'Block SQL injection in search queries' },
          { key: '', keyRuleType: 'value', value: '[<>"\']', ruleType: 'regex', listType: 'blacklist', notes: 'Block dangerous characters in search terms' }
        ]
      }
    }
  },

  // User data endpoints
  'user': {
    name: 'User Data Endpoint',
    description: 'User endpoints should validate authorization and protect sensitive data.',
    keywords: ['user', 'profile', 'account', 'settings', 'me', 'profile'],
    rules: {
      request: {
        headers: [
          { key: 'Authorization', keyRuleType: 'value', value: 'Bearer .+', ruleType: 'regex', listType: 'whitelist', notes: 'Require authentication token' }
        ],
        body: [
          { key: '', keyRuleType: 'value', value: '<script|javascript:|on(error|click)=', ruleType: 'regex', listType: 'blacklist', notes: 'Block XSS in user data' }
        ]
      }
    }
  },

  // Admin endpoints
  'admin': {
    name: 'Admin Endpoint',
    description: 'Admin endpoints require stricter security controls and should be monitored.',
    keywords: ['admin', 'administrator', 'dashboard', 'manage', 'control', 'settings', 'config'],
    rules: {
      request: {
        headers: [
          { key: '', keyRuleType: 'value', value: '(curl|wget|python|bot|scraper|anonymous)', ruleType: 'regex', listType: 'blacklist', notes: 'Block automated tools from admin area' },
          { key: 'X-Admin-Key', keyRuleType: 'value', value: '.+', ruleType: 'regex', listType: 'whitelist', notes: 'Require admin access key header' }
        ],
        body: [
          { key: '', keyRuleType: 'value', value: '(rm|rm -rf|dd|mkfs|chmod 777)', ruleType: 'regex', listType: 'blacklist', notes: 'Block destructive command patterns' }
        ]
      }
    }
  },

  // Webhook endpoints
  'webhook': {
    name: 'Webhook Endpoint',
    description: 'Webhooks should validate signatures and source authenticity.',
    keywords: ['webhook', 'hook', 'callback', 'event', 'notify'],
    rules: {
      request: {
        headers: [
          { key: 'X-Webhook-Signature', keyRuleType: 'value', value: '.+', ruleType: 'regex', listType: 'whitelist', notes: 'Require webhook signature for validation' }
        ]
      }
    }
  }
};

// Keywords to detect in endpoint paths (simple strings to check)
const endpointKeywords = Object.keys(ruleRecommendations);

// Detect keywords in an endpoint path
function detectKeywords(endpointPath) {
  const detected = [];
  const pathLower = endpointPath.toLowerCase();

  endpointKeywords.forEach(keyword => {
    const rec = ruleRecommendations[keyword];
    // Check if any of the keyword synonyms appear in the path
    const hasKeyword = rec.keywords.some(kw => pathLower.includes(kw));
    if (hasKeyword) {
      detected.push(keyword);
    }
  });

  return detected;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    pathAdviceOnly,
    adviceOnlyKeywords,
    sqlInjectionFieldNames,
    xssFieldNames,
    nosqlInjectionFieldNames,
    pathTraversalFieldNames,
    commandInjectionFieldNames,
    authFieldNames,
    fileUploadFieldNames,
    identifierFieldNames,
    businessLogicFieldNames,
    vulnerabilityPatterns,
    detectPathAdvice,
    parseBodyFieldNames,
    analyzeRequestVulnerabilities,
    ruleRecommendations,
    endpointKeywords,
    detectKeywords
  };
}

if (typeof window !== 'undefined') {
  window.securityAnalyzer = {
    pathAdviceOnly,
    adviceOnlyKeywords,
    sqlInjectionFieldNames,
    xssFieldNames,
    nosqlInjectionFieldNames,
    pathTraversalFieldNames,
    commandInjectionFieldNames,
    authFieldNames,
    fileUploadFieldNames,
    identifierFieldNames,
    businessLogicFieldNames,
    vulnerabilityPatterns,
    detectPathAdvice,
    parseBodyFieldNames,
    analyzeRequestVulnerabilities,
    ruleRecommendations,
    endpointKeywords,
    detectKeywords
  };
}

