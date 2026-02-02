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
  }
};

// Keywords that only get security advice (no proxy rules)
// NOTE: password, reset, forgot, recover, change-password are now handled by ruleRecommendations
const adviceOnlyKeywords = ['2fa', 'mfa', 'totp', 'otp', 'one-time-pass', 'authenticator', 'checkout', 'payment', 'pay', 'billing', 'subscription', 'invoice', 'transaction'];

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
// Dollar Parameter ($$) Security Detection
// ============================================================================
// Maps parameter names to security advice when found with =$$ pattern

const dollarParamAdvice = {
  // Authentication-related parameters
  'password': {
    name: 'Password Parameter with $$',
    severity: 'high',
    advice: '⚠️ This endpoint accepts passwords via dynamic parameter. Ensure proper hashing (bcrypt/Argon2), never log this value, and implement rate limiting to prevent brute force attacks.',
    recommendation: 'Use secure password handling with hashing, rate limiting, and proper input sanitization.',
    blockRules: [
      // Password field-specific blocking rules
      { value: '(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|EXEC|--|/#|/\\*)', ruleType: 'regex', listType: 'blacklist', notes: 'Block SQL injection patterns in password field' },
      { value: '<script|<iframe|<object|<embed|javascript:|vbscript:|on\\w+=', ruleType: 'regex', listType: 'blacklist', notes: 'Block XSS patterns in password field' },
      { value: '\\$\\{|\\$\\(|`', ruleType: 'regex', listType: 'blacklist', notes: 'Block command injection patterns' },
      { value: '^(.{0,3}|[^a-z]*|[^A-Z]*|[^0-9]*|[^!@#$%^&*]*)$', ruleType: 'regex', listType: 'blacklist', notes: 'Flag weak password patterns' }
    ]
  },
  'passwd': {
    name: 'Password Parameter with $$',
    severity: 'high',
    advice: '⚠️ This endpoint accepts passwords via dynamic parameter. Ensure proper hashing (bcrypt/Argon2), never log this value, and implement rate limiting.',
    recommendation: 'Use secure password handling with hashing, rate limiting, and proper input sanitization.'
  },
  'token': {
    name: 'Token Parameter with $$',
    severity: 'high',
    advice: '⚠️ This endpoint uses dynamic tokens. Validate token signatures, use short expiration times, implement token rotation, and ensure secure storage.',
    recommendation: 'Implement JWT/token security with proper validation, expiration, and rotation.'
  },
  'session': {
    name: 'Session Parameter with $$',
    severity: 'high',
    advice: '⚠️ This endpoint handles sessions dynamically. Use secure session cookies (HttpOnly, Secure, SameSite), implement session fixation protection, and set appropriate timeouts.',
    recommendation: 'Use secure session management with proper cookie attributes and timeout settings.'
  },
  'auth': {
    name: 'Authentication Parameter with $$',
    severity: 'high',
    advice: '⚠️ This endpoint uses dynamic authentication. Implement proper authentication checks, rate limiting, and ensure secure credential handling.',
    recommendation: 'Implement robust authentication with rate limiting and secure credential handling.'
  },
  'api_key': {
    name: 'API Key Parameter with $$',
    severity: 'high',
    advice: '⚠️ This endpoint accepts API keys dynamically. Validate API key format, implement key rotation, and log usage for monitoring.',
    recommendation: 'Use API key validation with format checking, rotation, and usage monitoring.'
  },
  
  // Authorization-related parameters
  'role': {
    name: 'Role Parameter with $$',
    severity: 'high',
    advice: '⚠️ This endpoint allows dynamic role assignment! NEVER trust client-provided roles. Always validate user authorization server-side and check if the current user has permission to modify roles.',
    recommendation: 'Implement server-side role validation. Never trust client-provided role values.'
  },
  'admin': {
    name: 'Admin Parameter with $$',
    severity: 'high',
    advice: '⚠️ This endpoint has admin access with dynamic parameter! This could allow privilege escalation. Implement strict server-side authorization checks.',
    recommendation: 'Implement strict admin authorization. Verify user permissions server-side.'
  },
  'user_role': {
    name: 'User Role Parameter with $$',
    severity: 'high',
    advice: '⚠️ This endpoint allows dynamic user role assignment! Never trust client-provided roles. Validate authorization server-side.',
    recommendation: 'Server-side role validation required. Check user permissions before role changes.'
  },
  'access_level': {
    name: 'Access Level Parameter with $$',
    severity: 'high',
    advice: '⚠️ This endpoint accepts dynamic access levels! Never trust client-provided access values. Validate authorization server-side.',
    recommendation: 'Implement server-side access level validation. Never trust client-provided values.'
  },
  'permission': {
    name: 'Permission Parameter with $$',
    severity: 'high',
    advice: '⚠️ This endpoint accepts dynamic permissions! This could lead to privilege escalation. Validate all permission changes server-side.',
    recommendation: 'Server-side permission validation required. Check authorization before granting permissions.'
  },
  'is_admin': {
    name: 'Is Admin Parameter with $$',
    severity: 'high',
    advice: '⚠️ This endpoint accepts admin flag dynamically! This is a critical security risk. Never trust client-provided admin flags.',
    recommendation: 'Implement server-side admin flag validation. Never trust client-provided values.'
  },
  
  // Business logic parameters
  'price': {
    name: 'Price Parameter with $$',
    severity: 'high',
    advice: '⚠️ This endpoint accepts prices dynamically! NEVER trust client-provided prices. Always calculate prices server-side based on product IDs and quantities.',
    recommendation: 'Calculate all prices server-side. Never trust client-provided price values.'
  },
  'cost': {
    name: 'Cost Parameter with $$',
    severity: 'high',
    advice: '⚠️ This endpoint accepts costs dynamically! Calculate costs server-side based on product data.',
    recommendation: 'Server-side cost calculation required. Never trust client-provided cost values.'
  },
  'amount': {
    name: 'Amount Parameter with $$',
    severity: 'high',
    advice: '⚠️ This endpoint accepts amounts dynamically! Validate and calculate amounts server-side.',
    recommendation: 'Server-side amount validation and calculation required.'
  },
  'total': {
    name: 'Total Parameter with $$',
    severity: 'high',
    advice: '⚠️ This endpoint accepts totals dynamically! Always calculate totals server-side from line items.',
    recommendation: 'Calculate all totals server-side. Never trust client-provided totals.'
  },
  'discount': {
    name: 'Discount Parameter with $$',
    severity: 'high',
    advice: '⚠️ This endpoint accepts discounts dynamically! Validate discount values against known promo codes server-side.',
    recommendation: 'Validate discounts server-side against valid promo codes only.'
  },
  'quantity': {
    name: 'Quantity Parameter with $$',
    severity: 'medium',
    advice: '⚠️ This endpoint accepts quantities dynamically! Validate quantities against available stock.',
    recommendation: 'Validate quantities against stock levels. Implement quantity limits.'
  },
  'qty': {
    name: 'Qty Parameter with $$',
    severity: 'medium',
    advice: '⚠️ This endpoint accepts quantity values dynamically! Validate quantities against stock.',
    recommendation: 'Validate quantities against available stock. Implement quantity limits.'
  },
  
  // User data parameters
  'email': {
    name: 'Email Parameter with $$',
    severity: 'medium',
    advice: '⚠️ This endpoint accepts emails dynamically! Validate email format server-side and implement rate limiting to prevent enumeration.',
    recommendation: 'Validate email format server-side. Implement rate limiting for email endpoints.'
  },
  'username': {
    name: 'Username Parameter with $$',
    severity: 'medium',
    advice: '⚠️ This endpoint accepts usernames dynamically! Validate format, check for reserved names, and implement rate limiting.',
    recommendation: 'Validate username format. Check reserved names. Implement rate limiting.'
  },
  'user': {
    name: 'User Parameter with $$',
    severity: 'medium',
    advice: '⚠️ This endpoint accepts user identifiers dynamically! Validate user authorization for all operations.',
    recommendation: 'Validate user authorization for all user-related operations.'
  },
  'user_id': {
    name: 'User ID Parameter with $$',
    severity: 'medium',
    advice: '⚠️ This endpoint accepts user IDs dynamically! This could indicate IDOR vulnerability. Verify the requesting user has access to the specified user ID.',
    recommendation: 'Implement IDOR protection. Verify user access to requested user ID.'
  },
  'id': {
    name: 'ID Parameter with $$',
    severity: 'medium',
    advice: '⚠️ This endpoint accepts IDs dynamically! This could indicate IDOR vulnerability. Verify authorization for all ID-based operations.',
    recommendation: 'Implement IDOR protection. Verify authorization for all ID-based access.'
  },
  
  // Search/query parameters
  'query': {
    name: 'Query Parameter with $$',
    severity: 'medium',
    advice: '⚠️ This endpoint accepts dynamic queries! Sanitize all query input to prevent SQL injection and implement rate limiting.',
    recommendation: 'Sanitize query input. Implement SQL injection protection and rate limiting.'
  },
  'search': {
    name: 'Search Parameter with $$',
    severity: 'medium',
    advice: '⚠️ This endpoint accepts dynamic search terms! Sanitize input to prevent XSS and SQL injection.',
    recommendation: 'Sanitize search input. Implement XSS and SQL injection protection.'
  },
  'filter': {
    name: 'Filter Parameter with $$',
    severity: 'medium',
    advice: '⚠️ This endpoint accepts dynamic filters! Validate filter structure to prevent NoSQL injection and other attacks.',
    recommendation: 'Validate filter structure. Implement NoSQL injection protection.'
  },
  
  // File-related parameters
  'filename': {
    name: 'Filename Parameter with $$',
    severity: 'high',
    advice: '⚠️ This endpoint accepts dynamic filenames! Validate file paths to prevent path traversal attacks.',
    recommendation: 'Validate file paths. Implement path traversal protection.'
  },
  'file': {
    name: 'File Parameter with $$',
    severity: 'high',
    advice: '⚠️ This endpoint handles dynamic file parameters! Validate file types and implement secure file storage.',
    recommendation: 'Validate file types. Implement secure file storage with random filenames.'
  },
  'path': {
    name: 'Path Parameter with $$',
    severity: 'high',
    advice: '⚠️ This endpoint accepts dynamic paths! This could indicate path traversal vulnerability. Validate and sanitize all path inputs.',
    recommendation: 'Validate and sanitize all path inputs. Implement path traversal protection.'
  },
  
  // Command-related parameters (critical)
  'command': {
    name: 'Command Parameter with $$',
    severity: 'critical',
    advice: '🔴 CRITICAL: This endpoint accepts dynamic commands! This could lead to command injection. Never execute client-provided commands.',
    recommendation: 'NEVER execute client-provided commands. Use whitelisted command names only.'
  },
  'cmd': {
    name: 'CMD Parameter with $$',
    severity: 'critical',
    advice: '🔴 CRITICAL: This endpoint accepts dynamic commands! This could lead to command injection. Never execute client-provided commands.',
    recommendation: 'NEVER execute client-provided commands. Use whitelisted command names only.'
  },
  'exec': {
    name: 'Exec Parameter with $$',
    severity: 'critical',
    advice: '🔴 CRITICAL: This endpoint accepts dynamic execution parameters! This could lead to command injection.',
    recommendation: 'NEVER execute client-provided code or commands. Use whitelisted operations only.'
  },
  'eval': {
    name: 'Eval Parameter with $$',
    severity: 'critical',
    advice: '🔴 CRITICAL: This endpoint accepts dynamic code for eval! This is extremely dangerous and could lead to remote code execution.',
    recommendation: 'NEVER use eval() with client-provided input. Use safe parsing instead.'
  },
  
  // Generic/wildcard advice for unknown parameters
  'default': {
    name: 'Dynamic Parameter with $$',
    severity: 'medium',
    advice: '⚠️ This endpoint accepts dynamic parameters ($$). Always validate and sanitize user input server-side.',
    recommendation: 'Implement proper input validation and sanitization for all dynamic parameters.'
  }
};

// ============================================================================
// Dollar Parameter Extraction Functions
// ============================================================================

/**
 * Extract parameter names from endpoint paths that contain =$$
 * Example: "/api/users?role=$$&id=123" returns ['role']
 * @param {string} endpointPath - The endpoint path to analyze
 * @returns {Array} - Array of parameter names found with =$$
 */
function extractDollarParams(endpointPath) {
  if (!endpointPath || typeof endpointPath !== 'string') {
    return [];
  }
  
  // Regex to find parameter names before =$$
  // Matches patterns like: name=$$ or name = $$ with optional spaces
  const dollarParamRegex = /([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\$\$/gi;
  
  const params = [];
  let match;
  
  while ((match = dollarParamRegex.exec(endpointPath)) !== null) {
    const paramName = match[1].toLowerCase();
    if (!params.includes(paramName)) {
      params.push(paramName);
    }
  }
  
  return params;
}

/**
 * Get security advice for a parameter name found with =$$
 * @param {string} paramName - The parameter name
 * @returns {Object} - Security advice object or null if not found
 */
function getDollarParamAdvice(paramName) {
  if (!paramName || typeof paramName !== 'string') {
    return null;
  }
  
  const normalizedName = paramName.toLowerCase();
  
  // Check for exact match first
  if (dollarParamAdvice[normalizedName]) {
    return dollarParamAdvice[normalizedName];
  }
  
  // Check for partial matches for compound names
  for (const [key, advice] of Object.entries(dollarParamAdvice)) {
    if (key !== 'default' && normalizedName.includes(key)) {
      return advice;
    }
  }
  
  // Return default advice if no match found
  return dollarParamAdvice['default'];
}

/**
 * Analyze all dollar parameters in an endpoint path and return security issues
 * @param {string} endpointPath - The endpoint path to analyze
 * @returns {Array} - Array of security issues for dollar parameters
 */
function analyzeDollarParams(endpointPath) {
  const issues = [];
  const dollarParams = extractDollarParams(endpointPath);
  
  if (dollarParams.length === 0) {
    return issues;
  }
  
  dollarParams.forEach(paramName => {
    const advice = getDollarParamAdvice(paramName);
    if (advice) {
      issues.push({
        type: 'dollarParam',
        paramName: paramName,
        name: advice.name,
        severity: advice.severity,
        recommendation: advice.recommendation,
        advice: advice.advice,
        location: 'endpoint query parameters'
      });
    }
  });
  
  return issues;
}

/**
 * Detect if an endpoint path contains =$$ pattern
 * @param {string} endpointPath - The endpoint path to check
 * @returns {boolean} - True if =$$ pattern is found
 */
function hasDollarParams(endpointPath) {
  if (!endpointPath || typeof endpointPath !== 'string') {
    return false;
  }
  
  // Simple check for =$$ pattern
  return endpointPath.includes('=$$');
}

// ============================================================================
// Dollar Parameter ($$) Security Advice Popup
// ============================================================================

/**
 * Show security advice popup for dollar parameter ($$) detections
 * @param {string} endpointPath - The endpoint path containing =$$
 * @param {Array} dollarParamIssues - Array of security issues from analyzeDollarParams
 * @param {Function} callback - Callback function after popup is closed
 */
function showDollarParamsPopup(endpointPath, dollarParamIssues, callback) {
  // Remove any existing dollar params popup
  const existingPopup = document.getElementById('dollarParamsPopup');
  const existingOverlay = document.getElementById('dollarParamsOverlay');
  if (existingPopup) existingPopup.remove();
  if (existingOverlay) existingOverlay.remove();

  // Create overlay
  const overlay = document.createElement('div');
  overlay.id = 'dollarParamsOverlay';
  overlay.style.cssText = 'position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(20, 20, 40, 0.8); z-index: 9998;';

  // Create popup container
  const popup = document.createElement('div');
  popup.id = 'dollarParamsPopup';
  popup.style.cssText = `
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background: linear-gradient(145deg, #2a2a44, #20203a);
    border-radius: 16px;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.8);
    padding: 2rem;
    max-width: 650px;
    width: 90%;
    max-height: 80vh;
    overflow-y: auto;
    z-index: 9999;
    color: #e0e0f0;
    font-family: 'Inter', sans-serif;
  `;

  // Build the issues content
  let issuesHTML = '';
  
  // Group issues by severity
  const criticalIssues = dollarParamIssues.filter(i => i.severity === 'critical');
  const highIssues = dollarParamIssues.filter(i => i.severity === 'high');
  const mediumIssues = dollarParamIssues.filter(i => i.severity === 'medium');

  if (criticalIssues.length > 0) {
    issuesHTML += `
      <div style="background: rgba(195, 0, 0, 0.2); border: 2px solid #c30000; border-radius: 10px; padding: 1rem; margin-bottom: 1rem;">
        <h4 style="color: #ff3333; margin: 0 0 0.5rem 0;">🔴 CRITICAL SECURITY ISSUES</h4>
        ${criticalIssues.map(issue => `
          <div style="margin-top: 0.5rem; padding: 0.75rem; background: rgba(195, 0, 0, 0.1); border-radius: 6px;">
            <strong>${issue.name}</strong>
            <p style="margin: 0.5rem 0 0 0; font-size: 0.9em; color: #ffcccc;">${issue.advice}</p>
          </div>
        `).join('')}
      </div>
    `;
  }

  if (highIssues.length > 0) {
    issuesHTML += `
      <div style="background: rgba(255, 87, 87, 0.15); border: 1px solid #ff5757; border-radius: 10px; padding: 1rem; margin-bottom: 1rem;">
        <h4 style="color: #ff5757; margin: 0 0 0.5rem 0;">⚠️ HIGH SEVERITY PARAMETERS</h4>
        ${highIssues.map(issue => `
          <div style="margin-top: 0.5rem; padding: 0.75rem; background: rgba(255, 87, 87, 0.1); border-radius: 6px;">
            <strong>${issue.name}</strong>
            <p style="margin: 0.5rem 0 0 0; font-size: 0.9em; color: #ffcccc;">${issue.advice}</p>
          </div>
        `).join('')}
      </div>
    `;
  }

  if (mediumIssues.length > 0) {
    issuesHTML += `
      <div style="background: rgba(255, 152, 0, 0.15); border: 1px solid #ff9800; border-radius: 10px; padding: 1rem; margin-bottom: 1rem;">
        <h4 style="color: #ff9800; margin: 0 0 0.5rem 0;">🟡 MEDIUM SEVERITY PARAMETERS</h4>
        ${mediumIssues.map(issue => `
          <div style="margin-top: 0.5rem; padding: 0.75rem; background: rgba(255, 152, 0, 0.1); border-radius: 6px;">
            <strong>${issue.name}</strong>
            <p style="margin: 0.5rem 0 0 0; font-size: 0.9em; color: #ffe0b3;">${issue.advice}</p>
          </div>
        `).join('')}
      </div>
    `;
  }

  // Get list of detected parameter names
  const paramNames = dollarParamIssues.map(i => i.paramName).join(', ');

  popup.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
      <h2 style="color: #ff9800; margin: 0;">⚠️ Dynamic Parameter Security Warning</h2>
      <button id="dollarParamsCloseBtn" style="background: transparent; border: none; color: #e0e0f0; font-size: 2rem; cursor: pointer; padding: 0; line-height: 1;">&times;</button>
    </div>
    
    <p style="margin-bottom: 1rem;">
      We detected <strong style="color: #64ffda;">${dollarParamIssues.length}</strong> dynamic parameter(s) using the <code style="background: #1a1a2e; padding: 0.2rem 0.5rem; border-radius: 4px;">$$</code> pattern in 
      <code style="background: #1a1a2e; padding: 0.2rem 0.5rem; border-radius: 4px;">${endpointPath}</code>
    </p>
    
    <div style="background: rgba(255, 152, 0, 0.1); border-radius: 10px; padding: 1rem; margin-bottom: 1.5rem; border-left: 4px solid #ff9800;">
      <p style="margin: 0; font-size: 0.9em; opacity: 0.9;">
        <strong style="color: #ff9800;">Parameters detected:</strong> <code style="background: #1a1a2e; padding: 0.2rem 0.5rem; border-radius: 4px;">${paramNames}</code>
      </p>
    </div>
    
    <div style="background: rgba(100, 255, 218, 0.05); border-radius: 10px; padding: 1rem; margin-bottom: 1.5rem; border-left: 4px solid #64ffda;">
      <p style="margin: 0; font-size: 0.9em; opacity: 0.8;">
        <strong style="color: #64ffda;">Important:</strong> Parameters with <code style="background: #1a1a2e; padding: 0.1rem 0.3rem; border-radius: 3px;">=$$</code> accept dynamic values. 
        These require <span style="color: #ff9800;">server-side security measures. <br></span> 
        Please review the security recommendations below and ensure they are implemented in your application code.
      </p>
    </div>
    
    <div style="margin-bottom: 1.5rem;">
      ${issuesHTML}
    </div>
    
    <div style="background: rgba(255, 87, 87, 0.1); border-radius: 10px; padding: 1rem; margin-bottom: 1.5rem;">
      <p style="margin: 0; font-size: 0.85em; opacity: 0.8;">
        <strong>Why is this a concern?</strong> Dynamic parameters like <code style="background: #1a1a2e; padding: 0.1rem 0.3rem; border-radius: 3px;">role=$$</code> or 
        <code style="background: #1a1a2e; padding: 0.1rem 0.3rem; border-radius: 3px;">price=$$</code> allow clients to send arbitrary values. 
        Never trust these values - always validate and authorize on the server side.
      </p>
    </div>
    
    <div style="display: flex; gap: 1rem; justify-content: flex-end;">
      <button id="dollarParamsAckBtn" style="padding: 0.8rem 1.5rem; border-radius: 8px; border: none; background: #64ffda; color: #23234a; cursor: pointer; font-weight: bold;">I Understand</button>
    </div>
  `;

  overlay.appendChild(popup);
  document.body.appendChild(overlay);

  // Event handlers
  document.getElementById('dollarParamsCloseBtn').addEventListener('click', () => {
    overlay.remove();
    if (callback) callback();
  });

  document.getElementById('dollarParamsAckBtn').addEventListener('click', () => {
    overlay.remove();
    if (callback) callback();
  });

  // Close on overlay click
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) {
      overlay.remove();
      if (callback) callback();
    }
  });

  // Escape key closes popup
  document.addEventListener('keydown', dollarParamsEscHandler);
  function dollarParamsEscHandler(e) {
    if (e.key === 'Escape') {
      overlay.remove();
      document.removeEventListener('keydown', dollarParamsEscHandler);
      if (callback) callback();
    }
  }
}

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

  // Password endpoints
  'password': {
    name: 'Password Management Endpoint',
    description: 'Password endpoints (reset, forgot, change, verify) require strict security controls to prevent credential stuffing, brute force attacks, and injection attacks.',
    keywords: ['password', 'passwd', 'pwd', 'reset', 'forgot', 'recover', 'change-password', 'update-password', 'set-password', 'new-password', 'current-password', 'confirm-password'],
    rules: {
      request: {
        headers: [
          // Block automated tools
          { key: '', keyRuleType: 'value', value: '(curl|wget|python-requests|python|bot|crawler|scraper|postman|insomnia|axios|fetch|node|java|perl|ruby)', ruleType: 'regex', listType: 'blacklist', notes: 'Block automated tools from password endpoints' },
          // Require Content-Type
          { key: 'Content-Type', keyRuleType: 'value', value: 'application/json', ruleType: 'value', listType: 'whitelist', notes: 'Require JSON content type for password operations' }
        ],
        body: [
          // Block SQL injection patterns
          { key: '', keyRuleType: 'value', value: '(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|EXEC|--|/#|/\\*|\\*/|\\$\\{|or\\s+\\d+=\\d+)', ruleType: 'regex', listType: 'blacklist', notes: 'Block SQL injection in password forms' },
          // Block XSS patterns
          { key: '', keyRuleType: 'value', value: '<script|<iframe|<object|<embed|javascript:|vbscript:|on(load|click|mouse|error|submit|change|focus|blur)=', ruleType: 'regex', listType: 'blacklist', notes: 'Block XSS attempts in password fields' },
          // Block NoSQL injection
          { key: '', keyRuleType: 'value', value: '\\$where|\\$ne|\\$gt|\\$lt|\\$regex|\\$in|\\$or|\\$and|\\$not', ruleType: 'regex', listType: 'blacklist', notes: 'Block NoSQL injection operators' },
          // Block path traversal (unlikely but possible)
          { key: '', keyRuleType: 'value', value: '\\.\\.\\/|\\.\\.\\\\|%2e%2e', ruleType: 'regex', listType: 'blacklist', notes: 'Block path traversal attempts' },
          // Block common weak/blank passwords (heuristic)
          { key: '', keyRuleType: 'value', value: '^(123456|password|qwerty|abc123|letmein|admin|welcome|login|111111|123123|12345678|trustno1)$', ruleType: 'regex', listType: 'blacklist', notes: 'Block common weak passwords' },
          // Block template injection
          { key: '', keyRuleType: 'value', value: '\\{\\{.*\\}\\}|<%.*%>', ruleType: 'regex', listType: 'blacklist', notes: 'Block template injection patterns' },
          // Block NULL bytes
          { key: '', keyRuleType: 'value', value: '%00|\\x00', ruleType: 'regex', listType: 'blacklist', notes: 'Block NULL byte injection' }
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
    detectKeywords,
    // Dollar parameter ($$) detection exports
    dollarParamAdvice,
    extractDollarParams,
    getDollarParamAdvice,
    analyzeDollarParams,
    hasDollarParams,
    showDollarParamsPopup
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
    detectKeywords,
    // Dollar parameter ($$) detection exports
    dollarParamAdvice,
    extractDollarParams,
    getDollarParamAdvice,
    analyzeDollarParams,
    hasDollarParams,
    showDollarParamsPopup
  };
}

// ============================================================================
// Dollar Parameter Blocking Rules Helper Functions
// ============================================================================

/**
 * Extract blocking rules for a dollar parameter name
 * @param {string} paramName - The parameter name (e.g., 'password', 'role')
 * @returns {Array} - Array of blocking rule objects
 */
function getDollarParamBlockRules(paramName) {
  if (!paramName || typeof paramName !== 'string') {
    return [];
  }

  const normalizedName = paramName.toLowerCase();

  // Check for exact match first
  if (dollarParamAdvice[normalizedName]?.blockRules) {
    return dollarParamAdvice[normalizedName].blockRules;
  }

  // Check for partial matches
  for (const [key, advice] of Object.entries(dollarParamAdvice)) {
    if (key !== 'default' && normalizedName.includes(key) && advice.blockRules) {
      return advice.blockRules;
    }
  }

  return [];
}

/**
 * Get all dollar parameter rules from an endpoint path
 * @param {string} endpointPath - The endpoint path to analyze
 * @returns {Object} - Object with 'advice' and 'rules' arrays
 */
function analyzeDollarParamsWithRules(endpointPath) {
  const result = {
    advice: [],
    rules: []
  };

  const dollarParams = extractDollarParams(endpointPath);

  dollarParams.forEach(paramName => {
    const advice = getDollarParamAdvice(paramName);
    const blockRules = getDollarParamBlockRules(paramName);

    if (advice) {
      result.advice.push({
        paramName,
        ...advice
      });
    }

    if (blockRules.length > 0) {
      result.rules.push({
        paramName,
        rules: blockRules
      });
    }
  });

  return result;
}

// Export helper functions for use in main.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    ...module.exports,
    getDollarParamBlockRules,
    analyzeDollarParamsWithRules
  };
}

if (typeof window !== 'undefined') {
  window.getDollarParamBlockRules = getDollarParamBlockRules;
  window.analyzeDollarParamsWithRules = analyzeDollarParamsWithRules;
}

