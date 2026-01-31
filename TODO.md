# TODO: Keyword-Based Rule Recommendations Implementation

## Phase 1: Rule Recommendations Database ✅ COMPLETED
- [x] Create ruleRecommendations object with keyword mappings
- [x] Define security rules for each keyword category

## Phase 2: UI Components ✅ COMPLETED
- [x] Create recommendation popup/modal HTML structure
- [x] Add CSS styling for recommendation UI
- [x] Create showRecommendationsPopup() function

## Phase 3: Endpoint Addition Integration ✅ COMPLETED
- [x] Modify addEndpointBtn handler to detect keywords
- [x] Detect keywords in endpoint path (auth, file, api, upload, login, etc.)
- [x] Trigger recommendation popup when keywords detected

## Phase 4: Rule Application Logic ✅ COMPLETED
- [x] Create applyRecommendedRules() function
- [x] Add rules to endpoint configuration
- [x] Handle individual and bulk rule application
- [x] Save endpoint settings after applying rules

## Phase 5: HTTP Request Analyzer ✅ NEW
- [x] Create security pattern detection system
- [x] Analyze request headers and body for security issues
- [x] Support patterns: SQL Injection, XSS, NoSQL Injection, Path Traversal, Command Injection
- [x] Detect sensitive data exposure, missing headers
- [x] Create analyzer UI with expand/collapse functionality
- [x] Display results grouped by severity (High/Medium/Low/Info)
- [x] Provide "Apply All Rules" button to add suggested rules
- [x] Include "Load Sample" button with malicious request examples

---

## Features Implemented

### Supported Keywords & Categories:
1. **Authentication** (`auth`, `login`, `signin`, `register`, `signup`, `password`, `credential`, `oauth`, `token`)
   - SQL injection protection, XSS blocking, automated tool blocking

2. **File Upload** (`file`, `upload`, `image`, `document`, `media`, `attachment`, `photo`, `video`)
   - Path traversal protection, executable file blocking, script pattern blocking

3. **API** (`api`, `v1`, `v2`, `rest`, `graphql`, `endpoint`, `service`)
   - Content-type validation, Bearer token requirement, NoSQL injection blocking

4. **Payment** (`payment`, `pay`, `billing`, `credit`, `card`, `subscription`, `invoice`, `transaction`, `money`, `checkout`)
   - Automated tool blocking, credit card number flagging

5. **Search** (`search`, `query`, `find`, `filter`, `list`, `results`)
   - SQL injection protection, dangerous character blocking

6. **User Data** (`user`, `profile`, `account`, `settings`, `me`)
   - Token authentication, XSS protection

7. **Admin** (`admin`, `administrator`, `dashboard`, `manage`, `control`, `config`)
   - Automated tool blocking, admin key requirement, destructive command blocking

8. **Webhook** (`webhook`, `hook`, `callback`, `event`, `notify`)
   - Signature validation requirement

### HTTP Request Analyzer Features:
| Security Check | Severity | Description |
|----------------|----------|-------------|
| SQL Injection | High | Detects SELECT, UNION, DROP, etc. patterns |
| XSS | High | Detects script tags, javascript: URLs, event handlers |
| NoSQL Injection | High | Detects $where, $ne, $gt operators |
| Path Traversal | High | Detects ../, %2e%2e, /etc/passwd |
| Command Injection | High | Detects shell commands, pipes, backticks |
| Sensitive Data | Medium | Flags passwords, API keys in requests |
| Missing Content-Type | Medium | Warns when Content-Type is not set |
| Missing Authorization | High | Warns when no auth header is present |

### User Experience:
- When adding an endpoint with detected keywords, a popup shows detected security contexts
- Users can apply all recommendations with one click or skip
- Popup shows total number of rules that will be applied
- Feedback message shows count of applied rules
- Duplicate rules are automatically filtered out
- Request Analyzer appears when editing an endpoint
- Paste sample requests to analyze for security issues
- Results show severity-coded recommendations
- One-click "Apply All Rules" to add security rules

