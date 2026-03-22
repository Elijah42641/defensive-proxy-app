package analyzer

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Vulnerability patterns and field lists ported from securityAnalyzer.js
var (
	sqlInjectionFieldNames     = []string{"username", "user", "email", "search", "query", "filter", "id", "uid", "pid", "category", "sort", "order", "where", "lookup", "keyword", "term", "s", "q"}
	xssFieldNames              = []string{"content", "body", "text", "message", "comment", "description", "bio", "about", "title", "name", "firstName", "lastName", "display", "input", "value", "html", "richtext", "summernote", "ckeditor", "tinymce"}
	nosqlInjectionFieldNames   = []string{"query", "filter", "criteria", "conditions", "match", "where", "find", "search"}
	pathTraversalFieldNames    = []string{"file", "path", "filename", "filepath", "dir", "directory", "folder", "location", "url", "uri", "src", "dest", "destination", "target", "resource"}
	commandInjectionFieldNames = []string{"command", "cmd", "exec", "execute", "shell", "bash", "system", "eval", "code", "script", "function", "callback"}
	authFieldNames             = []string{"password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "authorization", "auth", "credential", "session", "jwt", "oauth", "access", "key", "private", "crypt"}
	fileUploadFieldNames       = []string{"file", "upload", "image", "photo", "avatar", "document", "attachment", "media", "video", "audio", "pdf", "doc", "blob", "data"}
	identifierFieldNames       = []string{"user_id", "uid", "userid", "account_id", "accountid", "profile_id", "profileid", "order_id", "orderid", "transaction_id", "transactionid", "id", "pid", "cid", "customer_id", "customerid", "member_id", "memberid", "post_id", "postid", "item_id", "itemid", "product_id", "productid", "resource_id", "resourceid", "object_id", "objectid", "entity_id", "entityid", "record_id", "recordid"}
	businessLogicFieldNames    = []string{"price", "cost", "amount", "quantity", "qty", "discount", "tax", "total", "subtotal", "balance", "credit", "debit", "points", "credits", "status", "role", "level", "tier", "plan", "subscription", "permission", "access_level", "admin", "is_admin", "is_root", "is_superuser", "privilege"}
)

// Issue represents a detected security issue
type Issue struct {
	Type           string  `json:"type"`
	Name           string  `json:"name"`
	Severity       string  `json:"severity"`
	Recommendation string  `json:"recommendation"`
	SuggestedRule  *Rule   `json:"suggestedRule,omitempty"`
	Advice         *string `json:"advice,omitempty"`
	Location       string  `json:"location"`
}

// Rule for suggested fixes
type Rule struct {
	Key         string `json:"key"`
	KeyRuleType string `json:"keyRuleType"`
	Value       string `json:"value"`
	RuleType    string `json:"ruleType"`
	ListType    string `json:"listType"`
	Notes       string `json:"notes"`
}

// AnalyzeRequestVulnerabilities is the ported main analysis function from JS
func AnalyzeRequestVulnerabilities(headersJSON, bodyJSON, endpointPath string) ([]Issue, error) {
	var headers map[string]interface{}

	// Parse headers
	if headersJSON != "" {
		if err := json.Unmarshal([]byte(headersJSON), &headers); err != nil {
			return nil, fmt.Errorf("invalid headers JSON: %v", err)
		}
	}

	// Parse body field names (simulate JS parseBodyFieldNames)
	fieldNames := parseBodyFieldNames(bodyJSON)

	issues := []Issue{}

	// Vulnerability pattern checks (ported from JS vulnerabilityPatterns)
	patterns := []struct {
		names     []string
		severity  string
		name      string
		check     func([]string) bool
		recommend string
		suggested *Rule
	}{
		{
			sqlInjectionFieldNames,
			"high",
			"SQL Injection Risk",
			func(fields []string) bool { return hasField(fields, sqlInjectionFieldNames) },
			"User input fields detected - add SQL injection blocking rules",
			&Rule{
				Value:    "(SELECT|UNION|INSERT|DROP|DELETE|UPDATE|EXEC|--|#|/\\*|\\*/|\\$\\{)",
				RuleType: "regex",
				ListType: "blacklist",
				Notes:    "Block SQL injection patterns in user input fields",
			},
		},
		{
			xssFieldNames,
			"high",
			"XSS (Cross-Site Scripting) Risk",
			func(fields []string) bool { return hasField(fields, xssFieldNames) },
			"User content fields detected - add XSS blocking rules",
			&Rule{
				Value:    "<script|<iframe|<object|<embed|javascript:|vbscript:|on\\w+\\s*=",
				RuleType: "regex",
				ListType: "blacklist",
				Notes:    "Block XSS patterns in user content",
			},
		},
		{
			nosqlInjectionFieldNames,
			"high",
			"NoSQL Injection Risk",
			func(fields []string) bool { return hasField(fields, nosqlInjectionFieldNames) },
			"Query/filter fields detected - add NoSQL injection blocking rules",
			&Rule{
				Value:    "\\$where|\\$ne|\\$gt|\\$lt|\\$regex|\\$in|\\$or",
				RuleType: "regex",
				ListType: "blacklist",
				Notes:    "Block NoSQL injection operators",
			},
		},
		{
			pathTraversalFieldNames,
			"high",
			"Path Traversal Risk",
			func(fields []string) bool { return hasField(fields, pathTraversalFieldNames) },
			"File/path fields detected - add path traversal blocking rules",
			&Rule{
				Value:    "\\.\\.\\/|\\.\\.\\\\|%2e%2e|etc/passwd|windows/system",
				RuleType: "regex",
				ListType: "blacklist",
				Notes:    "Block path traversal attempts",
			},
		},
		{
			commandInjectionFieldNames,
			"high",
			"Command Injection Risk",
			func(fields []string) bool { return hasField(fields, commandInjectionFieldNames) },
			"Command/execution fields detected - add command injection blocking rules",
			&Rule{
				Value:    "(;|\\||&&|`|\\$\\(|\\$\\{).*(rm|cat|ls|wget|curl|nc|bash|sh)",
				RuleType: "regex",
				ListType: "blacklist",
				Notes:    "Block command injection patterns",
			},
		},
		{
			authFieldNames,
			"medium",
			"Sensitive Data Handling",
			func(fields []string) bool { return hasField(fields, authFieldNames) },
			"Authentication/secret fields detected - ensure proper logging/masking",
			nil,
		},
		{
			fileUploadFieldNames,
			"medium",
			"File Upload Risk",
			func(fields []string) bool { return hasField(fields, fileUploadFieldNames) },
			"File upload fields detected - add file type validation rules",
			&Rule{
				Key:         "Content-Type",
				KeyRuleType: "value",
				Value:       "(image/|application/pdf|text/|audio/|video/)",
				RuleType:    "regex",
				ListType:    "whitelist",
				Notes:       "Allow only safe file types for uploads",
			},
		},
		{
			identifierFieldNames,
			"medium",
			"IDOR Risk (Insecure Direct Object Reference)",
			func(fields []string) bool { return hasField(fields, identifierFieldNames) },
			"Identifier fields detected - ensure proper authorization checks",
			nil,
		},
		{
			businessLogicFieldNames,
			"high",
			"Business Logic Manipulation Risk",
			func(fields []string) bool { return hasField(fields, businessLogicFieldNames) },
			"Business-critical fields detected - ensure proper server-side validation",
			nil,
		},
	}

	// Check field-based patterns
	for _, p := range patterns {
		if p.check(fieldNames) {
			issue := Issue{
				Type:           p.name,
				Name:           p.name,
				Severity:       p.severity,
				Recommendation: p.recommend,
				Location:       "body",
			}
			if p.suggested != nil {
				issue.SuggestedRule = p.suggested
			}
			issues = append(issues, issue)
		}
	}

	// Endpoint path analysis (ported from endpointPathAdvice.check)
	endpointAdvice := analyzeEndpointPath(endpointPath)
	if endpointAdvice != nil {
		issues = append(issues, *endpointAdvice)
	}

	// Header analysis
	if len(headers) > 0 {
		headerIssues := analyzeHeaders(headers)
		issues = append(issues, headerIssues...)
	}

	// Risk assessment summary
	highCount := countSeverity(issues, "high")
	mediumCount := countSeverity(issues, "medium")

	if highCount >= 2 {
		issues = append([]Issue{{
			Type:           "riskAssessment",
			Name:           "🔴 High Overall Risk",
			Severity:       "high",
			Recommendation: fmt.Sprintf("This endpoint has %d high-severity vulnerability opportunities.", highCount),
		}}, issues...)
	} else if highCount >= 1 || mediumCount >= 2 {
		issues = append([]Issue{{
			Type:           "riskAssessment",
			Name:           "🟠 Medium Overall Risk",
			Severity:       "medium",
			Recommendation: "This endpoint has some vulnerability opportunities.",
		}}, issues...)
	}

	return issues, nil
}

func hasField(fields []string, fieldList []string) bool {
	for _, f := range fields {
		fLower := strings.ToLower(f)
		for _, target := range fieldList {
			if strings.Contains(fLower, strings.ToLower(target)) {
				return true
			}
		}
	}
	return false
}

func parseBodyFieldNames(bodyJSON string) []string {
	if bodyJSON == "" {
		return nil
	}

	// Extract potential field names from string using regex (no JSON parse needed for field detection)
	re := regexp.MustCompile(`"([^"]+)":`)
	matches := re.FindAllStringSubmatch(bodyJSON, -1)
	fieldNames := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			fieldNames = append(fieldNames, match[1])
		}
	}
	return fieldNames
}

func analyzeEndpointPath(path string) *Issue {
	pathLower := strings.ToLower(path)
	endpointAdvice := []struct {
		name     string
		severity string
		advice   string
		patterns []string
	}{
		{
			"Two-Factor Authentication Endpoint",
			"high",
			"Rate limiting, using a new cookie after validating OTP, time-based OTPs, device fingerprinting, logging.",
			[]string{"2fa", "mfa", "totp", "authenticator", "otp", "one-time-pass"},
		},
		{
			"Password Management Endpoint",
			"high",
			"Strict rate limiting, secure tokens, email notifications, 2FA.",
			[]string{"password", "reset", "forgot", "recover", "change-password"},
		},
		{
			"User Registration Endpoint",
			"medium",
			"Email uniqueness, rate limiting, email verification, logging.",
			[]string{"register", "signup", "create-account", "join"},
		},
		// Add more as needed
	}

	for _, advice := range endpointAdvice {
		for _, pattern := range advice.patterns {
			if strings.Contains(pathLower, pattern) {
				issue := Issue{
					Type:           "endpointPathAdvice",
					Name:           fmt.Sprintf("🛡️ %s", advice.name),
					Severity:       advice.severity,
					Recommendation: fmt.Sprintf("🛡️ %s", advice.name),
					Advice:         &advice.advice,
					Location:       "endpoint path",
				}
				return &issue
			}
		}
	}
	return nil
}

func analyzeHeaders(headers map[string]interface{}) []Issue {
	issues := []Issue{}
	headerKeys := make([]string, 0, len(headers))
	for k := range headers {
		headerKeys = append(headerKeys, strings.ToLower(fmt.Sprint(k)))
	}

	// Missing auth headers
	hasAuth := false
	hasCookie := false
	for _, key := range headerKeys {
		if strings.Contains(key, "authorization") {
			hasAuth = true
		}
		if strings.Contains(key, "cookie") {
			hasCookie = true
		}
	}

	if !hasAuth && !hasCookie {
		issues = append(issues, Issue{
			Type:           "missingAuth",
			Name:           "No Authentication Headers",
			Severity:       "info",
			Recommendation: "Consider requiring Authorization or Cookie headers for sensitive endpoints",
			Location:       "headers",
			SuggestedRule: &Rule{
				Key:         "Authorization",
				KeyRuleType: "value",
				Value:       "Bearer .+",
				RuleType:    "regex",
				ListType:    "whitelist",
				Notes:       "Require Bearer token",
			},
		})
	}

	return issues
}

func countSeverity(issues []Issue, severity string) int {
	count := 0
	for _, issue := range issues {
		if issue.Severity == severity {
			count++
		}
	}
	return count
}
