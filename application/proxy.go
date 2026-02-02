package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

var timeToBlock int
var redisConnected = false
var rdb *redis.Client
var endpoints []Endpoint
var proxyEnabled = false
var currentServerPort string
var connpool *pgxpool.Pool
var saveLimit int
var cancel context.CancelFunc
var autoBlockThreshhold int

var server *http.Server

const CHECK_PUBLIC_IPS_TABLE_EXISTENCE_SQL = `
select exists (
  select 1
  from information_schema.tables
  where table_schema = $1
  and table_name = $2
);
`

const DB_SETUP_RESPONSE = `
Please run this sql to create the ips table in schema public:
create table public.ips (
  id serial not null,
  ip character varying(45) not null,
  score integer null default 0,
  last_seen timestamp without time zone null default CURRENT_TIMESTAMP,
  created_at timestamp without time zone null default CURRENT_TIMESTAMP,
  constraint ips_pkey primary key (id),
  constraint ips_ip_key unique (ip)
) TABLESPACE pg_default;
`

const INSERT_PUBLIC_IP_SQL = `
insert into public.ips (ip, score, last_seen)
values ($1, $2, $3, now())
on conflict (ip) do update
set score = public.ips.score + 1,
last_seen = now(),
`

const CHECK_PUBLIC_IP_EXISTENCE_SQL = `
select exists (
  select 1
  from public.ips
  offset $1
)
`

// To persist proxy enabled state across refreshes, consider storing in a file or external state store
// For now, we keep it in memory and do not reset on refresh

func main() {
	//load env variables
	proxyPort := os.Getenv("PROXY_PORT")
	if proxyPort == "" {
		proxyPort = "3000"
	}

	serverPort := os.Getenv("SERVER_PORT")
	if serverPort == "" {
		serverPort = "4000"
	}
	currentServerPort = serverPort

	currentProject := os.Getenv("CURRENT_PROJECT")
	if currentProject == "" {
		log.Fatal("CURRENT_PROJECT environment variable is required")
	}

	log.Printf("Proxy started for project: %s on port: %s", currentProject, proxyPort)

	// Load endpoints
	endpoints = loadEndpoints(currentProject)

	// Create reverse proxy
	// IMPORTANT

	// Directs requests to the server to stop infinite looping
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = "localhost:" + currentServerPort
			req.Host = req.URL.Host
		},
	}

	///////////////////

	// Global panic recovery middleware
	recoveryHandler := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				//  uses built in go function to see if there is any panic
				if rec := recover(); rec != nil {
					log.Printf("Recovered from panic: %v", rec)
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("Internal Server Error"))
				}
			}()
			//  uses another handler for requests
			next.ServeHTTP(w, r)
		})
	}

	// Main handler
	mainHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// here is where we will check if the ip is blocked in the cache
		if redisConnected {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Extract IP only (no port)
			ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ipStr = r.RemoteAddr
			}

			reputationStr, err := rdb.Get(ctx, ipStr).Result()

			if err == redis.Nil {
			} else if err != nil {
				fmt.Println("Redis GET error:", err)
			} else {

				// Key exists now parse reputation
				reputation, err := strconv.Atoi(reputationStr)
				if err != nil {
					fmt.Println("Invalid reputation value:", reputationStr)
					return
				}

				// Block if below threshold
				if reputation <= autoBlockThreshhold {
					w.WriteHeader(http.StatusForbidden)
					return
				}
			}
		}

		// instead of taking the whole body it safely chunks it
		defer r.Body.Close()

		var bodyBuf bytes.Buffer
		buf := make([]byte, 32*1024) // 32 KB chunks

		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				bodyBuf.Write(buf[:n]) // append chunk to buffer
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				http.Error(w, "Error reading body", http.StatusInternalServerError)
				return
			}
		}

		bodyBytes := bodyBuf.Bytes()

		// Re-assign the body reader to the request.
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// Extract IP from remote address for loopback checks
		host := r.RemoteAddr
		if strings.Contains(host, ":") {
			host = strings.Split(host, ":")[0]
		}
		ip := net.ParseIP(host)

		// Make sure sure that files are only served for loopback addresses

		// Allow static files to be served regardless of project
		if len(r.URL.Path) >= 8 && ip.IsLoopback() && r.URL.Path[:8] == "/public/" {
			http.StripPrefix("/public/", http.FileServer(http.Dir("../public"))).ServeHTTP(w, r)
			return
		}

		// Check if this is an internal proxy API request (always allow API calls)
		internalAPI := false
		apiPath := r.URL.Path
		if strings.HasPrefix(apiPath, "/api/proxy/") || apiPath == "/api/redis/connect" || apiPath == "/api/endpoints" || apiPath == "/api/reload-endpoints" {
			internalAPI = true
		}

		userIsLocal := strings.Contains(r.RemoteAddr, "127.0.0.1") ||
			strings.Contains(r.RemoteAddr, "::1") ||
			ip.IsLoopback()

		if internalAPI && userIsLocal {
			// Internal API requests are handled by their specific handlers
			http.DefaultServeMux.ServeHTTP(w, r)
			return
		}

		// Check for endpoint match first
		path := strings.TrimPrefix(r.URL.Path, "/")
		var matchingEndpoint *Endpoint
		for _, ep := range endpoints {
			if matchEndpointPath(path, ep.Path) {
				matchingEndpoint = &ep
				break
			}
		}

		if matchingEndpoint != nil {
			result := checkRequestRules(r, matchingEndpoint.Path, matchingEndpoint.Request, bodyBytes)
			if !result {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("Request blocked by defensive proxy"))
				if redisConnected {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()

					// Extract IP from RemoteAddr (no port)
					ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
					if err != nil {
						ipStr = r.RemoteAddr
					}

					ip := net.ParseIP(ipStr)
					if ip == nil {
						fmt.Println("Invalid IP:", ipStr)
						return
					}

					repStr, err := rdb.Get(ctx, ipStr).Result()

					if err == redis.Nil {
						// Key does not exist → add if under save limit
						count, err := rdb.DBSize(ctx).Result()
						if err != nil {
							fmt.Println("Redis error:", err)
							return
						}

						if saveLimit <= -1 || count < int64(saveLimit) {
							err := rdb.Set(ctx, ipStr, 0, 0).Err()
							if err != nil {
								fmt.Println("Error adding IP:", err)
							} else {
								fmt.Println("Added new IP:", ipStr)
							}
						} else {
							fmt.Println("Save limit reached")
						}

					} else if err != nil {
						fmt.Println("Redis GET error:", err)
						return

					} else {
						// Key exists → decrement reputation
						rep, _ := strconv.Atoi(repStr)
						rep -= 1

						if rep <= autoBlockThreshhold {
							// Apply block TTL
							err := rdb.Set(
								ctx,
								ipStr,
								rep,
								time.Duration(timeToBlock)*time.Second,
							).Err()
							if err != nil {
								fmt.Println("Error blocking IP:", err)
							} else {
								fmt.Println(
									"Blocked IP:",
									ipStr,
									"rep:",
									rep,
									"for",
									timeToBlock,
									"seconds",
								)
							}
						} else {
							// Normal update (no TTL)
							err := rdb.Set(ctx, ipStr, rep, 0).Err()
							if err != nil {
								fmt.Println("Error updating IP reputation:", err)
							} else {
								fmt.Println("Updated IP reputation:", ipStr, "to", rep)
							}
						}
					}
				}

				return
			}

			proxy.ServeHTTP(w, r)
			return
		}

		// For other requests, check if it's HTML (serve UI) or proxy
		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.ServeFile(w, r, "../public/index.html")
			return
		}

		// Forward non-matching requests
		proxy.ServeHTTP(w, r)
	})

	// Wrap main handler with recovery middleware
	handlerWithRecovery := recoveryHandler(mainHandler)

	// Add API endpoint to check proxy status
	http.HandleFunc("/api/proxy/status", func(w http.ResponseWriter, r *http.Request) {
		// CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte("Method not allowed"))
			return
		}

		status := map[string]interface{}{
			"status":     "running",
			"enabled":    proxyEnabled,
			"project":    currentProject,
			"proxyPort":  proxyPort,
			"serverPort": currentServerPort,
			"timestamp":  time.Now().Unix(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(status)
	})

	// Add API endpoint to enable proxy (for browser UI)
	http.HandleFunc("/api/proxy/enable", func(w http.ResponseWriter, r *http.Request) {
		// CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte("Method not allowed"))
			return
		}

		// Parse JSON body to get serverPort
		type EnableRequest struct {
			ServerPort string `json:"serverPort"`
		}
		var reqBody EnableRequest
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid request body"))
			return
		}

		if reqBody.ServerPort != "" {
			currentServerPort = reqBody.ServerPort
		}

		proxyEnabled = true
		saveProxyEnabled(true)
		log.Printf("Proxy enabled via API, forwarding to server port: %s", currentServerPort)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Proxy enabled"})
	})

	// Add API endpoint to disable proxy (for browser UI)
	http.HandleFunc("/api/proxy/disable", func(w http.ResponseWriter, r *http.Request) {
		// CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte("Method not allowed"))
			return
		}

		proxyEnabled = false
		saveProxyEnabled(false)
		log.Println("Proxy disabled via API")

		// Shutdown the server to free the port
		if server != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := server.Shutdown(ctx); err != nil {
				log.Printf("Server shutdown error: %v", err)
			} else {
				log.Println("Server shutdown successfully")
			}
		}

		if connpool != nil {
			connpool.Close()
			connpool = nil
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Proxy disabled"})

	})

	// Add API endpoint to get current endpoints
	http.HandleFunc("/api/endpoints", func(w http.ResponseWriter, r *http.Request) {
		// CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte("Method not allowed"))
			return
		}

		data := map[string]interface{}{
			"project":   currentProject,
			"endpoints": endpoints,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(data)
	})

	// Add API endpoint to reload endpoints
	http.HandleFunc("/api/reload-endpoints", func(w http.ResponseWriter, r *http.Request) {
		// CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte("Method not allowed"))
			return
		}

		endpoints = loadEndpoints(currentProject)
		log.Printf("Endpoints reloaded for project: %s", currentProject)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Endpoints reloaded"})
	})

	http.HandleFunc("/api/redis/connect", func(w http.ResponseWriter, r *http.Request) {
		// CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte("Method not allowed"))
			return
		}

		// Handle Redis connection here
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", 500)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var body map[string]interface{}

		//parse body
		err = json.Unmarshal(data, &body)

		if err != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}

		type RequestBody struct {
			RedisHost           string `json:"host"`
			RedisPort           int    `json:"port"`
			RedisUsername       string `json:"username"`
			RedisPassword       string `json:"password"`
			RedisDatabase       int    `json:"database"`
			RedisTLS            bool   `json:"tls"`
			SaveLimit           int    `json:"saveLimit"`
			AutoBlockThreshhold int    `json:"autoBlockThreshhold"`
			TimeToBlock         int    `json:"timeToBlock"`
		}

		var redisFields RequestBody
		err = json.Unmarshal(data, &redisFields)
		if err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		redisHost := redisFields.RedisHost
		redisPort := redisFields.RedisPort
		redisUsername := redisFields.RedisUsername
		redisPassword := redisFields.RedisPassword
		redisDatabase := redisFields.RedisDatabase
		redisTLS := redisFields.RedisTLS
		saveLimit = redisFields.SaveLimit
		autoBlockThreshhold = redisFields.AutoBlockThreshhold
		timeToBlock = redisFields.TimeToBlock

		// Build address
		redisAddr := fmt.Sprintf("%s:%d", redisHost, redisPort)

		// Configure options
		options := &redis.Options{
			Addr:     redisAddr,
			Username: redisUsername, // optional, only if Redis uses ACL
			Password: redisPassword, // optional
			DB:       redisDatabase, // optional
		}

		// Enable TLS if required
		if redisTLS {
			options.TLSConfig = &tls.Config{
				InsecureSkipVerify: true, // set to false in production with valid certs
			}
		}

		// Connect to Redis
		rdb = redis.NewClient(options)

		ping, err := rdb.Ping(ctx).Result()
		if err != nil {
			panic(err)
		}
		fmt.Println("Connected to Redis:", ping)
		redisConnected = true

		w.Write([]byte("Successfully connected to Redis database"))
	})

	// Create server
	server = &http.Server{
		Addr:    ":" + proxyPort,
		Handler: handlerWithRecovery,
	}

	log.Printf("Proxy server starting on port %s", proxyPort)
	err := server.ListenAndServe()
	if err != nil {
		log.Printf("Server error: %v", err)
	}
}

type Rule struct {
	Key         string `json:"key"`
	KeyRuleType string `json:"keyRuleType"`
	Value       string `json:"value"`
	RuleType    string `json:"ruleType"`
	DateAdded   string `json:"dateAdded"`
	Notes       string `json:"notes"`
}

type RulesObj struct {
	Whitelist []Rule            `json:"whitelist"`
	Blacklist []Rule            `json:"blacklist"`
	Mode      string            `json:"mode"`
	ModeMap   map[string]string `json:"modeMap,omitempty"`
}

type Endpoint struct {
	Path           string `json:"path"`
	ObfuscatedPath string `json:"obfuscatedPath"`
	Method         string `json:"method"`
	Request        struct {
		Headers RulesObj `json:"headers"`
		Cookies RulesObj `json:"cookies"`
		Body    struct {
			RulesObj
			URLRules []URLPatternRule `json:"urlRules,omitempty"`
		} `json:"body"`
	} `json:"request"`
	Response struct {
		Headers RulesObj `json:"headers"`
		Cookies RulesObj `json:"cookies"`
		Body    RulesObj `json:"body"`
	} `json:"response"`
}

type URLPatternRule struct {
	Value    string `json:"value"`
	RuleType string `json:"ruleType"` // "value" or "regex"
	ListType string `json:"listType"` // "whitelist" or "blacklist"
	Notes    string `json:"notes,omitempty"`
}

type RulesFile struct {
	Endpoints []Endpoint `json:"endpoints"`
}

type ProjectFile struct {
	CurrentProject string     `json:"currentProject"`
	Endpoints      []Endpoint `json:"endpoints"`
	ProxyEnabled   *bool      `json:"proxyEnabled,omitempty"`
}

func loadEndpoints(project string) []Endpoint {
	filePath := "../public/current_project.json"
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Failed to read current_project.json: %v", err)
		return nil
	}
	var projectFile ProjectFile
	if err := json.Unmarshal(data, &projectFile); err != nil {
		log.Printf("Failed to parse current_project.json: %v", err)
		return nil
	}
	for i := range projectFile.Endpoints {
		projectFile.Endpoints[i].Path = strings.TrimPrefix(projectFile.Endpoints[i].Path, "/")
	}
	// Load proxyEnabled if present, default to false if not set
	if projectFile.ProxyEnabled != nil {
		proxyEnabled = *projectFile.ProxyEnabled
	} else {
		proxyEnabled = false // Default to false for new projects
	}
	log.Printf("Loaded proxyEnabled: %v for project: %s", proxyEnabled, project)
	return projectFile.Endpoints
}

func saveProxyEnabled(enabled bool) {
	filePath := "../public/current_project.json"
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Failed to read current_project.json for saving proxyEnabled: %v", err)
		return
	}
	var projectFile ProjectFile
	if err := json.Unmarshal(data, &projectFile); err != nil {
		log.Printf("Failed to parse current_project.json for saving proxyEnabled: %v", err)
		return
	}
	projectFile.ProxyEnabled = &enabled
	updatedData, err := json.MarshalIndent(projectFile, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal updated project file: %v", err)
		return
	}
	err = os.WriteFile(filePath, updatedData, 0644)
	if err != nil {
		log.Printf("Failed to write updated current_project.json: %v", err)
		return
	}
	log.Printf("Saved proxyEnabled: %v to file", enabled)
}

// checkRuleMatch attempts to match a request component (header/cookie/body key/value) against a rule.
func checkRuleMatch(rule Rule, componentKey, componentValue string) bool {
	trimmedRuleKey := strings.TrimSpace(rule.Key)
	trimmedRuleValue := strings.TrimSpace(rule.Value)

	if trimmedRuleKey == "" && trimmedRuleValue == "" {
		return false
	}

	hasKey := trimmedRuleKey != ""
	hasValue := trimmedRuleValue != ""
	keyMatch := false
	valueMatch := false

	keyRuleType := rule.KeyRuleType
	if keyRuleType == "" {
		keyRuleType = "value"
	}

	// Check key match (case-insensitive)
	if hasKey {
		if keyRuleType == "regex" {
			// Add case-insensitive flag to regex
			regexPattern := "(?i)" + trimmedRuleKey
			if re, err := regexp.Compile(regexPattern); err == nil {
				keyMatch = re.MatchString(componentKey)
			} else {
				return false
			}
		} else {
			keyMatch = strings.EqualFold(componentKey, trimmedRuleKey)
		}
	} else {
		keyMatch = true
	}

	// Check value match (case-sensitive for values, since they might contain sensitive data)
	if hasValue {
		if rule.RuleType == "regex" {
			if re, err := regexp.Compile(trimmedRuleValue); err == nil {
				valueMatch = re.MatchString(componentValue)
			} else {
				return false
			}
		} else {
			valueMatch = strings.Contains(componentValue, trimmedRuleValue)
		}
	} else {
		valueMatch = true
	}

	result := keyMatch && valueMatch

	return result
}

// matchEndpointPath matches a request path against an endpoint pattern with $$ wildcard support.
// $$ matches any sequence of characters (including empty) within a SINGLE path segment.
// Example: "/api/users/$$" matches "/api/users/123", "/api/users/abc" but NOT "/api/users/123/profile"
// Example: "a$$f" matches "af", "a123f", "axyzf" but NOT "df" or "ag"
// Example: "/api/$$/data" matches "/api/anything/data" but NOT "/api/a/b/data"
func matchEndpointPath(requestPath, pattern string) bool {
	// Exact match first for performance
	if requestPath == pattern {
		return true
	}

	// If no wildcard, no match (unless exact match which we already checked)
	if !strings.Contains(pattern, "$$") {
		return false
	}

	// Convert $$ pattern to regex
	// $$ means "anything or nothing within a single segment" - use [^/]* instead of .*
	// Escape special regex characters first
	escaped := regexp.QuoteMeta(pattern)
	// Replace $$ with [^/]* (matches any characters except /, within a single segment)
	regexPattern := strings.ReplaceAll(escaped, "\\$\\$", "[^/]*")

	// Anchor the pattern to match the entire string
	regexPattern = "^" + regexPattern + "$"

	re, err := regexp.Compile(regexPattern)
	if err != nil {
		log.Printf("Invalid regex pattern in endpoint match: %s, error: %v", regexPattern, err)
		return false
	}

	return re.MatchString(requestPath)
}

// extractDynamicValue extracts the dynamic part from a segment value based on the endpoint pattern
// For pattern "f$$d" and value "food", returns "oo"
// For pattern "$$" and value "abc", returns "abc"
// For pattern "a$$b$$c" with value "a123b456c", returns dynamic parts at each $$
// For pattern "d$$jdfdfdsf$$lmn$$" with value "d123jdfdfdsf456lmn789":
//   - First $$: extract "123" (between "d" and "jdfdfdsf")
//   - Second $$: extract "456" (between "jdfdfdsf" and "lmn")
//   - Third $$: extract "789" (after "lmn")
func extractDynamicValue(pattern, value string, whichDollar int) string {
	log.Printf("DEBUG extractDynamicValue: pattern='%s', value='%s', whichDollar=%d", pattern, value, whichDollar)

	// Count $$ in pattern
	dollarCount := strings.Count(pattern, "$$")
	log.Printf("DEBUG extractDynamicValue: dollarCount=%d", dollarCount)

	// If no $$ in pattern, return the whole value
	if dollarCount == 0 {
		log.Printf("DEBUG extractDynamicValue: no $$ in pattern, returning full value: '%s'", value)
		return value
	}

	// Find all $$ positions in the pattern
	positions := []int{}
	searchFrom := 0
	for {
		idx := strings.Index(pattern[searchFrom:], "$$")
		if idx == -1 {
			break
		}
		positions = append(positions, searchFrom+idx)
		searchFrom = positions[len(positions)-1] + 2
	}
	log.Printf("DEBUG extractDynamicValue: positions=%v", positions)

	// If we want a specific $$, extract that part
	if whichDollar >= 0 && whichDollar < len(positions) {
		// For single $$ marker, use prefix/suffix removal
		if dollarCount == 1 {
			dollarPos := positions[0]
			prefix := pattern[:dollarPos]
			suffix := ""
			if dollarPos+2 < len(pattern) {
				suffix = pattern[dollarPos+2:]
			}

			log.Printf("DEBUG extractDynamicValue: single $$, prefix='%s', suffix='%s'", prefix, suffix)

			if prefix == "" && suffix == "" {
				log.Printf("DEBUG extractDynamicValue: no prefix or suffix, returning full value: '%s'", value)
				return value
			}

			if prefix != "" && !strings.HasPrefix(value, prefix) {
				log.Printf("DEBUG extractDynamicValue: value doesn't start with prefix, returning empty")
				return ""
			}
			if suffix != "" && !strings.HasSuffix(value, suffix) {
				log.Printf("DEBUG extractDynamicValue: value doesn't end with suffix, returning empty")
				return ""
			}

			dynamicPart := value[len(prefix) : len(value)-len(suffix)]
			result := strings.TrimSpace(dynamicPart)
			log.Printf("DEBUG extractDynamicValue: extracted dynamic part: '%s'", result)
			return result
		}

		// For multiple $$ markers in a single segment, use direct position-based extraction
		// The dynamic value is the text between the static parts that bound this $$
		//
		// For pattern "s$$f$$r" with positions [1, 4]:
		// - This means: s + ($$) + f + ($$) + r
		// - whichDollar=0: between "s" and "f" → extracts "a" from "safr"
		// - whichDollar=1: between "f" and "r" → extracts "b" from "sfbr"
		//
		// For "safr" (s + a + f + r):
		// - First $$ matches "a" (between "s" and "f")
		// - Second $$ matches "" (between "f" and "r", nothing there)
		//
		// For "sfbr" (s + f + b + r):
		// - First $$ matches "" (between "s" and "f", nothing there)
		// - Second $$ matches "b" (between "f" and "r")

		// Get the static text BEFORE this $$
		var staticBefore string
		if whichDollar == 0 {
			staticBefore = pattern[:positions[0]]
		} else {
			// For whichDollar > 0, staticBefore is between the previous $$ and this $$
			prevDollarEnd := positions[whichDollar-1] + 2
			if prevDollarEnd < positions[whichDollar] {
				staticBefore = pattern[prevDollarEnd:positions[whichDollar]]
			}
		}

		// Get the static text AFTER this $$
		var staticAfter string
		if whichDollar+1 < len(positions) {
			// Static text between this $$ and next $$
			staticAfter = pattern[positions[whichDollar]+2 : positions[whichDollar+1]]
		} else {
			// Static text after last $$
			staticAfter = pattern[positions[whichDollar]+2:]
		}

		log.Printf("DEBUG extractDynamicValue: whichDollar=%d, staticBefore='%s', staticAfter='%s'", whichDollar, staticBefore, staticAfter)

		// Find staticBefore in value
		beforeIdx := -1
		if staticBefore != "" {
			beforeIdx = strings.Index(value, staticBefore)
		} else {
			beforeIdx = 0
		}

		if beforeIdx == -1 {
			log.Printf("DEBUG extractDynamicValue: staticBefore not found in value, returning empty")
			return ""
		}

		// Find staticAfter - start searching after staticBefore
		searchStart := beforeIdx + len(staticBefore)
		var afterIdx int
		if staticAfter != "" {
			idx := strings.Index(value[searchStart:], staticAfter)
			if idx == -1 {
				log.Printf("DEBUG extractDynamicValue: staticAfter not found in value, returning empty")
				return ""
			}
			afterIdx = searchStart + idx
		} else {
			afterIdx = len(value)
		}

		// The dynamic value is between staticBefore and staticAfter
		startIdx := beforeIdx + len(staticBefore)
		dynamicValue := value[startIdx:afterIdx]
		result := strings.TrimSpace(dynamicValue)
		log.Printf("DEBUG extractDynamicValue: extracted dynamic value: '%s' (from indices %d to %d)", result, startIdx, afterIdx)
		return result
	}

	// Default: return empty
	log.Printf("DEBUG extractDynamicValue: default, returning empty")
	return ""
}

// extractDynamicValuesFromPath extracts all dynamic values from a URL path based on the endpoint pattern
// Returns a slice of values to check against URL pattern rules
// For pattern "/api/users/$$" with request "/api/users/admin", returns ["admin"]
// For pattern "/api/$$/data" with request "/api/anything/data", returns ["anything"]
// For pattern "/api/$$/$$" with request "/api/user/123/profile", returns ["user", "123"]
func extractDynamicValuesFromPath(pattern, requestPath string) []string {
	log.Printf("DEBUG extractDynamicValuesFromPath: pattern='%s', requestPath='%s'", pattern, requestPath)

	// Split pattern and request into segments
	patternSegments := strings.Split(pattern, "/")
	requestSegments := strings.Split(requestPath, "/")

	log.Printf("DEBUG: patternSegments=%v, requestSegments=%v", patternSegments, requestSegments)

	var values []string

	for i, patternSeg := range patternSegments {
		if !strings.Contains(patternSeg, "$$") {
			continue
		}

		// Get the corresponding request segment
		if i >= len(requestSegments) {
			log.Printf("DEBUG: No corresponding request segment for pattern segment %d", i)
			continue
		}

		requestSeg := requestSegments[i]
		log.Printf("DEBUG: Processing segment %d - pattern='%s', request='%s'", i, patternSeg, requestSeg)

		// Count $$ markers in this pattern segment
		dollarCount := strings.Count(patternSeg, "$$")

		if dollarCount == 1 {
			// Single $$ marker - extract the dynamic part
			dollarPos := strings.Index(patternSeg, "$$")
			prefix := patternSeg[:dollarPos]
			suffix := ""
			if dollarPos+2 < len(patternSeg) {
				suffix = patternSeg[dollarPos+2:]
			}

			log.Printf("DEBUG: Single $$ - prefix='%s', suffix='%s'", prefix, suffix)

			// Extract the value between prefix and suffix
			var value string
			if prefix == "" && suffix == "" {
				// No prefix or suffix, entire segment is dynamic
				value = requestSeg
			} else if prefix == "" {
				// No prefix, value ends at suffix
				if strings.HasSuffix(requestSeg, suffix) {
					value = requestSeg[:len(requestSeg)-len(suffix)]
				} else {
					value = requestSeg
				}
			} else if suffix == "" {
				// No suffix, value starts after prefix
				if strings.HasPrefix(requestSeg, prefix) {
					value = requestSeg[len(prefix):]
				} else {
					value = requestSeg
				}
			} else {
				// Both prefix and suffix
				if strings.HasPrefix(requestSeg, prefix) && strings.HasSuffix(requestSeg, suffix) {
					value = requestSeg[len(prefix) : len(requestSeg)-len(suffix)]
				} else {
					value = requestSeg
				}
			}

			log.Printf("DEBUG: Extracted value: '%s'", value)
			values = append(values, value)
		} else {
			// Multiple $$ markers in single segment - this is a special case
			// For simplicity, we'll add the entire request segment
			log.Printf("DEBUG: Multiple $$ in single segment, using full segment value")
			values = append(values, requestSeg)
		}
	}

	log.Printf("DEBUG: Final extracted values: %v", values)

	// If no values extracted, return the full path as a fallback
	if len(values) == 0 {
		log.Printf("DEBUG: No values extracted, returning full path")
		return []string{requestPath}
	}

	return values
}

// checkRequestRules checks all request rules against the incoming request
func checkRequestRules(
	r *http.Request,
	endpointPath string,
	reqRules struct {
		Headers RulesObj `json:"headers"`
		Cookies RulesObj `json:"cookies"`
		Body    struct {
			RulesObj
			URLRules []URLPatternRule `json:"urlRules,omitempty"`
		} `json:"body"`
	},
	bodyBytes []byte,
) bool {

	/* ================= URL RULES ================= */
	path := r.URL.Path
	var urlRules []URLPatternRule
	urlRules = append(urlRules, reqRules.Body.URLRules...)

	// Add URL whitelist/blacklist rules from body
	for _, rule := range reqRules.Body.Whitelist {
		if strings.HasPrefix(rule.Key, "url_") {
			urlRules = append(urlRules, URLPatternRule{
				Value:    rule.Value,
				RuleType: rule.RuleType,
				ListType: "whitelist",
				Notes:    rule.Notes,
			})
		}
	}
	for _, rule := range reqRules.Body.Blacklist {
		if strings.HasPrefix(rule.Key, "url_") {
			urlRules = append(urlRules, URLPatternRule{
				Value:    rule.Value,
				RuleType: rule.RuleType,
				ListType: "blacklist",
				Notes:    rule.Notes,
			})
		}
	}

	// Check blacklist first
	for _, rule := range urlRules {
		if rule.ListType != "blacklist" {
			continue
		}
		matched := false
		if rule.RuleType == "regex" {
			re, err := regexp.Compile(rule.Value)
			if err != nil {
				continue
			}
			matched = re.MatchString(path)
		} else {
			matched = strings.Contains(path, rule.Value)
		}
		if matched {
			return false
		}
	}

	// Optionally check whitelist (doesn't block)
	// for _, rule := range urlRules {
	// 	if rule.ListType != "whitelist" {
	// 		continue
	// 	}
	// 	matched := false
	// 	if rule.RuleType == "regex" {
	// 		re, err := regexp.Compile(rule.Value)
	// 		if err != nil {
	// 			continue
	// 		}
	// 		matched = re.MatchString(path)
	// 	} else {
	// 		matched = strings.Contains(path, rule.Value)
	// 	}
	// }

	/* ================= BODY PARSING ================= */
	var bodyData map[string]interface{}
	contentType := strings.ToLower(r.Header.Get("Content-Type"))

	if strings.Contains(contentType, "application/json") {
		_ = json.Unmarshal(bodyBytes, &bodyData)
	} else if len(bodyBytes) > 0 {
		if form, err := url.ParseQuery(strings.ReplaceAll(string(bodyBytes), ":", "=")); err == nil {
			bodyData = make(map[string]interface{})
			for k, v := range form {
				if len(v) == 1 {
					bodyData[k] = v[0]
				} else {
					bodyData[k] = v
				}
			}
		}
	}

	/* ================= GENERIC EVALUATOR ================= */
	eval := func(
		section string,
		mode string,
		whitelist []Rule,
		blacklist []Rule,
		iter func(func(string, string)),
	) bool {

		var seen []string
		foundUnwhitelisted := false

		iter(func(k, v string) {
			seen = append(seen, k+"="+v)

			for _, r := range blacklist {
				if checkRuleMatch(r, k, v) && mode != "blacklist" {
					panic("blocked")
				}
			}

			if mode == "blacklist" {
				whitelisted := false
				for _, r := range whitelist {
					if checkRuleMatch(r, k, v) {
						whitelisted = true
						break
					}
				}
				if !whitelisted {
					foundUnwhitelisted = true
				}
			}
		})

		if mode == "blacklist" && len(seen) == 0 {
			return true
		}
		if mode == "blacklist" && foundUnwhitelisted {
			return false
		}

		return true
	}

	safeEval := func(fn func() bool) bool {
		defer func() { recover() }()
		return fn()
	}

	/* ================= HEADERS ================= */
	if !safeEval(func() bool {
		return eval("headers", reqRules.Headers.Mode, reqRules.Headers.Whitelist, reqRules.Headers.Blacklist,
			func(yield func(string, string)) {
				for k, vals := range r.Header {
					for _, v := range vals {
						yield(k, v)
					}
				}
			})
	}) {
		return false
	}

	/* ================= COOKIES ================= */
	if !safeEval(func() bool {
		return eval("cookies", reqRules.Cookies.Mode, reqRules.Cookies.Whitelist, reqRules.Cookies.Blacklist,
			func(yield func(string, string)) {
				for _, c := range r.Cookies() {
					yield(c.Name, c.Value)
				}
			})
	}) {
		return false
	}

	/* ================= BODY ================= */
	if bodyData != nil {
		if !safeEval(func() bool {
			return eval("body", reqRules.Body.Mode, reqRules.Body.Whitelist, reqRules.Body.Blacklist,
				func(yield func(string, string)) {
					for k, v := range bodyData {
						switch val := v.(type) {
						case []string:
							for _, s := range val {
								yield(k, s)
							}
						default:
							yield(k, fmt.Sprintf("%v", val))
						}
					}
				})
		}) {
			return false
		}
	}

	return true
}
