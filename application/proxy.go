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

var saveLocalIp = true
var redisConnected = false
var rdb *redis.Client
var endpoints []Endpoint
var proxyEnabled = false
var currentServerPort string
var supabaseConnected = false
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
		if strings.HasPrefix(apiPath, "/api/proxy/") || apiPath == "/api/redis/connect" || apiPath == "/api/endpoints" || apiPath == "/api/reload-endpoints" || apiPath == "/api/supabase/connect" {
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
			if path == ep.Path {
				matchingEndpoint = &ep
				break
			}
		}

		if matchingEndpoint != nil {
			result := checkRequestRules(r, matchingEndpoint.Request, bodyBytes)
			if !result {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("Request blocked by defensive proxy"))
				if redisConnected {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()

					// Extract IP from RemoteAddr
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
						// Key does not exist
						count, err := rdb.DBSize(ctx).Result()
						if err != nil {
							fmt.Println("Redis error:", err)
							return
						}

						if saveLimit <= -1 || count < int64(saveLimit) {
							// Add IP
							err := rdb.Set(ctx, ipStr, 0, 0).Err()
							if saveLocalIp {
								if strings.Contains(r.RemoteAddr, "127.0.0.1") ||
									strings.Contains(r.RemoteAddr, "::1") ||
									ip.IsLoopback() {
									saveLocalIp = false
								}
							}
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
					} else {
						// Increment reputation by penalty
						rep, _ := strconv.Atoi(repStr)
						rep -= 1
						err := rdb.Set(ctx, ipStr, rep, 0).Err()
						if err != nil {
							fmt.Println("Error updating IP reputation:", err)
						} else {
							fmt.Println("Updated IP reputation:", ipStr, "to", rep)
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
			log.Println("Supabase connection pool closed")
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

	http.HandleFunc("/api/supabase/connect", func(w http.ResponseWriter, r *http.Request) {
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

		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", 500)
			return
		}

		var body map[string]interface{}

		//parse body
		err = json.Unmarshal(data, &body)

		if err != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}

		type RequestBody struct {
			Password           string `json:"password"`
			ProjectId          string `json:"projectId"`
			SaveLimit          int    `json:"saveLimit"`
			AutoBlockThreshold int    `json:"autoBlockThreshhold"`
		}

		var supabaseFields RequestBody
		err = json.Unmarshal(data, &supabaseFields)
		if err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		passWordEncoded := url.QueryEscape(supabaseFields.Password)
		connectionUrl := fmt.Sprintf(`postgresql://postgres:%s@db.%s.supabase.co:5432/postgres`, passWordEncoded, supabaseFields.ProjectId)

		// create a context with timeout that cancels when finished
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// create connection pool
		connpool, err = pgxpool.New(ctx, connectionUrl)
		if err != nil {
			log.Fatalf("failed to create pool: %v", err)
		}

		// ping supabase url
		err = connpool.Ping(ctx)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to connect to database: %v", err), 500)
			return
		}

		var exists bool

		err = connpool.QueryRow(
			ctx,
			CHECK_PUBLIC_IPS_TABLE_EXISTENCE_SQL,
			"public",
			"ips",
		).Scan(&exists)

		if err != nil {
			log.Fatal(err)
		}

		if exists {
			w.Write([]byte("Successfully connected to Supabase database"))
			saveLimit = supabaseFields.SaveLimit

			return
		} else {
			w.Write([]byte(DB_SETUP_RESPONSE))
		}
		connpool.Close()
		connpool = nil
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
	Whitelist []Rule `json:"whitelist"`
	Blacklist []Rule `json:"blacklist"`
	Mode      string `json:"mode"`
}

type Endpoint struct {
	Path           string `json:"path"`
	ObfuscatedPath string `json:"obfuscatedPath"`
	Method         string `json:"method"`
	Request        struct {
		Headers RulesObj `json:"headers"`
		Cookies RulesObj `json:"cookies"`
		Body    RulesObj `json:"body"`
	} `json:"request"`
	Response struct {
		Headers RulesObj `json:"headers"`
		Cookies RulesObj `json:"cookies"`
		Body    RulesObj `json:"body"`
	} `json:"response"`
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
func checkRequestRules(r *http.Request, reqRules struct {
	Headers RulesObj `json:"headers"`
	Cookies RulesObj `json:"cookies"`
	Body    RulesObj `json:"body"`
}, bodyBytes []byte) bool {

	// --- BLACKLIST ENFORCEMENT (always check first - applies to all modes) ---
	// Check headers blacklist
	for _, rule := range reqRules.Headers.Blacklist {
		for k, v := range r.Header {
			for _, val := range v {
				if checkRuleMatch(rule, k, val) {
					return false
				}
			}
		}
	}

	// Check cookies blacklist
	for _, rule := range reqRules.Cookies.Blacklist {
		for _, c := range r.Cookies() {
			if checkRuleMatch(rule, c.Name, c.Value) {
				return false
			}
		}
	}

	// Parse body
	var bodyData map[string]interface{}
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(contentType, "application/json") {
		if err := json.Unmarshal(bodyBytes, &bodyData); err != nil {
			log.Printf("Error unmarshaling JSON body: %v", err)
		}
	} else {
		stringBody := strings.ReplaceAll(string(bodyBytes), ":", "=")
		if form, err := url.ParseQuery(stringBody); err == nil {
			bodyData = make(map[string]interface{})
			for k, v := range form {
				if len(v) == 1 {
					bodyData[k] = v[0]
				} else {
					bodyData[k] = v
				}
			}
		} else {
			bodyData = map[string]interface{}{"": string(bodyBytes)}
		}
	}

	// Check body blacklist
	if bodyData != nil {
		for _, rule := range reqRules.Body.Blacklist {
			for k, v := range bodyData {
				var vals []string
				if sl, ok := v.([]string); ok {
					vals = sl
				} else {
					vals = []string{fmt.Sprintf("%v", v)}
				}
				for _, val := range vals {
					if checkRuleMatch(rule, k, val) {
						return false
					}
				}
			}
		}
	}

	// --- MODE-SPECIFIC LOGIC (each data type operates independently) ---

	// Headers mode logic
	if reqRules.Headers.Mode == "whitelist" && len(reqRules.Headers.Whitelist) > 0 {
		// Whitelist mode: must match at least one whitelist rule if whitelist exists
		found := false
		for _, rule := range reqRules.Headers.Whitelist {
			for k, v := range r.Header {
				for _, val := range v {
					if checkRuleMatch(rule, k, val) {
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	} else if reqRules.Headers.Mode == "blacklist" {
		// Blacklist mode: every header must be explicitly whitelisted
		for k, v := range r.Header {
			for _, val := range v {
				found := false
				for _, rule := range reqRules.Headers.Whitelist {
					if checkRuleMatch(rule, k, val) {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}
		}
	}

	// Cookies mode logic
	if reqRules.Cookies.Mode == "whitelist" && len(reqRules.Cookies.Whitelist) > 0 {
		// Whitelist mode: must match at least one whitelist rule if whitelist exists
		found := false
		for _, rule := range reqRules.Cookies.Whitelist {
			for _, c := range r.Cookies() {
				if checkRuleMatch(rule, c.Name, c.Value) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	} else if reqRules.Cookies.Mode == "blacklist" {
		// Blacklist mode: every cookie must be explicitly whitelisted
		for _, c := range r.Cookies() {
			found := false
			for _, rule := range reqRules.Cookies.Whitelist {
				if checkRuleMatch(rule, c.Name, c.Value) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}

	// Body mode logic
	if reqRules.Body.Mode == "whitelist" && bodyData != nil && len(reqRules.Body.Whitelist) > 0 {
		// Whitelist mode: must match at least one whitelist rule if whitelist exists
		found := false
		for _, rule := range reqRules.Body.Whitelist {
			for k, v := range bodyData {
				var vals []string
				if sl, ok := v.([]string); ok {
					vals = sl
				} else {
					vals = []string{fmt.Sprintf("%v", v)}
				}
				for _, val := range vals {
					if checkRuleMatch(rule, k, val) {
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	} else if reqRules.Body.Mode == "blacklist" && bodyData != nil {
		// Blacklist mode: every body field must be explicitly whitelisted
		for k, v := range bodyData {
			var vals []string
			if sl, ok := v.([]string); ok {
				vals = sl
			} else {
				vals = []string{fmt.Sprintf("%v", v)}
			}
			for _, val := range vals {
				found := false
				for _, rule := range reqRules.Body.Whitelist {
					if checkRuleMatch(rule, k, val) {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}
		}
	}

	return true
}
