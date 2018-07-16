package web

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/jmoiron/sqlx"
	"github.com/juju/ratelimit"
	"github.com/letsdebug/letsdebug"
	"golang.org/x/net/idna"
)

var (
	regexDNSName = regexp.MustCompile(`^[\w\-.]+$`) // Very basic test, further validation later
)

type server struct {
	templates   map[string]*template.Template
	db          *sqlx.DB
	workCh      chan workRequest
	busyWorkers int32

	rateLimitByIP     map[string]*ratelimit.Bucket
	rateLimitByDomain map[string]*ratelimit.Bucket

	rateLimitCertwatch *ratelimit.Bucket
}

// Serve begins serving the web application over LETSDEBUG_WEB_LISTEN_ADDR,
// default 127.0.0.1:9150.
func Serve() error {
	s := &server{}
	r := chi.NewMux()

	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)
	r.Use(cors)

	// Bring up the database
	dsn := envOrDefault("DB_DSN", "")
	db, err := sqlx.Open(envOrDefault("DB_DRIVER", "postgres"), dsn)
	if err != nil {
		return err
	}
	s.db = db
	// and update the schema
	log.Printf("Running migrations ...")
	if err := s.migrateUp(); err != nil {
		return err
	}

	// Listen for test inserts
	go func() {
		if err := s.listenForTests(dsn); err != nil {
			log.Fatal(err)
		}
	}()

	go s.runWorkers(envOrDefaultInt("CONCURRENCY", 10))
	go s.vacuumTests()

	// Load templates
	log.Printf("Loading templates ...")
	s.templates = map[string]*template.Template{}
	names, _ := AssetDir("templates/layouts")
	includes, _ := AssetDir("templates/includes")

	for _, tplName := range names {
		tpl := template.New(tplName)
		for _, incName := range includes {
			if _, err := tpl.Parse(string(MustAsset("templates/includes/" + incName))); err != nil {
				return err
			}
		}
		if _, err := tpl.Parse(string(MustAsset("templates/layouts/" + tplName))); err != nil {
			return err
		}
		s.templates[tplName] = tpl
	}

	// Routes
	// - Home Page
	r.Get("/", s.httpHome)
	// - New Test (both browser and API)
	r.Post("/", s.httpSubmitTest)
	// - View test results (or test loading page)
	r.Get("/{domain}/{testID}", s.httpViewTestResult)
	// - View all tests for domain
	r.Get("/{domain}", s.httpViewDomain)
	// Certwatch query gateway
	r.Get("/certwatch-query", s.httpCertwatchQuery)

	s.rateLimitByDomain = map[string]*ratelimit.Bucket{}
	s.rateLimitByIP = map[string]*ratelimit.Bucket{}

	log.Printf("Starting web server ...")
	return http.ListenAndServe(envOrDefault("LISTEN_ADDR", "127.0.0.1:9150"), r)
}

func (s *server) httpCertwatchQuery(w http.ResponseWriter, r *http.Request) {
	if s.rateLimitCertwatch == nil {
		s.rateLimitCertwatch = ratelimit.NewBucket(
			time.Duration(envOrDefaultInt("RATELIMIT_CERTWATCH_GATEWAY", 1))*time.Second, 5)
	}

	if _, avail := s.rateLimitCertwatch.TakeMaxDuration(1, 100*time.Millisecond); !avail {
		http.Error(w, "Too busy, try again later", http.StatusTooManyRequests)
		return
	}

	q := r.URL.Query().Get("q")
	if q == "" || len(q) > 8192 {
		http.Error(w, "Query missing or not acceptable", http.StatusBadRequest)
		return
	}

	db, err := sqlx.Open("postgres", "user=guest dbname=certwatch host=crt.sh sslmode=disable connect_timeout=5")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to Certwatch: %v", err), http.StatusGatewayTimeout)
		return
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var out []map[string]interface{}
	rows, err := db.QueryxContext(ctx, q)
	if err != nil {
		http.Error(w, fmt.Sprintf("Query failed: %v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		r := map[string]interface{}{}
		if err := rows.MapScan(r); err != nil {
			log.Printf("Failed to unmarshal certwatch row: %v", err)
		} else {
			out = append(out, r)
		}
	}

	if err := rows.Err(); err != nil {
		http.Error(w, fmt.Sprintf("Reading rows failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(map[string]interface{}{
		"query":   q,
		"results": out,
	})
}

func (s *server) httpViewDomain(w http.ResponseWriter, r *http.Request) {
	domain := normalizeDomain(chi.URLParam(r, "domain"))

	isBrowser := r.Header.Get("accept") != "application/json"

	doError := func(msg string, code int) {
		if !isBrowser {
			http.Error(w, msg, code)
			return
		}
		s.render(w, code, "list.tpl", map[string]interface{}{
			"Error": msg,
		})
	}

	if !isValidDomain(domain) {
		doError("Invalid domain provided", http.StatusBadRequest)
		return
	}

	tests, err := s.findTests(domain)
	if err != nil {
		log.Printf("couldn't find tests for %s: %v", domain, err)
		doError("Internal error occurred finding tests", http.StatusInternalServerError)
		return
	}

	if isBrowser {
		s.render(w, http.StatusOK, "list.tpl", map[string]interface{}{
			"Domain": domain,
			"Tests":  tests,
		})
		return
	}

	if err := json.NewEncoder(w).Encode(tests); err != nil {
		log.Printf("failed to marshal test list: %v", err)
	}
}

func (s *server) httpViewTestResult(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	testID, err := strconv.Atoi(chi.URLParam(r, "testID"))

	isBrowser := r.Header.Get("accept") != "application/json"

	doError := func(msg string, code int) {
		if !isBrowser {
			http.Error(w, msg, code)
			return
		}
		s.render(w, code, "results.tpl", map[string]interface{}{
			"Error": msg,
		})
	}

	if domain == "" || err != nil {
		doError("Invalid request parameters.", http.StatusBadRequest)
		return
	}

	test, err := s.findTest(domain, testID)
	if err != nil {
		log.Printf("fetching %s/%d: %v", domain, testID, err)
		doError("An internal error occurred fetching that test.", http.StatusInternalServerError)
		return
	}

	if test == nil {
		doError("No such result exists.", http.StatusNotFound)
		return
	}

	if test.Status != "Complete" && test.Status != "Cancelled" {
		w.Header().Set("Refresh", fmt.Sprintf("3;url=%s", r.URL.String()))
	}

	isDebug := r.URL.Query().Get("debug") == "y"
	// Filter out debug
	if test.Status == "Complete" && test.Result != nil && len(test.Result.Problems) > 0 && !isDebug {
		deleted := 0
		for i := range test.Result.Problems {
			j := i - deleted
			if test.Result.Problems[j].Severity == letsdebug.SeverityDebug {
				test.Result.Problems = test.Result.Problems[:j+copy(test.Result.Problems[j:], test.Result.Problems[j+1:])]
				deleted++
			}
		}
	}

	if isBrowser {
		s.render(w, http.StatusOK, "results.tpl", map[string]interface{}{
			"Test":  test,
			"Debug": isDebug,
		})
		return
	}

	if err := json.NewEncoder(w).Encode(test); err != nil {
		log.Printf("Error encoding test result response: %v", err)
	}
}

func (s *server) httpSubmitTest(w http.ResponseWriter, r *http.Request) {
	var domain, method string
	var opts options

	isBrowser := true

	doError := func(msg string, code int) {
		if !isBrowser {
			http.Error(w, msg, code)
			return
		}
		s.render(w, code, "home.tpl", map[string]interface{}{
			"Error": msg,
		})
	}

	switch r.Header.Get("content-type") {
	case "application/x-www-form-urlencoded":
		domain = r.PostFormValue("domain")
		method = r.PostFormValue("method")
	case "application/json":
		isBrowser = false
		var testRequest struct {
			Domain  string  `json:"domain"`
			Method  string  `json:"method"`
			Options options `json:"options"`
		}
		if err := json.NewDecoder(r.Body).Decode(&testRequest); err != nil {
			log.Printf("Error decoding request: %v", err)
			doError("Request body was not valid JSON", http.StatusBadRequest)
			return
		}
		if len(testRequest.Options.HTTPRequestPath) > 255 || len(testRequest.Options.HTTPExpectResponse) > 255 {
			doError("Test options were not valid", http.StatusBadRequest)
			return
		}
		domain = testRequest.Domain
		method = testRequest.Method
		opts = testRequest.Options
	default:
		doError(http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}

	// Test case: entering https://短.co/home should work, at least for browser visitors

	// Try parse as URL in case somebody tried to paste a URL
	if isBrowser && (strings.HasPrefix(domain, "http:") || strings.HasPrefix(domain, "https:")) {
		asURL, err := url.Parse(domain)
		if err == nil {
			domain = asURL.Hostname()
		}
	}

	domain = normalizeDomain(domain)
	if !isValidDomain(domain) || method == "" || len(method) > 200 {
		doError("Please provide a valid domain name and validation method.", http.StatusBadRequest)
		return
	}

	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}

	// Enforce rate limits here.
	// - Per IP: 1 test per 10s, capacity 3
	ipLimit, ok := s.rateLimitByIP[ip]
	if !ok {
		ipLimit = ratelimit.NewBucket(
			time.Duration(envOrDefaultInt("RATELIMIT_IP_REGEN_SECS", 3))*time.Second,
			int64(envOrDefaultInt("RATELIMIT_IP_CAPACITY", 3)))
		s.rateLimitByIP[ip] = ipLimit
	}
	if _, takeOk := ipLimit.TakeMaxDuration(1, time.Second); !takeOk {
		doError(fmt.Sprintf("Too many tests from %s recently, try again soon.", ip), http.StatusTooManyRequests)
		return
	}
	// - Per domain: 3 tests per minute, capacity 3.
	domainLimit, ok := s.rateLimitByDomain[domain]
	if !ok {
		domainLimit = ratelimit.NewBucket(
			time.Duration(envOrDefaultInt("RATELIMIT_DOMAIN_REGEN_SECS", 20))*time.Second,
			int64(envOrDefaultInt("RATELIMIT_DOMAIN_CAPACITY", 3)))
		s.rateLimitByDomain[domain] = domainLimit
	}
	if _, takeOk := domainLimit.TakeMaxDuration(1, time.Second); !takeOk {
		doError(fmt.Sprintf("Too many tests for %s recently, try again soon.", domain), http.StatusTooManyRequests)
		return
	}

	log.Printf("[%s] Submitted test for %s/%s", ip, domain, method)

	id, err := s.createNewTest(domain, method, ip, opts)
	if err != nil {
		log.Printf("Failed to create test for %s/%s: %v\n", domain, method, err)
		doError(http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if isBrowser {
		http.Redirect(w, r, fmt.Sprintf("/%s/%d", domain, id), http.StatusFound)
		return
	}

	testResponse := struct {
		Domain string
		ID     uint64
	}{domain, id}
	if err := json.NewEncoder(w).Encode(testResponse); err != nil {
		log.Printf("Error encoding submit test response: %v", err)
	}
}

func (s *server) httpHome(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "home.tpl", map[string]interface{}{
		"WorkerCount": template.HTML(fmt.Sprintf("<!-- Busy Workers: %d -->", atomic.LoadInt32(&s.busyWorkers))),
	})
}

func (s *server) render(w http.ResponseWriter, statusCode int, templateName string, data interface{}) {
	tpl, ok := s.templates[templateName]
	if !ok {
		http.Error(w, "An internal rendering error occurred.", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(statusCode)
	if err := tpl.Execute(w, data); err != nil {
		log.Printf("Error executing %s template with error: %v", templateName, err)
		http.Error(w, "An internal rendering error occurred.", http.StatusInternalServerError)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv("LETSDEBUG_WEB_" + key); v != "" {
		return v
	}
	return fallback
}

func envOrDefaultInt(key string, fallback int) int {
	if i, err := strconv.Atoi(envOrDefault(key, "")); err == nil {
		return i
	}
	return fallback
}

func normalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	asASCII, err := idna.ToASCII(domain)
	if err == nil {
		domain = asASCII
	}
	return domain
}

func isValidDomain(domain string) bool {
	if strings.HasPrefix(domain, "*.") {
		domain = domain[2:]
	}
	return domain != "" && len(domain) <= 230 && regexDNSName.MatchString(domain)
}

func cors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := "*"
		if o := r.Header.Get("origin"); o != "" {
			origin = o
		}
		w.Header().Set("access-control-allow-origin", origin)
		w.Header().Set("access-control-allowed-methods", "GET,HEAD,POST")
		w.Header().Set("access-control-max-age", "86400")
		w.Header().Set("access-control-allow-headers", r.Header.Get("access-control-request-headers"))

		h.ServeHTTP(w, r)
	})
}
