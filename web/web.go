// Package web implements the web frontend of the Let's Debug service
package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

	// Export pprof on :9151 to investigate some memory leaks
	_ "net/http/pprof"
)

var (
	//go:embed templates
	resTemplates embed.FS

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

	// Create the channel early to avoid a race
	// between listenForTests and runWorkers
	s.workCh = make(chan workRequest)

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

	templateFiles, _ := resTemplates.ReadDir("templates/layouts")
	includeFiles, _ := resTemplates.ReadDir("templates/includes")

	for _, tplFile := range templateFiles {
		name := tplFile.Name()
		tpl := template.New(name)

		for _, incFile := range includeFiles {
			incData, _ := resTemplates.ReadFile("templates/includes/" + incFile.Name())
			if _, err := tpl.Parse(string(incData)); err != nil {
				return err
			}
		}

		tplData, _ := resTemplates.ReadFile("templates/layouts/" + name)
		if _, err := tpl.Parse(string(tplData)); err != nil {
			return err
		}

		s.templates[name] = tpl
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
	// Favicon
	r.Get("/favicon.ico", s.httpServeFavicon)
	// Robots.txt
	r.Get("/robots.txt", s.httpServeRobots)

	s.rateLimitByDomain = map[string]*ratelimit.Bucket{}
	s.rateLimitByIP = map[string]*ratelimit.Bucket{}

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		if err := http.ListenAndServe(envOrDefault("PPROF_LISTEN_ADDR", "127.0.0.1:9151"), nil); err != nil {
			log.Printf("pprof bind failed: %v", err)
		}
	}()

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
	_ = enc.Encode(map[string]interface{}{
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

	w.Header().Set("content-type", "application/json")
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

	w.Header().Set("content-type", "application/json")
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
	w.Header().Set("content-type", "application/json")
	if err := json.NewEncoder(w).Encode(testResponse); err != nil {
		log.Printf("Error encoding submit test response: %v", err)
	}
}

func (s *server) httpHome(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	method := r.URL.Query().Get("method")

	s.render(w, http.StatusOK, "home.tpl", map[string]interface{}{
		"WorkerCount": template.HTML(fmt.Sprintf("<!-- Busy Workers: %d -->", atomic.LoadInt32(&s.busyWorkers))),
		"Domain":      domain,
		"Method":      method,
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
	domain = strings.TrimPrefix(domain, "*.")
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

var favicon = []byte("GIF89a@\x00@\x00\xf3\x0e\x00+;h+;i,;h+<h+<i+=i,<h-<h,<i-<i,=i-=i,<j,=j\x00\x00\x00\x00\x00\x00!\xf9\x04\x01\x00\x00\x0e\x00,\x00\x00\x00\x00@\x00@\x00\x00\x04\xfe\xd0\xc9I\xab\xbd8\xeb\u037b\xff`(!di\x8a\xa8\u05d8l\x9b\xbe\x96\t`,\f\x13eg&\xb6\x98\x83\xa7\x9e\xe7g9\xach\xa4\x81\x90\xa3 Y\x18-\x04#\xe6\\j\x88\xa3(6\x8b\xb0\"\xbb\x94\xa8\xc1\x10\x9c@\xc1\xde\n\x89715\xa8\xd56\x82\x9d\xe6\xaaI\x86\xef{\x12X\xd7%ga[whvuQ\tZ-M\x8a\x85=\x8d\x90\x915=g\x92\x96\x8aB\x97\x9aZS6\x83\x19\x9f\xa0\b{0\xa1\x17d\x8e\x1b$\xa4/\xa6\x16\xa8@\xa3\x8fq\x1c\xb0\x1f\xab\xb3\xa9\x19\xb6C\xb20\x95\x04:e\x1b\x8ct\xb7\x9b\u0217yW\xc9\u0356\xa2%\x06\x89$P\t\xd6\xd7\xd8\xd7&c\xd9\u0749\x95\xd6\x06\x8c\xb4\x82\x8e\xae\x84\xcb\u00ac\x0e\x9f\u0444\x1f\xbc\ua129\x83\xe7\x14\xf1\x1c\xb8\xef\xfb\xe5\xf0\u4abe\xfa\xf1\x93\xa3\v\x03>\x80\xeb\xd8\xfd\xab\xf7oWCQ\t\x19\xd2{x\x8a\xe2\x05}\x023\x12\xf4W\x10ID\x8b\xcf\x037\x1cd\x96\xd0\a\xc8{'\x05\x95\fao\xc2H\x88\xb98\xc6Z\x19\xab\u3ad4\x1bYj\x91y\xacE'hQx\xf6\xda\xf9\x05\xc1\xb8\x96\x12^\x16%q\xf4\x82\x80-H\x1d(\xbd\x88 \x1d \x89\xe6pJ\xd5Z\xa9B\xd7;\xc6\fu\x98\x1aRl\xce;?Ejm\xb7\xd0(U\x9b(\xe1\xf2\xc1s\x81\x11\x15\x05\x15S\x92=[\xc1\xee\x1d\xbco\u01e6\\\xe1\xb6n[\xc0p\xe4\xeeU\xd8\xd1/\x05\x028\xa0\xa5\u035b\xcf\x14\x02\xc8&\x99j ;\ue3c3iR\x1c\xda\x1c\x96f\xc1\xa4\x9b\x05QE\xd5\x19\xb4\xc2\xc1F^$\x1d\xc5\xc3@Z$\x05\x05\x968\u06d4)\x94&\f\x8c\x10\xb7J\x99\x80\x01d\xc8c:\x04\xf2\xa4\x15\xc5\xea/\x9e\x936\x8fN\xbd:\x8c\b\x00;")

func (s *server) httpServeFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/gif")
	_, _ = w.Write(favicon)
}

const robotsTxt = `User-Agent: *
Allow: /
`

func (s *server) httpServeRobots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, robotsTxt)
}
