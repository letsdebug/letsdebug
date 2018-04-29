package web

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"net"

	"encoding/json"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/jmoiron/sqlx"
	"golang.org/x/net/idna"
)

var (
	regexDNSName = regexp.MustCompile(`^[\w\-.]+$`) // Very basic test, further validation later
)

type server struct {
	templates map[string]*template.Template
	db        *sqlx.DB
}

// Serve begins serving the web application over LETSDEBUG_WEB_LISTEN_ADDR,
// default 127.0.0.1:9150.
func Serve() error {
	s := &server{}
	r := chi.NewMux()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)

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

	log.Printf("Starting web server ...")
	return http.ListenAndServe(envOrDefault("LISTEN_ADDR", "127.0.0.1:9150"), r)
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
		doError("Internal error occured finding tests", http.StatusInternalServerError)
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
		w.Header().Set("Refresh", fmt.Sprintf("5;url=%s", r.URL.String()))
	}

	if isBrowser {
		s.render(w, http.StatusOK, "results.tpl", map[string]interface{}{
			"Test": test,
		})
		return
	}

	if err := json.NewEncoder(w).Encode(test); err != nil {
		log.Printf("Error encoding test result response: %v", err)
	}
}

func (s *server) httpSubmitTest(w http.ResponseWriter, r *http.Request) {
	var domain, method string

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
			Domain string
			Method string
		}
		if err := json.NewDecoder(r.Body).Decode(&testRequest); err != nil {
			log.Printf("Error decoding request: %v", err)
			doError("Request body was not valid JSON", http.StatusBadRequest)
			return
		}
		domain = testRequest.Domain
		method = testRequest.Method
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

	id, err := s.createNewTest(domain, method, ip)
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
	s.render(w, http.StatusOK, "home.tpl", nil)
}

func (s *server) render(w http.ResponseWriter, statusCode int, templateName string, data interface{}) {
	tpl, ok := s.templates[templateName]
	if !ok {
		http.Error(w, "An internal rendering error occured.", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(statusCode)
	if err := tpl.Execute(w, data); err != nil {
		log.Printf("Error executing %s template with error: %v", templateName, err)
		http.Error(w, "An internal rendering error occured.", http.StatusInternalServerError)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv("LETSDEBUG_WEB_" + key); v != "" {
		return v
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
	return domain != "" || len(domain) <= 230 && regexDNSName.MatchString(domain)
}
