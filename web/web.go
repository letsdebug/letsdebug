package web

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
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
	tpl *template.Template
	db  *sqlx.DB
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
	db, err := sqlx.Open(envOrDefault("DB_DRIVER", "postgres"), envOrDefault("DB_DSN", ""))
	if err != nil {
		return err
	}
	s.db = db
	// and update the schema
	log.Printf("Running migrations ...")
	if err := s.migrateUp(); err != nil {
		return err
	}

	// Load templates
	log.Printf("Loading templates ...")
	s.tpl = template.New("")
	names, _ := AssetDir("templates")
	for _, tpl := range names {
		if _, err := s.tpl.New(tpl).Parse(string(MustAsset("templates/" + tpl))); err != nil {
			return err
		}
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
}

func (s *server) httpViewTestResult(w http.ResponseWriter, r *http.Request) {
}

func (s *server) httpSubmitTest(w http.ResponseWriter, r *http.Request) {
	var domain, method string

	isBrowser := true

	doError := func(msg string, code int) {
		if !isBrowser {
			http.Error(w, msg, code)
			return
		}
		if err := s.tpl.ExecuteTemplate(w, "home.tpl", map[string]interface{}{
			"Error": msg,
		}); err != nil {
			log.Printf("Error executing home template with error: %v", err)
		}
	}

	switch r.Header.Get("content-type") {
	case "application/x-www-form-urlencoded":
		domain = r.PostFormValue("domain")
		method = r.PostFormValue("method")
	case "application/json":
		isBrowser = false
		var testRequest struct {
			Domain string `json:"domain"`
			Method string `json:"method"`
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

	// If the domain is a unicode-form IDN, convert it to ascii
	asASCII, err := idna.ToASCII(domain)
	if err == nil {
		domain = asASCII
	}

	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || method == "" || len(domain) > 230 || len(method) > 200 || !regexDNSName.MatchString(domain) {
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
		Domain string `json:"domain"`
		ID     uint64 `json:"id"`
	}{domain, id}
	if err := json.NewEncoder(w).Encode(&testResponse); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func (s *server) httpHome(w http.ResponseWriter, r *http.Request) {
	if err := s.tpl.ExecuteTemplate(w, "home.tpl", nil); err != nil {
		log.Printf("Error executing home template: %v", err)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv("LETSDEBUG_WEB_" + key); v != "" {
		return v
	}
	return fallback
}
