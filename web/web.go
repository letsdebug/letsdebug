package web

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/jmoiron/sqlx"
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
	fmt.Println("Running migrations ...")
	if err := s.migrateUp(); err != nil {
		return err
	}

	// Load templates
	fmt.Println("Loading templates ...")
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
	r.Post("/test", s.httpSubmitTest)
	// - View test results (or test loading page)
	// r.Get("/{domain}/{testID}", s.httpHome)
	// - View all tests for domain
	// r.Get("/{domain}", s.httpHome)

	fmt.Println("Starting web server ...")
	return http.ListenAndServe(envOrDefault("LISTEN_ADDR", "127.0.0.1:9150"), r)
}

func (s *server) httpSubmitTest(w http.ResponseWriter, r *http.Request) {
	switch r.Header.Get("content-type") {
	case "application/x-www-form-urlencoded":
		http.Redirect(w, r, fmt.Sprintf("/%s/%d", r.PostFormValue("domain"), time.Now().UnixNano()), 302)
	case "application/json":
		http.Error(w, "Not yet implemented", http.StatusNotImplemented)
	default:
		http.Error(w, "Expected content-types not found", http.StatusBadRequest)
	}
}

func (s *server) httpHome(w http.ResponseWriter, r *http.Request) {
	if err := s.tpl.ExecuteTemplate(w, "home.tpl", nil); err != nil {
		fmt.Println(err)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv("LETSDEBUG_WEB_" + key); v != "" {
		return v
	}
	return fallback
}

func envIntOrDefault(key string, fallback uint64) uint64 {
	if v, err := strconv.ParseUint(envOrDefault(key, ""), 10, 64); err != nil {
		return v
	}
	return fallback
}
