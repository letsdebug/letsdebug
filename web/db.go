package web

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/lib/pq"

	"github.com/golang-migrate/migrate/v4/database/postgres"

	"github.com/letsdebug/letsdebug"
)

type problems []letsdebug.Problem

func (probs problems) Len() int {
	return len(probs)
}

func (probs problems) Swap(i, j int) {
	probs[i], probs[j] = probs[j], probs[i]
}

// thedailywtf.com
func (probs problems) Less(i, j int) bool {
	p1 := probs[i]
	p2 := probs[j]

	naturalOrder := p1.Name < p2.Name

	if p1.Severity == p2.Severity {
		return naturalOrder
	}
	if p1.Severity == letsdebug.SeverityDebug {
		return false
	}
	if p1.Severity == letsdebug.SeverityFatal {
		return true
	}
	if p1.Severity == letsdebug.SeverityError &&
		(p2.Severity != letsdebug.SeverityFatal) {
		return true
	}
	if p1.Severity == letsdebug.SeverityWarning &&
		(p2.Severity != letsdebug.SeverityError && p2.Severity != letsdebug.SeverityFatal) {
		return true
	}

	return naturalOrder
}

type resultView struct {
	Error    string   `json:"error,omitempty"`
	Problems problems `json:"problems,omitempty"`
}

func (rv *resultView) Scan(src interface{}) error {
	buf, ok := src.([]byte)
	if !ok {
		return errors.New("bad type")
	}
	if err := json.Unmarshal(buf, &rv); err != nil {
		return err
	}
	sort.Sort(rv.Problems)
	return nil
}

type testView struct {
	ID            uint64      `db:"id,omitempty" json:"id,omitempty"`
	Domain        string      `db:"domain,omitempty" json:"domain,omitempty"`
	Method        string      `db:"method,omitempty" json:"method,omitempty"`
	Options       options     `db:"options,omitempty" json:"-"`
	Status        string      `db:"status,omitempty" json:"status,omitempty"`
	CreatedAt     time.Time   `db:"created_at,omitempty" json:"created_at,omitempty"`
	StartedAt     *time.Time  `db:"started_at,omitempty" json:"started_at,omitempty"`
	CompletedAt   *time.Time  `db:"completed_at,omitempty" json:"completed_at,omitempty"`
	SubmittedByIP string      `db:"submitted_by_ip,omitempty" json:"-"`
	Result        *resultView `db:"result,omitempty" json:"result,omitempty"`
}

func (t testView) QueueDuration() string {
	if t.StartedAt == nil {
		return ""
	}
	return t.StartedAt.Sub(t.CreatedAt).Truncate(time.Millisecond).String()
}

func (t testView) TestDuration() string {
	if t.StartedAt == nil || t.CompletedAt == nil {
		return ""
	}
	return t.CompletedAt.Sub(*t.StartedAt).Truncate(time.Second).String()
}

func (t testView) SubmitTime() string {
	timeAgo := time.Since(t.CreatedAt)
	if timeAgo.Hours() <= 72 {
		return timeAgo.Truncate(time.Second).String() + " ago"
	}
	return t.CreatedAt.Format("Jan 2 15:04:05 2006")
}

func (t testView) CreatedTimestamp() string {
	return t.CreatedAt.Format(time.RFC3339Nano)
}

func (t testView) IsRunningLong() bool {
	if t.StartedAt == nil {
		return false
	}
	return time.Since(*t.StartedAt) > time.Minute
}

func (t testView) Severity() string {
	if t.Status != "Complete" {
		return t.Status
	}

	if t.Result == nil {
		return "Unknown"
	}

	if t.Result.Error != "" {
		return "Failed"
	}

	if len(t.Result.Problems) == 0 {
		return "OK"
	}

	// Since problems are sorted, the first is the worst
	s := string(t.Result.Problems[0].Severity)
	if s == "Debug" {
		return "OK"
	}

	return s
}

func (t testView) Summary() string {
	if t.Result == nil {
		return "-"
	}
	if t.Result.Error != "" {
		return t.Result.Error
	}

	var fatalCount, errorCount, warningCount int
	for _, p := range t.Result.Problems {
		switch p.Severity {
		case "Fatal":
			fatalCount++
		case "Error":
			errorCount++
		case "Warning":
			warningCount++
		}
	}
	return fmt.Sprintf("%d fatal errors, %d errors and %d warnings", fatalCount, errorCount, warningCount)
}

func (t testView) LongSummary() string {
	if t.Result == nil {
		return "-"
	}
	if t.Result.Error != "" {
		return t.Result.Error
	}

	names := map[string]struct{}{}
	totalIssues := 0

	problemList := func() string {
		if len(names) == 0 {
			return ""
		}
		uniqueNames := []string{}
		for n := range names {
			uniqueNames = append(uniqueNames, n)
		}
		return fmt.Sprintf(" (%s)", strings.Join(uniqueNames, ", "))
	}

	for _, p := range t.Result.Problems {
		if p.Severity == letsdebug.SeverityDebug {
			continue
		}
		names[p.Name] = struct{}{}
		totalIssues++
	}

	return fmt.Sprintf("%d unique issue(s) detected%s", totalIssues, problemList())
}

type options struct {
	HTTPRequestPath    string `json:"http_request_path"`
	HTTPExpectResponse string `json:"http_expect_response"`
}

func (o options) Value() (driver.Value, error) {
	return json.Marshal(o)
}

func (o *options) Scan(src interface{}) error {
	buf, ok := src.([]byte)
	if !ok {
		return nil
	}

	var out options
	if err := json.Unmarshal(buf, &out); err != nil {
		return err
	}

	*o = out
	return nil
}

func (s *server) migrateUp() error {
	embedDriver, err := iofs.New(embedMigrations, "db_migrations")
	if err != nil {
		log.Fatal(err)
	}

	pgDriver, err := postgres.WithInstance(s.db.DB, &postgres.Config{})
	if err != nil {
		return err
	}

	m, err := migrate.NewWithInstance("iofs", embedDriver, s.db.DriverName(), pgDriver)
	if err != nil {
		return err
	}

	if e := m.Up(); e != nil && e != migrate.ErrNoChange {
		return e
	}
	return nil
}

func (s *server) createNewTest(domain, method, ip string, opts options) (uint64, error) {
	var newID uint64
	if err := s.db.QueryRow(`INSERT INTO tests (domain, method, status, submitted_by_ip, options) VALUES ($1, $2, 'Queued', $3, $4) RETURNING id;`,
		domain, method, ip, opts).Scan(&newID); err != nil {
		return 0, err
	}
	return newID, nil
}

func (s *server) findTest(domain string, id int) (*testView, error) {
	var t testView
	if err := s.db.Get(&t, "SELECT * FROM tests WHERE id = $1 and domain = $2;", id, domain); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &t, nil
}

func (s *server) listenForTests(dsn string) error {
	problemFunc := func(e pq.ListenerEventType, err error) {
		if err != nil {
			log.Fatal(err)
		}
	}

	listener := pq.NewListener(dsn, 10*time.Second, time.Minute, problemFunc)
	if err := listener.Listen("tests_events"); err != nil {
		return err
	}

	var notification workRequest

	for {
		select {
		case n := <-listener.Notify:
			if n == nil {
				// can be nil notifications sent during reconnections
				continue
			}

			if err := json.Unmarshal([]byte(n.Extra), &notification); err != nil {
				log.Printf("Error unmarshalling notification: %v (%s)", err, n.Extra)
				continue
			}

			s.workCh <- notification
		case <-time.After(time.Minute):
			go listener.Ping() //nolint:errcheck
		}
	}
}

func (s *server) vacuumTests() {
	for {
		if _, err := s.db.Exec(`UPDATE tests set status = 'Cancelled' WHERE status NOT IN ('Cancelled','Complete') AND created_at < now() - interval '30 minutes';`); err != nil {
			log.Printf("Failed to vacuum: %v", err)
		}
		time.Sleep(10 * time.Second)
	}
}

func (s *server) findTests(domain string) ([]testView, error) {
	var t []testView
	if err := s.db.Select(&t, `SELECT * FROM tests WHERE domain = $1 ORDER BY created_at DESC LIMIT 25;`, domain); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return t, nil
}
