package web

import (
	"database/sql"
	"log"
	"sort"
	"time"

	"github.com/lib/pq"

	"encoding/json"

	"errors"

	"github.com/golang-migrate/migrate"
	"github.com/golang-migrate/migrate/database/postgres"
	"github.com/golang-migrate/migrate/source/go-bindata"
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

	if p1.Severity == p2.Severity {
		return true
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

	return false
}

type resultView struct {
	Error    string   `json:"error"`
	Problems problems `json:"problems"`
}

func (rv *resultView) Scan(src interface{}) error {
	buf, ok := src.([]byte)
	if !ok {
		return errors.New("Bad type")
	}
	if err := json.Unmarshal(buf, &rv); err != nil {
		return err
	}
	sort.Sort(rv.Problems)
	return nil
}

type testView struct {
	ID            uint64      `db:"id,omitempty"`
	Domain        string      `db:"domain,omitempty"`
	Method        string      `db:"method,omitempty"`
	Status        string      `db:"status,omitempty"`
	CreatedAt     time.Time   `db:"created_at,omitempty"`
	StartedAt     *time.Time  `db:"started_at,omitempty"`
	CompletedAt   *time.Time  `db:"completed_at,omitempty"`
	SubmittedByIP string      `db:"submitted_by_ip,omitempty" json:"-"`
	Result        *resultView `db:"result,omitempty"`
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
	return time.Now().Sub(t.CreatedAt).Truncate(time.Second).String()
}

func (s *server) migrateUp() error {
	names, _ := AssetDir("db_migrations")
	res := bindata.Resource(names, func(name string) ([]byte, error) {
		return Asset("db_migrations/" + name)
	})

	src, err := bindata.WithInstance(res)
	if err != nil {
		return err
	}

	driver, err := postgres.WithInstance(s.db.DB, &postgres.Config{})
	if err != nil {
		return err
	}

	m, err := migrate.NewWithInstance("go-bindata", src, s.db.DriverName(), driver)
	if err != nil {
		return err
	}

	if e := m.Up(); e != nil && e != migrate.ErrNoChange {
		return e
	}
	return nil
}

func (s *server) createNewTest(domain, method, ip string) (uint64, error) {
	var newID uint64
	if err := s.db.QueryRow(`INSERT INTO tests (domain, method, status, submitted_by_ip) VALUES ($1, $2, 'Queued', $3) RETURNING id;`,
		domain, method, ip).Scan(&newID); err != nil {
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

	notification := struct {
		ID     int    `json:"id"`
		Domain string `json:"domain"`
		Method string `json:"method"`
	}{}

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

			log.Printf("Starting test: %+v", notification)

			// doesn't matter if this query fails
			s.db.Exec(`UPDATE tests SET started_at = CURRENT_TIMESTAMP, status = 'Processing' WHERE id = $1;`, notification.ID)

			result := runChecks(notification.Domain, notification.Method)

			strResult, _ := json.Marshal(result)
			if _, err := s.db.Exec(`UPDATE tests SET completed_at = CURRENT_TIMESTAMP, status = 'Complete', result = $2 WHERE id = $1;`,
				notification.ID, string(strResult)); err != nil {
				log.Printf("Error storing test %d result: %v", notification.ID, err)
				continue
			}

			log.Printf("Test %d complete", notification.ID)

		case <-time.After(5 * time.Minute):
			go listener.Ping()
		}
	}
}

func runChecks(domain, method string) resultView {
	resultCh := make(chan resultView)

	go func() {
		probs, err := letsdebug.Check(domain, letsdebug.ValidationMethod(method))
		if err != nil {
			resultCh <- resultView{err.Error(), probs}
			return
		}
		resultCh <- resultView{"", probs}
	}()

	select {
	case r := <-resultCh:
		return r

	case <-time.After(60 * time.Second):
		return resultView{"timeout", nil}
	}
}

func (s *server) vacuumTests() {
	for {
		if _, err := s.db.Exec(`UPDATE tests set status = 'Cancelled' WHERE status != 'Complete' AND created_at < now() - interval '5 minutes';`); err != nil {
			log.Printf("Failed to vacuum: %v", err)
		}
		time.Sleep(10 * time.Second)
	}
}
