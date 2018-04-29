package web

import (
	"database/sql"
	"log"
	"time"

	"github.com/lib/pq"

	"encoding/json"

	"os"

	"errors"

	"github.com/golang-migrate/migrate"
	"github.com/golang-migrate/migrate/database/postgres"
	"github.com/golang-migrate/migrate/source/go-bindata"
	"github.com/letsdebug/letsdebug"
)

type test struct {
	ID            uint64     `db:"id,omitempty"`
	Domain        string     `db:"domain,omitempty"`
	Method        string     `db:"method,omitempty"`
	Status        string     `db:"status,omitempty"`
	CreatedAt     time.Time  `db:"created_at,omitempty"`
	StartedAt     *time.Time `db:"started_at,omitempty"`
	CompletedAt   *time.Time `db:"completed_at,omitempty"`
	SubmittedByIP string     `db:"submitted_by_ip,omitempty" json:"-"`
	Result        *string    `db:"result,omitempty"`
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

func (s *server) findTest(domain string, id int) (*test, error) {
	var t test
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

	for {
		select {
		case n := <-listener.Notify:
			if n == nil {
				// can be nil notifications sent during reconnections
				continue
			}

			notification := struct {
				Id     int    `json:"id"`
				Domain string `json:"domain"`
				Method string `json:"method"`
			}{}

			if err := json.Unmarshal([]byte(n.Extra), &notification); err != nil {
				log.Printf("Error unmarshalling notification: %v (%s)", err, n.Extra)
				continue
			}

			log.Printf("Starting test: %+v", notification)

			// doesn't matter if this query fails
			s.db.Exec(`UPDATE tests SET started_at = CURRENT_TIMESTAMP, status = 'Processing' WHERE id = $1;`, notification.Id)

			result := runChecks(notification.Domain, notification.Method)

			strResult, _ := json.Marshal(result)
			if _, err := s.db.Exec(`UPDATE tests SET completed_at = CURRENT_TIMESTAMP, status = 'Complete', result = $2 WHERE id = $1;`,
				notification.Id, string(strResult)); err != nil {
				log.Printf("Error storing test %d result: %v", notification.Id, err)
				continue
			}

			log.Printf("Test %d complete", notification.Id)

		case <-time.After(5 * time.Minute):
			go listener.Ping()
		}
	}

	return nil
}

type dbResult struct {
	Problems []letsdebug.Problem `json:"problems"`
	Error    error               `json:"error"`
}

func runChecks(domain, method string) dbResult {
	os.Setenv("LETSDEBUG_DISABLE_CERTWATCH", "1")
	os.Setenv("LETSDEBUG_DISABLE_ACMESTAGING", "1")

	resultCh := make(chan dbResult)

	go func() {
		probs, err := letsdebug.Check(domain, letsdebug.ValidationMethod(method))
		resultCh <- dbResult{probs, err}
	}()

	select {
	case r := <-resultCh:
		return r

	case <-time.After(60 * time.Second):
		return dbResult{nil, errors.New("timeout")}
	}
}
