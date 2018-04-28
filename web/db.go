package web

import (
	"time"

	"github.com/golang-migrate/migrate"
	"github.com/golang-migrate/migrate/database/postgres"
	"github.com/golang-migrate/migrate/source/go-bindata"
)

type test struct {
	ID            uint64    `db:"id,omitempty"`
	Domain        string    `db:"domain,omitempty"`
	Method        string    `db:"method,omitempty"`
	Status        string    `db:"status,omitempty"`
	CreatedAt     time.Time `db:"created_at,omitempty"`
	StartedAt     time.Time `db:"started_at,omitempty"`
	CompletedAt   time.Time `db:"completed_at,omitempty"`
	SubmittedByIP string    `db:"submitted_by_ip,omitempty"`
	Result        string    `db:"result,omitempty"`
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
