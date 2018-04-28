CREATE TYPE test_status AS ENUM ('Queued', 'Processing', 'Complete');

CREATE TABLE tests (
  id SERIAL PRIMARY KEY,
  domain TEXT NOT NULL,
  method TEXT NOT NULL,
  status test_status NOT NULL,
  created_at timestamp DEFAULT current_timestamp,
  started_at timestamp,
  completed_at timestamp,
  submitted_by_ip TEXT NOT NULL,
  result jsonb
);

CREATE INDEX tests_lookup_idx ON tests (id, domain);
CREATE INDEX tests_domain_idx ON tests (domain);