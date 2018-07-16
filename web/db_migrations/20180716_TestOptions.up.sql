ALTER TABLE tests ADD COLUMN options json;

CREATE OR REPLACE FUNCTION notify_tests() RETURNS TRIGGER AS $$
DECLARE
  notification json;
BEGIN
  notification = json_build_object(
    'id', NEW.id,
    'domain', NEW.domain,
    'method', NEW.method,
    'options', NEW.options);
  PERFORM pg_notify('tests_events', notification::text);
  return NULL;
END;
$$ LANGUAGE plpgsql;