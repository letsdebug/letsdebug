CREATE OR FUNCTION notify_tests() RETURNS TRIGGER AS $$
DECLARE
  notification json;
BEGIN
  notification = json_build_object(
    'id', NEW.id,
    'domain', NEW.domain,
    'method', NEW.method);
  PERFORM pg_notify('tests_events', notification::text);
  return NULL;
END;
$$ LANGUAGE plpgsql;

ALTER TABLE tests DROP COLUMN options json;