.PHONY: clean test server-dev server-dev-db-up deploy

clean:
	rm -f letsdebug-server

test:
	go test -v ./...

server-dev:
	LETSDEBUG_WEB_DEBUG=1 \
	LETSDEBUG_WEB_DB_DSN="user=letsdebug dbname=letsdebug password=password sslmode=disable" \
	LETSDEBUG_DEBUG=1 \
	go run -race cmd/server/server.go

server-dev-db-up:
	docker run -d --name letsdebug-db -p 5432:5432 -e POSTGRES_PASSWORD=password -e POSTGRES_USER=letsdebug postgres:10.3-alpine

letsdebug-server:
	go build -o letsdebug-server cmd/server/server.go

letsdebug-cli:
	go build -o letsdebug-cli cmd/cli/cli.go

deploy: clean letsdebug-server
	rsync -vhz --progress letsdebug-server root@letsdebug.net:/usr/local/bin/ && \
	ssh root@letsdebug.net "systemctl restart letsdebug"
