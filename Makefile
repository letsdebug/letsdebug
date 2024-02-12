.PHONY: clean all server-dev server-dev-db-up deploy docker-build-setup docker-build

clean:
	rm -f letsdebug-server letsdebug-cli

test:
	go test -v ./...

server-dev:
	LETSDEBUG_WEB_DEBUG=1 \
	LETSDEBUG_WEB_DB_DSN="user=letsdebug dbname=letsdebug password=password sslmode=disable" \
	LETSDEBUG_DEBUG=1 go \
	run -race cmd/server/server.go

server-dev-db-up:
	docker run -d --name letsdebug-db -p 5432:5432 -e POSTGRES_PASSWORD=password -e POSTGRES_USER=letsdebug postgres:10.3-alpine

letsdebug-server:
	go build -o letsdebug-server cmd/server/server.go

letsdebug-cli:
	go build -o letsdebug-cli cmd/cli/cli.go

docker-build-setup:
	docker build --platform linux/arm64 -t letsdebug-build .

docker-build:
	docker run --platform linux/arm64 --rm -it -v $(PWD):/letsdebug letsdebug-build

deploy: letsdebug-server
	rsync -vhz --progress letsdebug-server root@server.letsdebug.net:/usr/local/bin/ && \
	ssh root@server.letsdebug.net "systemctl restart letsdebug"
