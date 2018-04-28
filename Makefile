.PHONY: clean all deps server-dev server-dev-db-up

deps:
	go get -u github.com/jteeuwen/go-bindata/...
	dep ensure

generate:
	go generate ./...

server-dev: generate
	LETSDEBUG_WEB_DEBUG=1 \
	LETSDEBUG_WEB_DB_DSN="user=letsdebug dbname=letsdebug password=password sslmode=disable" \
	LETSDEBUG_DEBUG=1 go \
	run cmd/server/server.go

server-dev-db-up:
	docker run -d --name letsdebug-db -p 5432:5432 -e POSTGRES_PASSWORD=password -e POSTGRES_USER=letsdebug postgres:10.3-alpine
