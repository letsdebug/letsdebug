package web

import (
	"embed"
)

var (
	//go:embed templates/includes/*
	embedIncludes embed.FS

	//go:embed templates/layouts/*
	embedLayouts embed.FS

	//go:embed db_migrations/*
	embedMigrations embed.FS
)
