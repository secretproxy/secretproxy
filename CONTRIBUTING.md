# Contributing

Thanks for contributing to `secretproxy`.

## Development setup

Requirements:

- Go 1.23+
- Git

Clone and run the standard checks:

```bash
make build
make test
make test-race
make vet
```

The local binary is written to `dist/secretproxy`.

## Project layout

- `cmd/secretproxy`: CLI entrypoint
- `internal/app`: proxy, masking, config, service management
- `internal/providers`: upstream provider-specific parsing helpers
- `.github/workflows`: CI and release automation

## Pull requests

- Keep changes scoped and explain the user-visible impact
- Add or update tests when behavior changes
- Update `README.md` and `CHANGELOG.md` when the CLI surface or install flow changes
- Avoid committing generated binaries or local state

## Release notes

User-facing changes should be added to the `Unreleased` section in `CHANGELOG.md`.
