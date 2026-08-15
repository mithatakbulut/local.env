# Contributing

Please discuss material product or security changes in an issue before opening
a pull request. v1 deliberately manages local-development environment values
only; do not add production, staging, CI, cloud-secret-manager, or browser
plaintext-editor features.

Run the required local checks before submitting a change:

```bash
gofmt -w $(rg --files -g '*.go')
go vet ./...
go test ./...
go build ./cmd/localenv ./cmd/localenv-server
git diff --check
```

Never put real secrets in tests, fixtures, command arguments, logs, issues, or
snapshots. Use a recognizable non-secret sentinel only when its test proves it
is not persisted or logged.
