## What changed

<!-- Describe the change clearly and keep this PR focused. -->

## Why

<!-- What problem does this solve? Link an issue when relevant. -->

## User / operator impact

<!-- Describe any visible behavior, migration, configuration, or workflow change. Write "None" if there is no external impact. -->

## Security impact

<!--
Consider authentication, authorization, encryption, device access, GitHub permissions,
storage, logging, filesystem writes, and whether managed plaintext can appear in a new place.
Write "None expected" when the security boundary is unchanged.
-->

## Validation

<!-- List the checks you ran. Remove items that are not relevant and add focused tests as needed. -->

- [ ] `gofmt` / `git diff --check`
- [ ] `go vet ./...`
- [ ] `go test ./...`
- [ ] `go build ./cmd/localenv ./cmd/localenv-server`
- [ ] `frontend`: `npm run check` and `npm run build`
- [ ] `website`: `npm run verify`
- [ ] Focused tests for the changed behavior

## Checklist

- [ ] This change stays within local.env's local-development scope.
- [ ] I did not add real secrets, tokens, credentials, repository keys, or private environment values to code, tests, logs, screenshots, or documentation.
- [ ] User-facing commands, configuration, workflows, or security behavior are documented where necessary.
- [ ] The dashboard remains metadata-only and does not accept or display managed plaintext secrets.
- [ ] Any change to authentication, encryption, device access, GitHub permissions, storage, or secret handling is explained above.
