# Public launch checklist

Use this checklist before changing the repository from private to public.

## Repository safety

- [ ] `main` requires pull requests.
- [ ] Required `go` and `website` checks are enabled for `main`.
- [ ] Force-push and branch deletion are disabled for `main`.
- [ ] Only the maintainer can merge to `main` under the chosen repository rules.
- [ ] GitHub secret scanning and push protection are enabled when available.
- [ ] The full Git history has been scanned for accidentally committed credentials or private environment values.

## Distribution

- [ ] Publish a stable release from the hardened release workflow, for example `v1.2.0`.
- [ ] Confirm the release contains macOS/Linux archives for amd64/arm64, `checksums.txt`, Sigstore bundles, SBOM, and `container-image-digest.txt`.
- [ ] Confirm the GHCR package created by the release is public so self-hosters can pull it anonymously.
- [ ] Run the installer from a clean machine and verify `localenv --version` reports the release tag.
- [ ] Pull the official GHCR image by tag and by immutable digest and verify `/healthz`.

## Public surfaces

- [ ] Confirm `https://www.local.env.best/install.sh` returns the installer without redirecting to the instance domain.
- [ ] Confirm website, docs, security policy, contribution guide, issue forms, and PR template are reachable.
- [ ] Confirm repository description, homepage, topics, and Apache-2.0 license are correct.

After these checks pass, change repository visibility to public and repeat the installer and GHCR anonymous-pull smoke tests without GitHub authentication.
