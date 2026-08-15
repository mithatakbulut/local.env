# Security model

local.env synchronizes local-development environment values, not production,
staging, CI, or general-purpose credentials.

The CLI creates a random per-repository encryption key and encrypts values
with XChaCha20-Poly1305 before upload. Associated data binds every ciphertext
to the instance, repository, file, key name, scope, version, and key epoch.
The server stores ciphertext and device-specific age-wrapped repository keys;
it never stores a plaintext managed value, plaintext repository key, or device
private identity.

The server validates current GitHub repository write access before returning a
ciphertext snapshot or accepting mutations. Device approval requires an
already-authorized device to re-wrap the repository key locally. Revocation
removes future access; repository-key rotation is required after revocation to
protect future ciphertext even if an old database copy later leaks.

`localenv sync` writes marker-bounded managed blocks atomically with Unix
`0600` permissions and preserves unrelated content. `localenv run -- …` is the
stronger option when a managed plaintext dotenv file is unnecessary: values
remain in the CLI and child-process environment only.

This does not protect a compromised developer machine, values a removed user
already learned, a malicious modified CLI binary, or an actively compromised
server during device provisioning. Compare device fingerprints carefully and
use signed releases. Server request logs contain only request IDs, methods,
status codes, and latency; secret request bodies, bearer tokens, plaintext
repository keys, and GitHub App credentials must never be logged.
