# CLI reference

`localenv login INSTANCE_URL` authenticates in a browser and stores the opaque
session in the operating-system credential store. `logout` revokes that
session; `status` shows non-secret account, repository, and device metadata.

Use `repo init` once to create a repository key locally. Use `resolve` or
`set KEY --pr NUMBER` for PR values and `import FILE` for declared baseline
keys. Interactive prompts name the target file and key so multiple missing
values stay distinguishable. These commands encrypt values locally before
upload.

`sync`, `sync --dry-run`, and `diff` retrieve ciphertext and decrypt only in
the CLI. `sync` writes only marker-bounded managed sections, and never prints
values. `run [--pr NUMBER] -- COMMAND` injects values into a child process
without writing a managed dotenv file. `doctor` is read-only diagnostics.

Use `devices`, `devices approve CODE`, and `devices revoke ID` for device
sharing. After revocation, run `keys rotate` from an active authorized device.
