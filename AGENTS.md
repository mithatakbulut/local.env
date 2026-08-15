# local.env implementation guidance

`docs/plan.md` is the v1 product and security specification. Do not silently
expand its scope or weaken its security guarantees.

## Persistent execution workflow

- `docs/v1-progress.md` is the authoritative cross-context implementation
  tracker. Read it before beginning work.
- Work on exactly one named implementation phase per context window unless the
  user explicitly asks to combine phases.
- At the beginning of a phase, mark it `IN PROGRESS` in the tracker and record
  the context date/goal.
- At completion, update its checklist, verification evidence, implementation
  notes, and the explicit next phase. Do not mark a phase complete solely
  because code was written: its stated exit criteria must pass or be clearly
  documented as externally blocked.
- End every implementation context with a concise handoff: completed phase,
  verification performed, known blockers/deferred items, and the exact next
  phase to begin in a new context.
- Keep `docs/plan.md` as the source of requirements. Update the tracker rather
  than copying or editing the plan unless the user requests a requirements
  change.

## Non-negotiable v1 constraints

- Local-development environment synchronization only; no production/staging
  secret-management features.
- Managed secret plaintext and plaintext repository encryption keys must never
  be persisted or logged server-side.
- Client-side encryption, deterministic AAD, authenticated decryption, and
  per-device wrapped repository keys are required protocol invariants.
- GitHub App permissions stay minimal and source-code write access is forbidden.
- `.env.local` updates must be marker-bounded, preserve unrelated content, use
  atomic writes, and use restrictive Unix permissions.
- Prefer small, explicit Go packages, `database/sql`, SQLite, and a single
  deployable container. Avoid an ORM, Redis, queues, cloud dependencies, and
  speculative abstractions.

## Safety and verification

- Never put a secret in fixtures, logs, error messages, command arguments, or
  snapshots. Tests may use an explicitly non-secret sentinel only when they
  also prove it does not persist in server storage.
- Add or update focused tests with each phase; run the relevant tests before
  handoff. Reserve full end-to-end and real-GitHub checks for the final phases.
- Preserve user changes already present in the working tree.
