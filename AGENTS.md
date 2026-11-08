# Agent notes — nice-Scan

## Commit conventions (owner rule)

- The repo owner must be the **sole author** of every commit: no
  `Co-Authored-By` trailers, no "Generated with …" footers, no AI
  attribution of any kind in commit messages.
- Do not amend or rebase published history; rewrite only unpushed commits.

## Verification

- `go build ./...`
- `go test ./...` (CI runs `-race`; keep new code race-clean)
- `gofmt` on touched files

## Project invariants (do not regress)

- Every outbound request stays inside the target scope unless the
  operator passed `--allow-out-of-scope`; credentials never cross origins.
- Non-idempotent HTTP methods are never retried.
- Destructive/state-changing actions require `--destructive` consent,
  enforced at the `exploit` package boundary, not only in the CLI.
- Findings must carry execution/differential evidence — no status-code
  or keyword-only verdicts.
- All report sinks (terminal, JSON, HTML, SARIF) pass through
  `types.RedactFinding` / `types.RedactText`.
