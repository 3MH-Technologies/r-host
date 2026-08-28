# Sentinel's Journal

Format: `## YYYY-MM-DD - [Title]`

## 2026-08-28 - Repo-went-public exposed the hardcoded admin fallback
**Vulnerability:** `ADMIN_PASSWORD = os.environ.get("ADMIN_PASS", "<hardcoded>")` — the app booted with a known admin password whenever the env var was unset, and the repo was pushed to a *public* GitHub org in the same session.
**Learning:** Env-fallback defaults that double as production credentials are only one `git push --set-upstream` away from being world-readable. The convenience blanket (predictable default) directly funded the attack.
**Prevention:** Fail closed — make `ADMIN_USER`/`ADMIN_PASS` required env vars and `sys.exit(1)` with a clear FATAL log if absent (Docker/HF Space must set them explicitly via secrets). Verify with `import app` both with and without env. Note: this also forces operators to stop relying on guessable creds.