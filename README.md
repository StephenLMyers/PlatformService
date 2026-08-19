# PlatformService

An extensible platform service written in C, starting with an identity module:
user registration with email verification, JWT authentication with rotating
refresh tokens, and role-based access control over a small set of user methods.

**Status:** all 10 phases complete — registration and email verification, JWT
login with rotating/reuse-detected refresh tokens, account lockout, RBAC with
default deny, admin user listing, rate limiting, and a full sanitizer/fuzz/
Valgrind validation sweep.

---

## What this is

A single HTTP service that owns user identity and gates everything behind
role-based security. The HTTP parser, router, JSON codec, JWT implementation,
authorization engine, and session logic are all written by hand. Only two
dependencies are permitted: **OpenSSL** for cryptographic primitives and
**SQLite** for storage — the two places where hand-rolling is a liability
rather than an education.

The full design, and the reasoning behind each decision, is in
[plans/00-project-plan.md](plans/00-project-plan.md).

## Requirements

Linux only (plan decision D2). On Windows, use WSL2 — not MSYS2 or Cygwin.

| Component | Minimum |
|---|---|
| GCC | 9+ |
| GNU Make | 4.0+ |
| OpenSSL dev headers | 1.1.1+, 3.x preferred |
| SQLite dev headers | 3.35+ |
| Valgrind | for `make memcheck` |
| Python | 3.11+, for the test harness |
| Clang | optional — only `make fuzz`/`make fuzz-smoke`/`make fuzz-long` need it (libFuzzer is LLVM-only) |

Full setup instructions, including WSL2 from scratch:
[plans/01-setup-and-prerequisites.md](plans/01-setup-and-prerequisites.md).

```bash
sudo apt-get install -y build-essential libssl-dev libsqlite3-dev \
                        pkg-config valgrind gdb python3 python3-venv
```

## Build and run

```bash
make                    # build (warnings are errors)
make dev-env            # generate an untracked .env with a strong secret
set -a; . ./.env; set +a
make check-config       # validate configuration and print it
make run                # run in dev mode
```

`make help` lists every target.

## Configuration

Resolution order is **defaults → config file → environment**, with the
environment winning. Every setting has a working default, so the service runs
with no config file at all.

See [config/platform.conf.example](config/platform.conf.example) for the full
list. Notable defaults: port **8443**, bound to **127.0.0.1**, database at
`./data/platform.db`.

Two rules are enforced by the loader rather than left to discipline:

- **Secrets come only from the environment.** A config file that names one is a
  startup failure. Config files get committed, and a secret in git history is
  permanent.
- **An unknown setting is fatal**, not ignored. A silently-dropped typo in a
  security setting is the worst outcome: the operator believes a limit is in
  force when it is not.

### Required environment

| Variable | When | Purpose |
|---|---|---|
| `PS_JWT_SECRET` | always | HS256 signing key, ≥ 32 bytes |
| `BOOTSTRAP_ADMIN_USERNAME` | first run only | seed administrator |
| `BOOTSTRAP_ADMIN_EMAIL` | first run only | seed administrator |
| `BOOTSTRAP_ADMIN_PASSWORD` | first run only | seed administrator |

There is **no default password anywhere in this project**. If the bootstrap
variables are absent on a database with no administrator, startup fails rather
than creating an account whose credentials are public knowledge.

```bash
export PS_JWT_SECRET="$(openssl rand -base64 48)"
```

## Development

```bash
make test           # build and run the C unit tests (tests/unit/)
make check-banned   # fail on unbounded string functions (strcpy, sprintf, ...)
make memcheck       # valgrind, gating on definite and indirect leaks
make dev-cert       # self-signed certificate; key written mode 0600
```

The build uses `-std=c99 -Wall -Wextra -Werror` plus `-Wshadow`,
`-Wcast-qual`, `-Wmissing-prototypes` and others. This codebase does not
accumulate warning debt.

Sanitizer builds (ASan/UBSan, ThreadSanitizer) are opt-in via `SANFLAGS`:

```bash
make clean && make test SANFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
make clean && make test SANFLAGS="-fsanitize=thread"
```

Always `make clean` first when switching `SANFLAGS` — object files are
cached by path, not by flag set, and linking objects built with different
sanitizers together fails with confusing linker errors rather than a clear
message.

### Database

The schema (`src/store/schema/001_init.sql`) is embedded into the binary at
build time and applied automatically on first startup — no separate
migration step. `./data/platform.db` is created if missing; delete it
(plus its `-wal`/`-shm` siblings) to start over.

```bash
python3 tools/seed_users.py --count 100      # deterministic test users, low-iteration hashes
```

Every seeded user shares the password printed by the script. Seeding writes
directly to the database file — the service must have run at least once
first so migrations have created the schema.

### Fuzzing

```bash
make fuzz         # build the libFuzzer targets
make fuzz-smoke   # run each for 60s against the tracked corpus
make fuzz-long    # run each for 30min (weekly CI cadence, not part of local dev's normal loop)
```

Three targets, each taking nothing but `(const uint8_t *data, size_t len)` and
parsing it: `http_request_parse`, `json_parse`, `jwt_decode` — the hand-written
parsers consuming untrusted bytes off the network. Any crash, hang, or
sanitizer report is a hard failure; the reproducer libFuzzer writes gets
copied into `tests/fuzz/corpus/regressions/` and committed, becoming a
permanent regression test.

**Requires Clang** — libFuzzer (`-fsanitize=fuzzer`) is an LLVM feature GCC
does not implement, so these targets use Clang directly regardless of `CC`.
Nothing else in this project needs Clang: every other build, test, and CI job
is GCC-only, matching the confirmed dev toolchain. In practice this makes
fuzzing CI-only — the `fuzz-smoke` (every push/PR) and `fuzz-long` (weekly,
Sunday 11pm Pacific) GitHub Actions jobs install Clang for themselves;
without Clang on `PATH`, `make fuzz` simply won't build here.

### Python harness

```bash
make harness       # black-box pytest suite against the real compiled binary
make rate-limits   # throttle tests only, against real (non-dev_mode) limits
```

`tests/harness/` builds the real binary, launches it as a subprocess with an
ephemeral port and a throwaway self-signed dev cert, and drives it entirely
over real TLS — `httpx` is pinned to that cert (`verify=<path>`), never
`verify=False`, so certificate validation stays real. `make harness` creates
its own venv under `tests/harness/.venv/` on first run from
`tests/harness/requirements.txt`.

`tests/harness/test_memory.py` is the §8.5 memory-footprint suite: it
samples the running process's `VmRSS`/`VmHWM` via `tools/memprobe.py`
(reads `/proc/<pid>/status` directly — `psutil` has no peak-RSS accessor on
Linux) at idle, under concurrent connections, after a burst of sequential
requests, and across repeated connect/disconnect cycles, gating on the
budgets recorded in `plans/00-project-plan.md` §8.5.

`tests/harness/test_rate_limits.py` (`make rate-limits`) is the one place
production rate limits are actually exercised — every other harness test
runs with `PS_DEV_MODE=true`, which relaxes them to a documented, still-finite
multiple so repeated automated requests don't trip a real-world-sized budget.

## API

All endpoints are served over TLS. This is a quick reference — full request/
response shapes, status codes, and design rationale are in
[plans/00-project-plan.md](plans/00-project-plan.md) §4.

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET`  | `/healthz` | public | liveness |
| `GET`  | `/readyz` | public | readiness; `503` while draining |
| `POST` | `/v1/auth/register` | public | rate-limited (per-IP + global) |
| `POST` | `/v1/auth/verify` | public | |
| `POST` | `/v1/auth/resend-verification` | public | rate-limited (per-email, not just per-IP) |
| `POST` | `/v1/auth/login` | public | rate-limited (per-IP + per-username); identical `401` for unknown/wrong-password/unverified |
| `POST` | `/v1/auth/refresh` | refresh token in body | every call rotates; reuse of a consumed token revokes the whole session family |
| `POST` | `/v1/auth/logout` | bearer + refresh token in body | revokes the whole session family, not just the presented token |
| `POST` | `/v1/auth/password` | bearer | requires `current_password`; revokes every other session family |
| `GET`  | `/v1/users/{userId}` | bearer | self or `ADMIN`; email disclosed only to the subject, never to an admin viewing someone else |
| `GET`  | `/v1/admin/users/count` | bearer, `ADMIN` | |
| `GET`  | `/v1/admin/users` | bearer, `ADMIN` | keyset pagination via `?after_id={n}&limit={n}`, `limit` capped at 1000 |

Every non-public route is denied by default (§6.5, D10 in the plan) — a route
with no explicit policy row is unreachable, never open. Run
`./build/platformservice --dump-routes` to print the live policy table (method,
path, policy kind, required role) directly from the binary.

Error responses are always `{ "error": { "code": "...", "message": "..." } }`
(§4.12); see the plan for the full code list (`BAD_REQUEST`, `UNAUTHORIZED`,
`FORBIDDEN`, `NOT_FOUND`, `CONFLICT`, `RATE_LIMITED`, `INTERNAL`, ...).

## Layout

```
src/platform/   sockets, TLS, threads, config, logging, rate limiting
src/http/       HTTP/1.1 parsing, routing, responses
src/json/       JSON parse and serialise
src/crypto/     OpenSSL wrappers, base64url, constant-time compare
src/auth/       JWT, passwords, registration, sessions, RBAC
src/store/      SQLite access and migrations
src/api/        request handlers
tests/harness/  Python black-box suite against the real binary
tests/unit/     C unit tests
tools/          seeding, memory probing, CI checks
```

## Security posture

The design decisions worth knowing before reading the code:

- **Default deny.** Every route is denied unless a policy table grants it.
  Shipping a handler without a policy row makes it unreachable, not open.
- **Ownership is not a role.** "Users see their own data" is checked against
  the `sub` claim of the verified token, never against anything the caller
  supplies.
- **Email is disclosed only to its subject** — not to administrators.
- **Refresh tokens rotate**, and replaying a consumed one revokes the entire
  session family, because two parties holding one token means one is a thief.
- **Lockout is temporary and self-clearing**, so it cannot be used as a
  denial-of-service weapon against a known username.
- **Rate limiting is sharded and bounded**, never a single global lock or an
  unbounded table an attacker cycling source IPs could turn into a
  memory-exhaustion vector in its own right (16-way sharded token-bucket
  limiter, `src/platform/ratelimit.c`, fixed capacity with LRU eviction).

## Backups

The database is SQLite in WAL mode: `./data/platform.db` plus its `-wal` and
`-shm` siblings. Two safe approaches:

1. **Stop the service, then copy the files.** Simplest and always correct —
   copy all three (`platform.db`, `-wal`, `-shm`) together, or none, while the
   process is not running.
2. **Online backup without stopping the service**, using SQLite's own backup
   mechanism rather than copying a live file out from under a writer:
   ```bash
   sqlite3 ./data/platform.db ".backup './backup/platform-$(date +%Y%m%d-%H%M%S).db'"
   ```
   This produces one self-contained, consistent snapshot file — no `-wal`/
   `-shm` siblings to also capture, and safe to run while the service is
   actively writing.

**Never** `cp` a live database file directly without stopping the service or
using `.backup` first. WAL mode means the canonical state is split across
`platform.db` and `platform.db-wal` until the next checkpoint; copying only
the former mid-write can produce a torn, inconsistent snapshot.

**Restoring:** stop the service, replace `./data/platform.db` (removing any
stale `-wal`/`-shm` siblings) with the backup file, start the service again —
migrations are idempotent and will not re-run against an already-current
schema.

## Licence

[MIT](LICENSE).
