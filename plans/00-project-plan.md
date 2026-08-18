# PlatformService — Project Plan

**Status:** Draft for review
**Date:** 2026-08-13
**Owner:** Stephen Myers
**Revision:** v2.2

### Changes in v2.2 — phase 8 complete: RBAC policy engine, default deny, GET /v1/users/{userId}
- **New module `api/rbac.c`/`.h`** (not `auth/rbac.c` as plan 3.2's aspirational source tree lists --
  plan 3.1's architecture diagram places "RBAC policy binding" in `api/`, and the policy table is keyed
  by `api/routes.h`'s `route_id`, so a lower-layer `auth/` module would need an upward, forbidden
  dependency on `api/`. See gotchas.md.): the plan 6.5/D10 declarative policy table (`PS_RBAC_POLICIES`)
  and `ps_rbac_check`, keyed by `route_id` rather than the plan's own illustrative (method,
  path_pattern) string sketch -- `route_id` already is that identity, assigned once by the router.
- **`api/routes.c`'s dispatch now enforces RBAC centrally**: looks up the route's policy (`NULL` =
  default deny, unconditional 401), authenticates once via the now-public
  `ps_auth_authenticate_bearer` (`api/auth_api.h`, exposed from what was phase 7's private
  `authenticate_bearer`) for any non-public policy, parses and validates the `userId` path parameter
  per §7.3 exactly once for `POLICY_SELF_OR_ROLE` routes, then calls `ps_rbac_check` before ever
  reaching a handler. `ps_auth_handle_logout`/`ps_auth_handle_password_change` (phase 7) now receive
  already-verified `claims` as a parameter instead of authenticating themselves a second time --
  a pure internal refactor (see gotchas.md), behavior unchanged, all phase 7 harness tests pass as-is.
- **New module `api/user_api.c`/`.h`**: `GET /v1/users/{userId}` (§4.8). Two response views, not a
  conditional field -- email present only when the subject is asking; an admin reading someone else's
  record gets `userId`/`username` only, the key itself absent, never null. `userId` is emitted as a
  JSON string, matching `json_parse.h`'s documented service-wide convention, not the bare number in
  §4.8's own (unmigrated) illustrative example -- see gotchas.md. `ADMIN_USER_READ` audited only when
  an admin reads a record that isn't their own, never for a self-read by anyone including an admin.
- **`main.c` gains `--dump-routes`**: prints the route table (method, path pattern, policy kind,
  required role) as tab-separated lines and exits, needing no environment at all (same shape as
  `--help`/`--version`, since the policy table is static data) -- this is what plan 8.3's default-deny
  suite reads to enumerate every registered route without a second, hand-maintained list.
- **New tests**: `tests/unit/test_rbac.c` (policy table invariants + `ps_rbac_check` truth table,
  including the D9 case), a traversal-style-path case added to `tests/unit/test_http_router.c` (plan
  8.4's IDOR case can't be exercised black-box through a real HTTP client -- see gotchas.md),
  `tests/harness/test_default_deny.py` (plan 8.3), `tests/harness/test_get_user.py` (plan 4.8's full
  RBAC matrix, the PII disclosure boundary, and the rest of the plan 8.4 IDOR suite: body field, query
  parameter, and `X-User-Id` header override attempts all ignored). `launch`/`db_query`/
  `latest_verification_token`, previously duplicated between `test_auth.py` and `test_sessions.py`,
  moved to `conftest.py` now that a third file needs them.
- **Coverage** (unit tests + harness combined) moved from 82.4% lines / 99.6% functions / 70.8%
  branches to 82.6% / 99.6% / 71.1% -- unlike every phase since 6, the percentages themselves rose
  slightly this time, not just the absolute covered count (+105 lines, +8 functions, +63 branches).

### Changes in v2.1 — fixed the pre-existing `server->draining` data race flagged in v2.0
- **`server->draining` (§7.2a step 1) changed from `volatile bool` to a plain `bool` accessed
  exclusively through `__atomic_store_n`/`__atomic_load_n` (`__ATOMIC_SEQ_CST`)** in `server.c`
  (write, on shutdown) and `api/health_api.c` (read, on every `/readyz`), with the pointer type in
  `ps_app_ctx_t.draining` (`api/routes.h`) updated to match. `volatile` never provided cross-thread
  visibility in C's memory model -- only that the compiler wouldn't cache/elide the access -- which is
  why ThreadSanitizer correctly flagged a real race between the main thread's write and a worker
  thread's read. Mirrors the existing `ps_listener_t.stopping` pattern already established in
  `platform/net.c`/`net.h` exactly (same builtins, same memory order, same comment convention). Two
  plain assignments (`main.c`'s initial `server.draining = false;` and the equivalent in
  `test_server.c`'s test fixture) are unchanged and still correct -- both happen before any worker
  thread exists. Verified fixed by rebuilding under ThreadSanitizer and re-running
  `tests/harness/test_readyz.py`'s drain test, the one that originally surfaced it, clean; full unit +
  harness suites also re-run clean under TSan, ASan/UBSan, and Valgrind memcheck. See gotchas.md.

### Changes in v2.0 — phase 7 complete: login, sessions, refresh rotation, logout, password change
- **`family_id` JWT claim added**, discussed with the user: a genuine design gap found mid-phase --
  password-change (§4.7) needs to spare "the session issuing the change" while revoking every other
  family, and the plan's own principle for access tokens is signature-only validation, zero DB I/O.
  Resolved by adding a 128-bit hex `family_id` claim (`auth/claims.h`) alongside `jti`, required on
  every token from phase 7 onward. `auth/claims.c` gained `ps_claims_roles_from_names`, sharing the
  existing role name/bitmask table with the store's role-name output rather than duplicating it.
- **New modules**: `store/session_store.c` (session families + refresh tokens, raw SQL, no owned
  transactions), `auth/session.c` (the rotation/reuse-detection algorithm: an atomic
  `UPDATE ... WHERE consumed_at IS NULL` claim is what makes concurrent presentation of the same
  refresh token resolve to exactly one winner, the other always treated as theft per §6.8).
- **`api/auth_api.c` gains `login`/`refresh`/`logout`/`password`** (§4.4-4.7). Login and password-change
  share one anti-enumeration shape (§7.4): the real PBKDF2 verify runs whenever a row is found --
  including locked/unverified/disabled accounts -- and a dummy PBKDF2 pass runs when it isn't, so
  response timing never reveals *why* a request failed, only that it did.
- **Minimal bearer-token authentication added** (`authenticate_bearer` in `auth_api.c`): extracts
  `Authorization: Bearer`, verifies via `ps_jwt_verify`, hands back claims. Deliberately not the RBAC
  policy engine (phase 8) -- logout and password-change only need "prove who is asking."
- **Account lockout (§6.9) implemented**: `store/user_store.c` gained
  `ps_user_store_set_login_failure_state`. The failed-attempt counter increments (and the lockout
  threshold is evaluated) only on an actual wrong-password attempt against a found, currently-unlocked
  account -- not on a correct password against a merely-unverified one, which is a legitimate
  credential holder, not a guessing attempt. See gotchas.md.
- **Coverage** (unit tests + harness combined) moved from 82.7% lines / 99.5% functions / 71.9%
  branches to 82.4% / 99.6% / 70.8%. Absolute coverage grew substantially (+547 lines, +23 functions,
  +237 branches actually exercised, against +677 new lines added); the percentage dipped for the same
  reason as every prior phase -- the new modules carry defensive error paths (SQL prepare failures,
  malloc failures, semaphore contention) that need fault injection to reach.
- **Found, not fixed**: a pre-existing ThreadSanitizer data race on `server->draining`
  (`server.c`/`health_api.c`, both untouched since phase 6), surfaced only by running the Python
  harness against a TSan build -- something no CI job currently does. Flagged to the user; deliberately
  left for its own dedicated fix rather than a drive-by change bundled into this phase. See gotchas.md.

### Changes in v1.9 — phase 6 complete: registration, verification, bootstrap
- **Rate-limiting scope for phase 6, decided with the user**: §7.7's KDF concurrency semaphore
  (`crypto/kdf_semaphore.c`) and resend's per-email throttle (DB-backed, using the `ratelimit.resend_*`
  config fields already present since phase 1) are built now, scoped tightly to the endpoints phase 6
  adds. The general per-IP/global sharded limiter (`platform/ratelimit.c`, §3.5) remains entirely
  unbuilt until phase 10, exactly as the phase table schedules it -- `register`/`login` have no per-IP
  or global rate limit yet.
- **`ps_user_store_insert` (phase 5) changed internally from `BEGIN`/`COMMIT` to `SAVEPOINT`/
  `RELEASE`**, discussed with the user: SQLite transactions don't nest, so register/bootstrap couldn't
  make the user-row insert, a verification-token insert, and an audit-log write commit atomically
  together (§6.10) until this changed. Behavior-preserving for every existing caller and test.
- **`peer_addr` now threads through `ps_conn_handle` and `ps_route_dispatch_fn`**, discussed with the
  user: `audit_log.source_ip` (§5 schema) had nothing populating it since nothing captured the client
  address past `ps_listener_accept`. `/healthz`/`/readyz`'s handler signatures are unchanged; only the
  new auth handlers use the added parameter.
- **`auth/password.c` gains the policy predicate** deferred from phase 4 (length bounds +
  `data/common-passwords.txt` breach denylist, loaded once at startup into a sorted array, looked up
  by binary search).
- **New modules**: `auth/validate.c` (username/email validation+normalization, shared by register and
  bootstrap), `auth/bootstrap.c` (D11 first-admin seeding, idempotent every boot), `store/token_store.c`
  (verification tokens), `mail/mailer_outbox.c` (the plan's only mail transport, dev_outbox),
  `crypto/sha256.c`, `crypto/kdf_semaphore.c`, `api/auth_api.c` (register/verify/resend-verification).
- **Harness regressions caught and fixed**: every launched instance now needs `BOOTSTRAP_ADMIN_*`
  (main.c refuses to start an admin-less DB without them) and its own `PS_DB_PATH` (previously all
  instances silently shared `./data/platform.db`, harmless until register/verify started writing real
  rows). See gotchas.md for the full account, including a `time(NULL)`-resolution testing pitfall in
  the resend-throttle test.
- **Coverage** (unit tests + harness combined) moved from 83.8% lines / 99.4% functions / 73.2%
  branches to 82.7% / 99.5% / 71.9%. Absolute coverage grew substantially (+599 lines, +247 branches
  actually exercised); the percentage dipped for the same reason it has each phase so far --
  `auth_api.c`, `bootstrap.c`, and the other new modules carry defensive error-handling for conditions
  that need fault injection to reach (malloc failure, a DB write failing mid-transaction), matching
  the pattern already established in `db.c`, `tls.c`, and `main.c`.

### Changes in v1.8 — phase 3 memory baselines calibrated
- **§8.5 budgets calibrated against real measurements**, captured via `tools/memprobe.py` and
  `tests/harness/test_memory.py` running against the actual compiled binary (dev machine: 8 cores).
  Every budget has comfortable headroom; none needed adjusting from the v1.0 initial targets. See the
  updated §8.5 table for the real numbers alongside each budget.
- **§8.5 tests 1, 2, 3 (adapted), and 8 are implemented now**; tests 4-7 need the batch-listing
  endpoint, the KDF/registration path, and JWTs, none of which exist before phases 5-7, and are
  deferred until those land. Test 3 substitutes repeated `/healthz` calls for the plan's "10,000
  authenticated requests," since login doesn't exist yet — it will be tightened to the real
  authenticated path once phase 7 lands.
- **Python pytest harness scaffold added** (`tests/harness/conftest.py`, `client.py`,
  `test_healthz.py`, `test_readyz.py`, `test_memory.py`), matching §8.1's shape: builds the real
  binary, launches it as a subprocess with an ephemeral port and a throwaway dev-CA-pinned cert (never
  `verify=False`, per §15.4), and exercises it black-box over real TLS. `make harness` runs it in a
  pinned venv (`tests/harness/requirements.txt`).

### Changes in v1.7 — fuzzing toolchain correction
- **§8.6 Fuzzing is CI-only, and requires Clang** — libFuzzer (`-fsanitize=fuzzer`) is an LLVM/Clang
  feature; GCC rejects the flag outright. The confirmed dev toolchain (§2) is GCC only, with no Clang
  anywhere in it — a gap in v1.6, discovered when phase 3 actually tried to build the fuzz targets.
  Rather than add Clang to local dev setup, the fuzz jobs install Clang for themselves in CI
  (`fuzz-smoke`/`fuzz-long`, §16.1) and nowhere else; `make fuzz`/`make fuzz-smoke` accordingly require
  Clang on whatever machine runs them, which is never assumed to be the dev machine. See §16.2 for the
  full reasoning.

### Changes in v1.6 — gap-closing pass
- **`POST /v1/auth/password`** (§4.7) — password change requiring re-authentication; also the only way
  the bootstrap admin's credential can ever be rotated
- **Account lockout** (§6.9) — `DISABLED`/`LOCKED` were declared and unreachable; lockout is now a
  self-clearing timestamp, and `LOCKED` is removed from the status enum
- **Audit log** (§6.10 + schema) — append-only, transactional with state changes, PII-free
- **§3.4 Maintenance thread** — nothing previously ran the "periodic sweep"; tables grew forever
- **§3.5 Shared mutable state** — rate-limiter sharding, LRU bound, and the wall-vs-monotonic clock rule
- **§7.2a** — keep-alive, CORS (off by default), graceful shutdown with `/readyz` draining
- **§8.6 Fuzzing** — libFuzzer against the hand-written HTTP, JSON, and JWT parsers
- **`/readyz`** added alongside `/healthz`; public allowlist now seven routes
- Five new risks (R17–R21) including lockout-as-DoS and the deferred JWT key rotation

### Changes in v1.5
- **§16 Continuous Integration** — job matrix, and the split between portable ratio assertions
  (hard-gated) and machine-specific absolute budgets (trended)

### Changes in v1.4
- **Email withheld from admins** for PII reasons — disclosed only to its subject (§4.7)
- **No mail server in v1** — the dev outbox is the delivery mechanism, transport choice deferred (§6.6)
- **§15 Running Locally as a Demo** — runtime defaults, `dev_mode`, and the demo-blocker review
- **NFKC normalization removed** — unimplementable under D1; the ASCII allowlist supersedes it (§6.6)
- **Breach denylist specified** — `data/common-passwords.txt`, top 10k, committed (§6.6)
- **All open questions closed** (§11)

### Changes in v1.3
- **Refresh tokens** (D12) — opaque, hashed, rotated on every use, with **reuse detection** that
  revokes the whole session family (§4.5, §6.8)
- **`POST /v1/auth/logout`** (§4.6) — real revocation, obtained as a side effect of D12
- The `jti` denylist idea is **dropped** — session families give revocation at zero per-request cost
- Only **two** open questions remain (§11)

### Changes in v1.2
- **Admin bootstrap** (D11) — one admin seeded at first startup; resolves "nobody can be an admin" (§6.7)
- **`POST /v1/auth/resend-verification`** added (§4.3), with per-address limits against email bombing
- **§13 Repository & Git Hygiene** — tree confirmed git-safe; `.gitignore` and `.gitattributes` specified
- **§14 Development Environment** — WSL2 + Ubuntu, user `stephen`, project on ext4
- Companion doc added: `plans/01-setup-and-prerequisites.md`

### Changes in v1.1
- **Linux-only** target (D2 reversed) — Windows/Winsock support dropped; dev environment moves to WSL2 + Ubuntu
- **Self-service registration** added, with email verification (§4.1, §4.2, §6.6, §7.6)
- **Default-deny** authorization made explicit and testable, with a minimal public allowlist (§6.5)
- **Flat role model** confirmed — `ADMIN` does not imply `USER` (§6.4)
- **Memory footprint testing** added to the test specification (§8.5)
- **D7 reassessed** — the `long` finding was Windows-specific and no longer describes a bug

---

## 1. Vision & Scope

### Long-term goal
A general-purpose **platform service** — a single, extensible C service that hosts many capability
modules behind one authenticated, role-secured HTTP API.

### v1 goal (this plan)
Prove the foundation with the **Identity module**:

1. Let a user **register**, verify their account, and request a fresh verification link.
2. Log a user in, issue a **JWT**, and keep the session alive with rotating refresh tokens.
3. Gate every other method behind **role-based security** driven by that JWT.
4. Ship three business methods:
   - Get user data by user ID
   - Count all users (admin only)
   - List users in batches of 1000 (admin only)

The point of v1 is not the methods. It is the **spine** — sockets, TLS, HTTP, JSON, crypto, JWT,
RBAC, storage, and a test harness — that every future module plugs into unchanged.

### Explicitly out of scope for v1
Password **reset** (change is in — §4.7), **real SMTP delivery** (the interface ships; the transport is
a dev outbox — §6.6), admin role-management and account-disable endpoints (operator/SQL only — §6.9),
JWT key rotation with `kid` (R21), account deletion and data export, OAuth/OIDC federation,
multi-tenancy, horizontal scaling / clustering, admin UI, metrics backend, alerting.

---

## 2. Confirmed Technical Decisions

| # | Decision | Choice | Rationale |
|---|---|---|---|
| D1 | Language & dependency policy | **C99 stdlib + OpenSSL + SQLite only** | Hand-write HTTP, routing, JSON, JWT, and all business logic. Delegate *only* cryptographic primitives and the storage engine. Never hand-roll security primitives. |
| D2 | Platform target | **Linux only** | Plain POSIX. No portability shim, no Winsock. Development in WSL2 + Ubuntu; deployment to Linux. |
| D3 | Persistence | **SQLite** (WAL mode) | Embedded, zero-admin, real indexes and 64-bit integer keys. Supports efficient keyset pagination for the 1000-row batches. |
| D4 | TLS | **In-process, OpenSSL** | v1 terminates TLS itself with `SSL_CTX`. Adds cert management to v1 scope; see §7.1 and Risk R1. |
| D5 | Test harness | **Python 3.11+, pytest** | Black-box HTTP tests against a real running binary. |
| D6 | Build system | **Makefile** | Plain `make`. No CMake dependency, and with a single target platform no detection logic is needed. |
| D7 | `userId` C type | **`int64_t`** | Explicit width, guaranteed by the standard. See the note below. |
| D8 | Account activation | **Email verification, pluggable delivery** | Real tokens, real lifecycle, fully tested. v1 delivery writes to a dev outbox table; SMTP is a later drop-in. |
| D9 | Role model | **Flat; `ADMIN` does not imply `USER`** | Roles are independent labels in a join table. An account needing both holds both, explicitly. |
| D10 | Authorization default | **Default deny** | Every route is denied unless a policy entry grants it. A six-route public allowlist is the only exception (§6.5). |
| D11 | Admin bootstrap | **One admin seeded at first startup** | Registration only ever grants `USER`, so the first `ADMIN` is created from config on an empty database. Idempotent, credential-checked, never re-created (§6.7). |
| D12 | Session management | **Opaque refresh tokens, rotated, with reuse detection** | Short access tokens stay short without forcing 15-minute re-logins. Server-side session records make real logout and revocation possible at zero per-request cost (§6.8). |

### D2 — Linux only (reversed from v1.0)

v1.0 specified a portable POSIX-first design with a Winsock2 shim. That is now dropped. The
consequences, all simplifications:

- `src/platform/sock_win32.c` and the `sock.h` abstraction are **deleted** — handlers call POSIX
  sockets directly. No `WSAStartup`, no `closesocket`/`close` split, no `SOCKET` typedef.
- The Makefile loses all platform detection.
- File-permission checks on the TLS private key become meaningful and enforceable (`chmod 600`),
  where on Windows they were approximate at best.
- **Valgrind, massif, and LSan become available** — this is what makes §8.5 memory testing possible,
  and is a real gain for a C project.
- Signal handling, `epoll` (if ever needed), and `/proc` introspection are all straightforwardly
  available.

### D7 — the `long` question, reassessed

v1.0 flagged this as a portability trap, verified on this machine:

```
Windows (LLP64):  sizeof(long)=4   sizeof(long long)=8   sizeof(int64_t)=8
Linux   (LP64):   sizeof(long)=8   sizeof(long long)=8   sizeof(int64_t)=8
```

**With D2 now Linux-only, that finding no longer describes a bug.** Linux is LP64, so `long` is
genuinely 64-bit and your original requirement — "user ID should be a long" — is satisfied literally.
The 32-bit truncation risk was specific to Win64, which is no longer a target.

We still write `int64_t` rather than `long`, but for weaker and more ordinary reasons: it states the
width at the point of use, it is guaranteed by the C standard rather than by the platform's data
model, and it pairs cleanly with `PRId64`, `strtoll`, and `sqlite3_bind_int64`. This is now a style
choice, not a correctness fix. A `_Static_assert(sizeof(int64_t) == 8, ...)` documents the assumption.

*(Retained here because it becomes a real bug again the moment Windows re-enters scope.)*

### Toolchain

**Current state (installed on the Windows host, 2026-08-13):**

| Component | Version | Status under D2 |
|---|---|---|
| Python | 3.13.15 | Usable — the harness can drive the service over TCP from Windows |
| MSYS2 / GCC 16.2.0 / OpenSSL 3.6.3 / SQLite 3.53.4 | — | ⚠️ **Now unused.** Windows toolchain, superseded by D2. Left installed; harmless. |

**Linux build environment — installed and verified 2026-08-13:**

| Component | Version | Purpose |
|---|---|---|
| Ubuntu (WSL2) | **26.04 LTS**, kernel 6.18.33.2 | Build and run target |
| GCC | **15.2.0** | Compiler |
| GNU Make | **4.4.1** | Build |
| OpenSSL (`libssl-dev`) | **3.5.5** | TLS, HMAC-SHA256, PBKDF2, CSPRNG |
| SQLite (`libsqlite3-dev`) | **3.46.1** | Storage |
| Valgrind | **3.26.0** | Leak detection and heap profiling (§8.5) |
| GDB | installed | Debugging |
| Python | **3.14.4** | Test harness |
| git | **2.53.0** | Version control |

Verified by compiling and running a program linking both libraries under
`-std=c99 -Wall -Wextra -Werror` with zero warnings: HMAC-SHA256 returns a 32-byte MAC, `RAND_bytes`
succeeds, SQLite opens an in-memory database, and **`sizeof(long)=8`** — confirming LP64 and D7's
premise. Valgrind reported **0 definite, 0 indirect, 0 possibly lost** (56 bytes still reachable from
OpenSSL init), `ERROR SUMMARY: 0 errors`.

**Clang is deliberately not part of this list (v1.7).** GCC is the only compiler the dev toolchain
ever needs. The one exception is fuzzing (§8.6): libFuzzer is an LLVM/Clang feature GCC does not
implement, and fuzzing runs CI-only for exactly that reason — whichever machine runs `make fuzz`
needs Clang, but that machine is never assumed to be this one.

Full reproducible instructions: **`plans/01-setup-and-prerequisites.md`**.

---

## 3. Architecture

### 3.1 Layering

Strict downward dependency. No layer may call upward.

```
  ┌─────────────────────────────────────────────┐
  │  api/       handlers, RBAC policy binding   │  business logic
  ├─────────────────────────────────────────────┤
  │  auth/      JWT, claims, password, register │
  │  store/     SQLite data access              │  domain services
  │  mail/      verification delivery interface │
  ├─────────────────────────────────────────────┤
  │  http/      HTTP/1.1 parse, route, respond  │
  │  json/      parse + serialize               │  protocol
  │  crypto/    OpenSSL wrappers, base64url     │
  ├─────────────────────────────────────────────┤
  │  platform/  sockets, TLS, threads, log, cfg │  foundation
  └─────────────────────────────────────────────┘
```

### 3.2 Source tree

```
PlatformService/
├── plans/                       # this document and successors
├── Makefile
├── README.md
├── .gitignore  .gitattributes   # §13 — required before first commit
├── config/
│   └── platform.conf.example    # names only, never values
├── data/
│   └── common-passwords.txt     # breach denylist, top 10k (§6.6) — tracked
├── certs/                       # dev cert + key, git-ignored, made by `make dev-cert`
├── src/
│   ├── main.c                   # wiring, startup, signal handling
│   ├── platform/
│   │   ├── net.c/.h             # POSIX sockets, accept loop
│   │   ├── tls.c/.h             # OpenSSL SSL_CTX lifecycle
│   │   ├── threadpool.c/.h      # bounded worker pool
│   │   ├── ratelimit.c/.h       # sharded token-bucket limiter (§3.5)
│   │   ├── maintenance.c/.h     # sweeper thread (§3.4)
│   │   ├── log.c/.h             # leveled, structured logging
│   │   └── config.c/.h          # file + env config loader
│   ├── http/
│   │   ├── request.c/.h         # HTTP/1.1 request parser
│   │   ├── response.c/.h        # response writer
│   │   ├── router.c/.h          # method+path matching, path params
│   │   └── middleware.c/.h      # auth, logging, error mapping chain
│   ├── json/
│   │   ├── json_parse.c/.h      # recursive-descent parser
│   │   └── json_write.c/.h      # escaping serializer
│   ├── crypto/
│   │   ├── hmac.c/.h            # HMAC-SHA256 (OpenSSL EVP)
│   │   ├── kdf.c/.h             # PBKDF2-HMAC-SHA256
│   │   ├── rand.c/.h            # RAND_bytes CSPRNG
│   │   ├── base64url.c/.h       # RFC 7515 unpadded base64url
│   │   └── ct.c/.h              # constant-time compare
│   ├── auth/
│   │   ├── jwt.c/.h             # encode, decode, verify
│   │   ├── claims.c/.h          # claim struct + validation
│   │   ├── password.c/.h        # hash, verify, policy check
│   │   ├── registration.c/.h    # signup, verify, resend workflow
│   │   ├── session.c/.h         # refresh rotation, reuse detection (D12)
│   │   ├── bootstrap.c/.h       # first-admin seeding (D11)
│   │   └── rbac.c/.h            # policy evaluation (default deny)
│   ├── mail/
│   │   ├── mailer.h             # delivery interface
│   │   └── mailer_outbox.c      # v1: writes to dev_outbox table
│   ├── store/
│   │   ├── db.c/.h              # connection pool, WAL, migrations
│   │   ├── user_store.c/.h      # user queries
│   │   ├── token_store.c/.h     # verification tokens
│   │   ├── session_store.c/.h   # families + refresh tokens
│   │   ├── audit_store.c/.h     # append-only audit writes (§6.10)
│   │   └── schema/
│   │       └── 001_init.sql
│   └── api/
│       ├── auth_api.c/.h        # register, verify, resend, login, refresh, logout
│       ├── user_api.c/.h        # GET /v1/users/{id}
│       └── admin_api.c/.h       # count + batch list
├── tests/
│   ├── unit/                    # C unit tests
│   └── harness/                 # Python black-box suite (3.14.4 installed)
└── tools/
    ├── seed_users.py            # generate large test datasets
    └── memprobe.py              # RSS/heap sampling for §8.5

# created at runtime, git-ignored:
#   data/platform.db (+ -wal, -shm)   build/   .venv/
```

### 3.3 Concurrency model

**Thread pool + blocking I/O.** A single acceptor thread hands connections to a bounded queue
drained by N workers (default `N = cpu_count`).

Chosen over an event loop because the workload is DB-bound with short handlers, and because blocking
code is dramatically simpler to get correct in C. If profiling shows the pool is the bottleneck,
`epoll` is the natural next step — now unambiguously available under D2.

- SQLite in **WAL mode**, compiled `SQLITE_THREADSAFE=1`, **one connection per worker thread**,
  `busy_timeout` **5000 ms** (a value, not a vague intention — without one, `SQLITE_BUSY` surfaces as
  a failed request the instant two writers overlap).
- Bounded accept queue with backpressure — reject with `503` rather than grow without limit.
- **A separate, smaller semaphore bounds concurrent PBKDF2 work** (§7.7). Password hashing is the
  most expensive operation in the service and it sits on two *unauthenticated* endpoints.

### 3.4 Maintenance thread

Several parts of the design generate rows that nothing would ever remove. Consumed refresh tokens are
**deliberately retained** so reuse detection can tell "already spent" from "never existed" (§6.8),
verification tokens outlive their 24-hour TTL, and audit rows accumulate by design. Without a sweeper
these tables grow for the life of the process — a slow leak that stays invisible for months.

One dedicated thread, its own SQLite connection, waking on a configurable interval (default 1 hour)
and once at startup:

| Swept | When eligible |
|---|---|
| `email_verification_tokens` | past `expires_at` + 24h grace |
| `refresh_tokens` | owning family past `absolute_exp` |
| `session_families` | past `absolute_exp`, or revoked more than 30 days ago |
| `dev_outbox` | older than 7 days |
| `audit_log` | older than the retention window (default 365 days) |
| `users.locked_until` | cleared once elapsed (§6.9) |

**Deletes run in bounded batches** (default 1,000 rows, then yield). A single unbounded `DELETE` over
a large table holds the WAL write lock long enough to stall every worker thread — the sweeper would
become the outage it exists to prevent. Each pass logs what it removed.

### 3.5 Shared mutable state

Two structures are touched by every worker thread, and both need their concurrency stated rather than
assumed:

**Rate limiter** (`platform/ratelimit.c`) — a hash table of token buckets keyed by IP and by
account/email. It is the only genuinely shared, mutable, per-request structure in the service.

- **Sharded 16 ways by key hash, one `pthread_mutex_t` per shard.** A single global lock would
  serialize every request through one mutex; sharding keeps contention proportional to key spread.
- **Bounded entry count with LRU eviction.** This matters more than it looks: an unbounded table keyed
  by source IP grows with every distinct address, so an attacker cycling IPs turns the *defense
  against* denial of service into a memory-exhaustion vector. Capacity is configured, and eviction
  under pressure is a documented, tested behavior — not an afterthought.
- Buckets refill from a **monotonic** clock, so a wall-clock adjustment cannot grant free requests.

**KDF semaphore** (§7.7) — a counting semaphore; `sem_wait`/`sem_post` with a non-blocking try so
excess load sheds to `503` rather than queueing.

Everything else is per-thread (SQLite connections), immutable after startup (config, policy table,
`SSL_CTX`, breach denylist), or owned by exactly one thread.

> **Clocks.** All *expiry* comparisons — token TTLs, lockout windows, session lifetimes — use wall
> time, because they must survive a restart and be meaningful across processes. All *interval*
> measurements — rate-limit refill, timeouts, sweep cadence — use `CLOCK_MONOTONIC`, so a clock
> adjustment cannot stall or accelerate them. Mixing these up is a classic source of bugs that appear
> only twice a year.

---

## 4. API Surface (v1)

Base path `/v1`. All responses `application/json`. All errors use one envelope (§4.12).

### 4.1 `POST /v1/auth/register` — public

```jsonc
// request
{ "username": "smyers", "email": "s@example.com", "password": "correct horse battery staple" }

// 202 Accepted — always this shape on success OR on duplicate email
{
  "status":  "PENDING_VERIFICATION",
  "message": "If this email address is not already registered, a verification link has been sent."
}
```

The server assigns `userId` and grants exactly the `USER` role. **No JWT is returned** — the account
cannot log in until verified. Any `userId`, `roles`, or `status` field in the request body is
**ignored**, not honored (§7.6).

**Response policy — deliberately asymmetric:**

| Condition | Response |
|---|---|
| Success | `202` + the body above |
| Email already registered | `202` + **byte-identical** body; a *"someone tried to register with your address"* notice goes to the existing owner instead of a verification link |
| Username already taken | `409 CONFLICT` |
| Password fails policy | `400 WEAK_PASSWORD` with the unmet rule |
| Malformed email / username | `400 BAD_REQUEST` |
| Rate limit tripped | `429 RATE_LIMITED` |

> **Why emails and usernames are treated differently.** An endpoint that says *"that email is taken"*
> is an oracle: an attacker feeds it a list of addresses and learns which people hold accounts here.
> So email existence is never confirmed or denied. Usernames cannot get the same protection — the user
> has to be told their chosen name is unavailable or they cannot complete signup. That leak is
> **accepted knowingly**, and it is a small one: usernames are already semi-public (they appear in the
> admin listing) and reveal nothing about a real-world identity the way an email address does. Rate
> limiting bounds how fast the username space can be probed. See Risk R8.

### 4.2 `POST /v1/auth/verify` — public

```jsonc
// request
{ "token": "3f9a...(43 chars, base64url)" }

// 200
{ "status": "ACTIVE" }
```

Single-use. Consumes the token, moves the account `PENDING_VERIFICATION → ACTIVE`. Invalid, expired,
and already-consumed tokens all return the same `400 INVALID_TOKEN` — no distinction, since telling
an attacker *"expired"* versus *"never existed"* confirms a token once existed.

### 4.3 `POST /v1/auth/resend-verification` — public

```jsonc
// request
{ "email": "s@example.com" }

// 202 — always, unconditionally
{ "message": "If this email address requires verification, a new link has been sent." }
```

**Always `202`, always the same body** — whether the address is unregistered, pending, already
active, or disabled. Anything else turns this into the enumeration oracle §4.1 was careful not to be.

Behavior when the address *does* belong to a pending account:
- **All outstanding tokens for that user are invalidated first**, then exactly one new token is
  issued. Tokens must not accumulate — every live token is another chance for one to leak, and a
  user who clicks resend five times should not leave five working activation links behind.
- Already-`ACTIVE` accounts do nothing at all (no email, no token) but still return the same `202`.

> **This endpoint is an email-bombing vector, and that shapes its rate limits.** Unlike register and
> login, the abuse target is not this service — it is a *third party*. An attacker who knows someone's
> address can hammer resend to flood their inbox, using our service and our sending reputation to do
> it. Per-IP limiting alone does not stop this, because a distributed caller trivially evades it.
> The limit that matters is **per-email-address and global**, enforced regardless of who is asking:
> at most **1 send per address per 60 seconds** and **5 per address per 24 hours**, counted
> server-side against the address itself. Requests past the limit still return the same `202` — the
> caller is told nothing, and no mail is sent.

No password hashing occurs here, so unlike register this endpoint does not enter the KDF semaphore
(§7.7). It is cheap to serve and expensive to *abuse*, which is exactly why the limits are on the
outbound side rather than the inbound one.

### 4.4 `POST /v1/auth/login` — public

```jsonc
// request
{ "username": "smyers", "password": "..." }

// 200
{
  "access_token":  "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "8c1d...(43 chars, base64url)",
  "token_type":    "Bearer",
  "expires_in":    900
}
```

A successful login opens a new **session family** (§6.8) and returns the first refresh token in it.

Failure is always `401` with an identical body and comparable timing whether the user is unknown, the
password is wrong, or **the account is unverified** (§7.4). An unverified account must not be
distinguishable from a nonexistent one at this endpoint.

### 4.5 `POST /v1/auth/refresh` — public route, refresh-token credential

```jsonc
// request
{ "refresh_token": "8c1d...(43 chars, base64url)" }

// 200
{
  "access_token":  "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "f04b...",          // NEW token — the old one is now dead
  "token_type":    "Bearer",
  "expires_in":    900
}
```

Listed as `POLICY_PUBLIC` because it carries no `Authorization` header — the refresh token *is* the
credential, and it is validated inside the handler. It is not unauthenticated in any meaningful
sense.

**Every call rotates.** The presented token is consumed and a replacement issued. A client must
replace its stored token on every refresh; there is no scenario where reusing one is correct.

Failure is always `401 UNAUTHORIZED`, identical body, for unknown, expired, consumed, or revoked
tokens — a caller learns nothing about *why*.

### 4.6 `POST /v1/auth/logout` — authenticated

```jsonc
// request
{ "refresh_token": "f04b..." }

// 204 No Content
```

Revokes the entire session family (§6.8), not just the presented token. Requires a valid access token
**and** the refresh token: the access token proves who is asking, the refresh token names which
session to end. Logging out of a phone should not end the session on a laptop, so the family is the
right unit — and `sub` from the access token must match the family's owner, or the request is `403`.

Idempotent: revoking an already-revoked family still returns `204`.

> **This is what makes logout real.** Without a server-side session record, "logout" only deletes the
> client's copy while the token stays valid until `exp`. Here the family is revoked server-side, so
> the next refresh fails and the access token expires within 15 minutes on its own.

### 4.7 `POST /v1/auth/password` — authenticated

```jsonc
// request
{ "current_password": "...", "new_password": "..." }

// 204 No Content
```

**The current password is required even though the caller already holds a valid access token.** A
token proves the session was authenticated at some point; it does not prove the person at the keyboard
is the account owner. Without re-authentication, a stolen access token — or an unlocked laptop —
converts into permanent account takeover in one request. Re-entering the password is what makes that
step cost something.

- New password is subject to the full §6.6 policy, breach denylist included
- Rehashed at the **current** `kdf_iters`, so the cost factor rises with the configured default
- Wrong `current_password` → `401`, rate-limited on the same counter as login
- **On success, every other session family for that user is revoked.** The session issuing the change
  survives; all others die. A password change is the standard response to "I think someone has my
  account", and it would be worthless if the attacker's session kept working.
- Audited as `PASSWORD_CHANGE` (§6.10)

> This also closes the D11 gap: the bootstrap admin's password arrives from an environment variable at
> first boot, and until now nothing could ever change it. That account can now rotate its own
> credential like any other.

### 4.8 `GET /v1/users/{userId}` — authenticated

`userId` is a signed 64-bit integer (`int64_t`; see D7).

**The response shape depends on who is asking.** Email is PII and is disclosed only to its subject.

```jsonc
// 200 — owner reading their own record (sub == userId)
{ "userId": 1234567890123, "username": "smyers", "email": "s@example.com" }

// 200 — ADMIN reading someone else's record: NO email
{ "userId": 1234567890123, "username": "smyers" }
```

**Authorization:** caller may read the record if `sub == userId` **OR** caller holds `ADMIN`.

> **Design note — two views, not a conditional field.** Administrative access grants the *existence*
> and identity of a record, not its personal data. This narrows the original "admins can view any
> user data" deliberately: an admin needs to administer accounts, which requires `userId` and
> `username`, and almost never requires the subject's email address. It also makes the service
> consistent — the batch listing (§4.10) already withholds email, so email is now disclosed in exactly
> one place, to exactly one person.
>
> Implement this as **two distinct serializer functions** — `user_write_self()` and
> `user_write_admin()` — chosen at the call site, rather than one function with an `include_email`
> flag. A boolean parameter defaults wrong under maintenance: someone adds a caller, omits the
> argument or passes the wrong one, and PII leaks silently. Two functions cannot be called
> ambiguously, and the admin one has no code path that can emit an email at all.

> **Design note — IDOR.** *Insecure Direct Object Reference* is the vulnerability where an endpoint
> fetches a record by a caller-supplied identifier without checking the caller is entitled to it —
> Alice authenticates as user 1001, requests `/v1/users/1002`, and receives Bob's record. It requires
> no tooling to exploit: change one digit in the URL.
>
> "A user can see their own data" is *ownership*-based, not role-based, so the policy engine evaluates
> **role + resource ownership together**. The ownership check compares the path ID against the `sub`
> claim of the **verified token** — never against a body field, query parameter, or header such as
> `X-User-Id`, all of which are equally attacker-controlled. This is the most likely place in the
> service to introduce a real vulnerability, so it gets a dedicated suite (§8.4).

### 4.9 `GET /v1/admin/users/count` — ADMIN only

```jsonc
{ "count": 2500 }
```

### 4.10 `GET /v1/admin/users?after_id={n}&limit={n}` — ADMIN only

Keyset (seek) pagination, **not** `OFFSET`. `limit` defaults to and is capped at **1000**.

```jsonc
{
  "users":       [ { "userId": 1, "username": "alice" }, /* ... */ ],
  "count":       1000,
  "nextAfterId": 1000,
  "hasMore":     true
}
```

`SELECT user_id, username FROM users WHERE user_id > ? ORDER BY user_id ASC LIMIT ?`

Keyset paging is O(log n) per page rather than O(offset), and stays stable when rows are inserted
mid-iteration. The client walks pages by feeding `nextAfterId` back in until `hasMore` is false.
This endpoint deliberately returns **only** `userId` and `username` — no email.

### 4.11 `GET /healthz` and `GET /readyz` — public

Two probes, because they answer different questions and a load balancer needs both:

| Route | Question | Fails when |
|---|---|---|
| `/healthz` | *Is the process alive?* | the process is wedged — a restart is the remedy |
| `/readyz` | *Should traffic be sent here?* | DB unreachable, migrations still running, or the service is **draining** during shutdown |

Conflating them causes real outages in both directions: a liveness probe that checks the database
restarts a healthy process because the DB blipped, and a readiness probe that only checks liveness
sends traffic to a process that is shutting down. Neither returns sensitive detail — a status and
nothing more. Both public by explicit decision (§6.5) so orchestrators can probe without credentials.

### 4.12 Error envelope

```jsonc
{ "error": { "code": "FORBIDDEN", "message": "Insufficient privileges" } }
```

| Status | Code | Used when |
|---|---|---|
| 400 | `BAD_REQUEST` | malformed JSON, unparseable/overflowing `userId`, bad email or username |
| 400 | `WEAK_PASSWORD` | password fails policy (§6.6) |
| 400 | `INVALID_TOKEN` | verification token invalid, expired, or already used |
| 401 | `UNAUTHORIZED` | missing, malformed, expired, or bad-signature token; failed login; unknown, consumed, expired, or revoked refresh token |
| 403 | `FORBIDDEN` | valid token, insufficient role or not the owner |
| 404 | `NOT_FOUND` | no such user, or no such route |
| 405 | `METHOD_NOT_ALLOWED` | path exists, method does not |
| 409 | `CONFLICT` | username already taken |
| 413 | `PAYLOAD_TOO_LARGE` | body over cap |
| 429 | `RATE_LIMITED` | login or registration throttle tripped (**never** resend — see §4.3) |
| 500 | `INTERNAL` | unexpected — never leaks internals to the client |
| 501 | `NOT_IMPLEMENTED` | unsupported HTTP feature, e.g. chunked encoding (§7.2) |
| 503 | `UNAVAILABLE` | accept queue or KDF semaphore saturated |

**401 vs 403 discipline:** 401 means *"I don't know who you are."* 403 means *"I know who you are and
the answer is no."* Requesting another user's record as a non-admin returns **403, not 404** — the
caller is already authenticated, so hiding existence buys nothing.

---

## 5. Data Model

```sql
CREATE TABLE users (
    user_id          INTEGER PRIMARY KEY,  -- SQLite INTEGER is 64-bit → int64_t
    username         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email            TEXT    NOT NULL,     -- as supplied, for display and delivery
    email_normalized TEXT    NOT NULL UNIQUE,  -- trimmed + lowercased; uniqueness key
    password_hash    BLOB    NOT NULL,     -- PBKDF2-HMAC-SHA256, 32 bytes
    password_salt    BLOB    NOT NULL,     -- 16 bytes, CSPRNG
    kdf_iters        INTEGER NOT NULL,     -- per-row so cost can rise over time
    status           TEXT    NOT NULL DEFAULT 'PENDING_VERIFICATION',
                                           -- PENDING_VERIFICATION | ACTIVE | DISABLED
    failed_logins    INTEGER NOT NULL DEFAULT 0,   -- consecutive; reset on success
    locked_until     INTEGER,               -- NULL when not locked; see §6.9
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL
);

CREATE TABLE roles (
    role_id INTEGER PRIMARY KEY,
    name    TEXT NOT NULL UNIQUE           -- 'USER', 'ADMIN'
);

CREATE TABLE user_roles (
    user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Verification tokens are stored HASHED. A database leak must not yield
-- working activation links.
CREATE TABLE email_verification_tokens (
    token_hash  BLOB    PRIMARY KEY,       -- SHA-256 of the raw token
    user_id     INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    expires_at  INTEGER NOT NULL,
    consumed_at INTEGER,                   -- NULL until used; enforces single-use
    created_at  INTEGER NOT NULL
);
CREATE INDEX idx_evt_user ON email_verification_tokens(user_id);

-- Session families (D12). One row per login; every rotation in that lineage
-- shares the family_id so the whole chain can be revoked together.
CREATE TABLE session_families (
    family_id    BLOB    PRIMARY KEY,      -- 128-bit CSPRNG
    user_id      INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    absolute_exp INTEGER NOT NULL,         -- created_at + 90d; never extended
    revoked_at   INTEGER,                  -- NULL while live
    revoke_cause TEXT                      -- 'LOGOUT' | 'REUSE_DETECTED' | 'EXPIRED'
);
CREATE INDEX idx_sf_user ON session_families(user_id);

-- Refresh tokens are stored HASHED, like verification tokens.
-- Consumed rows are RETAINED, not deleted -- reuse detection depends on
-- recognizing a token that was already spent.
CREATE TABLE refresh_tokens (
    token_hash  BLOB    PRIMARY KEY,       -- SHA-256 of the raw token
    family_id   BLOB    NOT NULL REFERENCES session_families(family_id) ON DELETE CASCADE,
    generation  INTEGER NOT NULL,          -- 1, 2, 3... within the family
    idle_exp    INTEGER NOT NULL,          -- issued_at + 30d
    consumed_at INTEGER,                   -- NULL until rotated
    issued_at   INTEGER NOT NULL
);
CREATE INDEX idx_rt_family ON refresh_tokens(family_id);

-- v1 delivery sink (D8). Replaced by real SMTP later; the interface does not change.
CREATE TABLE dev_outbox (
    id         INTEGER PRIMARY KEY,
    to_email   TEXT NOT NULL,
    subject    TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- Append-only security audit trail (§6.10). Distinct from application logging.
-- Contains NO passwords, tokens, hashes, or email addresses -- subjects are
-- referenced by user_id only, consistent with the PII stance in §4.8.
CREATE TABLE audit_log (
    id             INTEGER PRIMARY KEY,
    occurred_at    INTEGER NOT NULL,
    event          TEXT    NOT NULL,   -- see the event table in §6.10
    outcome        TEXT    NOT NULL,   -- 'SUCCESS' | 'FAILURE'
    actor_user_id  INTEGER,            -- who acted; NULL when unauthenticated
    target_user_id INTEGER,            -- who was acted upon; may equal actor
    source_ip      TEXT,
    request_id     TEXT,               -- correlates with the application log
    detail         TEXT                -- small JSON object; never secrets
);
CREATE INDEX idx_audit_time   ON audit_log(occurred_at);
CREATE INDEX idx_audit_actor  ON audit_log(actor_user_id, occurred_at);
CREATE INDEX idx_audit_target ON audit_log(target_user_id, occurred_at);
CREATE INDEX idx_audit_event  ON audit_log(event, occurred_at);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_status   ON users(status);
CREATE TABLE schema_version (version INTEGER NOT NULL);
```

`user_id` as `INTEGER PRIMARY KEY` is an alias for SQLite's 64-bit rowid — the `long` semantics
required, plus the clustered ordering that makes keyset pagination fast.

Roles are a **join table, not a column**, so a user can hold several and new roles cost no schema
change — necessary for the "services all kinds of needs" goal.

**`email_normalized` carries the `UNIQUE` constraint, not `email`.** Uniqueness is decided on the
trimmed, lowercased form so `S@Example.com` and `s@example.com` cannot both register. Normalization
stops at lowercasing — provider-specific canonicalization (stripping Gmail dots or `+tags`) is
deliberately *not* done, because those rules vary by provider and applying them wrongly locks
legitimate users out of addresses they genuinely control.

**Consumed refresh tokens are kept, not deleted.** Deleting a spent token would make a replayed
token indistinguishable from one that never existed, and reuse detection (§6.8) depends on telling
those apart. A periodic sweep removes rows only once their family is past `absolute_exp`, by which
point replay is meaningless.

Migrations are forward-only numbered SQL files applied at startup inside a transaction, tracked in
`schema_version`.

---

## 6. Authentication & Authorization Design

### 6.1 Token format

**JWS Compact, HS256** (HMAC-SHA256), symmetric secret loaded from environment/config — never
committed, minimum 32 bytes, refused at startup if weaker.

```jsonc
// header
{ "alg": "HS256", "typ": "JWT" }

// payload
{
  "iss":   "platformservice",
  "sub":   "1234567890123",     // userId as string — JS-safe for large 64-bit values
  "aud":   "platformservice-api",
  "exp":   1755100800,
  "iat":   1755099900,
  "nbf":   1755099900,
  "jti":   "b1f0...",           // 128-bit CSPRNG, enables future revocation
  "roles": ["USER"]
}
```

Access token TTL **900s (15 min)**. Tokens are issued **only** to accounts in `ACTIVE` status.

> **Upgrade path.** HS256 is right for a single service — one secret, one verifier. The moment a
> second service must *verify* tokens this platform issues, that secret would have to be shared with
> every verifier, and any one of them could then mint tokens. Plan to move to **RS256/ES256** at that
> point so verifiers hold only the public key. Keeping `alg` handling centralized in `jwt.c` from day
> one makes that a contained change.

### 6.2 Verification order

Cheapest and most decisive checks first; **fail closed** at every step.

1. `Authorization: Bearer <token>` header present and well-formed
2. Exactly three base64url segments
3. Header decodes and **`alg` is literally `HS256`**
4. Recompute HMAC over `header.payload`; **constant-time** compare (`CRYPTO_memcmp`)
5. Validate `exp`, `nbf`, `iat` with ±60s clock skew
6. Validate `iss` and `aud` match configuration
7. Parse `sub` to `int64_t`; parse `roles`

> **Critical:** step 3 must never *dispatch on* the token's own `alg` field. Trusting attacker-supplied
> `alg` is the classic JWT break — `alg: "none"` yields a token that verifies with no signature, and
> algorithm confusion lets an attacker sign with a key the server treats as public. The expected
> algorithm is a **server-side constant**; the header's `alg` is only ever compared against it.
> Signature verification precedes claim parsing so untrusted bytes never reach the claim logic.

### 6.3 Password storage

**PBKDF2-HMAC-SHA256**, 600,000 iterations (current OWASP guidance), 16-byte CSPRNG salt, 32-byte
output. Iteration count stored per row so it can be raised later and rehashed on next login.

PBKDF2 is chosen over bcrypt/scrypt/Argon2 purely because it is available directly in OpenSSL under
decision D1. Argon2id is the stronger primitive; revisit if libsodium ever enters the dependency set.

### 6.4 Role model (D9 — flat)

Two roles in v1: `USER` and `ADMIN`. They are **independent labels with no inheritance** — holding
`ADMIN` does *not* imply `USER`.

```
alice  → USER
root   → USER, ADMIN     (both, granted explicitly)
svc    → ADMIN           (a service account with no self-serve access)
```

A role check asks exactly one question — *does this user hold role X?* — with no traversal and no
implied edges, so "who can reach this endpoint" is answerable by reading one table.

**Consequence to be aware of:** an `ADMIN`-only account still passes `GET /v1/users/{self}` because
that route's ownership branch matches on `sub` regardless of role. Ownership and role are independent
grants; either suffices.

Registration always grants exactly `USER`. There is no self-service path to `ADMIN`; the first and
only administrator is seeded at startup (§6.7).

### 6.5 RBAC policy engine — default deny (D10)

Declarative table rather than `if` statements scattered through handlers, so the whole security
posture is auditable in one screen:

```c
typedef enum { POLICY_PUBLIC, POLICY_AUTHENTICATED,
               POLICY_ROLE, POLICY_SELF_OR_ROLE } policy_kind_t;

typedef struct {
    const char   *method;
    const char   *path_pattern;   /* "/v1/users/{userId}" */
    policy_kind_t kind;
    const char   *required_role;  /* NULL when not applicable */
} route_policy_t;

static const route_policy_t POLICIES[] = {
  /* ---- public allowlist: exactly seven routes, nothing else ---- */
  { "POST", "/v1/auth/register",            POLICY_PUBLIC,  NULL    },
  { "POST", "/v1/auth/verify",              POLICY_PUBLIC,  NULL    },
  { "POST", "/v1/auth/resend-verification", POLICY_PUBLIC,  NULL    },
  { "POST", "/v1/auth/login",               POLICY_PUBLIC,  NULL    },
  { "POST", "/v1/auth/refresh",             POLICY_PUBLIC,  NULL    },
  { "GET",  "/healthz",                     POLICY_PUBLIC,  NULL    },
  { "GET",  "/readyz",                      POLICY_PUBLIC,  NULL    },
  /* ---- everything below requires a valid access token ---- */
  { "POST", "/v1/auth/logout",              POLICY_AUTHENTICATED, NULL },
  { "POST", "/v1/auth/password",            POLICY_AUTHENTICATED, NULL },
  { "GET",  "/v1/users/{userId}",     POLICY_SELF_OR_ROLE,  "ADMIN" },
  { "GET",  "/v1/admin/users/count",  POLICY_ROLE,          "ADMIN" },
  { "GET",  "/v1/admin/users",        POLICY_ROLE,          "ADMIN" },
};
```

**Default deny is structural, not conventional.** The lookup returns "no policy" for any unlisted
route, and the middleware treats that as `401`/`403` — never as "allow". Adding a handler without
adding a policy row makes the endpoint **unreachable**, which is the correct failure direction: a
forgotten policy costs an outage, not a breach.

The five public auth routes are public by necessity — a caller with no account and no access token
could not otherwise obtain one, and a user whose verification link expired could not recover.
`/v1/auth/refresh` is listed public because it carries no `Authorization` header, but it demands a
valid refresh token in the body and is not open in any practical sense. `/healthz` and `/readyz` are
public by explicit choice for operational probing, and return only status with no internal detail.

`POLICY_SELF_OR_ROLE` is the ownership case from §4.8: pass if `claims.sub == path.userId`, else pass
if the caller holds the role, else 403.

> Enforced by test, not by discipline: §8.3 enumerates every route the router registers and asserts
> that each one absent from the public allowlist returns `401` when called with no token. A new
> endpoint that forgets its policy fails that test.

### 6.6 Registration & verification workflow (D8)

```
POST /v1/auth/register
  ├─ validate username charset/length, email syntax/length, password policy
  ├─ normalize: username → ASCII lowercase;  email → trim + ASCII lowercase
  ├─ hash password (PBKDF2, under the KDF semaphore)
  ├─ INSERT user (status = PENDING_VERIFICATION) ─┐
  │    relying on UNIQUE constraints, in a txn    │ atomic
  ├─ INSERT user_roles (USER)                     │
  ├─ generate 256-bit CSPRNG token                │
  ├─ INSERT sha256(token) into verification table ┘
  ├─ hand the RAW token to the mailer interface (v1 → dev_outbox)
  └─ 202 Accepted

POST /v1/auth/verify
  ├─ sha256(submitted token) → primary-key lookup
  ├─ reject if absent, expired, or consumed_at IS NOT NULL   → 400 INVALID_TOKEN
  ├─ set consumed_at, set user status = ACTIVE                (one txn)
  └─ 200 { "status": "ACTIVE" }
```

> **No mail server in v1 — decided, not pending.** The `dev_outbox` table *is* the delivery
> mechanism. Nothing sends SMTP, nothing connects outbound, and the service has no mail dependency to
> configure or fail on. `mailer.h` stays a two-function interface (`send`, plus an error return) so a
> real transport can be added later without touching registration logic, but choosing that transport
> is explicitly out of scope. See §15 for how a human reads a verification link out of the outbox
> during a local demo.

**Token design.** 256 bits from `RAND_bytes`, base64url-encoded for the link. Stored as its
**SHA-256 hash**, so a database compromise yields no usable activation links. Lookup is by primary
key on the hash — an attacker cannot submit a partial token and learn anything from timing, because
the raw token is never compared byte-by-byte. TTL **24 hours**, single-use via `consumed_at`.

No password stretching is needed on the token itself (unlike a password) because it is 256 bits of
full-entropy random data, not a guessable human secret — a plain hash is sufficient and fast.

**Password policy** (NIST SP 800-63B, which favors length over composition):

| Rule | Value |
|---|---|
| Minimum length | 12 characters |
| Maximum length | 128 characters — **accepted and hashed in full, never silently truncated** |
| Allowed characters | all printable Unicode including spaces; hashed as **raw UTF-8 bytes** |
| Composition rules | **none** — no forced upper/lower/digit/symbol mix |
| Breach denylist | rejected if present in the bundled list (see below) |
| Forced rotation | none |

Composition rules are deliberately omitted: they push users toward predictable patterns like
`Password1!` while blocking genuinely strong passphrases, and current NIST guidance recommends
against them. Length plus a breach denylist does more real work.

**No Unicode normalization — and this is a D1 consequence, not an oversight.** Earlier drafts
specified NFKC normalization. NFKC requires the full Unicode decomposition and compatibility tables,
which exist in neither the C standard library, OpenSSL, nor SQLite. Implementing it under D1 would
mean either adding ICU (a dependency violation) or hand-writing Unicode normalization (a project
larger than this service). So:

- **Passwords** are hashed as the raw UTF-8 bytes received. Normalization only matters when the same
  password is entered through input methods that emit different byte sequences for the same glyphs —
  a rare case, and the near-universal behavior of real deployments is to hash the bytes as sent.
- **Usernames** never needed it: the `[a-z0-9_-]` allowlist (§7.6) is pure ASCII, so ASCII
  lowercasing is exact. The allowlist already does the job NFKC would have done — rejecting
  homoglyphs and confusables — and does it more decisively.

**Breach denylist asset.** `data/common-passwords.txt` — the **top 10,000** passwords from a public
breach corpus (SecLists `Passwords/Common-Credentials/10k-most-common.txt`), one per line, lowercase,
LF-terminated, sorted unique, and committed to the repository (10,000 entries, 73 KB). Loaded into a hash set at startup; lookup is on the
lowercased candidate. Ten thousand entries catch the overwhelming majority of real-world guessing
attempts while staying small enough to bundle and load instantly. A k-anonymity API lookup against a
live breach service would cover more, but adds a network dependency on the registration path and is
therefore out of scope for v1.

### 6.7 Admin bootstrap (D11)

Because registration can never grant `ADMIN`, a fresh database would otherwise contain no
administrator and the admin endpoints would be permanently unreachable. One admin is therefore seeded
at startup.

```
on startup, inside the migration transaction:
  ├─ count users holding the ADMIN role
  ├─ if count > 0  → do nothing, log "admin present", continue     ← idempotent
  └─ if count == 0 → read BOOTSTRAP_ADMIN_{USERNAME,EMAIL,PASSWORD}
       ├─ any missing            → refuse to start, explain which
       ├─ password fails policy  → refuse to start
       ├─ create user, status = ACTIVE   (no verification e-mail)
       ├─ grant USER *and* ADMIN         (flat roles — D9, both explicit)
       ├─ log "bootstrap admin created: <username>"   (never the password)
       └─ OPENSSL_cleanse the password buffer
```

**Design rules, each load-bearing:**

- **Trigger is "no admin exists", not "database is new."** Keyed on the *absence of the thing being
  created*, so re-running is harmless and an admin accidentally deleted can be recovered by restart.
- **Credentials come from environment variables, not the config file.** Config files get committed;
  a `BOOTSTRAP_ADMIN_PASSWORD=` line in a repo is a permanent backdoor. The example config documents
  the variables without containing a value.
- **There is no default password.** Not `admin`, not `changeme`, not a generated-and-logged value.
  If the variables are absent on an admin-less database the service **refuses to start** with a clear
  message. A service that boots with known credentials is worse than one that does not boot.
- **The bootstrap password is subject to the full §6.6 policy**, breach denylist included. Bootstrap
  is not an exemption from the rules; it is the single most valuable account in the system.
- **Created `ACTIVE`, bypassing verification** — deliberate and safe. There is no mail transport at
  first boot and nobody to click a link, and the account's authenticity is established by possession
  of the server environment, which is strictly stronger evidence than control of an inbox.
- **Runs inside the migration transaction**, so a partially-created admin cannot survive a crash.

> **Known limitation, accepted for v1.** There is exactly one admin and no mechanism to promote a
> second — no `grant-role` CLI, no role-management endpoint. If that account is lost, recovery means
> direct database surgery. This is acceptable at v1 scale and is the natural first item for v2; see
> Risk R12.

### 6.8 Sessions & refresh tokens (D12)

Access token lifetime is a forced tradeoff: short is secure but forces constant re-login, long is
convenient but hands an attacker a stateless credential that cannot be revoked. Splitting the
credential in two resolves it.

| | Access token | Refresh token |
|---|---|---|
| Format | JWT (HS256) | **opaque, 256-bit CSPRNG** |
| Lifetime | 15 minutes | 30 days idle / 90 days absolute |
| Sent to | every endpoint | `/v1/auth/refresh` and `/v1/auth/logout` only |
| Validated by | signature, no I/O | database lookup |
| Revocable | no | **yes** |

The design inverts exposure and value: the credential that travels everywhere is nearly worthless
after 15 minutes, while the valuable one barely travels and can be killed server-side.

#### Refresh tokens are deliberately *not* JWTs

This is the most commonly botched part of the pattern. A JWT refresh token is self-validating, which
makes it **unrevocable** — precisely the property the design exists to buy. Since a refresh token
requires a database lookup on every use regardless, a JWT adds size and risk for nothing. Ours is 256
bits from `RAND_bytes`, base64url-encoded, and stored **SHA-256-hashed** exactly like verification
tokens (§6.6), so a database leak yields no usable sessions.

#### Rotation and reuse detection

Every refresh consumes the presented token and issues a new one. Rotation by itself is only
bookkeeping; what it *enables* is theft detection.

```
Login → R1                          family F, generation 1

Attacker steals R1 and refreshes first:
    R1 → R2(attacker)               R1 marked consumed

Real user then presents R1:
    R1 is ALREADY CONSUMED
        └── two parties hold the same token; one is a thief,
            and the server cannot tell which
        └── REVOKE THE ENTIRE FAMILY F  (R1, R2, all descendants)
        └── both parties must re-authenticate
```

Without this, a stolen refresh token grants **silent, indefinite** access — the thief simply keeps
rotating. With it, theft surfaces at the next refresh by *either* party, and the blast radius is one
session. Revoking the whole family rather than the reused token is the point: the attacker's `R2` is
a descendant, so nothing less would evict them.

This requires a **family identifier** on every token, so the lineage from one login can be revoked
together.

#### Two expiries, both required

- **Idle: 30 days.** Measured from last use. Sliding.
- **Absolute: 90 days.** Measured from the login that created the family, never extended.

The absolute cap is not optional. Rotation refreshes the idle window on every use, so without it a
session that is merely *used* stays alive forever — long past any reasonable claim that it is still
the same person at the keyboard.

#### Logout and revocation, obtained for free

`POST /v1/auth/logout` deletes the family. The next refresh fails and the access token expires on its
own within 15 minutes.

> This is a strictly better answer than the `jti` denylist floated earlier for revocation. The
> denylist would cost a database lookup on **every authenticated request** to catch a rare event.
> Session families give real revocation at **zero** per-request cost, because the access token stays
> stateless and simply expires quickly. Adding refresh tokens therefore resolves logout as a side
> effect rather than as extra work.

#### What is deliberately not done

**No IP or device binding.** It sounds protective and breaks real users — a phone moving from wifi to
cellular changes IP mid-session, and the resulting forced logouts train users to expect random
failures. Rotation with reuse detection catches the theft case without punishing mobility.

### 6.9 Account status lifecycle & lockout

Earlier drafts declared `DISABLED` and `LOCKED` in the schema and then never set either — states that
existed on paper and were unreachable in code. This defines who moves an account and when.

```
                  register
                     │
                     ▼
        PENDING_VERIFICATION ──verify──► ACTIVE ◄──────┐
                     │                    │  │         │
                     │                    │  └─ N failed logins ─┐
                     │                    │                      ▼
                     │                    │              locked_until set
                     │                    │              (still status=ACTIVE)
                     │                    │                      │
                     │                    │      ◄── window elapses, auto-clear
                     │                    ▼
                     └──────────────► DISABLED   (operator action only)
```

**Lockout is a timestamp, not a status.** `locked_until` is a column on an otherwise-`ACTIVE` account
rather than a `LOCKED` status value. A status would have to be actively cleared by something, which
means either an unlock endpoint or a support ticket; a timestamp expires on its own. `LOCKED` is
therefore removed from the status enum entirely.

| Setting | Default | Config key |
|---|---|---|
| Failed attempts before lock | 10 consecutive | `auth.lockout_threshold` |
| Lock duration | 15 minutes | `auth.lockout_duration_s` |
| Counter reset | on any successful login | — |

**Why a temporary lock and not a permanent one.** A hard lockout hands an attacker a denial-of-service
primitive: fail ten logins against any username and that person is locked out until an operator
intervenes. Do that across every account and you have taken down the service without guessing a single
password. Current OWASP and NIST guidance both favor temporary lockout or progressive delay for
exactly this reason. Fifteen minutes reduces an online guessing attack to roughly 40 attempts per hour
— useless for brute force — while a locked-out real user simply gets coffee.

> **A locked account is indistinguishable from a wrong password.** Login returns the same `401`, same
> body, same timing whether the password was wrong, the account is locked, unverified, disabled, or
> nonexistent (§7.4). Saying *"account locked"* would confirm the username exists and tell an attacker
> their spray is landing.

**`DISABLED` is operator-only in v1.** There is no admin endpoint to disable an account — consistent
with D11, which likewise ships no role-management endpoint. It is set by direct SQL or a future CLI,
and a disabled account cannot log in and has all session families revoked. Documented as a v2 gap
alongside admin promotion (R12).

### 6.10 Audit log

An identity service with administrators and no durable record of who did what is not defensible.
`audit_log` is **append-only** and deliberately separate from application logging: different purpose,
different retention, different consumer. Application logs are for debugging and rotate away; the audit
trail answers *"what happened to this account, and who did it"* weeks later.

**Events recorded:**

| Event | Actor | Notes |
|---|---|---|
| `REGISTER` | none | outcome distinguishes new account from duplicate-email no-op |
| `VERIFY` | none | success or invalid token |
| `RESEND_REQUESTED` | none | records that a request arrived, including throttled ones that sent nothing |
| `LOGIN` | the user | `SUCCESS` or `FAILURE`; failures carry a reason **in `detail`, never in the response** |
| `LOGOUT` | the user | family revoked |
| `PASSWORD_CHANGE` | the user | and the count of sessions revoked |
| `TOKEN_REFRESH` | the user | success only; failures land as `REFRESH_REUSE_DETECTED` or a plain failure |
| `REFRESH_REUSE_DETECTED` | the user | **high severity** — probable token theft (§6.8) |
| `ACCOUNT_LOCKED` | none | threshold reached |
| `ACCOUNT_DISABLED` | operator | out-of-band change observed at startup or by CLI |
| `ADMIN_USER_READ` | the admin | admin reading a record that is not their own |
| `ADMIN_USER_LIST` | the admin | includes the page range requested |
| `BOOTSTRAP_ADMIN_CREATED` | none | once per database, ever |

**Rules, each with a reason:**

- **No secrets, and no PII.** Never a password, token, or hash. Subjects are referenced by
  `user_id`, **not email address** — an audit table full of email addresses would quietly undo the
  §4.8 decision to disclose email only to its subject. `detail` is a small JSON object and is
  reviewed for leakage the same way responses are.
- **Audit writes for state changes share the transaction with the change itself.** If the account
  update commits, its audit row commits; if one rolls back, both do. Any other arrangement produces a
  trail that disagrees with the data, which is worse than no trail because it is trusted.
- **Read events are best-effort** and outside the transaction. Failing a user's request because an
  `ADMIN_USER_READ` row could not be written trades availability for a record of a read — the wrong
  way round.
- **Failed logins are audited with a reason; the response still says nothing.** This is the whole
  value of an audit log: the server knows the account was locked, the client is told only `401`.
- **Append-only by construction.** No `UPDATE` or `DELETE` statement against `audit_log` exists
  anywhere in the codebase except the retention sweep (§3.4). Enforced by the same CI grep that bans
  `strcpy`.
- **Retention** defaults to 365 days, config-driven, swept by the maintenance thread.

> Audit records are also the input to any future alerting. `REFRESH_REUSE_DETECTED` and a spike in
> `ACCOUNT_LOCKED` are the two events genuinely worth waking someone for, and both are recorded from
> day one even though v1 ships no alerting.

---

## 7. Security Requirements

### 7.1 Transport (D4 — in-process TLS)
- TLS 1.2 minimum, TLS 1.3 preferred; modern cipher suites only
- `SSL_CTX` built once at startup, shared across worker threads
- Cert and key paths from config; **self-signed dev cert** generated by a `make dev-cert` target
- Private key must be mode `0600` and owned by the service user — **startup refuses otherwise**
  (enforceable now that D2 is Linux-only)
- `SSL_shutdown` handled correctly on both graceful and abrupt close

### 7.2 Input handling — the C-specific risk surface
This is where C will bite if we are careless. Non-negotiable rules:

- **No unbounded string functions.** `strcpy`/`strcat`/`sprintf`/`gets` are banned; enforced by a grep
  check in CI. Use explicit-length variants with checked truncation.
- Every buffer carries its length; every parser takes `(ptr, len)`, never a bare `char *`.
- Request line ≤ 8 KB; headers ≤ 64 total, ≤ 16 KB combined; body ≤ 1 MB (`413` past that).
- `Content-Length` validated against bytes actually read; chunked encoding either fully implemented or
  explicitly rejected with `501` — never partially handled.
- JSON parser depth-capped (32) to prevent stack exhaustion from nested input.
- Read/write timeouts (30s) and an idle timeout to defeat slowloris.
- Every `malloc`/`calloc` return checked. Single owner per allocation, freed on **all** paths
  including errors — `goto cleanup` is the house style.

### 7.2a Connection handling, CORS, and shutdown

Three behaviors that were previously unstated and are cheapest to decide before the code exists.

**Keep-alive.** HTTP/1.1 is persistent by default, so this is not optional — a client that sends a
second request on the same connection must be served, not dropped.
- Persistent by default; honor `Connection: close` and close after responding
- **Cap requests per connection** (default 100) and idle time between them (default 15s), so one
  connection cannot monopolize a worker indefinitely
- On any parse error, respond and **close** — never attempt to resynchronize mid-stream, which is how
  request-smuggling bugs are born

**CORS: disabled by default, and off entirely in v1.** No `Access-Control-*` headers are emitted and
`OPTIONS` returns `405` unless an origin allowlist is configured. There is no browser client, and a
service that reflects arbitrary origins with credentials enabled is a straightforward account-takeover
vector. The configuration hook exists so the decision is a config change later, not a code change —
but **wildcard origin combined with credentials is refused at startup**, not merely discouraged.

**Graceful shutdown.** On `SIGTERM` / `SIGINT`:
1. `/readyz` starts failing immediately — the load balancer stops sending new traffic while the
   process is still serving what it has
2. Stop accepting new connections; keep draining in-flight requests
3. Wait up to a configurable grace period (default 30s) for workers to finish
4. Checkpoint WAL, close SQLite connections, free the `SSL_CTX`, exit `0`

Step 1 is the one that is usually missed, and it is the difference between a deploy that drops
requests and one that does not. A second signal during draining exits immediately.

### 7.3 The `userId` parameter specifically
`userId` arrives as untrusted text and becomes an `int64_t`:
- Parse with `strtoll`, pre-clearing and then checking `errno == ERANGE`
- Reject trailing garbage (`endptr` must land on the terminator)
- Reject empty input, lone `+`/`-`, and leading whitespace
- Explicit tests at `0`, `-1`, `INT64_MAX`, `INT64_MIN`, `INT64_MAX + 1`, and non-numeric input
- Always bind via `sqlite3_bind_int64` in a **prepared statement** — no string-built SQL anywhere

### 7.4 Anti-enumeration and abuse
- Login returns an identical response for unknown user, wrong password, **and unverified account**
- On unknown user, still run a **dummy PBKDF2** so response timing does not leak account existence
- Registration never confirms or denies email existence (§4.1); neither does resend (§4.3)
- Per-IP and per-username login rate limiting; per-IP and global registration rate limiting
  (token bucket, in-memory for v1)
- **Resend is limited per-email-address, not just per-IP** — the abuse target there is a third
  party's inbox, and per-IP limits do not protect them (§4.3)
- Passwords, tokens, secrets, and hashes are **never** logged; log a `jti` prefix, never the token.
  Verification tokens must not appear in logs, access logs, or error messages.
- Secrets zeroed with `OPENSSL_cleanse` after use — including the plaintext password buffer
  immediately after hashing

### 7.5 Response hygiene
- All JSON string output escaped by the serializer, no exceptions
- `500` bodies carry a correlation ID only; the detail goes to the server log
- Security headers: `Cache-Control: no-store` on authenticated responses, `X-Content-Type-Options: nosniff`

### 7.6 Registration-specific hardening

**Mass assignment.** The request parser reads **exactly three fields** — `username`, `email`,
`password` — from an explicit allowlist. Every other key in the body is discarded before the object
reaches any business logic. `userId`, `roles`, `status`, and `kdf_iters` are server-assigned, always.
A body of `{"username":"x","email":"y","password":"z","roles":["ADMIN"],"status":"ACTIVE"}` must
produce an ordinary pending `USER`. This is asserted directly in §8.2.

**Uniqueness races (TOCTOU).** Never `SELECT` to check availability and then `INSERT` — two
simultaneous registrations both see "available" and one violates the constraint, or worse, both
succeed under a weaker check. The `INSERT` runs inside a transaction and relies on the **database
`UNIQUE` constraints** as the sole arbiter, catching `SQLITE_CONSTRAINT_UNIQUE` and mapping it to the
right response (409 for username, the indistinguishable 202 for email).

**Identifier validation.**
- Username: 3–32 characters, allowlist `[a-z0-9_-]` after ASCII lowercasing, must start alphanumeric
- Reserved-name denylist: `admin`, `administrator`, `root`, `system`, `support`, `security`, `null`,
  `undefined`, and similar
- Confusable/mixed-script usernames rejected by the charset allowlist — restricting to ASCII
  lowercase sidesteps homoglyph impersonation (`раypal` in Cyrillic) entirely
- Email: ≤ 254 characters, must contain exactly one `@` with non-empty local and domain parts, and a
  dot in the domain. Validation stays **deliberately loose** — full RFC 5322 is famously
  unimplementable in practice and over-strict regexes reject valid addresses. Deliverability is
  proven by the verification email actually arriving, not by parsing.

**No auto-login.** Registration returns no JWT and no session. The account is unusable until verified,
so a signup with someone else's email address grants the attacker nothing.

### 7.7 KDF denial-of-service — a consequence of adding registration

600,000 PBKDF2 iterations is intentionally expensive: roughly **tens of milliseconds of pure CPU per
call**. That cost is a defense on a login endpoint, but registration now puts a *second*
unauthenticated endpoint in front of it, and an attacker who can trigger it freely converts the
service's own hardening into a CPU-exhaustion vector — a few hundred concurrent signups can saturate
every core and starve legitimate traffic.

Mitigations, all required:
- A **counting semaphore** bounds concurrent KDF operations to roughly `cpu_count`; work beyond that
  is **rejected with `503`**, never queued unboundedly (queueing converts CPU exhaustion into memory
  exhaustion — see §8.5)
- Aggressive per-IP rate limiting on both `register` and `login`, applied **before** the KDF is entered
- A global registration ceiling per minute, independent of source IP, so a distributed attempt still
  hits a wall
- Rate-limit rejections must be cheap: reject on the accept path, before hashing

§8.5 measures this directly — sustained registration load must not grow memory without bound.

---

## 8. Test Harness (Python 3.11+, pytest)

### 8.1 Shape
Black-box HTTP tests against the **real compiled binary**, so the tests exercise the socket, TLS, and
parser code paths a unit test would skip.

A session fixture: builds the binary, creates a temp SQLite DB, generates a dev cert, launches the
service on an ephemeral port, waits for `/healthz`, yields a client, then tears down and asserts a
clean exit. Every test run starts from a known dataset — no shared mutable state between runs.

Because registration is asynchronous by design, the fixture also exposes an **outbox reader** that
pulls the most recent verification token for an address straight out of `dev_outbox`. That is what
makes the signup → verify → login path testable end to end without SMTP.

```
tests/harness/
├── conftest.py             # build, launch, seed, outbox, teardown fixtures
├── client.py               # thin httpx wrapper, dev-cert trust
├── test_register.py
├── test_verify.py
├── test_resend.py
├── test_bootstrap_admin.py
├── test_login.py
├── test_refresh.py
├── test_logout.py
├── test_password_change.py
├── test_lockout.py
├── test_audit_log.py
├── test_maintenance.py
├── test_connection.py
├── test_jwt_security.py
├── test_get_user.py
├── test_rbac_matrix.py
├── test_default_deny.py
├── test_admin_count.py
├── test_admin_batch.py
├── test_input_validation.py
├── test_http_protocol.py
└── test_memory.py          # §8.5
```

Dependencies: `pytest`, `httpx`, `pytest-xdist`, `psutil`, in a venv with a pinned `requirements.txt`.

### 8.2 Coverage by area

**Registration**
- happy path → `202`, status `PENDING_VERIFICATION`, a token lands in the outbox
- **the account cannot log in before verification** → `401`
- duplicate email → `202` with a body **byte-identical** to the success case, and no new user row
- duplicate username → `409`
- **privilege escalation via mass assignment**: bodies carrying `"roles":["ADMIN"]`, `"status":"ACTIVE"`,
  `"userId":1`, and `"kdf_iters":1` each produce an ordinary pending `USER` with a server-assigned ID
- password policy: 11 chars → `400`; 12 → accepted; 128 → accepted and **verifiably not truncated**
  (login with the full 128-char password succeeds, login with its first 72 chars fails); a
  known-breached password → `400`
- username validation: too short, too long, illegal charset, leading non-alphanumeric, reserved names,
  Cyrillic homoglyphs
- email validation: no `@`, two `@`, empty local part, empty domain, no dot in domain, > 254 chars
- case-insensitive uniqueness: `S@Example.com` after `s@example.com` → `202`, no second row
- concurrent duplicate registration (N simultaneous identical requests) → exactly **one** row created
- rate limit trips → `429`
- no JWT is present anywhere in the response

**Verification**
- valid token → `200`, status `ACTIVE`, login now succeeds
- **replay**: the same token a second time → `400`
- expired token (clock injected via config) → `400`
- unknown/garbage/empty token → `400`, response indistinguishable from expired
- a token belonging to user A must not activate user B
- the raw token is **not** recoverable from the database (only its hash is stored)

**Resend verification**
- pending account → `202`, a **new** token appears in the outbox and works
- **prior tokens are invalidated** — the token from the original registration must now fail with `400`
- unregistered address → `202`, body byte-identical, **nothing written to the outbox**
- already-`ACTIVE` account → `202`, body byte-identical, **nothing written to the outbox**
- per-address rate limit: a second call within 60s returns `202` but sends nothing; the 6th call in
  24h likewise sends nothing
- **the per-address limit holds across different source IPs** — the anti-email-bombing property from
  §4.3, and the one a per-IP limiter would miss
- responses for unregistered, pending-but-throttled, and already-active are mutually indistinguishable

**Admin bootstrap (D11)**
- empty DB + valid `BOOTSTRAP_ADMIN_*` env → admin exists, holds **both** `USER` and `ADMIN`, status
  `ACTIVE`, and can immediately reach the admin endpoints
- **idempotence**: restarting against the same DB creates no second admin and does not alter the first
- missing any `BOOTSTRAP_ADMIN_*` variable on an admin-less DB → **service refuses to start**, with a
  message naming the missing variable and a non-zero exit code
- bootstrap password failing §6.6 policy → refuses to start
- the password appears in **no** log line, and not in the process's `/proc/<pid>/environ` after startup
- a DB that already has an admin starts cleanly with the `BOOTSTRAP_ADMIN_*` variables absent
- the bootstrap admin can log in normally through `POST /v1/auth/login`

**Login** — valid credentials; wrong password; unknown user; unverified account; disabled account;
missing fields; malformed JSON; token decodes to the right `sub` and `roles`; rate limit trips.

**Refresh & session lifecycle (D12)**
- login returns both an access token and a refresh token
- refresh returns a **new** access token *and* a **new** refresh token
- **the presented refresh token stops working immediately** after rotation
- a rotated access token carries the same `sub` and `roles` as the original
- a chain of 10 sequential rotations all succeed, and only the newest token is live
- **reuse detection**: replay a consumed token → `401`, **and the entire family is revoked** —
  the *newest* legitimately-issued token in that family also stops working
- reuse detection revokes only the affected family: a second concurrent login for the same user is
  unaffected, proving families are independent
- idle expiry: a token past `idle_exp` → `401` (clock injected via config)
- **absolute expiry: rotating continuously past `absolute_exp` still fails** — the cap cannot be
  extended by activity, which is the property that makes it meaningful
- unknown, empty, malformed, and truncated refresh tokens → `401`, all indistinguishable
- a refresh token is **not** accepted as a Bearer access token on any endpoint
- an access token is **not** accepted in the `refresh_token` field
- the raw refresh token is not recoverable from the database (only its hash is stored)

**Logout**
- `204`, then the refresh token fails and the whole family is dead
- logging out of family A leaves family B (a second device) working — the multi-device property
- logout with a refresh token belonging to **another user** → `403`, and that family stays live
- logout is idempotent: a second call still returns `204`
- after logout the access token still works until `exp` — documented and expected (§6.8), not a bug

**Password change (§4.7)**
- correct current password → `204`, old password no longer works, new one does
- **wrong current password → `401`**, and the password is unchanged
- **omitting `current_password` → `401`** — a valid access token alone must never suffice
- new password failing §6.6 policy → `400`, password unchanged
- **all other session families are revoked**: a refresh token from a second device stops working,
  while the session that performed the change keeps working
- the bootstrap admin can change its own password and log in with the new one (closing the D11 gap)
- rate-limited on the login counter

**Account lockout (§6.9)**
- 9 failed logins then a correct one → succeeds, and the counter resets to zero
- 10 failed logins → account locked; **the correct password now also returns `401`**
- the locked response is **byte-identical and time-comparable** to a wrong-password response — no
  `429`, no "locked" message, nothing that confirms the username exists
- lock expires after the configured window and login succeeds again with no operator action
- lockout is **per account, not per IP**: locking user A does not affect user B from the same IP,
  and failures from different IPs against one account still accumulate (this is the password-spray
  case rate limiting alone misses)
- a `DISABLED` account cannot log in and its refresh tokens are dead

**Audit log (§6.10)**
- each of login success, login failure, register, verify, password change, logout, and refresh writes
  exactly one row with the right `event`, `outcome`, and `target_user_id`
- `REFRESH_REUSE_DETECTED` is written when a consumed token is replayed
- `ADMIN_USER_READ` is written when an admin reads someone else's record, and **not** when a user
  reads their own
- **no audit row anywhere contains an email address, password, token, or hash** — asserted by
  scanning every row's `detail` and column values
- a rolled-back state change leaves **no** audit row (transactional consistency)
- a failed login records the reason in `detail` while the HTTP response still reveals nothing —
  compared directly in one test
- rows are append-only: no code path updates or deletes except the retention sweep

**Maintenance sweeper (§3.4)**
- expired verification tokens, families past `absolute_exp`, and old outbox rows are removed
- **a consumed refresh token inside a still-live family is NOT removed** — reuse detection depends on
  it, and this is the assertion that stops someone "optimizing" the sweep later
- audit rows inside the retention window survive; older ones do not
- sweeping a large table proceeds in batches and does not block concurrent requests beyond a
  configured bound

**Connection handling (§7.2a)**
- two sequential requests on one keep-alive connection both succeed
- `Connection: close` closes after the response
- the per-connection request cap is enforced
- a parse error closes the connection rather than resynchronizing
- no `Access-Control-*` header is emitted by default, and `OPTIONS` returns `405`
- graceful shutdown: `/readyz` fails while an in-flight request still completes successfully

**JWT security** *(negative-first — these are the tests that matter)*
- `alg: "none"` with signature stripped → 401
- signature from a different secret → 401
- payload mutated, original signature retained → 401
- role escalated to `ADMIN` inside the payload → 401
- expired `exp`; future `nbf`; wrong `iss`; wrong `aud`
- token from a *different* user replayed against another user's record
- garbage, empty, two-segment, and four-segment tokens
- `Bearer` missing, lowercase, or duplicated

**RBAC matrix** — every (caller, target, endpoint) combination asserted explicitly:

| Caller | `GET /users/{self}` | `GET /users/{other}` | `/admin/users/count` | `/admin/users` |
|---|---|---|---|---|
| No token | 401 | 401 | 401 | 401 |
| Unverified user | 401 | 401 | 401 | 401 |
| USER | **200** | **403** | 403 | 403 |
| ADMIN | 200 | **200** | **200** | **200** |

Plus a D9 case: an `ADMIN`-only account (not holding `USER`) still reads its own record — confirming
ownership and role are independent grants.

**PII disclosure boundary (§4.7)** — asserted by field, not by status code:
- owner reading self → body **contains** `email`
- admin reading another user → `200`, and the body **does not contain an `email` key at all** (not
  null, not empty string — absent)
- admin reading *their own* record → contains `email`, since they are the subject
- the batch listing (§4.9) contains no `email` for any row
- no endpoint outside `GET /v1/users/{self}` emits an email address anywhere in its response

**Batch listing** — seeded with **2500+ users** so paging is genuinely exercised:
- full walk via `nextAfterId` returns every user exactly once, no gaps, no duplicates
- page 1 and 2 return exactly 1000; final page returns the remainder with `hasMore: false`
- `limit` above 1000 is clamped to 1000, not honored
- `limit` of 0, negative, and non-numeric handled
- `after_id` beyond the last user returns an empty list, not an error
- response contains **no** email field
- ordering is strictly ascending and stable across repeated calls

**Input validation** — the §7.3 boundary set, plus oversized bodies, oversized headers, and
depth-bombed JSON.

**HTTP protocol** — unknown method → 405; unknown path → 404; missing `Content-Type`; truncated body
vs `Content-Length`; pipelined requests; abrupt disconnect mid-request.

### 8.3 Default-deny suite (`test_default_deny.py`)

Enforces D10 structurally rather than by inspection. The service exposes its route table under a
debug build flag; the test reads it and asserts:

1. Every registered route **not** in the seven-entry public allowlist returns `401` with no token.
2. The public allowlist contains **exactly** `POST /v1/auth/register`, `POST /v1/auth/verify`,
   `POST /v1/auth/resend-verification`, `POST /v1/auth/login`, `POST /v1/auth/refresh`,
   `GET /healthz`, `GET /readyz` — a new public route fails the test until deliberately added here.
3. A route registered with no policy entry is unreachable (`401`/`403`), never open.

This is the test that catches the dangerous mistake — shipping a handler whose policy row was
forgotten.

### 8.4 Dedicated IDOR suite

Per the §4.8 design note, `test_get_user.py` asserts the ownership decision derives **only** from the
verified token's `sub` — never from a body field, query parameter, or header. Includes attempts to
override identity via `X-User-Id`, a `userId` in the body, a duplicated query parameter, and a
path-traversal-style `/v1/users/1001/../1002`.

### 8.5 Memory footprint testing (`test_memory.py`)

D2 being Linux-only is what makes this practical: `/proc/<pid>/status` gives exact `VmRSS` and
`VmHWM`, and Valgrind runs natively.

**Measurement method.** `tools/memprobe.py` samples the service PID via `psutil` and `/proc`,
recording `VmRSS` (current resident), `VmHWM` (peak resident since start), and heap size. Samples are
taken at defined points rather than continuously, so results are reproducible.

**Budgets** *(v1.0 initial targets; calibrated against real measurements in phase 3 — v1.8 — and now
frozen as regression gates. "Measured" is a single dev-machine run, 8 cores, no DB open yet — schema
lands in phase 5, so "DB open" is not yet part of the idle scenario; that column will be re-measured
once it is)*:

| Scenario | Metric | Budget | Measured (v1.8) |
|---|---|---|---|
| Idle, post-startup | `VmRSS` | ≤ 16 MB | 8.9 MB |
| Per established TLS connection | marginal `VmRSS` | ≤ 256 KB | 103 KB |
| 100 concurrent idle connections | `VmRSS` | ≤ 48 MB | 20.0 MB |
| Peak during a 1000-row batch response | `VmHWM` delta | ≤ 8 MB | *deferred — no batch endpoint until phase 8* |
| After 10,000 sequential requests, back to idle | `VmRSS` vs. baseline | ≤ +2 MB | +0.90 MB *(against `/healthz`; re-measure against an authenticated path once phase 7 lands)* |
| Sustained registration load (KDF path) | `VmRSS` | bounded, no monotonic growth | *deferred — no registration endpoint until phase 6* |
| 1000 connect/TLS-handshake/disconnect cycles | `VmRSS` vs. baseline | ≤ +2 MB *(v1.8, added to match test 8 below)* | +0.91 MB |

**Tests**

1. **Idle baseline** *(implemented, phase 3)* — start, settle, sample. Regression gate on startup
   footprint.
2. **Per-connection cost** *(implemented, phase 3)* — sample at 0, 10, 50, 100 open TLS connections;
   assert the marginal cost per connection stays within budget and is roughly linear. Catches
   per-connection buffers that are larger than intended.
3. **Leak canary** *(implemented, phase 3, adapted)* — the plan's original shape is 10,000 sequential
   **authenticated** requests; login doesn't exist until phase 7, so phase 3 runs this against
   `/healthz` instead and it will be tightened to the real authenticated path once phase 7 lands. Then
   let connections close and settle. RSS must return to within +2 MB of baseline. A steady climb across
   the run is the classic signature of a per-request allocation that is never freed, and this is the
   single highest-value memory test in the suite.
4. **Batch-response peak** *(deferred to phase 8 — needs the admin listing endpoint)* — the 1000-row
   admin listing is the largest single response the service produces (~60–80 KB of JSON). Sample
   `VmHWM` before and after. This measures whether the serializer builds the response in one growing
   buffer or streams it, and asserts that a large page does not cause a disproportionate spike.
5. **Batch scaling** *(deferred to phase 8 — needs the admin listing endpoint)* — compare peak for
   `limit=10` against `limit=1000`. Growth must be roughly linear in row count, not quadratic;
   quadratic indicates repeated buffer reallocation without amortized growth.
6. **KDF-path memory under load** *(deferred to phase 6 — needs registration)* — sustained concurrent
   registrations while the semaphore (§7.7) sheds excess with `503`. Asserts rejected requests are
   *rejected*, not *queued*: memory must stay flat, confirming the DoS mitigation does not convert a
   CPU problem into a memory problem.
7. **Error-path leaks** *(deferred to phase 6/7 — needs registration and token endpoints)* —
   malformed JSON, oversized bodies, bad tokens, and failed registrations in a loop. Error paths are
   where `goto cleanup` discipline breaks down and are consistently the least-tested allocation paths
   in C services.
8. **Connection-churn** *(implemented, phase 3)* — 1000 connect/TLS-handshake/disconnect cycles. `SSL`
   object leaks are a common and expensive failure that steady-state request tests miss entirely.

**Tooling beyond the pytest suite**

- `valgrind --leak-check=full --show-leak-kinds=all --errors-for-leak-kinds=definite,indirect` over a
  scripted full-API exercise. **Gate: zero definite and zero indirect leaks.** Still-reachable
  allocations held for process lifetime are acceptable and documented.
- `valgrind --tool=massif` for a heap profile over the same run, to attribute peak usage to specific
  call sites. Run per phase, not per commit — it is slow.
- **ASan + LSan** (`-fsanitize=address`) on every CI run — cheaper than Valgrind and catches overflows
  as well as leaks.
- **UBSan** (`-fsanitize=undefined`) alongside, for the integer and pointer UB that C makes easy.
- A `make memcheck` target running the Valgrind pass, so it is one command locally.

Memory results are recorded per phase in `plans/`, so a regression is visible as a number moving
rather than discovered when the service falls over in production.

### 8.6 Fuzzing the hand-written parsers

The HTTP/1.1 parser and the JSON parser are hand-written C consuming untrusted bytes from the network.
That is the highest-risk code in the project, and example-based tests only find the malformed inputs
someone thought to write down. **Fuzzing generates the inputs nobody thought of**, which is precisely
the gap.

- **libFuzzer targets** (`-fsanitize=fuzzer,address,undefined`) against three entry points, each
  taking `(const uint8_t *data, size_t len)` and doing nothing but parse:
  `http_request_parse`, `json_parse`, and `jwt_decode`
- **Corpus seeded from the harness** — capture real request bytes during a §8.2 run and use them as
  the starting corpus, so the fuzzer begins from valid structure and mutates outward rather than
  spending hours rediscovering that requests start with a verb
- **Dictionary** of HTTP tokens (methods, header names, `\r\n`, `Content-Length`) to reach deep states
- Any crash, hang, OOM, or sanitizer report is a **hard failure**; the reproducer is committed to
  `tests/fuzz/corpus/regressions/` so it becomes a permanent unit test
- Runs briefly on every CI run (60s smoke) and long-form nightly (§16.1)

This is the single highest-value security investment available for this codebase — cheaper than a
code audit, and it does not get bored.

**CI-only, by necessity (v1.7).** libFuzzer requires Clang, and the confirmed dev toolchain (§2) is
GCC only — `-fsanitize=fuzzer` is simply not a flag GCC understands. Rather than add a second compiler
to local dev setup for one feature, the `fuzz-smoke`/`fuzz-long` CI jobs install Clang for themselves,
scoped to those jobs only; every other job (build, sanitizers, memory, valgrind) stays GCC, matching
the dev machine exactly. The practical consequence: `make fuzz` and `make fuzz-smoke` need Clang on
PATH to build at all, `tests/fuzz/` targets are Clang-only translation units (built with their own
sanitizer flags, isolated from the main `build/` tree the same way `SANFLAGS` already is — see the
Makefile), and a contributor without Clang installed simply doesn't run them locally, the same way
nobody runs the Python harness without a venv. Corpus regressions committed under
`tests/fuzz/corpus/regressions/` (from a crash CI found) are still just C unit-test-shaped inputs
once captured, so replaying one manually never requires Clang.

### 8.7 Tooling
- `tools/seed_users.py` — generate N users with deterministic, reproducible data, writing rows
  directly (bypassing PBKDF2 with a low iteration count for seeded fixtures, so a 2500-user seed does
  not take minutes)
- `tools/memprobe.py` — the §8.5 sampler
- C unit tests under `tests/unit/` for the pure functions where black-box coverage is weak:
  base64url round-trip, JSON parser edge cases, `strtoll` wrapper, HMAC against RFC 4231 vectors,
  password-policy predicate, username normalization
- Run under **ASan + UBSan** in CI — the highest-value single quality lever available for a C service

---

## 9. Phased Delivery

Each phase ends in something runnable and demonstrable.

| # | Phase | Deliverable | Exit criteria |
|---|---|---|---|
| 0 | Environment | Linux toolchain, `plans/`, this document, setup guide | ✅ **Done** — Ubuntu 26.04 / GCC 15.2.0 / OpenSSL 3.5.5 / SQLite 3.46.1 / Valgrind 3.26.0 / Python 3.14.4; smoke test clean under `-Werror`, Valgrind clean |
| 1 | Scaffolding & build | Makefile, tree, config, logging, `main.c` | `make` produces a binary that starts and exits cleanly on Linux |
| 2 | Platform foundation | POSIX sockets, TLS, thread pool, **keep-alive**, **graceful shutdown** (§7.2a) | TLS listener serves two requests on one connection; `SIGTERM` drains in-flight work and exits 0 |
| 3 | HTTP core | Parser, router, response writer, JSON, **CORS-off default**, `/healthz` + `/readyz` | Both probes return real JSON over TLS; **memory baselines captured and budgets calibrated (§8.5)** |
| 4 | Crypto & JWT | HMAC, PBKDF2, base64url, encode/verify | Unit tests pass RFC 4231 vectors; round-trip verified |
| 5 | Data layer | Schema, migrations, connection pool, queries, **audit store (§6.10)**, **maintenance thread (§3.4)** | DB created on boot; seeded users queryable; audit rows written transactionally; sweeper removes expired rows in batches |
| 6 | Registration & verification | `register`, `verify`, `resend-verification`, mailer interface, dev outbox, password policy, **admin bootstrap (D11)** | Signup → outbox token → verify → `ACTIVE`; resend invalidates prior tokens; mass-assignment tests pass; bootstrap admin seeded idempotently and refuses to start without credentials |
| 7 | Login & sessions | `login`, `refresh`, `logout`, `password` change, rotation + reuse detection (D12), **lockout (§6.9)** | Valid creds on a **verified** account return a JWT and refresh token; unverified, locked, and unknown are mutually indistinguishable; replaying a consumed refresh token revokes the family; password change revokes other sessions |
| 8 | RBAC + user read | Policy engine, default deny, `GET /v1/users/{id}` | Full §8.2 RBAC matrix and the §8.3 default-deny suite pass |
| 9 | Admin methods | Count + batch list | 2500-user walk returns all rows, correctly paged |
| 10 | Harden & document | Sanitizers, Valgrind gate, **fuzzing (§8.6)**, rate limiting, README, LICENSE, API docs, backup notes | Clean ASan/UBSan/Valgrind run; **fuzzers survive a long-form run with zero crashes**; all §8.5 budgets met; full suite green |

The Python harness is **not** a final phase. It starts at phase 3 (`/healthz`) and grows with each
endpoint, so every phase lands with tests already written against it. Memory testing likewise starts
at phase 3, not phase 10 — baselines are only useful if they exist before the code that regresses them.

---

## 10. Risks

| ID | Risk | Impact | Mitigation |
|---|---|---|---|
| R1 | In-process TLS (D4) adds real complexity — cert lifecycle, handshake errors, thread-safe `SSL_CTX` | Slips phase 2 | Isolate entirely behind `platform/tls.c`; `make dev-cert` target; a plaintext fallback flag for local debugging only, refused when a production config is loaded |
| R2 | Memory safety defects — the dominant risk class in C | Critical vulnerability | Banned-function CI grep; length-carrying buffers; `goto cleanup` ownership; ASan/UBSan every CI run; Valgrind gate; §8.5 budgets |
| R3 | JWT verification subtly wrong (alg confusion, non-constant-time compare) | Auth bypass | Server-side constant `alg`; `CRYPTO_memcmp` only; negative-first test suite written **before** the implementation |
| R4 | IDOR on `GET /v1/users/{id}` | Data leak | Ownership from `sub` only; declarative policy table; dedicated suite §8.4 |
| R5 | Hand-written HTTP parser mishandles edge cases | Crash / smuggling | Strict caps; reject rather than guess; explicit `501` for unimplemented features; protocol abuse tests |
| R6 | SQLite write contention — registration and **refresh rotation** make the workload write-heavier than v1.0 assumed. Rotation writes on *every* refresh, i.e. once per active session per 15 min | Latency, `SQLITE_BUSY` | WAL mode; per-thread connections; busy-timeout configured; rotation is a single small transaction; Postgres remains an option behind `store/` |
| R7 | Scope creep from "services all kinds of needs" | Never ships | v1 is frozen to the listed methods; the extensibility proof is the *layering*, not extra features |
| R8 | Username enumeration via the `409` on registration | Minor information disclosure | Accepted knowingly (§4.1) — unavoidable without breaking signup UX. Bounded by per-IP and global rate limiting; usernames are already semi-public and carry no real-world identity |
| R9 | KDF CPU exhaustion via unauthenticated registration | Denial of service | Bounded KDF semaphore shedding to `503`; pre-KDF rate limiting; global registration ceiling; verified by §8.5 test 6 |
| R10 | Mass assignment grants `ADMIN` at signup | **Privilege escalation** | Three-field parse allowlist; roles server-assigned; explicit negative tests in §8.2 |
| R11 | Verification tokens leak via logs or a DB dump | Account takeover | Tokens stored SHA-256-hashed; raw token never logged; single-use with 24h TTL |
| R12 | **Single point of administrative failure** — one bootstrap admin, no promotion mechanism (§6.7) | Total loss of admin access | Accepted for v1. Recovery is by restart against an admin-less DB, or direct SQL. A `grant-role` CLI is the first v2 item |
| R13 | Resend abused to flood a third party's inbox | Reputation damage, complicity in harassment | Per-**address** and global send limits enforced server-side, independent of source IP; throttled requests return the standard `202` and send nothing (§4.3) |
| R14 | Bootstrap credentials committed to the repo in a config file | Permanent backdoor | Credentials read from environment only; example config carries names, never values; `.gitignore` covers real config and `.env` (§13) |
| R15 | Refresh token stolen — a 30-day credential, far more valuable than an access token | Prolonged account access | Opaque and hashed at rest; single-use rotation; **reuse detection revokes the whole family**, capping silent theft at one refresh cycle; absolute 90-day ceiling (§6.8) |
| R16 | Rotation race — two legitimate concurrent refreshes from one client trip reuse detection and log the user out | Spurious forced logout | Rotation is a single atomic transaction; a short grace window on the immediately-prior generation is the fallback if telemetry shows real clients hitting this. **Deliberately not implemented up front** — a grace window is a hole in reuse detection and is only worth opening against evidence |
| R17 | **Lockout used as a denial-of-service weapon** — fail 10 logins against any username to lock that person out | Targeted or mass account denial | Lock is **temporary and self-clearing** (15 min), never permanent; no operator action needed; per-account counters sit behind per-IP rate limiting, so mass lockout requires sustained volume that trips the limiter first (§6.9) |
| R18 | Rate-limiter table grows unbounded as an attacker cycles source IPs — the DoS defense becomes a memory-exhaustion vector | Service death | Bounded capacity with LRU eviction, tested under IP churn; sharded locking keeps eviction cheap (§3.5) |
| R19 | Audit log leaks the PII that §4.8 withholds, or diverges from actual state | Privacy breach; untrustworthy trail | Subjects referenced by `user_id` only, never email; `detail` reviewed like a response body; state-change audits share the transaction with the change; asserted by test (§8.2) |
| R20 | Maintenance sweep holds the WAL write lock and stalls all workers | Self-inflicted outage | Bounded batches with yields between them; sweep interval and batch size configurable; concurrency asserted by test (§3.4) |
| R21 | **JWT signing key cannot be rotated without invalidating every session** — no `kid`, single key | Forced mass logout, or a compromised key left in service | **Accepted for v1.** Deferred to v2: a `kid` header plus an accepted-keys list allows overlap during rotation. Noted now because retrofitting `kid` after tokens are in the wild is harder than shipping it |

---

## 11. Open Questions

### Resolved

- ~~**How does anyone become an ADMIN?**~~ → **D11**: one admin seeded at first startup (§6.7).
- ~~**Resend verification?**~~ → **In.** `POST /v1/auth/resend-verification` (§4.3).
- ~~**WSL2 + Ubuntu not installed.**~~ → Installed and verified; see §14 and `01-setup-and-prerequisites.md`.
- ~~**Refresh tokens?**~~ → **In.** **D12**: opaque, rotated, reuse-detected (§6.8).
- ~~**Logout / revocation?**~~ → **Resolved by D12.** Session families give real revocation at zero
  per-request cost; the `jti` denylist is no longer needed.

- ~~**Should an admin see another user's email?**~~ → **No.** Email is withheld from admins for PII
  reasons; disclosed only to its subject (§4.7).
- ~~**Production mail transport?**~~ → **Deferred.** v1 runs with **no mail server at all**; the dev
  outbox is the only delivery mechanism (§6.6). Transport choice is out of scope until a real
  deployment exists.

### Still open

**None.** All questions raised during planning are resolved. Items deliberately deferred to v2 are
tracked as risks rather than open questions: admin promotion (R12), refresh-rotation grace window
(R16), and real mail transport (§6.6).

---

## 12. Success Criteria for v1

1. `make` builds cleanly from scratch on Linux with `-Wall -Wextra -Werror`, zero warnings.
2. The service starts, serves TLS, and survives a clean shutdown with no leaks under ASan.
3. A new user can register, receive a token via the outbox, verify, and log in — and **cannot** log in
   before verifying.
4. Registration cannot be tricked into granting `ADMIN` or choosing its own `userId`.
5. Resend issues a working token, invalidates prior ones, and is indistinguishable across
   unregistered / pending / already-active addresses.
6. The bootstrap admin is seeded idempotently, and the service refuses to start on an admin-less
   database with no credentials supplied.
7. A valid login returns a JWT that opens the protected methods, plus a refresh token.
8. Refresh rotates both tokens; replaying a consumed refresh token revokes the entire session family;
   the absolute expiry cannot be extended by continued rotation.
9. Logout revokes one family and leaves a second device's session working.
10. A password change requires the current password, and revokes every other session.
11. Ten failed logins lock an account temporarily, the lock self-clears, and a locked account is
    indistinguishable from a wrong password.
12. Every security-relevant action writes an audit row, and **no audit row contains PII or secrets**.
13. The maintenance sweeper removes expired rows without removing consumed tokens in live families.
14. Fuzzers run clean against the HTTP, JSON, and JWT parsers.
8. The full §8.2 RBAC matrix passes, including every negative case.
9. Every route outside the seven-entry public allowlist returns `401` without a token (§8.3).
10. A 2500-user dataset walks completely through the batch endpoint, 1000 at a time, no gaps or
    duplicates.
11. Every JWT tampering test in §8.2 is rejected with 401.
12. All §8.5 memory budgets are met; Valgrind reports zero definite and zero indirect leaks.
13. The Python harness runs green end-to-end against a freshly built binary via a single command.

---

## 13. Repository & Git Hygiene

**The §3.2 tree is git-compatible.** It was checked against the things that actually break
repositories, and clears all of them:

| Check | Status |
|---|---|
| Case-only filename collisions (break on Windows/macOS checkout) | ✅ none — no two paths differ only by case |
| Windows-reserved names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`…) | ✅ none |
| Spaces, colons, or non-ASCII in paths | ✅ none — all lowercase ASCII with `_`, `-`, `.` |
| Deep nesting / long paths | ✅ max depth 4, well inside limits |
| Empty directories (git cannot track them) | ✅ every *tracked* directory holds at least one file. `certs/`, `build/`, and the runtime DB are created on demand and ignored — never committed as empty placeholders |
| Secrets in tracked files | ✅ by design — see below |
| Generated artifacts mixed into source dirs | ✅ objects build to `build/`, which is ignored |

Two files must exist **before the first commit**:

**`.gitignore`**
```gitignore
# build output
build/
*.o
*.d
platformservice

# database — including SQLite's WAL sidecars
*.db
*.db-wal
*.db-shm

# TLS material — never commit keys or certs, not even dev ones
*.pem
*.key
*.crt
*.csr
certs/

# real configuration and secrets (the .example file IS tracked)
config/platform.conf
.env

# python harness
.venv/
__pycache__/
.pytest_cache/
*.pyc

# tooling output
valgrind-*.log
massif.out.*
core
core.*
```

**`.gitattributes`**
```gitattributes
* text=auto eol=lf
*.sh  text eol=lf
*.c   text eol=lf
*.h   text eol=lf
*.py  text eol=lf
*.sql text eol=lf
Makefile text eol=lf
```

> **Why `.gitattributes` is not optional here.** The workflow is Windows editor → WSL2 build. If a
> `.sh` or `Makefile` picks up CRLF line endings, bash fails with an opaque `\r: command not found`
> and `make` reports a missing separator — errors that look like corruption and cost real time.
> Forcing LF at the repository level removes the failure mode entirely.

**Two things git cannot carry, which the setup script must handle:**

1. **File modes beyond the executable bit.** §7.1 requires the TLS private key be `0600`, and git
   records no such thing. Key generation and `chmod` belong to `make dev-cert`, never to a
   committed file — which is fine, since keys are ignored anyway.
2. **The dev certificate itself.** Each clone generates its own. A committed dev key is a real
   credential leak, even when labelled "dev only", because it grants a working TLS identity to
   anyone who reads the repo.

**Secrets policy.** `config/platform.conf.example` is tracked and documents every setting *by name
with no values*. The JWT signing secret and `BOOTSTRAP_ADMIN_PASSWORD` come from the environment
(D11, R14) and never appear in a tracked file. Reviewing this is worth doing once at first commit,
because a secret committed and later deleted is still in history forever.

---

## 14. Development Environment

Confirmed choices for this machine:

| Item | Value |
|---|---|
| Environment | WSL2 + Ubuntu (Docker deferred — no Dockerfile until phase 10) |
| Linux user | `stephen`, with passwordless sudo |
| Project location | `~/PlatformService` on the WSL **ext4** filesystem |
| Windows access | `\\wsl$\Ubuntu\home\stephen\PlatformService`, or VS Code "Connect to WSL" |

The project lives on ext4 rather than `/mnt/c` deliberately: compiles, `git status`, and pytest runs
cross the 9p filesystem bridge otherwise, which is slow enough to be felt on every iteration, and
file-watching is unreliable there.

Full reproducible setup instructions — for this machine or any other, Windows or Linux — are in
**`plans/01-setup-and-prerequisites.md`**.

---

## 15. Running Locally as a Demo

A design that cannot be demonstrated on a laptop is not finished. This section fixes the runtime
defaults the plan previously left unstated and defines the dev affordances that make a demo possible
**without a mail server, a CA, or a reverse proxy**.

### 15.1 Runtime defaults

Previously unspecified, and each would have blocked or degraded a first run:

| Setting | Default | Why |
|---|---|---|
| Listen port | **8443** | Ports below 1024 need root. Never default to 443 |
| Bind address | `127.0.0.1` | Loopback only unless explicitly overridden — a dev build must not be reachable from the LAN by accident |
| Database path | `./data/platform.db` | Created with its parent directory on first run |
| TLS cert / key | `./certs/dev-cert.pem`, `./certs/dev-key.pem` | Produced by `make dev-cert` |
| Access token TTL | 900s, **config-overridable** | A demo sets 60s to show rotation without waiting 15 minutes |
| Refresh idle / absolute | 30d / 90d, **config-overridable** | Same reason |
| Config file | optional | Every setting has a working default; absence is not an error |

**Every TTL and limit is config-driven.** Hardcoded durations make both the demo and the §8.2 expiry
tests impossible.

### 15.2 Dev mode

A single `dev_mode` flag, **off by default**, refused outright when a production config is loaded
(same gate as the §7.1 plaintext-TLS fallback). It changes exactly three things:

1. Logs the verification URL at `INFO` on registration and resend (§15.3)
2. Relaxes rate limits to a documented, still-finite set
3. Enables `GET /v1/dev/outbox` — the outbox as JSON

Nothing else. Dev mode must never alter authorization, token validation, password policy, or the PII
boundary — otherwise the demo stops demonstrating the real system.

### 15.3 The verification problem, solved three ways

With no mail server, a registered account is stuck in `PENDING_VERIFICATION` and **cannot log in**.
This is the single biggest obstacle to a local demo, so there are three escape hatches, in
increasing order of convenience:

```
1. SQL (always available, zero code):
     sqlite3 data/platform.db \
       "SELECT body FROM dev_outbox ORDER BY id DESC LIMIT 1;"

2. Server log (dev_mode only):
     INFO  verification link (dev_mode): https://localhost:8443/verify?token=3f9a...

3. make target (dev_mode only):
     make dev-verify EMAIL=demo@example.com
       -> reads the newest outbox entry, POSTs /v1/auth/verify, prints the result
```

Option 1 works even in a production-shaped build, which is what makes the outbox a genuine delivery
mechanism rather than a stub.

### 15.4 First-run sequence

```bash
make                                    # build
make dev-cert                           # self-signed cert, key chmod 600 (else startup refuses)
export PS_JWT_SECRET="$(openssl rand -base64 48)"
export BOOTSTRAP_ADMIN_USERNAME=admin
export BOOTSTRAP_ADMIN_EMAIL=admin@example.com
export BOOTSTRAP_ADMIN_PASSWORD='correct horse battery staple'
./platformservice --dev

# demo flow
curl -k -X POST https://localhost:8443/v1/auth/register \
     -d '{"username":"demo","email":"demo@example.com","password":"a long enough passphrase"}'
make dev-verify EMAIL=demo@example.com
curl -k -X POST https://localhost:8443/v1/auth/login -d '{"username":"demo","password":"..."}'
```

`make dev-env` writes an untracked `.env` with a generated secret and the bootstrap variables, so the
export block is one command in practice.

> **`-k` is required and expected.** The dev certificate is self-signed, so curl and browsers will
> refuse it without `-k` / an exception. This is TLS working correctly, not a defect. The Python
> harness pins the dev CA rather than disabling verification, so the tests still exercise real
> certificate validation (§8.1).

### 15.5 Demo-blocking issues found in review, and their resolution

| # | Issue | Severity | Resolution |
|---|---|---|---|
| 1 | Verified accounts unreachable with no mail server | **Blocker** | §15.3 — three retrieval paths |
| 2 | Service refuses to start without `PS_JWT_SECRET` and `BOOTSTRAP_ADMIN_*` | **Blocker** | Correct behavior, kept. `make dev-env` makes it one step (§15.4) |
| 3 | NFKC normalization is unimplementable under D1 | **Blocker** | Removed; ASCII allowlist supersedes it (§6.6) |
| 4 | Breach denylist source, size, and format unspecified | **Blocker** | `data/common-passwords.txt`, top 10k, committed (§6.6) |
| 5 | No default port, bind address, or DB path | High | §15.1 — 8443, loopback, `./data/platform.db` |
| 6 | TTLs hardcoded would make rotation undemonstrable and expiry untestable | High | All config-driven (§15.1) |
| 7 | Rate limits could trip during a live demo — resend is 1 per address per 60s | Medium | Relaxed under `dev_mode` (§15.2) |
| 8 | Self-signed cert rejected by clients | Low | Expected; `-k`, documented (§15.4) |
| 9 | TLS key must be `0600` or startup refuses | Low | `make dev-cert` chmods (§7.1) |
| 10 | 600k-iteration PBKDF2 makes a 2500-user seed take minutes | Low | Seeder writes low-iteration hashes directly; test-fixture path only, never production (§8.7) |

**Conclusion: nothing in the design blocks a local demo.** Items 1–4 were genuine gaps in the plan
and are now closed. The rest were unstated defaults, now stated.

---

## 16. Continuous Integration

The harness is well suited to CI by construction. Two earlier decisions do the work: the suite is
**black-box over TCP**, so CI builds a binary and talks to it with no test-only build variant; and
**D2 is Linux-only**, so `ubuntu-latest` *is* the target platform rather than an approximation.

Everything required is present on a stock runner — `build-essential`, `libssl-dev`, `libsqlite3-dev`,
`valgrind`, the `openssl` CLI for `make dev-cert`, Python 3.11+, and `/proc/<pid>/status` for the
§8.5 sampler. The two `fuzz-*` jobs additionally install **Clang** (v1.7) — nothing else does, and
`ubuntu-latest` carries it via one `apt-get install clang` line, not a custom image.

### 16.1 Job matrix

| Job | Build | Runs | Cadence |
|---|---|---|---|
| `build-and-test` | `-O2`, debug route table | Full harness, `dev_mode`, `xdist` parallel | every push/PR |
| `sanitizers` | `-fsanitize=address,undefined` | Full harness, **memory budgets excluded** | every push/PR |
| `memory` | `-O2`, no sanitizers | §8.5, ratio assertions gated | every push/PR |
| `rate-limits` | `-O2` | Throttle tests, **serial**, production limits | every push/PR |
| `valgrind` | `-O2 -g` | memcheck over a scripted full-API exercise | `main` + nightly |
| `fuzz-smoke` | Clang, `-fsanitize=fuzzer,address,undefined` | 60s per target from the committed corpus | every push/PR |
| `fuzz-long` | Clang, same | 30 min per target; new crashes filed and corpus updated | nightly |

Every job above `fuzz-*` builds with GCC, matching the dev machine exactly (§2). Only `fuzz-smoke` and
`fuzz-long` touch Clang, and only because libFuzzer leaves them no choice (§8.6, §16.2).

### 16.2 Three things that fail on the first run if unaddressed

**Rate limiting versus parallel tests.** Every `xdist` worker connects from `127.0.0.1`, and a per-IP
limiter cannot distinguish four workers from one attacker. Login and registration throttles trip
nondeterministically depending on scheduling; resend is worst at 1 per address per 60 seconds.

> Resolution: the parallel job runs under `dev_mode` with relaxed limits (§15.2). The throttles are
> still genuinely tested — the separate `rate-limits` job runs **serially with production limits**,
> which is the only configuration where those assertions are meaningful anyway.

**ASan and the memory budgets are mutually exclusive.** AddressSanitizer replaces `malloc` and adds
redzones plus a quarantine, inflating RSS several-fold. Running §8.5's `VmRSS` budgets against an
ASan build yields numbers that mean nothing.

> Resolution: two jobs, two builds. `sanitizers` proves correctness; `memory` measures footprint.
> Neither attempts the other's job.

**libFuzzer needs Clang; the confirmed dev toolchain is GCC only (v1.7).** `-fsanitize=fuzzer` is an
LLVM feature GCC has no equivalent for — it isn't a missing package, GCC simply doesn't implement it.
Discovered when phase 3 tried to build the fuzz targets on the GCC-only dev machine and the compiler
rejected the flag outright.

> Resolution: fuzzing stays CI-only. `fuzz-smoke` and `fuzz-long` install Clang for themselves and use
> it only for the three fuzz targets (`tests/fuzz/`), built into their own object directory so they
> never mix with the GCC-built `build/` tree. Every other job, and all of local dev, stays GCC-only —
> adding Clang to the base dev setup for one feature was rejected as more toolchain surface than the
> benefit justified, given the fuzz jobs can get it for free in CI. The tradeoff: a contributor without
> Clang installed cannot run `make fuzz` locally, only in CI, or after installing Clang themselves.

### 16.3 Portable versus absolute assertions

The §8.5 budgets are calibrated on the dev machine at phase 3. A runner differs in core count, glibc,
malloc arena behavior, and page-cache pressure, so absolute figures drift and gate on environment
rather than on code. Assertions are therefore split by kind:

| Kind | Example | Portable? | CI treatment |
|---|---|---|---|
| **Ratio / delta** | RSS returns to within +2 MB of baseline after 10k requests; peak scales linearly from `limit=10` to `limit=1000` | **Yes** | **Hard gate** |
| **Absolute** | idle ≤ 16 MB; ≤ 256 KB per connection | No | Recorded and trended; gated only against a CI-calibrated baseline |

This costs less than it appears. The leak canary and the linear-scaling check are the two
highest-value tests in §8.5, and both are ratio-based — so the assertions worth gating are exactly
the ones that travel between machines.

### 16.4 Configuration CI must pin

- **Thread pool size and KDF semaphore** default to `cpu_count`. A runner's core count differs from
  the dev machine, and §8.5 test 6 (KDF shedding to `503`) depends on saturating available cores.
  Both are set explicitly in CI rather than inherited from hardware.
- **`kdf_iters`** is lowered via config for the bulk of auth tests. At 600,000 iterations each call
  costs ~50–100 ms and there are dozens of auth tests. A small number of tests keep production
  iterations so the real cost path stays covered.
- **Clock injection** (already required by the §8.2 expiry tests) means no test sleeps to observe an
  expiry. Nothing in the suite should ever call `sleep` for a TTL.
- **Debug route table** must be enabled, or `test_default_deny.py` (§8.3) cannot enumerate routes.

### 16.5 Environment and artifacts

`PS_JWT_SECRET` and `BOOTSTRAP_ADMIN_*` are workflow `env:` values, **not** repository secrets — they
are throwaway test credentials, and storing them as secrets would falsely imply they guard something.
Real deployment credentials never enter CI.

Uploaded on failure: Valgrind logs, massif output, the service log, and the memory sample series.
Cached between runs: apt packages and the pip venv.

---

## Appendix A — Task status

> "The success condition for the first task is a Plan."

This document is that deliverable, now at **v1.6**: registration with verification and resend,
Linux-only targeting, default-deny authorization, a flat role model, a bootstrapped admin, rotating
refresh tokens with reuse detection, password change, temporary account lockout, an append-only audit
log, a maintenance sweeper, memory footprint testing, fuzzing, CI, git hygiene, and a documented local
demo path.

**Phase 0 is complete** — the Linux toolchain is installed and verified (§2, §14). **No open questions
remain** (§11); everything deferred is tracked as a risk with its reasoning recorded.

**Recommended next step:** initialize the git repository with the §13 files, then begin phase 1.
