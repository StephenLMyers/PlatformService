# PlatformService

An extensible platform service written in C, starting with an identity module:
user registration with email verification, JWT authentication with rotating
refresh tokens, and role-based access control over a small set of user methods.

**Status:** phase 1 of 10 — scaffolding, configuration, logging, and lifecycle.
No listener yet; that arrives in phase 2.

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
make check-banned   # fail on unbounded string functions (strcpy, sprintf, ...)
make memcheck       # valgrind, gating on definite and indirect leaks
make dev-cert       # self-signed certificate; key written mode 0600
```

The build uses `-std=c99 -Wall -Wextra -Werror` plus `-Wshadow`,
`-Wcast-qual`, `-Wmissing-prototypes` and others. This codebase does not
accumulate warning debt.

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

## Licence

Not yet chosen — see plan phase 10.
