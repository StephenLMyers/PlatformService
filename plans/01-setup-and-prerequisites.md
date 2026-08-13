# PlatformService — Setup & Prerequisites

**Purpose:** stand up a complete PlatformService development environment from nothing, on Windows or
Linux. Written to be followed by another engineer or another agent with no prior context.

**Companion to:** `00-project-plan.md` (architecture and requirements)
**Last verified:** 2026-08-13

---

## 0. What you are building toward

A C99 HTTP service with in-process TLS, backed by SQLite, tested by a Python harness. The target
platform is **Linux only** (plan decision D2). On Windows that means WSL2 — not MSYS2, not MinGW, not
Cygwin.

**End state of this document:** `gcc`, `make`, OpenSSL headers, SQLite headers, Valgrind, GDB, Python
3.11+, and git, all present in a Linux environment, verified by compiling and running a program that
actually links OpenSSL and SQLite.

---

## 1. Requirements

| Component | Minimum | Why |
|---|---|---|
| Linux | any current distro; Ubuntu 22.04+ verified | Plan decision D2 |
| GCC | 9+ (C99 with `_Static_assert`) | Compiler |
| GNU Make | 4.0+ | Build |
| OpenSSL dev headers | 1.1.1+, 3.x preferred | TLS, HMAC-SHA256, PBKDF2, CSPRNG |
| SQLite dev headers | 3.35+ | Storage; needs WAL and `RETURNING` |
| Valgrind | 3.15+ | Memory budgets, §8.5 of the plan |
| GDB | any | Debugging |
| Python | 3.11+ (3.13 verified) | Test harness |
| git | 2.30+ | Version control |

Roughly **3 GB** of disk for the toolchain, plus ~2 GB if installing WSL2 from scratch.

---

## 2. Path A — Windows host (WSL2)

Skip to §3 if you are already on Linux.

### 2.1 Check what you have

```powershell
wsl --status
wsl --list --verbose
```

WSL2 must be present and the default version must be `2`. A "Default Version: 2" line confirms it.

> **Gotcha encountered on the reference machine.** A WSL installation from 2022 (kernel 5.10) does
> not support `wsl --version` or the `--no-launch` flag. Without `--no-launch`, installing a distro
> immediately launches it and blocks on an interactive username/password prompt — which hangs any
> non-interactive or automated session. **Update WSL before installing a distro.**

### 2.2 Update WSL

```powershell
wsl --update
```

Expect `Windows Subsystem for Linux has been installed.` This may require elevation. If WSL was
never enabled at all:

```powershell
wsl --install --no-distribution
```

then reboot.

### 2.3 Install Ubuntu without the interactive prompt

```powershell
wsl --install -d Ubuntu --no-launch
```

`--no-launch` is what keeps this scriptable. The distro is registered but not started, so no
first-run account wizard appears.

### 2.4 Create the user non-interactively

Running as `root` avoids the wizard entirely, then we create the real user ourselves:

```powershell
$U = "stephen"   # change to taste

wsl -d Ubuntu -u root -- bash -lc "useradd -m -s /bin/bash $U && usermod -aG sudo $U"
wsl -d Ubuntu -u root -- bash -lc "echo '$U ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-$U && chmod 440 /etc/sudoers.d/90-$U"
wsl -d Ubuntu -u root -- bash -lc "printf '[user]\ndefault=$U\n' >> /etc/wsl.conf"
wsl --terminate Ubuntu
```

The `wsl.conf` entry makes `$U` the default login user; terminating forces it to take effect.

> **On passwordless sudo.** It keeps automated setup from blocking on password prompts. This is a
> single-developer machine, so the tradeoff is reasonable. If you would rather not, drop the
> `sudoers.d` line and run `wsl -d Ubuntu -u root passwd $U` to set a password, then expect to type
> it during §3.

Set a password anyway if the account will ever be reached over SSH:

```powershell
wsl -d Ubuntu -u root -- bash -lc "passwd $U"   # interactive — run from a real terminal
```

### 2.5 Verify

```powershell
wsl -d Ubuntu -- bash -lc "whoami; lsb_release -d"
```

Expect your username and an Ubuntu release line.

---

## 3. Install the toolchain

From inside Linux (`wsl -d Ubuntu` on Windows, or a normal shell on Linux):

### Debian / Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    libssl-dev \
    libsqlite3-dev \
    sqlite3 \
    pkg-config \
    valgrind \
    gdb \
    git \
    python3 \
    python3-venv \
    python3-pip \
    curl \
    ca-certificates
```

### Fedora / RHEL

```bash
sudo dnf install -y gcc make openssl-devel sqlite-devel sqlite pkgconf-pkg-config \
                    valgrind gdb git python3 python3-pip
```

### Arch

```bash
sudo pacman -S --needed base-devel openssl sqlite pkgconf valgrind gdb git python
```

> **The `-dev` / `-devel` packages are the ones that matter.** `libssl3` and `libsqlite3-0` ship the
> runtime libraries and are usually already present; without `libssl-dev` and `libsqlite3-dev` there
> are no headers and the build fails at `#include <openssl/hmac.h>`.

---

## 4. Verify the toolchain — do not skip this

Installing packages is not proof the build will work. Compile something that genuinely links both
libraries.

### 4.1 Versions

```bash
gcc --version | head -1
make --version | head -1
pkg-config --modversion openssl
pkg-config --modversion sqlite3
valgrind --version
python3 --version
git --version
```

### 4.2 Link test

```bash
cat > /tmp/smoke.c <<'EOF'
#include <stdio.h>
#include <stdint.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sqlite3.h>

int main(void) {
    unsigned char mac[32], salt[16];
    unsigned int len = 0;
    sqlite3 *db = NULL;

    HMAC(EVP_sha256(), "key", 3, (const unsigned char *)"msg", 3, mac, &len);
    printf("hmac-sha256 len=%u first_byte=%02x\n", len, mac[0]);
    printf("rand_bytes ok=%d\n", RAND_bytes(salt, (int)sizeof salt));
    printf("openssl=%s\n", OpenSSL_version(OPENSSL_VERSION_STRING));
    printf("sqlite=%s\n", sqlite3_libversion());
    printf("sqlite_open rc=%d\n", sqlite3_open(":memory:", &db));
    sqlite3_close(db);

    printf("sizeof(long)=%zu sizeof(int64_t)=%zu\n", sizeof(long), sizeof(int64_t));
    return 0;
}
EOF

gcc -std=c99 -Wall -Wextra -Werror /tmp/smoke.c -o /tmp/smoke \
    $(pkg-config --cflags --libs openssl sqlite3)
/tmp/smoke
```

**Expected output** (versions will differ):

```
hmac-sha256 len=32 first_byte=2d
rand_bytes ok=1
openssl=OpenSSL 3.x.x
sqlite=3.4x.x
sqlite_open rc=0
sizeof(long)=8 sizeof(int64_t)=8
```

Every line matters:

| Line | Confirms |
|---|---|
| `len=32` | HMAC-SHA256 links and produces a correct-width MAC |
| `rand_bytes ok=1` | CSPRNG works — required for salts, `jti`, and verification tokens |
| `sqlite_open rc=0` | SQLite links and opens a database |
| `sizeof(long)=8` | **LP64.** Confirms plan decision D7's premise. If this prints `4`, you are not on Linux — stop and re-read §2 |
| compiled under `-Werror` | The project builds with warnings as errors; the toolchain must be clean at that level |

### 4.3 Valgrind check

```bash
valgrind --leak-check=full --error-exitcode=1 /tmp/smoke
```

Expect `All heap blocks were freed` or only *still reachable* bytes from OpenSSL's one-time init.
**Definite** or **indirect** leaks here mean a broken Valgrind install, not a broken program.

```bash
rm -f /tmp/smoke /tmp/smoke.c
```

---

## 5. Project location

Place the repository on the **Linux filesystem**, not under `/mnt/c`:

```bash
cd ~
git clone <repo-url> PlatformService     # or: mkdir -p ~/PlatformService
cd ~/PlatformService
```

> **This is a performance decision, not a preference.** Files under `/mnt/c` are reached through the
> 9p protocol bridge. Compiles, `git status`, and pytest runs are several times slower there, and
> inotify-based file watching does not work reliably. Keep the source on ext4.

Reach it from Windows at:

```
\\wsl$\Ubuntu\home\<user>\PlatformService
```

VS Code: install the **WSL** extension and use *Connect to WSL* — the editor runs on Windows while
the language server, terminal, and build all run inside Linux.

---

## 6. Python harness environment

```bash
cd ~/PlatformService
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install pytest httpx pytest-xdist psutil
pip freeze > tests/harness/requirements.txt
```

`psutil` is required by the memory-footprint tests (plan §8.5); the others drive the black-box HTTP
suite. The venv is git-ignored.

---

## 7. Git initialization

If the repository is not yet initialized:

```bash
cd ~/PlatformService
git init
git config user.name  "Your Name"
git config user.email "you@example.com"
```

Create `.gitignore` and `.gitattributes` **before the first commit** — their contents are specified in
plan §13.

```bash
git add .gitattributes .gitignore
git commit -m "Add git hygiene files"
git add plans/
git commit -m "Add project plan and setup documentation"
```

> **`.gitattributes` first, deliberately.** It pins line endings to LF. Committing source before it
> exists risks CRLF entering history from a Windows editor, which surfaces later as
> `bash: \r: command not found` or `Makefile: missing separator` — errors that read like corruption.

**Never commit:** `*.pem`, `*.key`, `*.crt`, `config/platform.conf`, `.env`, or `*.db`. A secret
committed and later deleted remains in history permanently.

---

## 8. Environment variables

The service reads secrets from the environment, never from a tracked file (plan D11, R14).

| Variable | Required | Purpose |
|---|---|---|
| `PS_JWT_SECRET` | yes | HS256 signing key. **≥ 32 bytes**; startup refuses anything shorter |
| `BOOTSTRAP_ADMIN_USERNAME` | first run only | Seed admin username |
| `BOOTSTRAP_ADMIN_EMAIL` | first run only | Seed admin email |
| `BOOTSTRAP_ADMIN_PASSWORD` | first run only | Seed admin password — must pass the §6.6 policy |

The `BOOTSTRAP_ADMIN_*` set is read **only when the database contains no admin**. Once one exists they
are ignored and may be unset.

Generate a signing secret:

```bash
export PS_JWT_SECRET="$(openssl rand -base64 48)"
```

For local development put these in an untracked `.env` and source it. **There is no default password
for the bootstrap admin** — if the variables are missing on an admin-less database, the service
refuses to start rather than boot with known credentials.

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `wsl --version` → invalid option | WSL predates the flag | `wsl --update` (§2.2) |
| Distro install hangs with no output | Interactive account prompt | Install with `--no-launch`, create the user as root (§2.4) |
| `fatal error: openssl/hmac.h: No such file` | Runtime lib present, headers missing | Install `libssl-dev` / `openssl-devel` |
| `undefined reference to sqlite3_open` | Headers found, link flags absent | Append `$(pkg-config --libs sqlite3)` **after** the source files |
| `sizeof(long)=4` in the smoke test | Not running on 64-bit Linux | You are on a Windows toolchain — see §2 |
| `bash: \r: command not found` | CRLF endings in a shell script | `.gitattributes` per §7; fix with `dos2unix` |
| `Makefile: missing separator` | Spaces instead of a tab, or CRLF | Same as above |
| Builds are very slow | Source under `/mnt/c` | Move to `~/PlatformService` (§5) |
| `WSL_E_DEFAULT_DISTRO_NOT_FOUND` | Only `docker-desktop` distros registered | `wsl --set-default Ubuntu` |
| Valgrind reports OpenSSL leaks | One-time library init | *Still reachable* is expected; gate only on definite/indirect |

---

## 10. Verification checklist

Environment is ready when every line is true:

- [ ] `gcc --version` reports 9 or newer
- [ ] `pkg-config --modversion openssl` prints a version
- [ ] `pkg-config --modversion sqlite3` prints a version
- [ ] `valgrind --version` prints a version
- [ ] `python3 --version` reports 3.11 or newer
- [ ] `git --version` prints a version
- [ ] The §4.2 smoke test compiles under `-Wall -Wextra -Werror` with **zero warnings**
- [ ] The smoke test prints `len=32`, `rand_bytes ok=1`, `sqlite_open rc=0`
- [ ] The smoke test prints `sizeof(long)=8`
- [ ] Valgrind reports no definite or indirect leaks on it
- [ ] The project lives on the Linux filesystem, not `/mnt/c`
- [ ] `.gitignore` and `.gitattributes` exist and are committed
- [ ] `PS_JWT_SECRET` is set and at least 32 bytes

With all boxes ticked, phase 0 of the plan is complete and phase 1 can begin.

---

## Appendix — Reference machine

Recorded so drift is detectable later.

| | |
|---|---|
**Verified end to end on 2026-08-13.** Every version below was observed, not assumed.

| | |
|---|---|
| Host | Windows 10 Home 19045 |
| WSL | Updated 2026-08-13 from a 2022 build (kernel 5.10 → 6.18.33.2) |
| Distro | **Ubuntu 26.04 LTS**, installed via `wsl --install -d Ubuntu --no-launch` |
| Kernel | 6.18.33.2-microsoft-standard-WSL2 |
| Linux user | `stephen`, passwordless sudo, default login user |
| Project path | `~/PlatformService` (ext4) |
| GCC | 15.2.0 (Ubuntu 15.2.0-16ubuntu1) |
| GNU Make | 4.4.1 |
| OpenSSL (dev) | 3.5.5 |
| SQLite (dev) | 3.46.1 |
| Valgrind | 3.26.0 |
| Python | 3.14.4 |
| git | 2.53.0 |
| Host Python | 3.13.15 — the Windows-side install; the harness uses the Linux `python3` |

**Verification results:**
- Smoke test compiled under `-std=c99 -Wall -Wextra -Werror` with **zero warnings**
- `hmac-sha256 len=32`, `rand_bytes ok=1`, `sqlite_open rc=0`
- `sizeof(long)=8 sizeof(int64_t)=8 sizeof(void*)=8` — LP64 confirmed (plan D7)
- Valgrind: **0 definite, 0 indirect, 0 possibly lost**; 56 bytes still reachable from OpenSSL
  one-time init; `ERROR SUMMARY: 0 errors`; 6,778 allocs / 6,777 frees

**Superseded:** MSYS2 with GCC 16.2.0, OpenSSL 3.6.3, and SQLite 3.53.4 was installed on the Windows
host on 2026-08-13 and verified working, before plan decision D2 made the target Linux-only. It is
harmless but unused. Do **not** build the project with it — the code assumes POSIX sockets and has no
Winsock path.
