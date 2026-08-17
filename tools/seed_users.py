#!/usr/bin/env python3
"""
Seeds N deterministic, reproducible users directly into the users/
user_roles tables (plan 8.7) -- bypassing the real 600,000-iteration KDF
with a low iteration count, so a several-thousand-user seed takes seconds,
not minutes. This is a fixture generator for local testing/load work, never
a path a running service takes: it writes straight to the database file
with Python's stdlib sqlite3, the same way a human with the sqlite3 CLI
would, and expects the schema to already exist (start the service once
first -- migrations run on boot).

All seeded users share one fixed, documented password. Their salts and
password hashes are derived deterministically from the username, so
running this script twice against a fresh database produces byte-identical
rows -- useful for reproducible benchmarks and bug reports.
"""
import argparse
import hashlib
import sqlite3
import sys
import time

SEEDED_PASSWORD = "SeedPassword123!"
DEFAULT_ITERATIONS = 100  # real default (config auth.kdf_iterations) is 600,000
SALT_LEN = 16
HASH_LEN = 32


def derive_salt(username: str) -> bytes:
    """Deterministic, not random: same username always yields the same
    salt, so a re-run of this script is byte-for-byte reproducible."""
    return hashlib.sha256(f"platformservice-seed-salt:{username}".encode()).digest()[:SALT_LEN]


def derive_hash(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=HASH_LEN)


def schema_is_present(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'"
    ).fetchone()
    return row is not None


def seed(conn: sqlite3.Connection, count: int, start_index: int, iterations: int) -> int:
    now = int(time.time())
    inserted = 0
    for i in range(start_index, start_index + count):
        username = f"seeduser{i:05d}"
        email = f"{username}@example.test"
        salt = derive_salt(username)
        password_hash = derive_hash(SEEDED_PASSWORD, salt, iterations)

        cur = conn.execute(
            "INSERT OR IGNORE INTO users "
            "(username, email, email_normalized, password_hash, password_salt, kdf_iters, "
            " status, failed_logins, locked_until, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', 0, NULL, ?, ?)",
            (username, email, email, password_hash, salt, iterations, now, now),
        )
        if cur.rowcount == 0:
            continue  # already seeded (username collision) -- idempotent re-runs
        user_id = cur.lastrowid
        conn.execute(
            "INSERT INTO user_roles (user_id, role_id) SELECT ?, role_id FROM roles WHERE name = 'USER'",
            (user_id,),
        )
        inserted += 1
    return inserted


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db-path", default="./data/platform.db", help="SQLite file (default: %(default)s)")
    parser.add_argument("--count", type=int, default=100, help="number of users to seed (default: %(default)s)")
    parser.add_argument("--start-index", type=int, default=1,
                        help="first numeric suffix, for seeding in disjoint batches (default: %(default)s)")
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS,
                        help="PBKDF2 iterations -- low on purpose, never the real default (default: %(default)s)")
    args = parser.parse_args()

    if args.count < 1:
        print("--count must be at least 1", file=sys.stderr)
        return 1

    conn = sqlite3.connect(args.db_path)
    try:
        if not schema_is_present(conn):
            print(
                f"{args.db_path} has no `users` table yet -- start the service once first "
                "so migrations can run, then re-run this script.",
                file=sys.stderr,
            )
            return 1

        inserted = seed(conn, args.count, args.start_index, args.iterations)
        conn.commit()
    finally:
        conn.close()

    print(f"seeded {inserted} user(s) (skipped {args.count - inserted} already present) "
         f"into {args.db_path}")
    print(f"all seeded users share the password: {SEEDED_PASSWORD}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
