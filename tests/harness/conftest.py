"""
Black-box pytest harness (plan 8.1): builds the real compiled binary, runs
it as a subprocess with its own ephemeral port and throwaway dev cert, and
gives tests an httpx client talking real TLS to a real process -- no mocks,
no test-only build variant.
"""
import base64
import os
import signal
import socket
import ssl
import subprocess
import time
from pathlib import Path

import httpx
import pytest

from client import make_client

REPO_ROOT = Path(__file__).resolve().parents[2]
BINARY = REPO_ROOT / "build" / "platformservice"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def generate_dev_cert(cert_dir: Path) -> tuple[Path, Path]:
    """A throwaway self-signed cert, distinct from the developer's own
    certs/dev-cert.pem (make dev-cert) -- tests must never depend on
    whatever a developer happens to have generated locally."""
    cert_path = cert_dir / "cert.pem"
    key_path = cert_dir / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
            "-days", "1", "-nodes",
            "-keyout", str(key_path), "-out", str(cert_path),
            "-subj", "/CN=localhost/O=PlatformService Harness",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    key_path.chmod(0o600)
    return cert_path, key_path


#: Every harness-launched instance's bootstrap admin (plan 6.7) -- fixed,
#: not secret, exists only inside a throwaway per-test database.
BOOTSTRAP_USERNAME = "harnessadmin"
BOOTSTRAP_EMAIL = "harnessadmin@example.test"
BOOTSTRAP_PASSWORD = "harness bootstrap admin password"


def base_env(port: int, cert_path: Path, key_path: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PS_JWT_SECRET"] = base64.b64encode(os.urandom(48)).decode()
    env["PS_BIND_ADDRESS"] = "127.0.0.1"
    env["PS_PORT"] = str(port)
    env["PS_TLS_CERT_PATH"] = str(cert_path)
    env["PS_TLS_KEY_PATH"] = str(key_path)
    # Every caller already passes a per-instance work_dir via cert_path
    # (cert_path.parent); reusing it for the database means every
    # harness-launched instance gets its own file for free, with no new
    # parameter. Without this, every instance defaults to the same
    # ./data/platform.db -- harmless while only healthz/readyz existed,
    # but register/verify now write real, uniquely-checked rows that
    # different tests' instances would otherwise collide on.
    env["PS_DB_PATH"] = str(cert_path.parent / "platform.db")
    # A fresh per-test database has no administrator yet; main.c refuses to
    # start without these on an admin-less database (plan 6.7) -- every
    # harness-launched instance needs them, not just tests that use them.
    env["BOOTSTRAP_ADMIN_USERNAME"] = BOOTSTRAP_USERNAME
    env["BOOTSTRAP_ADMIN_EMAIL"] = BOOTSTRAP_EMAIL
    env["BOOTSTRAP_ADMIN_PASSWORD"] = BOOTSTRAP_PASSWORD
    # Real default is 600,000 (plan 6.3); every harness instance now pays
    # this once at startup for the bootstrap admin, so keep it fast the
    # same way tests/unit/test_password.c does -- this is test
    # infrastructure, not a security boundary.
    env["PS_KDF_ITERATIONS"] = "1000"
    return env


def wait_for_healthz(base_url: str, cert_path: Path, proc: subprocess.Popen,
                     timeout: float = 10.0) -> None:
    ctx = ssl.create_default_context(cafile=str(cert_path))
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            pytest.fail(f"service exited early with code {proc.returncode}")
        try:
            resp = httpx.get(f"{base_url}/healthz", verify=ctx, timeout=1.0)
            if resp.status_code == 200:
                return
        except httpx.HTTPError as exc:
            last_error = exc
        time.sleep(0.05)
    pytest.fail(f"service never became healthy within {timeout}s: {last_error}")


def stop_and_reap(proc: subprocess.Popen, log_path: Path, timeout: float = 10.0) -> int:
    """Sends SIGTERM and waits for a clean exit, matching the shutdown path
    main.c installs (plan 7.2a). Returns the exit code; fails the test on
    a timeout rather than leaking the process."""
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            return proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
            pytest.fail(
                f"service did not exit within {timeout}s of SIGTERM; log:\n"
                f"{log_path.read_text(errors='replace')}"
            )
    return proc.returncode


@pytest.fixture(scope="session")
def built_binary() -> Path:
    """Builds the real binary once per session -- the harness is black-box
    over exactly what a developer or CI would run, never a test-only build."""
    subprocess.run(["make", "-C", str(REPO_ROOT)], check=True)
    assert BINARY.exists(), f"build did not produce {BINARY}"
    return BINARY


@pytest.fixture(scope="session")
def service(built_binary, tmp_path_factory):
    """Launches one shared service instance for the whole session, yields
    (base_url, cert_path), then sends SIGTERM and asserts a clean (exit 0)
    shutdown. Tests that need to control a service's lifecycle themselves
    (e.g. observing /readyz mid-shutdown) must launch their own instance
    instead of disturbing this shared one -- see test_readyz.py."""
    work_dir = tmp_path_factory.mktemp("platformservice")
    cert_path, key_path = generate_dev_cert(work_dir)
    port = free_port()
    env = base_env(port, cert_path, key_path)

    log_path = work_dir / "service.log"
    with open(log_path, "wb") as log_file:
        proc = subprocess.Popen(
            [str(built_binary)], env=env, stdout=log_file, stderr=subprocess.STDOUT,
        )

    base_url = f"https://127.0.0.1:{port}"
    try:
        wait_for_healthz(base_url, cert_path, proc)
        yield base_url, cert_path
    finally:
        exit_code = stop_and_reap(proc, log_path)
        assert exit_code == 0, (
            f"service exited {exit_code}, expected 0; log:\n"
            f"{log_path.read_text(errors='replace')}"
        )


@pytest.fixture
def client(service):
    """Per-test httpx client pinned to the dev CA (plan 15.4): verification
    stays real even against a self-signed cert, never verify=False."""
    base_url, cert_path = service
    with make_client(base_url, cert_path) as c:
        yield c
