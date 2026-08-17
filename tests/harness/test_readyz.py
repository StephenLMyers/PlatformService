"""Black-box tests for GET /readyz (plan 8.1, api/health_api.c)."""
import signal
import subprocess
import time

from client import make_client
from conftest import base_env, free_port, generate_dev_cert, stop_and_reap, wait_for_healthz


def test_returns_ok_when_not_draining(client):
    resp = client.get("/readyz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_wrong_method_is_405(client):
    resp = client.post("/readyz")
    assert resp.status_code == 405


def test_draining_flips_readyz_but_keeps_in_flight_connection_alive(
    built_binary, tmp_path_factory
):
    """Exercises graceful shutdown end-to-end (plan 7.2a): the instant the
    service is signaled to stop, /readyz must report draining, while a
    connection already open at that moment keeps being served rather than
    getting cut off. Uses its own dedicated instance (not the shared
    `service` fixture) since it needs to SIGTERM the process itself
    without taking down every other test in the session.
    """
    work_dir = tmp_path_factory.mktemp("platformservice-drain")
    cert_path, key_path = generate_dev_cert(work_dir)
    port = free_port()
    env = base_env(port, cert_path, key_path)

    log_path = work_dir / "service.log"
    with open(log_path, "wb") as log_file:
        proc = subprocess.Popen(
            [str(built_binary)], env=env, stdout=log_file, stderr=subprocess.STDOUT,
        )
    base_url = f"https://127.0.0.1:{port}"
    wait_for_healthz(base_url, cert_path, proc)

    try:
        with make_client(base_url, cert_path) as conn:
            resp = conn.get("/readyz")
            assert resp.status_code == 200

            proc.send_signal(signal.SIGTERM)

            deadline = time.monotonic() + 5.0
            draining_seen = False
            while time.monotonic() < deadline:
                resp = conn.get("/readyz")
                if resp.status_code == 503:
                    draining_seen = True
                    assert resp.json() == {"status": "draining"}
                    break
                assert resp.status_code == 200
                time.sleep(0.02)
            assert draining_seen, "service never reported draining after SIGTERM"

            # This connection was accepted before the listener stopped, so
            # the worker thread handling it must keep serving it.
            resp = conn.get("/healthz")
            assert resp.status_code == 200
            assert resp.json() == {"status": "ok"}
    finally:
        exit_code = stop_and_reap(proc, log_path)
        assert exit_code == 0, (
            f"service exited {exit_code}, expected 0; log:\n"
            f"{log_path.read_text(errors='replace')}"
        )
