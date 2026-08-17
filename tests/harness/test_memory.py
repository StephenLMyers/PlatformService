"""
§8.5 memory footprint testing, scoped to what phase 3 actually has built.

Only /healthz and /readyz exist right now, so this covers:
  1. idle baseline
  2. per-connection cost
  3. leak canary (substituting repeated /healthz calls for the plan's
     "10,000 authenticated requests", since login doesn't exist yet)
  8. connection churn

Tests 4-7 (batch-response peak/scaling, KDF-path load, registration
error-path leaks) need endpoints that land in phases 5-7 and are deferred
until then -- see plans/00-project-plan.md §8.5.

Each test launches its own dedicated instance rather than sharing
conftest.py's session-scoped `service` fixture: an "idle baseline" is only
meaningful measured before any other test's traffic has touched the
process, and the per-connection test needs to override PS_WORKER_THREADS
(see below), which the shared instance can't do after it's already started.
"""
import contextlib
import subprocess
import ssl
import sys
import time

import httpx

from conftest import REPO_ROOT, base_env, free_port, generate_dev_cert, stop_and_reap, wait_for_healthz

sys.path.insert(0, str(REPO_ROOT / "tools"))
from memprobe import sample  # noqa: E402

IDLE_RSS_BUDGET_KB = 16 * 1024
PER_CONN_MARGINAL_BUDGET_KB = 256
HUNDRED_CONN_RSS_BUDGET_KB = 48 * 1024
DRIFT_BUDGET_KB = 2 * 1024


@contextlib.contextmanager
def launch(built_binary, tmp_path_factory, name, env_overrides=None):
    work_dir = tmp_path_factory.mktemp(name)
    cert_path, key_path = generate_dev_cert(work_dir)
    port = free_port()
    env = base_env(port, cert_path, key_path)
    if env_overrides:
        env.update(env_overrides)

    log_path = work_dir / "service.log"
    with open(log_path, "wb") as log_file:
        proc = subprocess.Popen(
            [str(built_binary)], env=env, stdout=log_file, stderr=subprocess.STDOUT,
        )
    base_url = f"https://127.0.0.1:{port}"
    wait_for_healthz(base_url, cert_path, proc)
    time.sleep(0.2)  # let post-startup allocation settle before sampling
    try:
        yield base_url, cert_path, proc
    finally:
        exit_code = stop_and_reap(proc, log_path)
        assert exit_code == 0, (
            f"service exited {exit_code}, expected 0; log:\n"
            f"{log_path.read_text(errors='replace')}"
        )


def test_idle_baseline(built_binary, tmp_path_factory):
    """§8.5 test 1: startup footprint, before any request is served."""
    with launch(built_binary, tmp_path_factory, "mem-idle") as (_url, _cert, proc):
        mem = sample(proc.pid)
        print(f"\n[memprobe] idle: VmRSS={mem.vm_rss_kb} KiB VmHWM={mem.vm_hwm_kb} KiB")
        assert mem.vm_rss_kb <= IDLE_RSS_BUDGET_KB, (
            f"idle VmRSS {mem.vm_rss_kb} KiB exceeds budget {IDLE_RSS_BUDGET_KB} KiB"
        )


def test_per_connection_cost(built_binary, tmp_path_factory):
    """§8.5 test 2: sample at 0/10/50/100 open TLS connections and assert
    the marginal per-connection RSS stays within budget and is roughly
    linear. Each open connection occupies a worker thread for its whole
    keep-alive lifetime (src/http/conn.c), so the pool needs at least as
    many workers as connections under test -- overridden here since the
    default is nproc (8 on this machine), far fewer than 100."""
    with launch(
        built_binary, tmp_path_factory, "mem-perconn",
        env_overrides={"PS_WORKER_THREADS": "150"},
    ) as (base_url, cert_path, proc):
        ctx = ssl.create_default_context(cafile=str(cert_path))
        readings = {0: sample(proc.pid).vm_rss_kb}
        open_clients: list[httpx.Client] = []
        try:
            for target in (10, 50, 100):
                while len(open_clients) < target:
                    c = httpx.Client(base_url=base_url, verify=ctx, timeout=5.0)
                    resp = c.get("/healthz")
                    assert resp.status_code == 200
                    open_clients.append(c)
                time.sleep(0.1)
                readings[target] = sample(proc.pid).vm_rss_kb
        finally:
            for c in open_clients:
                c.close()

        print(f"\n[memprobe] per-connection readings (VmRSS KiB): {readings}")
        marginal_100 = (readings[100] - readings[0]) / 100
        print(f"[memprobe] marginal per-connection: {marginal_100:.1f} KiB")
        assert marginal_100 <= PER_CONN_MARGINAL_BUDGET_KB, (
            f"marginal RSS per connection {marginal_100:.1f} KiB exceeds "
            f"budget {PER_CONN_MARGINAL_BUDGET_KB} KiB (readings: {readings})"
        )
        assert readings[100] <= HUNDRED_CONN_RSS_BUDGET_KB, (
            f"VmRSS at 100 connections {readings[100]} KiB exceeds budget "
            f"{HUNDRED_CONN_RSS_BUDGET_KB} KiB"
        )


def test_leak_canary_sequential_requests(built_binary, tmp_path_factory):
    """§8.5 test 3 (adapted): 10,000 sequential requests on one keep-alive
    connection, then settle. RSS must return within budget of baseline --
    a steady climb is the classic signature of a per-request allocation
    that's never freed. The plan calls for authenticated requests; login
    doesn't exist before phase 7, so this uses /healthz instead."""
    with launch(built_binary, tmp_path_factory, "mem-canary") as (base_url, cert_path, proc):
        ctx = ssl.create_default_context(cafile=str(cert_path))
        baseline = sample(proc.pid).vm_rss_kb

        with httpx.Client(base_url=base_url, verify=ctx, timeout=5.0) as c:
            for _ in range(10_000):
                resp = c.get("/healthz")
                assert resp.status_code == 200

        time.sleep(0.3)
        after = sample(proc.pid).vm_rss_kb
        drift = after - baseline
        print(f"\n[memprobe] leak canary: baseline={baseline} KiB after={after} KiB drift={drift} KiB")
        assert drift <= DRIFT_BUDGET_KB, (
            f"VmRSS drifted {drift} KiB after 10,000 requests (baseline "
            f"{baseline} KiB, after {after} KiB); budget {DRIFT_BUDGET_KB} KiB"
        )


def test_connection_churn(built_binary, tmp_path_factory):
    """§8.5 test 8: 1000 connect/TLS-handshake/disconnect cycles. SSL
    object leaks are a common failure the other tests miss entirely, since
    none of them ever close a connection mid-run."""
    with launch(built_binary, tmp_path_factory, "mem-churn") as (base_url, cert_path, proc):
        ctx = ssl.create_default_context(cafile=str(cert_path))
        baseline = sample(proc.pid).vm_rss_kb

        for _ in range(1000):
            with httpx.Client(base_url=base_url, verify=ctx, timeout=5.0) as c:
                resp = c.get("/healthz")
                assert resp.status_code == 200

        time.sleep(0.3)
        after = sample(proc.pid).vm_rss_kb
        drift = after - baseline
        print(f"\n[memprobe] churn: baseline={baseline} KiB after={after} KiB drift={drift} KiB")
        assert drift <= DRIFT_BUDGET_KB, (
            f"VmRSS drifted {drift} KiB after 1000 connect/disconnect cycles "
            f"(baseline {baseline} KiB, after {after} KiB); budget {DRIFT_BUDGET_KB} KiB"
        )
