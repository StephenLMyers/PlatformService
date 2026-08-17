"""
Black-box tests for main.c's own CLI/config-validation paths -- --help,
--version, --check-config, an unknown flag, and a missing PS_JWT_SECRET.

Unlike every other harness test, these never launch a persistent service:
main.c handles all five of these before ever opening a listener (--help
and --version return before config even loads), so a one-shot
subprocess.run against the built binary is enough. This is also the only
targeted coverage main.c gets at all -- it's excluded from unit-test
linkage (it supplies main()), so these paths were previously exercised by
nothing.
"""
import subprocess

from conftest import BINARY

VALID_SECRET = "a" * 32  # PS_JWT_SECRET_MIN is 32 bytes


def run_cli(args, env=None, timeout=5):
    return subprocess.run(
        [str(BINARY), *args],
        env=env if env is not None else {},
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def test_help_flag_exits_zero_and_prints_usage(built_binary):
    result = run_cli(["--help"])
    assert result.returncode == 0
    assert "Usage:" in result.stdout
    assert "PS_JWT_SECRET" in result.stdout


def test_short_help_flag_matches_long_form(built_binary):
    result = run_cli(["-h"])
    assert result.returncode == 0
    assert "Usage:" in result.stdout


def test_version_flag_exits_zero_and_prints_version(built_binary):
    result = run_cli(["--version"])
    assert result.returncode == 0
    assert result.stdout.strip() != ""


def test_short_version_flag_matches_long_form(built_binary):
    result = run_cli(["-v"])
    assert result.returncode == 0
    assert result.stdout.strip() != ""


def test_help_and_version_need_no_environment_at_all(built_binary):
    """Confirms these two are handled before config load -- no
    PS_JWT_SECRET, no PATH, nothing."""
    result = run_cli(["--help"], env={})
    assert result.returncode == 0


def test_check_config_with_valid_secret_exits_zero(built_binary):
    result = run_cli(["--check-config"], env={"PS_JWT_SECRET": VALID_SECRET})
    assert result.returncode == 0
    assert "configuration is valid" in result.stderr


def test_check_config_without_secret_fails(built_binary):
    result = run_cli(["--check-config"], env={})
    assert result.returncode != 0
    assert "PS_JWT_SECRET" in result.stderr


def test_missing_jwt_secret_fails_on_a_normal_run_too(built_binary):
    """Not just --check-config -- a real (non-check) run refuses to start
    at all without a secret, before ever touching a socket."""
    result = run_cli([], env={})
    assert result.returncode != 0
    assert "PS_JWT_SECRET" in result.stderr


def test_unknown_flag_rejected(built_binary):
    result = run_cli(["--not-a-real-flag"], env={})
    assert result.returncode != 0
    assert "unknown option" in result.stderr


def test_config_flag_missing_its_path_argument_rejected(built_binary):
    result = run_cli(["--config"], env={})
    assert result.returncode != 0
    assert "requires a path argument" in result.stderr
