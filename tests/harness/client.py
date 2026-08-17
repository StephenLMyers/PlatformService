"""
Thin httpx wrapper pinned to the dev CA (plan 15.4). Verification stays on
even against the harness's self-signed cert -- the point is to keep real
certificate validation in the test path, never `verify=False`.
"""
import ssl
from pathlib import Path

import httpx


def make_client(base_url: str, cert_path: Path) -> httpx.Client:
    ctx = ssl.create_default_context(cafile=str(cert_path))
    return httpx.Client(base_url=base_url, verify=ctx, timeout=5.0)
