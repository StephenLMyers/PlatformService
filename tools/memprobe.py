#!/usr/bin/env python3
"""
§8.5 memory sampler: VmRSS (current resident) and VmHWM (peak resident
since start) for a running PID, read straight from /proc/<pid>/status.
psutil has no peak-RSS accessor on Linux (its `memory_info()` exposes rss/
vms/shared/etc, but not VmHWM), so /proc is the only source for that field;
psutil is used only to give a clean "process not running" error instead of
a raw FileNotFoundError.
"""
import argparse
import json
import sys
from dataclasses import asdict, dataclass

import psutil


@dataclass(frozen=True)
class MemSample:
    vm_rss_kb: int
    vm_hwm_kb: int


def sample(pid: int) -> MemSample:
    if not psutil.pid_exists(pid):
        raise ProcessLookupError(f"no such process: {pid}")

    rss_kb = None
    hwm_kb = None
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                rss_kb = int(line.split()[1])
            elif line.startswith("VmHWM:"):
                hwm_kb = int(line.split()[1])

    if rss_kb is None or hwm_kb is None:
        raise RuntimeError(f"VmRSS/VmHWM missing from /proc/{pid}/status")
    return MemSample(vm_rss_kb=rss_kb, vm_hwm_kb=hwm_kb)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sample VmRSS/VmHWM for a running PID (plan 8.5)."
    )
    parser.add_argument("pid", type=int)
    args = parser.parse_args()
    print(json.dumps(asdict(sample(args.pid))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
