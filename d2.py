#!/usr/bin/env python3
"""
Compute the four mechanical D2 metrics for a Phase 2 run directory:
    throughput (Mb/s), CPU avg %, CPU peak %, memory peak (GB).

Expects a run directory containing:
    stats.log         - Suricata stats.log
    timing.log        - output of /usr/bin/time -v on the suricata invocation
    cpu_mem.log       - output of  sar -u -r 5

Usage:
    python3 compute_d2.py <run_directory>
    python3 compute_d2.py <run_directory> --json

The fifth D2 metric (alert latency) is not computed here — it requires picking
a specific known-bad packet timestamp from the pcap and the matching alert.
See compute_latency.py or measure it during Phase 5 live attacks instead.
"""

import argparse
import json
import re
import sys
from pathlib import Path


# ---- helpers ----

def parse_decoder_bytes(stats_log: Path):
    """Return the last (highest) total decoder.bytes value from stats.log."""
    pat = re.compile(r"decoder\.bytes\s*\|\s*Total\s*\|\s*(\d+)")
    total = 0
    for line in stats_log.read_text().splitlines():
        m = pat.search(line)
        if m:
            total = int(m.group(1))   # keep the last value seen
    return total


def parse_elapsed_seconds(timing_log: Path):
    """Parse 'Elapsed (wall clock) time' line from /usr/bin/time -v output.

    Format is one of:
        h:mm:ss
        m:ss
        m:ss.ss
    """
    for line in timing_log.read_text().splitlines():
        if "Elapsed (wall clock) time" in line:
            value = line.split(":", 1)[1]
            value = value.split(")", 1)[-1].strip()
            parts = value.split(":")
            secs = 0.0
            for p in parts:
                secs = secs * 60 + float(p)
            return secs
    return 0.0


def parse_cpumem(cpu_mem_log: Path):
    """Parse interleaved sar -u -r output.

    Returns (cpu_user_vals, cpu_sys_vals, mem_used_vals).
    """
    cpu_user, cpu_sys, mem_used = [], [], []
    section = None
    cpu_user_idx = cpu_sys_idx = mem_used_idx = mem_pct_idx = None

    for line in cpu_mem_log.read_text().splitlines():
        parts = line.split()
        if not parts:
            section = None
            continue
        if parts[0] in ("Linux", "Average:"):
            section = None
            continue
        if "%user" in parts and "%system" in parts:
            section = "cpu"
            cpu_user_idx = parts.index("%user")
            cpu_sys_idx = parts.index("%system")
            continue
        if "kbmemused" in parts and "%memused" in parts:
            section = "mem"
            mem_used_idx = parts.index("kbmemused")
            mem_pct_idx = parts.index("%memused")
            continue
        if section == "cpu" and cpu_user_idx is not None:
            try:
                cpu_user.append(float(parts[cpu_user_idx].replace(",", ".")))
                cpu_sys.append(float(parts[cpu_sys_idx].replace(",", ".")))
            except (ValueError, IndexError):
                pass
        elif section == "mem" and mem_used_idx is not None:
            try:
                used = int(parts[mem_used_idx])
                pct = float(parts[mem_pct_idx].replace(",", "."))
                if used > 0 and 0.0 <= pct <= 100.0:
                    mem_used.append(used)
            except (ValueError, IndexError):
                pass

    return cpu_user, cpu_sys, mem_used


# ---- main ----

def compute(run_dir: Path):
    stats_log = run_dir / "stats.log"
    timing_log = run_dir / "timing.log"
    cpu_mem_log = run_dir / "cpu_mem.log"

    missing = [p.name for p in (stats_log, timing_log, cpu_mem_log) if not p.exists()]
    if missing:
        print(f"WARN: missing in {run_dir}: {missing}", file=sys.stderr)

    result = {"run_dir": str(run_dir)}

    # Throughput
    if stats_log.exists() and timing_log.exists():
        decoder_bytes = parse_decoder_bytes(stats_log)
        elapsed = parse_elapsed_seconds(timing_log)
        if elapsed > 0:
            result["decoder_bytes"] = decoder_bytes
            result["elapsed_seconds"] = round(elapsed, 2)
            result["throughput_Mbps"] = round(decoder_bytes * 8 / elapsed / 1_000_000, 2)

    # CPU / memory
    if cpu_mem_log.exists():
        cu, cs, mem = parse_cpumem(cpu_mem_log)
        if cu:
            total = [u + s for u, s in zip(cu, cs)]
            result["cpu_samples"] = len(total)
            result["cpu_avg_pct"] = round(sum(total) / len(total), 2)
            result["cpu_peak_pct"] = round(max(total), 2)
        if mem:
            result["mem_samples"] = len(mem)
            result["mem_baseline_GB"] = round(min(mem) / 1024 / 1024, 2)
            result["mem_peak_absolute_GB"] = round(max(mem) / 1024 / 1024, 2)
            result["mem_peak_attributable_GB"] = round((max(mem) - min(mem)) / 1024 / 1024, 2)

    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir", type=Path)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    res = compute(args.run_dir)

    if args.json:
        print(json.dumps(res, indent=2))
        return

    print(f"=== D2 metrics for {res['run_dir']} ===")
    if "throughput_Mbps" in res:
        print(f"  Throughput        : {res['throughput_Mbps']} Mb/s")
        print(f"    decoder.bytes   = {res['decoder_bytes']:,}")
        print(f"    elapsed seconds = {res['elapsed_seconds']}")
    else:
        print("  Throughput        : -- (stats.log or timing.log missing)")
    if "cpu_avg_pct" in res:
        print(f"  CPU avg (user+sys): {res['cpu_avg_pct']} %")
        print(f"  CPU peak          : {res['cpu_peak_pct']} %")
    else:
        print("  CPU               : -- (cpu_mem.log missing or empty)")
    if "mem_peak_attributable_GB" in res:
        print(f"  Mem baseline      : {res['mem_baseline_GB']} GB")
        print(f"  Mem peak absolute : {res['mem_peak_absolute_GB']} GB")
        print(f"  Mem attributable  : {res['mem_peak_attributable_GB']} GB  ← use for D2 'Mem peak GB'")
    else:
        print("  Memory            : -- (no memory rows in cpu_mem.log — see note 'memory rows missing')")


if __name__ == "__main__":
    main()