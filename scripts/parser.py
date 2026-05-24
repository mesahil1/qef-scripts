#!/usr/bin/env python3
"""Parse interleaved 'sar -u -r' output. Locates CPU and memory columns from headers."""
import argparse, json, sys

def parse(path):
    cu, cs, mem = [], [], []
    section = None
    cu_i = cs_i = mu_i = mp_i = None
    with open(path) as f:
        for line in f:
            parts = line.split()
            if not parts:
                section = None; continue
            if parts[0] in ("Linux", "Average:"):
                section = None; continue
            if "%user" in parts and "%system" in parts:
                section = "cpu"; cu_i = parts.index("%user"); cs_i = parts.index("%system"); continue
            if "kbmemused" in parts and "%memused" in parts:
                section = "mem"; mu_i = parts.index("kbmemused"); mp_i = parts.index("%memused"); continue
            if section == "cpu" and cu_i is not None:
                try:
                    cu.append(float(parts[cu_i].replace(",", ".")))
                    cs.append(float(parts[cs_i].replace(",", ".")))
                except (ValueError, IndexError): pass
            elif section == "mem" and mu_i is not None:
                try:
                    used = int(parts[mu_i])
                    pct = float(parts[mp_i].replace(",", "."))
                    if used > 0 and 0.0 <= pct <= 100.0:
                        mem.append(used)
                except (ValueError, IndexError): pass
    return cu, cs, mem

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile"); ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    cu, cs, mem = parse(a.logfile)
    if not cu:
        print(f"ERROR: no CPU rows in {a.logfile}", file=sys.stderr); sys.exit(1)
    tot = [u+s for u,s in zip(cu, cs)]
    out = {"cpu_samples": len(tot), "cpu_avg_pct": round(sum(tot)/len(tot), 2),
           "cpu_peak_pct": round(max(tot), 2)}
    if mem:
        out["mem_samples"] = len(mem)
        out["mem_baseline_GB"] = round(min(mem)/1024/1024, 2)
        out["mem_peak_absolute_GB"] = round(max(mem)/1024/1024, 2)
        out["mem_peak_attributable_GB"] = round((max(mem)-min(mem))/1024/1024, 2)
    if a.json:
        print(json.dumps(out, indent=2))
    else:
        print(f"=== sar parsing summary ===")
        print(f"  CPU samples       : {out['cpu_samples']}")
        print(f"  CPU avg (user+sys): {out['cpu_avg_pct']} %")
        print(f"  CPU peak          : {out['cpu_peak_pct']} %")
        if "mem_peak_attributable_GB" in out:
            print(f"  Mem samples       : {out['mem_samples']}")
            print(f"  Mem baseline      : {out['mem_baseline_GB']} GB  (idle floor)")
            print(f"  Mem peak absolute : {out['mem_peak_absolute_GB']} GB  (whole VM at peak)")
            print(f"  Mem attributable  : {out['mem_peak_attributable_GB']} GB  <- use for D2 'Mem peak GB'")
        else:
            print("  No memory rows found.")