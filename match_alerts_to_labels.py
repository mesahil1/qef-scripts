#!/usr/bin/env python3
"""
Match Suricata eve.json alerts to CICIDS 2017 ISCX-format labels.

Reports TP / FP / FN / TN, computes TPR and FPR, and counts the distinct
CICIDS attack categories that triggered at least one alert.

Usage:
    python3 match_alerts_to_labels.py \\
        --eve   /path/to/eve.json \\
        --label /path/to/Tuesday-WorkingHours.pcap_ISCX.csv \\
        --out   /path/to/matched.json

The labels CSV uses 5-tuple flow keys (Source IP, Destination IP, Source Port,
Destination Port, Protocol) and a Label column of either "BENIGN" or an attack
name (e.g., "FTP-Patator", "SSH-Patator", "DoS Hulk", etc.). Suricata alerts
are aggregated to flow-level (i.e., a flow that produced any alert is counted
as detected, regardless of how many alerts).

The script is symmetric with respect to direction — it considers both
A→B and B→A as the same flow, because Suricata's alert direction may differ
from CICFlowMeter's flow direction.
"""

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path


def normalise_flow_key(src_ip, dst_ip, src_port, dst_port):
    """Direction-agnostic 5-tuple — sort endpoints so A→B == B→A."""
    try:
        sp = int(src_port) if src_port else 0
        dp = int(dst_port) if dst_port else 0
    except (TypeError, ValueError):
        sp, dp = 0, 0
    a = (str(src_ip), sp)
    b = (str(dst_ip), dp)
    if a <= b:
        return (a[0], b[0], a[1], b[1])
    return (b[0], a[0], b[1], a[1])


def load_labels(path):
    """Return dict[flow_key] -> label_string, plus the set of attack categories."""
    flows = {}
    categories = set()
    # CICIDS CSVs use Windows-1252 in some distributions; try utf-8 then fall back.
    for encoding in ("utf-8", "latin-1"):
        try:
            handle = open(path, encoding=encoding, errors="strict")
            handle.readline()  # probe header
            handle.seek(0)
            break
        except UnicodeDecodeError:
            continue
    else:
        sys.exit(f"FATAL: could not decode {path} with utf-8 or latin-1")

    reader = csv.DictReader(handle)
    # Column names in CICIDS CSV typically have a leading space.
    field_map = {}
    for desired in ("Source IP", "Destination IP", "Source Port",
                    "Destination Port", "Label"):
        for actual in reader.fieldnames or []:
            if actual.strip() == desired:
                field_map[desired] = actual
                break
    missing = [k for k in ("Source IP", "Destination IP", "Source Port",
                           "Destination Port", "Label") if k not in field_map]
    if missing:
        sys.exit(f"FATAL: CSV header missing columns: {missing}\n"
                 f"Available columns: {reader.fieldnames}")

    for row in reader:
        key = normalise_flow_key(
            row[field_map["Source IP"]],
            row[field_map["Destination IP"]],
            row[field_map["Source Port"]],
            row[field_map["Destination Port"]],
        )
        label = row[field_map["Label"]].strip()
        flows[key] = label
        if label != "BENIGN":
            categories.add(label)
    handle.close()
    return flows, categories


def load_alerts(path):
    """Return dict[flow_key] -> list of alert signatures that fired on that flow."""
    alerts = defaultdict(list)
    with open(path) as f:
        for line in f:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") != "alert":
                continue
            key = normalise_flow_key(
                event.get("src_ip"),
                event.get("dest_ip"),
                event.get("src_port"),
                event.get("dest_port"),
            )
            sig = event.get("alert", {}).get("signature", "")
            alerts[key].append(sig)
    return alerts


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--eve", required=True, type=Path,
                   help="Suricata eve.json from the run")
    p.add_argument("--label", required=True, type=Path,
                   help="CICIDS labels CSV (e.g., Tuesday-WorkingHours.pcap_ISCX.csv)")
    p.add_argument("--out", required=True, type=Path,
                   help="Output JSON summary file")
    p.add_argument("--debug", action="store_true",
                   help="Print first 5 unmatched flows for diagnosis")
    args = p.parse_args()

    print(f"Loading labels from {args.label} ...", flush=True)
    labels, expected_categories = load_labels(args.label)
    print(f"  {len(labels)} flows, {len(expected_categories)} attack categories", flush=True)

    print(f"Loading alerts from {args.eve} ...", flush=True)
    alerts = load_alerts(args.eve)
    print(f"  {len(alerts)} flows triggered at least one alert", flush=True)

    tp = fp = fn = tn = 0
    detected_categories = set()
    unmatched_alerts = []

    for key, label in labels.items():
        is_attack = (label != "BENIGN")
        is_alerted = key in alerts
        if is_attack and is_alerted:
            tp += 1
            detected_categories.add(label)
        elif is_attack and not is_alerted:
            fn += 1
        elif not is_attack and is_alerted:
            fp += 1
        else:
            tn += 1

    # Alerts on flows that don't appear in the labels CSV
    for key in alerts:
        if key not in labels:
            unmatched_alerts.append({"flow": key, "signatures": alerts[key][:3]})

    tpr = 100.0 * tp / (tp + fn) if (tp + fn) else 0.0
    fpr_per_1k = 1000.0 * fp / (fp + tn) if (fp + tn) else 0.0

    summary = {
        "labels_file": str(args.label),
        "eve_file": str(args.eve),
        "labelled_flows_total": len(labels),
        "labelled_attack_flows": tp + fn,
        "labelled_benign_flows": fp + tn,
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "TPR_percent": round(tpr, 3),
        "FPR_per_1k_benign": round(fpr_per_1k, 3),
        "expected_attack_categories": sorted(expected_categories),
        "detected_attack_categories": sorted(detected_categories),
        "categories_detected_count": len(detected_categories),
        "alerts_on_unmatched_flows": len(unmatched_alerts),
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2))

    print()
    print("=" * 60)
    print(f"  TP  : {tp}")
    print(f"  FP  : {fp}")
    print(f"  FN  : {fn}")
    print(f"  TN  : {tn}")
    print(f"  TPR : {tpr:.2f}%")
    print(f"  FPR : {fpr_per_1k:.2f} per 1k benign flows")
    print(f"  Categories detected: {len(detected_categories)} / {len(expected_categories)}")
    print(f"  Detected: {sorted(detected_categories)}")
    print(f"  Missed:   {sorted(expected_categories - detected_categories)}")
    print(f"  Alerts on flows not in labels CSV: {len(unmatched_alerts)}")
    print("=" * 60)
    print(f"Summary written to {args.out}")

    if args.debug and unmatched_alerts:
        print("\nFirst 5 unmatched alerts (debug):")
        for entry in unmatched_alerts[:5]:
            print(f"  flow={entry['flow']}  sigs={entry['signatures']}")


if __name__ == "__main__":
    main()
