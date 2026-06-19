import pandas as pd
import json
import os

BASE_DIR    = "/home/vagrant/"
CSV_DIR     = BASE_DIR + "labels/"
CICIDS_DIR  = BASE_DIR + "pcaps/"
SUR_DIR     = BASE_DIR + "suricata/"
RESULTS_DIR = BASE_DIR + "qef-results/"

ATTACK_CSV_FILES = [
    CSV_DIR + "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    CSV_DIR + "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    CSV_DIR + "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    CSV_DIR + "Tuesday-WorkingHours.pcap_ISCX.csv",
    CSV_DIR + "Wednesday-workingHours.pcap_ISCX.csv",
    CSV_DIR + "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    CSV_DIR + "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
]
BENIGN_CSV  = CICIDS_DIR + "Monday-WorkingHours.pcap_ISCX.csv"
ATTACK_DAYS = ["tuesday", "wednesday", "thursday", "friday"]
BENIGN_DAY  = "monday"

def get_unique_alert_ips(eve_file):
    alerted_ips = set()
    try:
        with open(eve_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get('event_type') == 'alert':
                        src_ip = event.get('src_ip', '')
                        dst_ip = event.get('dest_ip', '')
                        src_port = event.get('src_port', 0)
                        dst_port = event.get('dest_port', 0)
                        proto = event.get('proto', '')
                        flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
                        alerted_ips.add(flow_key)
                except:
                    pass
    except Exception as e:
        print(f"  Error: {e}")
    return alerted_ips

def get_alert_categories(eve_file):
    categories = set()
    try:
        with open(eve_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get('event_type') == 'alert':
                        cat = event.get('alert', {}).get('category', '')
                        if cat:
                            categories.add(cat)
                except:
                    pass
    except:
        pass
    return categories

def get_unique_flows(eve_file):
    flows = set()
    try:
        with open(eve_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get('event_type') == 'flow':
                        src_ip   = event.get('src_ip', '')
                        dst_ip   = event.get('dest_ip', '')
                        src_port = event.get('src_port', 0)
                        dst_port = event.get('dest_port', 0)
                        proto    = event.get('proto', '')
                        flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{proto}"
                        flows.add(flow_key)
                except:
                    pass
    except Exception as e:
        print(f"  Error: {e}")
    return flows

print("=" * 60)
print("   SURICATA DETECTION METRICS (FIXED)")
print("=" * 60)

# Load attack CSVs
print("\nLoading attack CSV files...")
attack_dfs = []
for csv_file in ATTACK_CSV_FILES:
    try:
        df = pd.read_csv(csv_file, encoding='latin-1', low_memory=False)
        df.columns = df.columns.str.strip()
        attack_dfs.append(df)
        print(f"  Loaded: {os.path.basename(csv_file)} — {len(df):,} rows")
    except Exception as e:
        print(f"  Error: {e}")

attack_gt = pd.concat(attack_dfs, ignore_index=True)
attacks = attack_gt[attack_gt['Label'] != 'BENIGN']

# Load benign CSV
print("\nLoading benign CSV...")
try:
    benign_gt = pd.read_csv(BENIGN_CSV, encoding='latin-1', low_memory=False)
    benign_gt.columns = benign_gt.columns.str.strip()
    print(f"  Loaded: Monday — {len(benign_gt):,} rows")
except Exception as e:
    print(f"  Error: {e}")
    benign_gt = pd.DataFrame()

total_attack_flows = len(attacks)
total_benign_flows = len(benign_gt)
categories         = attacks['Label'].unique()

print(f"\nTotal attack flows : {total_attack_flows:,}")
print(f"Total benign flows : {total_benign_flows:,}")

# Get unique alerted flows per day
print("\nCounting unique alerted flows...")
attack_alerted_flows = set()
all_categories = set()

print("\n  Attack days:")
for day in ATTACK_DAYS:
    eve_file = SUR_DIR + f"{day}/eve.json"
    alerted  = get_unique_alert_ips(eve_file)
    cats     = get_alert_categories(eve_file)
    all_categories.update(cats)
    attack_alerted_flows.update(alerted)
    print(f"  {day}: {len(alerted):,} unique alerted flows")

print("\n  Benign day (Monday):")
benign_eve     = SUR_DIR + f"{BENIGN_DAY}/eve.json"
benign_alerted = get_unique_alert_ips(benign_eve)
print(f"  monday: {len(benign_alerted):,} unique alerted flows (FP)")

# Also get total unique flows processed
print("\n  Total unique flows processed:")
for day in ATTACK_DAYS + [BENIGN_DAY]:
    eve_file = SUR_DIR + f"{day}/eve.json"
    flows    = get_unique_flows(eve_file)
    print(f"  {day}: {len(flows):,} unique flows")

# Calculate metrics using unique flows
TP = len(attack_alerted_flows)
FP = len(benign_alerted)
FN = max(0, total_attack_flows - TP)
TN = max(0, total_benign_flows - FP)

TPR       = TP / total_attack_flows if total_attack_flows > 0 else 0
FPR       = FP / total_benign_flows if total_benign_flows > 0 else 0
Precision = TP / (TP + FP)         if (TP + FP) > 0         else 0
F1        = (2 * Precision * TPR / (Precision + TPR)
             if (Precision + TPR) > 0 else 0)
Accuracy  = ((TP + TN) / (TP + TN + FP + FN)
             if (TP + TN + FP + FN) > 0 else 0)

print("\n" + "=" * 60)
print("   SURICATA FINAL DETECTION METRICS")
print("=" * 60)
print(f"  Total attack flows         : {total_attack_flows:,}")
print(f"  Total benign flows         : {total_benign_flows:,}")
print(f"  Unique attack flow alerts  : {TP:,}")
print(f"  Unique benign flow alerts  : {FP:,}")
print(f"  ─────────────────────────────────")
print(f"  TP                         : {TP:,}")
print(f"  FP                         : {FP:,}")
print(f"  FN                         : {FN:,}")
print(f"  TN                         : {TN:,}")
print(f"  ─────────────────────────────────")
print(f"  TPR (Detection Rate)       : {TPR:.4f} ({TPR*100:.2f}%)")
print(f"  FPR (False Pos Rate)       : {FPR:.4f} ({FPR*100:.2f}%)")
print(f"  Precision                  : {Precision:.4f}")
print(f"  F1 Score                   : {F1:.4f}")
print(f"  Accuracy                   : {Accuracy:.4f} ({Accuracy*100:.2f}%)")
print(f"  Attack categories detected : {len(all_categories)}/7")
print(f"  Categories: {list(all_categories)}")
print("=" * 60)

# Save results
output_file = RESULTS_DIR + "suricata_detection_metrics.txt"
with open(output_file, 'w') as f:
    f.write("SURICATA DETECTION METRICS\n")
    f.write("==========================\n")
    f.write(f"Total attack flows         : {total_attack_flows:,}\n")
    f.write(f"Total benign flows         : {total_benign_flows:,}\n")
    f.write(f"Unique attack flow alerts  : {TP:,}\n")
    f.write(f"Unique benign flow alerts  : {FP:,}\n")
    f.write(f"TP                         : {TP:,}\n")
    f.write(f"FP                         : {FP:,}\n")
    f.write(f"FN                         : {FN:,}\n")
    f.write(f"TN                         : {TN:,}\n")
    f.write(f"TPR                        : {TPR:.4f}\n")
    f.write(f"FPR                        : {FPR:.4f}\n")
    f.write(f"Precision                  : {Precision:.4f}\n")
    f.write(f"F1 Score                   : {F1:.4f}\n")
    f.write(f"Accuracy                   : {Accuracy:.4f}\n")
    f.write(f"Attack categories          : {len(all_categories)}/7\n")
    f.write(f"Categories                 : {list(all_categories)}\n")

print(f"\nResults saved to: {output_file}")