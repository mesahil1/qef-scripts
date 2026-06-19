import json
import os

BASE_DIR  = "/home/khagendra/thesis_results/"
SUR_DIR   = BASE_DIR + "suricata/"
PERF_DIR  = BASE_DIR + "performance/"
CICIDS_DIR = BASE_DIR + "cicids2017/"

def count_alerts(eve_file):
    try:
        count = 0
        with open(eve_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get('event_type') == 'alert':
                        count += 1
                except:
                    pass
        return count
    except Exception as e:
        print(f"  Error: {e}")
        return 0

def count_flows(eve_file):
    try:
        count = 0
        with open(eve_file, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get('event_type') == 'flow':
                        count += 1
                except:
                    pass
        return count
    except:
        return 0

def parse_sar_file(filepath):
    cpu_values = []
    ram_values = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 8 and parts[2] == 'all':
                    try:
                        cpu = float(parts[3]) + float(parts[5])
                        cpu_values.append(cpu)
                    except:
                        pass
                if len(parts) >= 9 and 'kbmemfree' not in line and \
                   'CPU' not in line and 'Linux' not in line:
                    try:
                        val = float(parts[4])
                        if val > 100000:
                            ram_values.append(val)
                    except:
                        pass
    except Exception as e:
        print(f"  Error: {e}")
    avg_cpu  = sum(cpu_values) / len(cpu_values) if cpu_values else 0
    peak_ram = max(ram_values) / 1024 if ram_values else 0
    return avg_cpu, peak_ram

# Total attack flows from CICIDS
TOTAL_ATTACK_FLOWS = 846248

print("=" * 60)
print("   SURICATA RESILIENCE METRICS (D3)")
print("=" * 60)

# 1x results
print("\n--- FRIDAY 1x SPEED ---")
friday_1x_alerts = count_alerts(SUR_DIR + "friday/eve.json")
friday_1x_flows  = count_flows(SUR_DIR + "friday/eve.json")
avg_cpu_1x, peak_ram_1x = parse_sar_file(
    PERF_DIR + "suricata_friday_perf.txt")

TPR_1x = friday_1x_alerts / TOTAL_ATTACK_FLOWS if TOTAL_ATTACK_FLOWS > 0 else 0

print(f"  Alerts generated   : {friday_1x_alerts:,}")
print(f"  TPR at 1x          : {TPR_1x:.4f} ({TPR_1x*100:.2f}%)")
print(f"  Avg CPU            : {avg_cpu_1x:.2f} %")
print(f"  Peak RAM           : {peak_ram_1x:.0f} MB")

# 2x results
print("\n--- FRIDAY 2x SPEED ---")
friday_2x_alerts = count_alerts(SUR_DIR + "friday_2x/eve.json")
friday_2x_flows  = count_flows(SUR_DIR + "friday_2x/eve.json")
avg_cpu_2x, peak_ram_2x = parse_sar_file(
    PERF_DIR + "suricata_friday_2x_perf.txt")

TPR_2x = friday_2x_alerts / TOTAL_ATTACK_FLOWS if TOTAL_ATTACK_FLOWS > 0 else 0

print(f"  Alerts generated   : {friday_2x_alerts:,}")
print(f"  TPR at 2x          : {TPR_2x:.4f} ({TPR_2x*100:.2f}%)")
print(f"  Avg CPU            : {avg_cpu_2x:.2f} %")
print(f"  Peak RAM           : {peak_ram_2x:.0f} MB")

# Calculate degradation
TPR_degradation = max(0, (TPR_1x - TPR_2x) / TPR_1x * 100) if TPR_1x > 0 else 0

if friday_1x_flows > 0:
    packet_drop = max(0, (friday_1x_flows - friday_2x_flows) / friday_1x_flows * 100)
else:
    packet_drop = 0.0

# D3 Scores
if TPR_degradation <= 2:
    tpr_score = 5
elif TPR_degradation <= 5:
    tpr_score = 4
elif TPR_degradation <= 10:
    tpr_score = 3
elif TPR_degradation <= 20:
    tpr_score = 2
else:
    tpr_score = 1

if packet_drop < 0.5:
    drop_score = 5
elif packet_drop < 2:
    drop_score = 4
elif packet_drop < 5:
    drop_score = 3
elif packet_drop < 15:
    drop_score = 2
else:
    drop_score = 1

d3_score = (tpr_score + drop_score) / 2

print("\n" + "=" * 60)
print("   RESILIENCE ANALYSIS")
print("=" * 60)
print(f"  TPR at 1x speed        : {TPR_1x*100:.2f}%")
print(f"  TPR at 2x speed        : {TPR_2x*100:.2f}%")
print(f"  TPR Degradation        : {TPR_degradation:.2f}%")
print(f"  Packet Drop Rate       : {packet_drop:.2f}%")
print(f"  ─────────────────────────────────")
print(f"  TPR Degradation Score  : {tpr_score}/5")
print(f"  Packet Drop Score      : {drop_score}/5")
print(f"  D3 Overall Score       : {d3_score:.1f}/5")
print("=" * 60)

output_file = BASE_DIR + "suricata_resilience_metrics.txt"
with open(output_file, 'w') as f:
    f.write("SURICATA RESILIENCE METRICS\n")
    f.write("===========================\n\n")
    f.write(f"TPR at 1x speed       : {TPR_1x*100:.2f}%\n")
    f.write(f"TPR at 2x speed       : {TPR_2x*100:.2f}%\n")
    f.write(f"TPR Degradation       : {TPR_degradation:.2f}%\n")
    f.write(f"Packet Drop Rate      : {packet_drop:.2f}%\n")
    f.write(f"TPR Degradation Score : {tpr_score}/5\n")
    f.write(f"Packet Drop Score     : {drop_score}/5\n")
    f.write(f"D3 Overall Score      : {d3_score:.1f}/5\n")

print(f"\nResults saved to: {output_file}")