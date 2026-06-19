import os

BASE_DIR   = "/home/khagendra/thesis_results/"
PERF_DIR   = BASE_DIR + "performance/"
SUR_DIR    = BASE_DIR + "suricata/"
CICIDS_DIR = BASE_DIR + "cicids2017/"

DAYS = {
    "monday"    : "Monday-WorkingHours.pcap",
    "tuesday"   : "Tuesday-WorkingHours.pcap",
    "wednesday" : "Wednesday-WorkingHours.pcap",
    "thursday"  : "Thursday-WorkingHours.pcap",
    "friday"    : "Friday-WorkingHours.pcap",
}

PERF_FILE_NAMES = {
    "monday"    : "suricata_monday_perf.txt",
    "tuesday"   : "suricata_tuesday_perf.txt",
    "wednesday" : "suricata_wednesday_perf.txt",
    "thursday"  : "suricata_thursday_perf.txt",
    "friday"    : "suricata_friday_perf.txt",
}

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
                   'CPU' not in line and 'Linux' not in line and \
                   'Average' not in line:
                    try:
                        val = float(parts[4])
                        if val > 100000:
                            ram_values.append(val)
                    except:
                        pass
    except Exception as e:
        print(f"  Error: {e}")
    avg_cpu  = sum(cpu_values) / len(cpu_values) if cpu_values else 0
    peak_cpu = max(cpu_values) if cpu_values else 0
    avg_ram  = sum(ram_values) / len(ram_values) / 1024 if ram_values else 0
    peak_ram = max(ram_values) / 1024 if ram_values else 0
    return avg_cpu, peak_cpu, avg_ram, peak_ram

def count_alerts(eve_file):
    try:
        import json
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
    except:
        return 0

def get_pcap_size_mb(pcap_file):
    try:
        return os.path.getsize(pcap_file) / (1024 * 1024)
    except:
        return 0

def get_runtime_seconds(perf_file):
    times = []
    try:
        with open(perf_file, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[2] == 'all':
                    times.append(parts[0] + " " + parts[1])
    except:
        pass
    return len(times)

print("=" * 60)
print("   SURICATA PERFORMANCE METRICS")
print("=" * 60)

results = {}

for day, pcap_name in DAYS.items():
    print(f"\n--- {day.upper()} ---")
    perf_file = PERF_DIR + PERF_FILE_NAMES[day]
    eve_file  = SUR_DIR + f"{day}/eve.json"
    pcap_file = CICIDS_DIR + pcap_name

    avg_cpu, peak_cpu, avg_ram, peak_ram = parse_sar_file(perf_file)
    alerts    = count_alerts(eve_file)
    pcap_size = get_pcap_size_mb(pcap_file)
    runtime   = get_runtime_seconds(perf_file)
    throughput = (pcap_size * 8) / runtime if runtime > 0 else 0

    print(f"  Average CPU usage  : {avg_cpu:.2f} %")
    print(f"  Peak CPU usage     : {peak_cpu:.2f} %")
    print(f"  Average RAM usage  : {avg_ram:.0f} MB")
    print(f"  Peak RAM usage     : {peak_ram:.0f} MB")
    print(f"  Alerts generated   : {alerts:,}")
    print(f"  PCAP size          : {pcap_size:.0f} MB")
    print(f"  Runtime            : {runtime} seconds")
    print(f"  Throughput         : {throughput:.2f} Mbps")

    results[day] = {
        'avg_cpu'    : avg_cpu,
        'peak_cpu'   : peak_cpu,
        'avg_ram'    : avg_ram,
        'peak_ram'   : peak_ram,
        'alerts'     : alerts,
        'pcap_size'  : pcap_size,
        'runtime'    : runtime,
        'throughput' : throughput,
    }

print("\n" + "=" * 60)
print("   OVERALL AVERAGES")
print("=" * 60)

all_cpu  = [v['avg_cpu']    for v in results.values() if v['avg_cpu'] > 0]
all_ram  = [v['avg_ram']    for v in results.values() if v['avg_ram'] > 0]
all_tput = [v['throughput'] for v in results.values() if v['throughput'] > 0]

overall_cpu  = sum(all_cpu)  / len(all_cpu)  if all_cpu  else 0
overall_ram  = sum(all_ram)  / len(all_ram)  if all_ram  else 0
overall_tput = sum(all_tput) / len(all_tput) if all_tput else 0

print(f"  Overall Avg CPU        : {overall_cpu:.2f} %")
print(f"  Overall Avg RAM        : {overall_ram:.0f} MB")
print(f"  Overall Avg Throughput : {overall_tput:.2f} Mbps")

output_file = BASE_DIR + "suricata_performance_metrics.txt"
with open(output_file, 'w') as f:
    f.write("SURICATA PERFORMANCE METRICS\n")
    f.write("============================\n\n")
    for day, vals in results.items():
        f.write(f"{day.upper()}\n")
        f.write(f"  Avg CPU     : {vals['avg_cpu']:.2f} %\n")
        f.write(f"  Peak CPU    : {vals['peak_cpu']:.2f} %\n")
        f.write(f"  Avg RAM     : {vals['avg_ram']:.0f} MB\n")
        f.write(f"  Peak RAM    : {vals['peak_ram']:.0f} MB\n")
        f.write(f"  Alerts      : {vals['alerts']:,}\n")
        f.write(f"  Throughput  : {vals['throughput']:.2f} Mbps\n\n")
    f.write("OVERALL AVERAGES\n")
    f.write(f"  Avg CPU        : {overall_cpu:.2f} %\n")
    f.write(f"  Avg RAM        : {overall_ram:.0f} MB\n")
    f.write(f"  Avg Throughput : {overall_tput:.2f} Mbps\n")

print(f"\nResults saved to: {output_file}")
print("=" * 60)