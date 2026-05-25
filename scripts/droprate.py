import re
import sys
log_path = sys.argv[1]
last = {"packets": 0, "drops": 0}
with open(log_path) as f:
    for line in f:
        m = re.search(r"capture\.kernel_(packets|drops)\s*\|\s*Total\s*\|\s*(\d+)", line)
        if m:
            last[m.group(1)] = int(m.group(2))
total = last["packets"] + last["drops"]
rate = 100 * last["drops"] / total if total else 0
print(f"kernel_packets seen   = {last['packets']:,}")
print(f"kernel_drops          = {last['drops']:,}")
print(f"Drop rate at 2x       = {rate:.3f}%")