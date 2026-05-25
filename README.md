
# Create a folder for results
```mkdir -p /qef-result/suricata/phase2/run-<Days>```

## Run CPU-Mem.log
```sar -u -r 5 > cpu_mem.log &```
```SAR_PID=$! ```

# For Suricata, we will run it in single mode to process the pcap file and capture the CPU and Memory utilization using sar.
``` /usr/bin/time -v sudo suricata -c /etc/suricata/suricata.yaml  -r <path_to_pcap_file> -l . -k none --runmode=single 2> timing.log```

# Kill the SAR command 
```kill $SAR_PID```

# Phase 1: Run the match_v2.py script to match the alerts in the eve.json file with the labels in the CSV file and output the matched results to a new JSON file.
```python3 ~/match_v2.py --eve <path_to_output_folder>/eve.json --label <path_to_pcap_file> --out  <path_to_output_folder>/filename.json```

## Phase 2: Parse the cpu_mem.log file to extract the CPU and Memory metrics.
```python3 parser.py <path_to_cpu_mem.log>```
Sample Example:

| Metric | Value | Notes |
| --- | ---: | --- |
| CPU samples | 258 | Total sample count |
| CPU avg (user+sys) | 92.64 % | Mean CPU usage |
| CPU peak | 100.0 % | Maximum CPU usage |
| Mem samples | 258 | Total sample count |
| Mem baseline | 0.16 GB | Idle floor |
| Mem peak absolute | 0.95 GB | Whole VM at peak |
| Mem attributable | 0.78 GB | Use for D2 "Mem peak GB" |


## Prerequisite: create a veth pair with large MTU

Before running Phase 3, create a veth pair and set the MTU. Note: the requested MTU `66535` exceeds the system maximum; use `65535` instead.

Run as root or with `sudo`:

```bash
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 mtu 65535
sudo ip link set veth1 mtu 65535
sudo ip link set veth0 up
sudo ip link set veth1 up
```

You can then replace `veth0` below with the interface you want Suricata to listen on (for example `qef0`).

## Phase 3: Run Suricata in worker mode and replay traffic

Phase 3 runs Suricata in `workers` mode while replaying PCAP traffic and collecting CPU/memory samples with `sar`.

Quick start:

- Make the script executable and run it:

  ```bash
  chmod +x phase3.sh
  ./phase3.sh
  ```

- Output directories: `~/qef-results/suricata/phase3/run-<Day>` (one per day)

- The script automates starting `sar`, launching Suricata with worker mode, replaying the PCAPs, and collecting `timing.log`, `stats.log` and `cpu_mem.log` for each run.

- Run parser scripts on the collected logs:

  ```bash
  python3 parser.py <path_to_cpu_mem.log>
  ```

   This will extract CPU and memory metrics from the `cpu_mem.log` file.

- Run drop rate analysis:

  ```bash
  python3 droprate.py <path_to_stats.log>
  ```
    This will extract packet and drop counts from the `stats.log` file and calculate the drop rate.
- 
