
# Create a folder for results
mkdir -p /qef-result/suricata/phase2/run-<Days>  ## For All the Datasets

## Run CPU-Mem.log
sar -u -r 5 > cpu_mem.log &
SAR_PID=$! ### Running sar for the cpu utilization in background

# Run Suricata on pcap files
 /usr/bin/time -v sudo suricata \
     -c /etc/suricata/suricata.yaml \
     -r ~/pcap/Monday-WorkingHours.pcap \
     -l . \
     -k none --runmode=single 2> timing.log

# Kill the SAR command 
kill $SAR_PID

# use matched python script
python3 ~/match_v2.py \
  --eve ~/qef-results/suricata/phase2/run-Monday/eve.json \
  --label ~/labels/Monday-WorkingHours.pcap_ISCX.csv \
  --out  ~/qef-results/suricata/phase2/run-Monday/Monday_matched_v2.json

## Use Parser to get CPU and Memory Utilization
python3 parser.py ~/qef-results/suricata/phase2/cpu_mem.log

Sample Example:

"""=== sar parsing summary ===
  CPU samples       : 258
  CPU avg (user+sys): 92.64 %
  CPU peak          : 100.0 %
  Mem samples       : 258
  Mem baseline      : 0.16 GB  (idle floor)
  Mem peak absolute : 0.95 GB  (whole VM at peak)
  Mem attributable  : 0.78 GB  <- use for D2 'Mem peak GB'
"""

  <!-- sudo tcpreplay -i veth0 --topspeed  --stats=10 \ -->
  <!-- ~/pcap/Friday-WorkingHours.pcap 2>&1 | tee tcpreplay.log -->