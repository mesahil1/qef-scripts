#/bin/bash
for day in Wednesday Thursday Friday; do
  mkdir -p ~/qef-results/suricata/phase3/run-$day
  cd ~/qef-results/suricata/phase3/run-$day
  sar -u -r 5 > cpu_mem.log &
  SAR_PID=$!
  sudo /usr/bin/time -v suricata -c /etc/suricata/suricata.yaml -i qef0 -l . --runmode=workers 2> timing.log &
  SUR_PID=$!
  sleep 5
  sudo tcpreplay -i qef0 --multiplier=2 --stats=10 ~/pcap/${day}-WorkingHours.pcap 2>&1 | tee tcpreplay.log
  sleep 10
  sudo kill -SIGINT $SUR_PID
  wait $SUR_PID 2>/dev/null
  kill $SAR_PID 2>/dev/null
  echo "=== $day done ==="
done