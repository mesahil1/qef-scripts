import argparse, csv, json, sys
from collections import defaultdict
from pathlib import Path

def norm(sip,dip,sp,dp):
    try: sp,dp = int(sp or 0), int(dp or 0)
    except: sp,dp = 0,0
    a,b = (str(sip),sp),(str(dip),dp)
    return (a[0],b[0],a[1],b[1]) if a<=b else (b[0],a[0],b[1],a[1])

def load_labels(path):
    flows, cats = {}, set()
    for enc in ("utf-8","latin-1"):
        try: f=open(path,encoding=enc); f.readline(); f.seek(0); break
        except UnicodeDecodeError: continue
    rd = csv.DictReader(f)
    fm = {}
    for want in ("Source IP","Destination IP","Source Port","Destination Port","Label"):
        for got in rd.fieldnames or []:
            if got.strip()==want: fm[want]=got; break
    for row in rd:
        k = norm(row[fm["Source IP"]], row[fm["Destination IP"]],
                 row[fm["Source Port"]], row[fm["Destination Port"]])
        lbl = row[fm["Label"]].strip()
        flows[k] = lbl
        if lbl != "BENIGN": cats.add(lbl)
    return flows, cats

def load_alerts(path, exclude_internal=True):
    alerts = defaultdict(list)
    for line in open(path):
        try: e = json.loads(line)
        except: continue
        if e.get("event_type") != "alert": continue
        sig = e.get("alert",{}).get("signature","")
        if exclude_internal and sig.startswith("SURICATA"): continue
        k = norm(e.get("src_ip"), e.get("dest_ip"),
                 e.get("src_port"), e.get("dest_port"))
        alerts[k].append(sig)
    return alerts

ap = argparse.ArgumentParser()
ap.add_argument("--eve", required=True); ap.add_argument("--label", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--include-internal", action="store_true",
                help="Include SURICATA decoder events (default: exclude)")
a = ap.parse_args()

labels, exp_cats = load_labels(a.label)
alerts = load_alerts(a.eve, exclude_internal=not a.include_internal)

tp=fp=fn=tn=0
det = set()
for k,lbl in labels.items():
    is_atk = lbl != "BENIGN"
    is_alt = k in alerts
    if is_atk and is_alt:    tp+=1; det.add(lbl)
    elif is_atk:              fn+=1
    elif is_alt:              fp+=1
    else:                     tn+=1

tpr = 100*tp/(tp+fn) if (tp+fn) else 0
fpr = 1000*fp/(fp+tn) if (fp+tn) else 0

result = dict(TP=tp,FP=fp,FN=fn,TN=tn,
              TPR_percent=round(tpr,3), FPR_per_1k_benign=round(fpr,3),
              expected=sorted(exp_cats), detected=sorted(det),
              categories_detected=len(det))
Path(a.out).write_text(json.dumps(result, indent=2))
print(json.dumps(result, indent=2))