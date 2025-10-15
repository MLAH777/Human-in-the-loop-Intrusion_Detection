from flask import Flask, render_template_string, request, redirect
import json, pandas as pd, time, os
APP = Flask(__name__)
LOG = "detections.json"
DATA = "big_threat_dataset.csv"
COLUMNS = ["AttackType","SourceIP","DestIP","Port","URL/Domain","Username","Attempts","HumanDecision","HumanReason"]
template = """
<!doctype html>
<html>
<head>
 <title>Human Interference Needed</title>
 <style>
  body{font-family:Arial;margin:20px}
  .prevent{background:#d9534f;color:#fff;padding:6px 10px;border:none}
  .safe{background:#5cb85c;color:#fff;padding:6px 10px;border:none}
  table{border-collapse:collapse;width:100%}
  th,td{border:1px solid #ddd;padding:8px}
 </style>
</head>
<body>
<h2>Pending Detections</h2>
{% if detections %}
<table><tr><th>Time</th><th>Tool</th><th>Summary</th><th>Action</th></tr>
{% for d in detections %}
<tr>
 <td>{{ d['t'] }}</td>
 <td>{{ d['tool'] }}</td>
 <td>{{ d['summary'] }}</td>
 <td>
  <form method="POST" action="/handle">
    <input type="hidden" name="idx" value="{{ loop.index0 }}">
    <input type="hidden" name="tool" value="{{ d['tool'] }}">
    <button name="action" value="Safe" class="safe">Safe</button>
    <button name="action" value="Prevent" class="prevent">Prevent</button>
  </form>
 </td>
</tr>
{% endfor %}
<tr>
 <td>{{d['t']}}</td>
 <td>{{d['tool']}}</td>
 <td>{{d['summary']}}</td>
 <td>
  <form method="POST" action="/handle">
    <input type="hidden" name="idx" value="{{i}}">
    <input type="hidden" name="tool" value="{{d['tool']}}">
    <button name="action" value="Safe" class="safe">Safe</button>
    <button name="action" value="Prevent" class="prevent">Prevent</button>
  </form>
 </td>
</tr>
{% endfor %}
</table>
{% else %}
<p>No pending detections.</p>
{% endif %}
</body>
</html>
"""
def load_log():
    try:
        a = json.load(open(LOG,"r"))
    except:
        a = []
    out = []
    for e in a:
        t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e.get("timestamp", time.time())))
        if e.get("tool")=="port":
            summary = f"Open port {e.get('port')} on {e.get('dst')}"
        elif e.get("tool")=="phish":
            summary = f"URL {e.get('url')} score {e.get('heuristic_score')}"
        else:
            summary = f"IP {e.get('src')} attempts {e.get('attempts')}"
        out.append({"tool":e.get("tool"),"summary":summary,"raw":e,"t":t})
    return out
def pop_log_index(idx):
    try:
        arr = json.load(open(LOG,"r"))
    except:
        arr = []
    if 0 <= idx < len(arr):
        entry = arr.pop(idx)
        json.dump(arr, open(LOG,"w"), indent=2)
        return entry
    return None
def append_dataset(row):
    if not os.path.exists(DATA):
        pd.DataFrame(columns=COLUMNS).to_csv(DATA,index=False)
    df = pd.read_csv(DATA)
    df = pd.concat([df, pd.DataFrame([row])], ignore_index=True)
    df.to_csv(DATA,index=False)
@APP.route("/", methods=["GET"])
def home():
    det = load_log()
    return render_template_string(template, detections=det)
@APP.route("/handle", methods=["POST"])
def handle():
    idx = int(request.form["idx"])
    action = request.form["action"]
    entry = pop_log_index(idx)
    if not entry:
        return redirect("/")
    raw = entry
    if action == "Prevent":
        reason = request.form.get("reason","")
        human_reason = reason or "Prevented via UI"
        human_decision = "Prevent"
    else:
        human_reason = "-"
        human_decision = "Safe"
    tool = raw.get("tool")
    if tool == "port":
        row = {"AttackType":"PortScan","SourceIP":raw.get("src","-"),"DestIP":raw.get("dst","-"),"Port":str(raw.get("port","-")),
               "URL/Domain":"-","Username":"-","Attempts":"-","HumanDecision":human_decision,"HumanReason":human_reason}
    elif tool == "phish":
        row = {"AttackType":"Phishing","SourceIP":"-","DestIP":"-","Port":"-","URL/Domain":raw.get("url","-"),
               "Username":"-","Attempts":"-","HumanDecision":human_decision,"HumanReason":human_reason}
    else:
        row = {"AttackType":"BruteForce","SourceIP":raw.get("src","-"),"DestIP":raw.get("dst","-"),"Port":str(raw.get("port","-")),
               "URL/Domain":"-","Username":raw.get("username","-"),"Attempts":str(raw.get("attempts","-")),"HumanDecision":human_decision,"HumanReason":human_reason}
    append_dataset(row)
    return redirect("/")
if __name__ == "__main__":
    APP.run(host="0.0.0.0", port=5000, debug=False)

