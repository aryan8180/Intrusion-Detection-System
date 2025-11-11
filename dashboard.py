#!/usr/bin/env python3
from flask import Flask, render_template_string, request, redirect, url_for, jsonify
import sqlite3
import subprocess
import io, base64, signal
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import sqlite3, os

DB_FILE = "alerts.db"

# Ensure database and table exist
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        src_ip TEXT,
        dst_ip TEXT,
        proto TEXT,
        pkt_count INTEGER,
        byte_count INTEGER,
        duration REAL,
        score REAL,
        severity TEXT,
        extra TEXT
    )
    """)
    conn.commit()
    conn.close()

init_db()


app = Flask(__name__)
DB_FILE = "alerts.db"

# Track running subprocesses
processes = {
    "capture": None,
    "detector": None
}

# =======================
# Helper: Get Process Status
# =======================
def get_status():
    return {
        "capture": "Running" if processes["capture"] else "Stopped",
        "detector": "Running" if processes["detector"] else "Stopped"
    }

# =======================
# HTML TEMPLATE
# =======================
HTML = """
<!doctype html>
<html>
<head>
  <title>IDS Dashboard</title>
  <meta http-equiv="refresh" content="5">
  <style>
    body { font-family: Arial; margin: 20px; background: #f6f7fb; }
    h1 { text-align:center; }
    table { border-collapse: collapse; width: 100%; margin-top: 20px; }
    th, td { padding: 8px; border: 1px solid #ccc; text-align: center; }
    th { background-color: #e0e0e0; }
    .HIGH { background-color: #ffb3b3; }
    .MEDIUM { background-color: #ffe6b3; }
    .LOW { background-color: #b3ffb3; }
    .filter { text-align:center; margin-top: 10px; }
    .chart-link { text-align:center; margin-top: 20px; }
    .controls { text-align:center; margin:15px; }
    button { padding: 8px 16px; margin: 5px; border:none; border-radius:5px; color:white; cursor:pointer; }
    .startcap { background:#4CAF50; }
    .stopcap { background:#f44336; }
    .startdet { background:#2196F3; }
    .stopdet { background:#FF9800; }
    .status { text-align:center; margin:10px; font-size:16px; }
  </style>
</head>
<body>
  <h1>🛡️ Intrusion Detection Dashboard</h1>

  <div class="status">
    <strong>Capture:</strong>
    {% if status['capture'] == 'Running' %}
      <span style="color:green;">🟢 Running</span>
    {% else %}
      <span style="color:red;">🔴 Stopped</span>
    {% endif %}
    &nbsp;&nbsp;|&nbsp;&nbsp;
    <strong>Detection:</strong>
    {% if status['detector'] == 'Running' %}
      <span style="color:green;">🟢 Running</span>
    {% else %}
      <span style="color:red;">🔴 Stopped</span>
    {% endif %}
  </div>

  <div class="controls">
    <form action="/start_capture" method="post" style="display:inline;">
      <button class="startcap">Start Capture</button>
    </form>
    <form action="/stop_capture" method="post" style="display:inline;">
      <button class="stopcap">Stop Capture</button>
    </form>
    <form action="/start_detection" method="post" style="display:inline;">
      <button class="startdet">Start Detection</button>
    </form>
    <form action="/stop_detection" method="post" style="display:inline;">
      <button class="stopdet">Stop Detection</button>
    </form>
  </div>

  <div class="filter">
    <form method="get">
      <label>Filter by Severity:</label>
      <select name="severity" onchange="this.form.submit()">
        <option value="ALL" {% if filter=='ALL' %}selected{% endif %}>ALL</option>
        <option value="HIGH" {% if filter=='HIGH' %}selected{% endif %}>HIGH</option>
        <option value="MEDIUM" {% if filter=='MEDIUM' %}selected{% endif %}>MEDIUM</option>
        <option value="LOW" {% if filter=='LOW' %}selected{% endif %}>LOW</option>
      </select>
    </form>
  </div>

  <h3 style="text-align:center;">Total Alerts: {{ total }} | HIGH: {{ counts['HIGH'] }} | MEDIUM: {{ counts['MEDIUM'] }} | LOW: {{ counts['LOW'] }}</h3>

  <table>
    <tr>
      <th>ID</th><th>Time</th><th>Src</th><th>Dst</th><th>Proto</th>
      <th>Packets</th><th>Bytes</th><th>Duration</th><th>Score</th><th>Severity</th>
    </tr>
    {% for row in rows %}
    <tr class="{{ row['severity'] }}">
      <td>{{ row['id'] }}</td>
      <td>{{ row['ts'] }}</td>
      <td>{{ row['src_ip'] }}</td>
      <td>{{ row['dst_ip'] }}</td>
      <td>{{ row['proto'] }}</td>
      <td>{{ row['pkt_count'] }}</td>
      <td>{{ row['byte_count'] }}</td>
      <td>{{ row['duration'] }}</td>
      <td>{{ "%.4f"|format(row['score']) }}</td>
      <td>{{ row['severity'] }}</td>
    </tr>
    {% endfor %}
  </table>

  <div class="chart-link">
    <hr>
    <h2 style="text-align:center;">📊 Real-Time IDS Metrics</h2>
    <div id="charts" style="display:flex;justify-content:center;gap:40px;">
      <div id="chart1" style="width:45%;"></div>
      <div id="chart2" style="width:45%;"></div>
    </div>

    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <script>
    async function updateCharts() {
      const res = await fetch("/data");
      const data = await res.json();

      Plotly.newPlot('chart1', [{
        x: data.time_labels,
        y: data.time_values,
        type: 'scatter',
        mode: 'lines+markers',
        line: { color: '#2196F3' }
      }], {
        title: 'Alerts per Minute (Last 15 min)',
        xaxis: { title: 'Time (HH:MM)' },
        yaxis: { title: 'Count' }
      });

      Plotly.newPlot('chart2', [{
        labels: data.severity_labels,
        values: data.severity_values,
        type: 'pie',
        marker: { colors: ['#ff6666', '#ffd966', '#93c47d'] }
      }], { title: 'Alert Severity Distribution' });
    }
    updateCharts();
    setInterval(updateCharts, 5000);
    </script>

    <a href="/chart">📊 View Static Chart</a>
  </div>

  <hr>
  <h2 style="text-align:center;">🧾 Recent System Logs</h2>
  <iframe src="/logs" width="100%" height="200" style="border:1px solid #ccc; background:#fff;"></iframe>

  <script>
  setInterval(() => {
      document.querySelector("iframe").src = "/logs?" + new Date().getTime();
  }, 7000);
  </script>
</body>
</html>
"""

# =======================
# ROUTES
# =======================
@app.route("/")
def index():
    severity_filter = request.args.get("severity", "ALL").upper()

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    if severity_filter == "ALL":
        cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 100")
    else:
        cur.execute("SELECT * FROM alerts WHERE severity=? ORDER BY id DESC LIMIT 100", (severity_filter,))
    rows = cur.fetchall()
    conn.close()

    # counts
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
    data = cur.fetchall()
    conn.close()
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for d in data:
        counts[d[0]] = d[1]

    status = get_status()
    return render_template_string(HTML, rows=rows, counts=counts, total=len(rows),
                                  filter=severity_filter, status=status)

# =======================
# LOGS ROUTE
# =======================
@app.route("/logs")
def logs():
    log_lines = []
    for name, proc in processes.items():
        if proc and proc.stdout:
            try:
                lines = proc.stdout.readlines()[-10:]
                if lines:
                    log_lines.append(f"[{name}] " + "".join(line.decode('utf-8') for line in lines))
            except Exception:
                pass
    if not log_lines:
        log_lines = ["(No active process output)"]
    return "<pre style='padding:10px; font-size:13px;'>" + "\n".join(log_lines) + "</pre>"

# =======================
# PROCESS CONTROL ROUTES
# =======================
@app.route("/start_capture", methods=["POST"])
def start_capture():
    if processes["capture"] is None:
        try:
            iface = "Wi-Fi"  # change this for your interface
            processes["capture"] = subprocess.Popen(
                ["python", "capture_live.py", "-i", iface],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
            print("✅ Started capture_live.py")
        except Exception as e:
            print("❌ Error starting capture:", e)
    else:
        print("⚠️ Capture already running.")
    return redirect(url_for("index"))

@app.route("/stop_capture", methods=["POST"])
def stop_capture():
    if processes["capture"]:
        try:
            processes["capture"].terminate()
            processes["capture"] = None
            print("🛑 Stopped capture_live.py")
        except Exception as e:
            print("❌ Error stopping capture:", e)
    else:
        print("⚠️ No capture process running.")
    return redirect(url_for("index"))

@app.route("/start_detection", methods=["POST"])
def start_detection():
    if processes["detector"] is None:
        try:
            processes["detector"] = subprocess.Popen(
                ["python", "realtime_detector.py"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
            print("✅ Started realtime_detector.py")
        except Exception as e:
            print("❌ Error starting detector:", e)
    else:
        print("⚠️ Detector already running.")
    return redirect(url_for("index"))

@app.route("/stop_detection", methods=["POST"])
def stop_detection():
    if processes["detector"]:
        try:
            processes["detector"].terminate()
            processes["detector"] = None
            print("🛑 Stopped realtime_detector.py")
        except Exception as e:
            print("❌ Error stopping detector:", e)
    else:
        print("⚠️ No detector process running.")
    return redirect(url_for("index"))

# =======================
# DATA + CHARTS
# =======================
@app.route("/data")
def data():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        SELECT strftime('%H:%M', ts), COUNT(*)
        FROM alerts
        WHERE ts >= datetime('now','-15 minutes')
        GROUP BY strftime('%H:%M', ts)
        ORDER BY ts ASC
    """)
    time_data = cur.fetchall()
    cur.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
    sev_data = cur.fetchall()
    conn.close()
    return jsonify({
        "time_labels": [t[0] for t in time_data],
        "time_values": [t[1] for t in time_data],
        "severity_labels": [s[0] for s in sev_data],
        "severity_values": [s[1] for s in sev_data]
    })

@app.route("/chart")
def chart():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
    data = cur.fetchall()
    conn.close()

    labels = [d[0] for d in data] if data else ["No Data"]
    values = [d[1] for d in data] if data else [0]

    plt.figure(figsize=(5,4))
    plt.bar(labels, values, color=["#ff6666", "#ffd966", "#93c47d"])
    plt.title("Alerts by Severity")
    plt.xlabel("Severity Level")
    plt.ylabel("Count")
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format="png")
    buf.seek(0)
    img = base64.b64encode(buf.getvalue()).decode("utf-8")
    buf.close()

    return f"""
    <html><head><meta http-equiv="refresh" content="10"></head>
    <body style="text-align:center;font-family:Arial;">
      <h2>📊 Alert Severity Chart (Auto-refresh 10s)</h2>
      <img src="data:image/png;base64,{img}" />
      <br><br><a href="/">⬅ Back to Dashboard</a>
    </body></html>
    """

# =======================
# MAIN
# =======================
if __name__ == "__main__":
    print("Starting IDS Dashboard at http://127.0.0.1:5000")
    app.run(debug=True)
