"""
reporter.py — HTML Mission Report Generator
FIX: log.attr vs log['key'] — now handles BOTH dict and ORM object return types
     from db.get_all() so it works regardless of which DB backend is used.
"""

import os
import datetime
from jinja2 import Template
from rich.console import Console
from rich.panel import Panel
from core.database import db

console = Console()

TEMPLATE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{{ title }}</title>
  <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    body         { background:#0d1117; color:#c9d1d9; font-family:monospace; margin:20px; }
    h1,h2        { color:#ff7b72; }
    #network-map { width:100%; height:600px; border:1px solid #30363d; background:#000; margin-bottom:30px; }
    .log-entry   { background:#161b22; border:1px solid #30363d; margin-bottom:10px; padding:12px; border-radius:4px; }
    .severity-CRITICAL { border-left:5px solid #ff7b72; }
    .severity-HIGH     { border-left:5px solid #f0883e; }
    .severity-INFO     { border-left:5px solid #58a6ff; }
    pre          { white-space:pre-wrap; word-break:break-all; color:#8b949e; margin:6px 0 0 0; }
  </style>
</head>
<body>
  <h1>⚡ DAVOID // MISSION DATABASE EXPORT</h1>
  <p>Generated: <strong>{{ timestamp }}</strong></p>

  <h2>Threat Network Map</h2>
  <div id="network-map"></div>

  <h2>All Log Records ({{ logs|length }})</h2>
  {% for log in logs %}
  <div class="log-entry severity-{{ log.severity }}">
    <strong>[{{ log.severity }}] {{ log.timestamp }} | {{ log.module }} → {{ log.target }}</strong>
    <pre>{{ log.details }}</pre>
  </div>
  {% endfor %}

  <script>
    var nodes = new vis.DataSet({{ nodes_json }});
    var edges = new vis.DataSet({{ edges_json }});
    var net   = new vis.Network(
      document.getElementById('network-map'),
      { nodes: nodes, edges: edges },
      { nodes: { shape:'dot', size:15, font:{color:'#ffffff'} },
        physics: { stabilization:false } }
    );
  </script>
</body>
</html>
"""


def _get_attr(obj, key):
    """
    Universal accessor — works whether obj is a dict or an ORM row object.
    Returns empty string if attribute/key is missing.
    """
    if isinstance(obj, dict):
        return obj.get(key, "")
    return getattr(obj, key, "")


def generate_report():
    console.print(Panel("Accessing Mission Database...",
                  title="Reporter", border_style="cyan"))

    try:
        raw_logs = db.get_all()
    except Exception as e:
        console.print(f"[red][!] Cannot read database: {e}[/red]")
        return

    if not raw_logs:
        console.print(
            "[yellow][!] Database is empty. Run scans first.[/yellow]")
        return

    # Normalise every log row into a plain dict so Jinja2 can access attributes
    logs = []
    for row in raw_logs:
        logs.append({
            "timestamp": str(_get_attr(row, "timestamp") or ""),
            "module":    str(_get_attr(row, "module") or ""),
            "target":    str(_get_attr(row, "target") or ""),
            "severity":  str(_get_attr(row, "severity") or "INFO"),
            "details":   str(_get_attr(row, "details") or ""),
        })

    # Build vis.js network graph
    nodes = [{"id": 0, "label": "DAVOID-HQ", "color": "#ff7b72", "size": 30}]
    edges = []
    seen = set()

    for idx, log in enumerate(logs, 1):
        tgt = log["target"]
        if tgt and tgt not in seen:
            seen.add(tgt)
            nodes.append({"id": idx, "label": tgt, "color": "#2ea043"})
            edges.append({"from": 0, "to": idx})

    try:
        html = Template(TEMPLATE_HTML).render(
            title="Davoid Threat Map",
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            logs=logs,
            nodes_json=nodes,
            edges_json=edges,
        )

        fname = f"Mission_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.html"
        with open(fname, "w", encoding="utf-8") as f:
            f.write(html)

        console.print(
            f"[bold green][+] Report generated: {fname}[/bold green]")

        # Try to open in default browser
        if os.name == 'posix':
            os.system(
                f"open '{fname}' 2>/dev/null || xdg-open '{fname}' 2>/dev/null &")

    except Exception as e:
        console.print(f"[red][!] Report error: {e}[/red]")


if __name__ == "__main__":
    generate_report()
