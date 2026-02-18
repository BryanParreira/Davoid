import os
import datetime
import re
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
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        body { background-color: #0d1117; color: #c9d1d9; font-family: monospace; margin: 20px; }
        #network-map { width: 100%; height: 600px; border: 1px solid #30363d; background: #000; }
        .log-entry { background: #161b22; border: 1px solid #30363d; margin-bottom: 10px; padding: 10px; }
        .severity-CRITICAL { border-left: 5px solid #ff7b72; }
        .severity-INFO { border-left: 5px solid #58a6ff; }
    </style>
</head>
<body>
    <h1>DAVOID // MISSION DATABASE EXPORT</h1>
    <p>Generated: {{ timestamp }}</p>
    <div id="network-map"></div>
    
    <h2>DATABASE RECORDS</h2>
    {% for log in logs %}
    <div class="log-entry severity-{{ log.severity }}">
        <strong>{{ log.timestamp }} | {{ log.module }} -> {{ log.target }}</strong>
        <pre>{{ log.data }}</pre>
    </div>
    {% endfor %}

    <script type="text/javascript">
        var nodes = new vis.DataSet({{ nodes_json }});
        var edges = new vis.DataSet({{ edges_json }});
        var container = document.getElementById('network-map');
        var data = { nodes: nodes, edges: edges };
        var options = {
            nodes: { shape: 'dot', size: 15, font: { color: '#ffffff' } },
            physics: { stabilization: false }
        };
        var network = new vis.Network(container, data, options);
    </script>
</body>
</html>
"""

def generate_report():
    console.print(Panel("Accessing Mission Database...", title="Reporter", border_style="cyan"))
    
    # FETCH FROM DB
    logs = db.get_all()
    if not logs:
        return console.print("[yellow][!] Database is empty. Run scans first.[/yellow]")

    # Build Graph Data from DB
    nodes = [{"id": 0, "label": "DAVOID-HQ", "color": "#ff7b72", "size": 30}]
    edges = []
    seen_ips = set()
    
    for idx, log in enumerate(logs, 1):
        if log.target and log.target not in seen_ips:
            seen_ips.add(log.target)
            nodes.append({"id": idx, "label": log.target, "color": "#2ea043"})
            edges.append({"from": 0, "to": idx})

    try:
        t = Template(TEMPLATE_HTML)
        html = t.render(
            title="Davoid Threat Map (DB)",
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            logs=logs,
            nodes_json=nodes,
            edges_json=edges
        )
        
        fname = f"Mission_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.html"
        with open(fname, "w") as f: f.write(html)
            
        console.print(f"[bold green][+] Report Generated: {fname}[/bold green]")
        if os.name == 'posix': os.system(f"open {fname} 2>/dev/null || xdg-open {fname} 2>/dev/null")
            
    except Exception as e:
        console.print(f"[red][!] Reporting Error: {e}[/red]")

if __name__ == "__main__":
    generate_report()