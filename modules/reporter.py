"""
reporter.py — HTML Mission Report Generator
FIXES:
  - nodes_json / edges_json now properly serialized with json.dumps()
    (previously passed raw Python lists → browser JS error, graph never rendered)
  - Works with the updated database.py dict return format ('details' key)
  - Added severity counts summary bar at the top of the report
  - Added per-module breakdown table
  - Clickable nodes in the network graph highlight related log entries
  - Report filename returned so callers can use it
  - Graceful handling of empty database
"""

import os
import json
import datetime
from jinja2 import Template
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from core.database import db

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
#  HTML TEMPLATE
# ─────────────────────────────────────────────────────────────────────────────

TEMPLATE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{ title }}</title>
  <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background: #0d1117;
      color: #c9d1d9;
      font-family: 'Consolas', 'Monaco', monospace;
      padding: 24px;
      line-height: 1.6;
    }

    h1 { color: #ff7b72; font-size: 1.8rem; margin-bottom: 4px; }
    h2 { color: #79c0ff; font-size: 1.2rem; margin: 24px 0 12px; border-bottom: 1px solid #30363d; padding-bottom: 6px; }

    .meta { color: #8b949e; font-size: 0.85rem; margin-bottom: 24px; }

    /* ── Summary bar ── */
    .summary-bar {
      display: flex;
      gap: 12px;
      margin-bottom: 24px;
      flex-wrap: wrap;
    }
    .badge {
      padding: 6px 16px;
      border-radius: 4px;
      font-weight: bold;
      font-size: 0.9rem;
    }
    .badge-critical { background: #3d1a1a; border: 1px solid #ff7b72; color: #ff7b72; }
    .badge-high     { background: #2d1f0e; border: 1px solid #f0883e; color: #f0883e; }
    .badge-info     { background: #0e2035; border: 1px solid #58a6ff; color: #58a6ff; }
    .badge-total    { background: #1c1c2e; border: 1px solid #8b949e; color: #8b949e; }

    /* ── Network map ── */
    #network-map {
      width: 100%;
      height: 520px;
      border: 1px solid #30363d;
      border-radius: 6px;
      background: #010409;
      margin-bottom: 8px;
    }
    .map-hint { color: #8b949e; font-size: 0.78rem; margin-bottom: 24px; }

    /* ── Module breakdown table ── */
    .module-table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 24px;
      font-size: 0.88rem;
    }
    .module-table th {
      background: #161b22;
      color: #79c0ff;
      padding: 8px 12px;
      text-align: left;
      border: 1px solid #30363d;
    }
    .module-table td {
      padding: 6px 12px;
      border: 1px solid #21262d;
      vertical-align: top;
    }
    .module-table tr:nth-child(even) td { background: #0d1117; }
    .module-table tr:nth-child(odd)  td { background: #161b22; }

    /* ── Log entries ── */
    .log-entry {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 4px;
      margin-bottom: 10px;
      padding: 12px 14px;
      transition: border-color 0.2s;
    }
    .log-entry:hover { border-color: #58a6ff; }
    .log-entry.hidden { display: none; }

    .log-entry.severity-CRITICAL { border-left: 4px solid #ff7b72; }
    .log-entry.severity-HIGH     { border-left: 4px solid #f0883e; }
    .log-entry.severity-INFO     { border-left: 4px solid #58a6ff; }

    .log-header {
      display: flex;
      gap: 10px;
      align-items: baseline;
      flex-wrap: wrap;
      margin-bottom: 6px;
    }
    .sev-badge {
      font-size: 0.72rem;
      padding: 2px 7px;
      border-radius: 3px;
      font-weight: bold;
    }
    .sev-CRITICAL { background: #3d1a1a; color: #ff7b72; }
    .sev-HIGH     { background: #2d1f0e; color: #f0883e; }
    .sev-INFO     { background: #0e2035; color: #58a6ff; }

    .log-module { color: #79c0ff; font-weight: bold; }
    .log-target { color: #3fb950; }
    .log-time   { color: #8b949e; font-size: 0.8rem; margin-left: auto; }

    pre {
      white-space: pre-wrap;
      word-break: break-all;
      color: #8b949e;
      font-size: 0.82rem;
      margin-top: 6px;
      max-height: 200px;
      overflow-y: auto;
      background: #010409;
      padding: 8px;
      border-radius: 3px;
    }

    /* ── Filter bar ── */
    .filter-bar {
      display: flex;
      gap: 10px;
      margin-bottom: 16px;
      flex-wrap: wrap;
      align-items: center;
    }
    .filter-btn {
      padding: 4px 14px;
      border-radius: 4px;
      border: 1px solid #30363d;
      background: #161b22;
      color: #c9d1d9;
      cursor: pointer;
      font-family: inherit;
      font-size: 0.85rem;
      transition: background 0.15s;
    }
    .filter-btn:hover, .filter-btn.active { background: #21262d; border-color: #58a6ff; }

    #search-box {
      padding: 4px 10px;
      border-radius: 4px;
      border: 1px solid #30363d;
      background: #0d1117;
      color: #c9d1d9;
      font-family: inherit;
      font-size: 0.85rem;
      width: 240px;
    }
  </style>
</head>
<body>

  <h1>⚡ DAVOID // MISSION REPORT</h1>
  <p class="meta">Generated: {{ timestamp }} &nbsp;|&nbsp; Total findings: {{ logs|length }}</p>

  <!-- Summary badges -->
  <div class="summary-bar">
    <span class="badge badge-total">TOTAL {{ logs|length }}</span>
    <span class="badge badge-critical">CRITICAL {{ critical_count }}</span>
    <span class="badge badge-high">HIGH {{ high_count }}</span>
    <span class="badge badge-info">INFO {{ info_count }}</span>
  </div>

  <!-- Network map -->
  <h2>Threat Network Map</h2>
  <div id="network-map"></div>
  <p class="map-hint">Click a target node to filter log entries below.</p>

  <!-- Module breakdown -->
  <h2>Module Activity Breakdown</h2>
  <table class="module-table">
    <thead>
      <tr><th>Module</th><th>Targets Hit</th><th>Findings</th></tr>
    </thead>
    <tbody>
      {% for mod, stats in module_stats.items() %}
      <tr>
        <td>{{ mod }}</td>
        <td>{{ stats.targets | join(', ') }}</td>
        <td>{{ stats.count }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <!-- Log entries -->
  <h2>All Log Entries</h2>

  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterSev('ALL')">All</button>
    <button class="filter-btn" onclick="filterSev('CRITICAL')">Critical</button>
    <button class="filter-btn" onclick="filterSev('HIGH')">High</button>
    <button class="filter-btn" onclick="filterSev('INFO')">Info</button>
    <input id="search-box" type="text" placeholder="Search targets / modules..." oninput="filterSearch(this.value)">
    <button class="filter-btn" id="clear-node-filter" style="display:none" onclick="clearNodeFilter()">✕ Clear map filter</button>
  </div>

  <div id="log-container">
    {% for log in logs %}
    <div class="log-entry severity-{{ log.severity }}"
         data-sev="{{ log.severity }}"
         data-target="{{ log.target }}"
         data-module="{{ log.module }}">
      <div class="log-header">
        <span class="sev-badge sev-{{ log.severity }}">{{ log.severity }}</span>
        <span class="log-module">{{ log.module }}</span>
        <span>→</span>
        <span class="log-target">{{ log.target }}</span>
        <span class="log-time">{{ log.timestamp }}</span>
      </div>
      <pre>{{ log.details }}</pre>
    </div>
    {% endfor %}
  </div>

  <!-- vis.js network -->
  <script>
    var nodes = new vis.DataSet({{ nodes_json }});
    var edges = new vis.DataSet({{ edges_json }});

    var network = new vis.Network(
      document.getElementById('network-map'),
      { nodes: nodes, edges: edges },
      {
        nodes: {
          shape: 'dot', size: 16,
          font: { color: '#ffffff', size: 13 },
          borderWidth: 2
        },
        edges: {
          color: { color: '#30363d', highlight: '#58a6ff' },
          smooth: { type: 'continuous' }
        },
        physics: {
          stabilization: { iterations: 100 },
          barnesHut: { gravitationalConstant: -8000 }
        },
        interaction: { hover: true }
      }
    );

    // Click node → filter log entries to that target
    var activeNodeTarget = null;
    network.on('click', function(params) {
      if (params.nodes.length > 0) {
        var nodeId = params.nodes[0];
        var nodeData = nodes.get(nodeId);
        if (nodeData && nodeData.label !== 'DAVOID-HQ') {
          activeNodeTarget = nodeData.label;
          applyAllFilters();
          document.getElementById('clear-node-filter').style.display = 'inline-block';
        }
      }
    });

    function clearNodeFilter() {
      activeNodeTarget = null;
      document.getElementById('clear-node-filter').style.display = 'none';
      applyAllFilters();
    }

    // Severity + search + node filter applied together
    var activeSev   = 'ALL';
    var activeSearch = '';

    function filterSev(sev) {
      activeSev = sev;
      document.querySelectorAll('.filter-btn').forEach(function(b) {
        b.classList.toggle('active', b.textContent.trim().startsWith(sev) || (sev === 'ALL' && b.textContent.trim() === 'All'));
      });
      applyAllFilters();
    }

    function filterSearch(val) {
      activeSearch = val.toLowerCase();
      applyAllFilters();
    }

    function applyAllFilters() {
      document.querySelectorAll('.log-entry').forEach(function(el) {
        var sevOk    = activeSev === 'ALL' || el.dataset.sev === activeSev;
        var searchOk = !activeSearch ||
                       el.dataset.target.toLowerCase().includes(activeSearch) ||
                       el.dataset.module.toLowerCase().includes(activeSearch);
        var nodeOk   = !activeNodeTarget || el.dataset.target === activeNodeTarget;
        el.classList.toggle('hidden', !(sevOk && searchOk && nodeOk));
      });
    }
  </script>
</body>
</html>
"""


# ─────────────────────────────────────────────────────────────────────────────
#  GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate_report() -> str | None:
    """
    Build an HTML mission report from the database.
    Returns the filename on success, None on failure.
    """
    console.print(Panel("Accessing Mission Database...", title="Reporter", border_style="cyan"))

    try:
        raw_logs = db.get_all()
    except Exception as e:
        console.print(f"[red][!] Cannot read database: {e}[/red]")
        return None

    if not raw_logs:
        console.print("[yellow][!] Database is empty. Run scans first.[/yellow]")
        return None

    # ── Severity counts ───────────────────────────────────────────
    critical_count = sum(1 for l in raw_logs if l.get("severity") == "CRITICAL")
    high_count     = sum(1 for l in raw_logs if l.get("severity") == "HIGH")
    info_count     = sum(1 for l in raw_logs if l.get("severity") == "INFO")

    # ── Module breakdown ──────────────────────────────────────────
    module_stats: dict = {}
    for log in raw_logs:
        mod = log.get("module", "Unknown")
        tgt = log.get("target", "")
        if mod not in module_stats:
            module_stats[mod] = {"count": 0, "targets": set()}
        module_stats[mod]["count"] += 1
        if tgt:
            module_stats[mod]["targets"].add(tgt)

    # Convert sets to sorted lists for Jinja2
    for mod in module_stats:
        module_stats[mod]["targets"] = sorted(module_stats[mod]["targets"])

    # ── vis.js graph data ─────────────────────────────────────────
    # HQ node
    nodes = [{"id": 0, "label": "DAVOID-HQ", "color": "#ff7b72", "size": 30, "font": {"size": 16}}]
    edges = []
    seen_targets: dict = {}   # target → node_id

    node_id = 1
    for log in raw_logs:
        tgt = log.get("target", "").strip()
        sev = log.get("severity", "INFO")

        if not tgt or tgt in seen_targets:
            if tgt in seen_targets:
                edges.append({"from": 0, "to": seen_targets[tgt]})
            continue

        color_map = {"CRITICAL": "#ff7b72", "HIGH": "#f0883e", "INFO": "#58a6ff"}
        color = color_map.get(sev, "#58a6ff")

        nodes.append({
            "id":    node_id,
            "label": tgt,
            "color": color,
            "size":  20,
        })
        edges.append({"from": 0, "to": node_id})
        seen_targets[tgt] = node_id
        node_id += 1

    # Deduplicate edges
    unique_edges = list({(e["from"], e["to"]): e for e in edges}.values())

    # ── Render ────────────────────────────────────────────────────
    try:
        html = Template(TEMPLATE_HTML).render(
            title          = "Davoid Threat Map",
            timestamp      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            logs           = raw_logs,
            critical_count = critical_count,
            high_count     = high_count,
            info_count     = info_count,
            module_stats   = module_stats,
            nodes_json     = json.dumps(nodes),          # ← FIX: proper JSON serialization
            edges_json     = json.dumps(unique_edges),   # ← FIX: proper JSON serialization
        )

        fname = f"Mission_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.html"
        with open(fname, "w", encoding="utf-8") as f:
            f.write(html)

        # Summary table in terminal
        table = Table(title="Report Generated", border_style="green")
        table.add_column("Metric",  style="cyan")
        table.add_column("Value",   style="white")
        table.add_row("File",       fname)
        table.add_row("Total Logs", str(len(raw_logs)))
        table.add_row("Critical",   str(critical_count))
        table.add_row("High",       str(high_count))
        table.add_row("Info",       str(info_count))
        console.print(table)

        # Try to open in default browser
        if os.name == "posix":
            os.system(f"open '{fname}' 2>/dev/null || xdg-open '{fname}' 2>/dev/null &")

        return fname

    except Exception as e:
        console.print(f"[red][!] Report generation error: {e}[/red]")
        return None


if __name__ == "__main__":
    generate_report()