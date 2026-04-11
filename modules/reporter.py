"""
reporter.py — Professional Mission Report Generator
UPGRADED:
  - Findings grouped by severity (CRITICAL → HIGH → INFO)
  - Executive summary with risk counts at the top
  - Operator / company name from config
  - Optional PDF export via weasyprint (graceful fallback if not installed)
  - Interactive vis.js network threat map
  - Clean, print-ready CSS styling
"""

import os
import datetime
from jinja2 import Template
from rich.console import Console
from rich.panel import Panel
from core.database import db

console = Console()

# ── Pull operator info from config (falls back to defaults gracefully) ─────────
try:
    from core.config import get as cfg_get
    OPERATOR = cfg_get("reporting", "operator_name") or "Red Team Operator"
    COMPANY  = cfg_get("reporting", "company_name")  or "Davoid Security"
    OUT_DIR  = cfg_get("reporting", "output_dir")    or "reports"
except Exception:
    OPERATOR = "Red Team Operator"
    COMPANY  = "Davoid Security"
    OUT_DIR  = "reports"

os.makedirs(OUT_DIR, exist_ok=True)

# ══════════════════════════════════════════════════════════════════════════════
#  HTML TEMPLATE
# ══════════════════════════════════════════════════════════════════════════════

TEMPLATE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{ company }} — Pentest Report</title>
  <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    /* ── Reset & base ───────────────────────────────────────────── */
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #0d1117;
      color: #c9d1d9;
      font-family: 'Segoe UI', system-ui, sans-serif;
      font-size: 14px;
      line-height: 1.6;
      padding: 40px;
    }
    a { color: #58a6ff; }

    /* ── Cover block ─────────────────────────────────────────────── */
    .cover {
      border: 2px solid #ff7b72;
      border-radius: 8px;
      padding: 40px;
      margin-bottom: 40px;
      background: #161b22;
    }
    .cover h1 { font-size: 2rem; color: #ff7b72; margin-bottom: 8px; }
    .cover .meta { color: #8b949e; font-size: 0.9rem; margin-top: 12px; }

    /* ── Executive summary ───────────────────────────────────────── */
    .exec-summary {
      display: flex;
      gap: 16px;
      margin-bottom: 40px;
      flex-wrap: wrap;
    }
    .risk-card {
      flex: 1;
      min-width: 140px;
      border-radius: 8px;
      padding: 20px;
      text-align: center;
      background: #161b22;
    }
    .risk-card .count { font-size: 2.5rem; font-weight: 700; }
    .risk-card .label { font-size: 0.8rem; color: #8b949e; margin-top: 4px; }
    .critical { border: 2px solid #ff7b72; }
    .critical .count { color: #ff7b72; }
    .high     { border: 2px solid #f0883e; }
    .high     .count { color: #f0883e; }
    .medium   { border: 2px solid #d29922; }
    .medium   .count { color: #d29922; }
    .info     { border: 2px solid #58a6ff; }
    .info     .count { color: #58a6ff; }

    /* ── Section headers ─────────────────────────────────────────── */
    h2 {
      color: #ff7b72;
      border-bottom: 1px solid #30363d;
      padding-bottom: 8px;
      margin: 40px 0 20px;
      font-size: 1.25rem;
    }
    h3 { color: #e6edf3; margin: 24px 0 8px; font-size: 1rem; }

    /* ── Network map ─────────────────────────────────────────────── */
    #network-map {
      width: 100%;
      height: 500px;
      border: 1px solid #30363d;
      border-radius: 8px;
      background: #0d1117;
      margin-bottom: 40px;
    }

    /* ── Finding cards ───────────────────────────────────────────── */
    .finding {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      margin-bottom: 16px;
      overflow: hidden;
    }
    .finding-header {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 14px 16px;
      border-bottom: 1px solid #30363d;
    }
    .badge {
      display: inline-block;
      padding: 3px 10px;
      border-radius: 12px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .badge-CRITICAL { background: #3d1a1a; color: #ff7b72; border: 1px solid #ff7b72; }
    .badge-HIGH     { background: #2d1e0f; color: #f0883e; border: 1px solid #f0883e; }
    .badge-INFO     { background: #0d2137; color: #58a6ff; border: 1px solid #58a6ff; }
    .finding-meta { color: #8b949e; font-size: 0.82rem; }
    .finding-body { padding: 14px 16px; }
    pre {
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 12px;
      white-space: pre-wrap;
      word-break: break-all;
      color: #8b949e;
      font-size: 0.82rem;
      margin-top: 8px;
    }

    /* ── Stats table ─────────────────────────────────────────────── */
    table { width: 100%; border-collapse: collapse; margin-bottom: 24px; }
    th, td {
      text-align: left;
      padding: 10px 14px;
      border-bottom: 1px solid #21262d;
      font-size: 0.88rem;
    }
    th { color: #8b949e; font-weight: 600; background: #161b22; }
    tr:hover td { background: #161b22; }

    /* ── Print overrides ─────────────────────────────────────────── */
    @media print {
      body { background: #fff; color: #000; padding: 20px; }
      .cover { border-color: #cc0000; background: #fff; }
      .cover h1 { color: #cc0000; }
      pre { background: #f5f5f5; color: #333; }
      #network-map { display: none; }
    }
  </style>
</head>
<body>

  <!-- Cover -->
  <div class="cover">
    <h1>⚡ {{ company }}</h1>
    <h2 style="border:none;margin:4px 0;color:#e6edf3;font-size:1.1rem;">
      Penetration Test — Mission Report
    </h2>
    <div class="meta">
      Operator: <strong>{{ operator }}</strong> &nbsp;|&nbsp;
      Generated: <strong>{{ timestamp }}</strong> &nbsp;|&nbsp;
      Total Findings: <strong>{{ logs|length }}</strong>
    </div>
  </div>

  <!-- Executive Summary -->
  <h2>Executive Summary</h2>
  <div class="exec-summary">
    <div class="risk-card critical">
      <div class="count">{{ critical_count }}</div>
      <div class="label">CRITICAL</div>
    </div>
    <div class="risk-card high">
      <div class="count">{{ high_count }}</div>
      <div class="label">HIGH</div>
    </div>
    <div class="risk-card info">
      <div class="count">{{ info_count }}</div>
      <div class="label">INFO</div>
    </div>
    <div class="risk-card" style="border:2px solid #30363d;">
      <div class="count" style="color:#e6edf3;">{{ unique_targets }}</div>
      <div class="label">TARGETS</div>
    </div>
    <div class="risk-card" style="border:2px solid #30363d;">
      <div class="count" style="color:#e6edf3;">{{ unique_modules }}</div>
      <div class="label">MODULES USED</div>
    </div>
  </div>

  <!-- Module breakdown table -->
  <h3>Activity by Module</h3>
  <table>
    <thead><tr><th>Module</th><th>Findings</th><th>Unique Targets</th></tr></thead>
    <tbody>
      {% for row in module_stats %}
      <tr>
        <td>{{ row.module }}</td>
        <td>{{ row.count }}</td>
        <td>{{ row.targets }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <!-- Threat Network Map -->
  <h2>Threat Network Map</h2>
  <div id="network-map"></div>

  <!-- Findings grouped by severity -->
  {% for severity in ["CRITICAL", "HIGH", "INFO"] %}
  {% set group = logs | selectattr("severity", "equalto", severity) | list %}
  {% if group %}
  <h2>
    {{ severity }} Findings
    <span style="font-size:0.85rem;font-weight:400;color:#8b949e;">
      ({{ group|length }})
    </span>
  </h2>
  {% for log in group %}
  <div class="finding">
    <div class="finding-header">
      <span class="badge badge-{{ log.severity }}">{{ log.severity }}</span>
      <div>
        <strong style="color:#e6edf3;">{{ log.module }}</strong>
        <span style="color:#58a6ff;margin-left:8px;">→ {{ log.target }}</span>
        <div class="finding-meta">{{ log.timestamp }}</div>
      </div>
    </div>
    <div class="finding-body">
      <pre>{{ log.details }}</pre>
    </div>
  </div>
  {% endfor %}
  {% endif %}
  {% endfor %}

  <!-- vis.js network graph -->
  <script>
    var nodes = new vis.DataSet({{ nodes_json }});
    var edges = new vis.DataSet({{ edges_json }});
    var net   = new vis.Network(
      document.getElementById('network-map'),
      { nodes: nodes, edges: edges },
      {
        nodes: {
          shape: 'dot', size: 15,
          font: { color: '#ffffff', size: 13 },
          borderWidth: 2,
        },
        edges: { color: { color: '#30363d' }, width: 1.5 },
        physics: { stabilization: { iterations: 100 } },
        interaction: { hover: true },
      }
    );
  </script>
</body>
</html>
"""


# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _get_attr(obj, key):
    if isinstance(obj, dict):
        return obj.get(key, "")
    return getattr(obj, key, "")


def _try_pdf_export(html_path: str) -> str | None:
    """Try to export the HTML report to PDF using weasyprint."""
    try:
        import weasyprint
        pdf_path = html_path.replace(".html", ".pdf")
        weasyprint.HTML(filename=html_path).write_pdf(pdf_path)
        return pdf_path
    except ImportError:
        return None
    except Exception as e:
        console.print(f"[dim red][!] PDF export failed: {e}[/dim red]")
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

def generate_report():
    console.print(Panel("Accessing Mission Database...",
                        title="Reporter", border_style="cyan"))

    try:
        raw_logs = db.get_all()
    except Exception as e:
        console.print(f"[red][!] Cannot read database: {e}[/red]")
        return

    if not raw_logs:
        console.print("[yellow][!] Database is empty. Run scans first.[/yellow]")
        return

    # ── Normalise to plain dicts ──────────────────────────────────────────────
    logs = []
    for row in raw_logs:
        logs.append({
            "timestamp": str(_get_attr(row, "timestamp") or ""),
            "module":    str(_get_attr(row, "module")    or ""),
            "target":    str(_get_attr(row, "target")    or ""),
            "severity":  str(_get_attr(row, "severity")  or "INFO"),
            "details":   str(_get_attr(row, "details")   or ""),
        })

    # ── Stats ─────────────────────────────────────────────────────────────────
    critical_count  = sum(1 for l in logs if l["severity"] == "CRITICAL")
    high_count      = sum(1 for l in logs if l["severity"] == "HIGH")
    info_count      = sum(1 for l in logs if l["severity"] == "INFO")
    unique_targets  = len({l["target"] for l in logs if l["target"]})
    unique_modules  = len({l["module"] for l in logs if l["module"]})

    # Module breakdown
    from collections import defaultdict
    mod_findings = defaultdict(set)
    mod_counts   = defaultdict(int)
    for l in logs:
        mod_counts[l["module"]]   += 1
        mod_findings[l["module"]].add(l["target"])

    module_stats = sorted([
        {"module": m, "count": mod_counts[m], "targets": len(mod_findings[m])}
        for m in mod_counts
    ], key=lambda x: x["count"], reverse=True)

    # ── vis.js network graph ──────────────────────────────────────────────────
    nodes = [{"id": 0, "label": "DAVOID-HQ",
               "color": "#ff7b72", "size": 30}]
    edges = []
    seen  = {}
    node_id = 1

    for log in logs:
        tgt = log["target"]
        if tgt and tgt not in seen:
            seen[tgt] = node_id
            sev_color = (
                "#ff7b72" if log["severity"] == "CRITICAL" else
                "#f0883e" if log["severity"] == "HIGH" else
                "#2ea043")
            nodes.append({
                "id":    node_id,
                "label": tgt,
                "color": sev_color,
                "size":  18,
            })
            edges.append({"from": 0, "to": node_id})
            node_id += 1

    # ── Render ────────────────────────────────────────────────────────────────
    import json as json_mod

    try:
        from jinja2 import Environment
        env      = Environment()
        env.filters["selectattr"] = lambda seq, attr, op, val: [
            x for x in seq if x.get(attr) == val]
        template = env.from_string(TEMPLATE_HTML)
    except Exception:
        template = Template(TEMPLATE_HTML)

    try:
        html = Template(TEMPLATE_HTML).render(
            company        = COMPANY,
            operator       = OPERATOR,
            timestamp      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            logs           = logs,
            critical_count = critical_count,
            high_count     = high_count,
            info_count     = info_count,
            unique_targets = unique_targets,
            unique_modules = unique_modules,
            module_stats   = module_stats,
            nodes_json     = json_mod.dumps(nodes),
            edges_json     = json_mod.dumps(edges),
        )

        ts      = datetime.datetime.now().strftime('%Y%m%d_%H%M')
        fname   = os.path.join(OUT_DIR, f"Mission_Report_{ts}.html")
        with open(fname, "w", encoding="utf-8") as f:
            f.write(html)

        console.print(
            f"[bold green][+] HTML Report: {fname}[/bold green]")

        # ── Optional PDF export ───────────────────────────────────────────────
        try:
            import questionary as q
            want_pdf = q.confirm(
                "Export as PDF? (requires: pip install weasyprint)",
                default=False).ask()
            if want_pdf:
                pdf = _try_pdf_export(fname)
                if pdf:
                    console.print(f"[bold green][+] PDF Report: {pdf}[/bold green]")
                else:
                    console.print(
                        "[yellow][!] weasyprint not installed. "
                        "Run: pip install weasyprint[/yellow]")
        except Exception:
            pass

        # Open in browser
        if os.name == 'posix':
            os.system(
                f"open '{fname}' 2>/dev/null || "
                f"xdg-open '{fname}' 2>/dev/null &")

    except Exception as e:
        console.print(f"[red][!] Report error: {e}[/red]")


if __name__ == "__main__":
    generate_report()