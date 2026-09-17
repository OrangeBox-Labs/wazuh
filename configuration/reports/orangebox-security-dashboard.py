#!/usr/bin/env python3
"""OrangeBox Wazuh Security Dashboard.

Reporte HTML adicional orientado a dashboard ejecutivo/operacional.

IMPORTANTE:
- No reemplaza orangebox-security-report.py.
- Usa exactamente la misma función load_events() del reporte clásico.
- El dashboard solo cambia la presentación de los datos ya recopilados.
- Mantiene los mismos períodos, grupos de agentes y filtros.

Uso:
  ./orangebox-security-dashboard.py --yesterday --group production --email soporte@orangebox.cl
  ./orangebox-security-dashboard.py --lastweek --group all --email soporte@orangebox.cl --email cliente@example.com
  ./orangebox-security-dashboard.py --thismonth --group clientes --email soporte@orangebox.cl,cliente@example.com
"""

import argparse
import html
import importlib.util
import re
import smtplib
from collections import Counter
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
REPORT_PATH = BASE_DIR / "orangebox-security-report.py"
DEFAULT_FROM = "wazuh@orangebox.cl"
SMTP_HOST = "localhost"
SMTP_PORT = 25
ARCHIVE_DIR = Path("/var/ossec/reports/archive")
LOGO_URL = "https://www.orangebox.cl/obox/img/logo-dark.png"

CATEGORY_LABELS = {
    "authentication": "Autenticación",
    "web": "Web",
    "fim": "Integridad de archivos",
    "malware": "Malware / WebShell",
    "privilege": "Privilegios",
    "attack": "Ataques",
}

CATEGORY_ICONS = {
    "authentication": "🔐",
    "web": "🌐",
    "fim": "📁",
    "malware": "🦠",
    "privilege": "🔑",
    "attack": "🎯",
}


def load_report_module():
    """Carga el reporte clásico para reutilizar su extracción y clasificación."""
    spec = importlib.util.spec_from_file_location("orangebox_security_report", REPORT_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit(f"No se pudo cargar {REPORT_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def esc(value):
    return html.escape(str(value), quote=True)


def fmt_number(value):
    try:
        return f"{int(value):,}".replace(",", ".")
    except (TypeError, ValueError):
        return esc(value)


def css():
    """CSS autocontenido para correo HTML y navegador."""
    return """
    <style>
      :root { color-scheme: light; }
      * { box-sizing: border-box; }
      body { margin:0; background:#eef1f5; color:#17202a; font-family:Arial,Helvetica,sans-serif; }
      .page { max-width:1180px; margin:0 auto; padding:24px 14px 36px; }
      .header { background:#17202a; border-radius:16px; padding:24px 26px; color:#fff; }
      .brand { display:flex; align-items:center; gap:16px; }
      .logo-wrap { flex:0 0 auto; background:#fff; border:1px solid #d9e0e5; border-radius:10px; padding:7px 10px; line-height:0; box-shadow:0 2px 8px rgba(0,0,0,.12); }
      .logo { display:block; width:auto; max-width:190px; height:58px; object-fit:contain; }
      .brand-copy { min-width:0; }
      .brand-title { margin:0; color:#fff; font-size:27px; font-weight:800; line-height:1.15; }
      .brand-subtitle { margin:7px 0 0; color:#d5dee4; font-size:14px; }
      h1 { margin:0; font-size:27px; line-height:1.15; }
      .subtitle { margin:7px 0 0; color:#cbd3db; font-size:14px; }
      .period { margin-top:18px; padding-top:14px; border-top:1px solid #46515d; font-size:13px; color:#e4e8ec; }
      .grid { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin:16px 0; }
      .card { background:#fff; border-radius:14px; padding:18px; box-shadow:0 2px 10px rgba(23,32,42,.08); }
      .metric-label { color:#68737d; font-size:12px; text-transform:uppercase; letter-spacing:.06em; }
      .metric { font-size:31px; font-weight:700; margin-top:6px; }
      .metric-note { margin-top:5px; color:#7b858e; font-size:12px; }
      .two { display:grid; grid-template-columns:1fr 1fr; gap:14px; margin:14px 0; }
      .section { background:#fff; border-radius:14px; padding:20px; box-shadow:0 2px 10px rgba(23,32,42,.08); }
      h2 { margin:0 0 8px; font-size:18px; }
      .section-subtitle { margin:0 0 14px; color:#7b858e; font-size:12px; line-height:1.45; }
      table { width:100%; border-collapse:collapse; font-size:13px; }
      th { text-align:left; color:#68737d; font-size:11px; text-transform:uppercase; letter-spacing:.05em; border-bottom:2px solid #e7eaee; padding:8px; }
      td { border-bottom:1px solid #edf0f2; padding:9px 8px; vertical-align:top; }
      .num { text-align:right; font-weight:700; white-space:nowrap; }
      .bar { height:9px; background:#e9edf1; border-radius:20px; overflow:hidden; margin-top:7px; }
      .bar > span { display:block; height:100%; background:#e66a16; border-radius:20px; }
      .pill { display:inline-block; padding:5px 9px; margin:0 5px 5px 0; border-radius:999px; background:#edf2f6; font-size:11px; font-family:monospace; }
      .empty { color:#7b858e; padding:12px 0; font-size:13px; }
      .good { color:#147a4a; }
      .firewall { border-left:4px solid #d54b39; background:#fff8f7; }
      .firewall .metric { color:#c43d2b; }
      .footer { text-align:center; color:#7b858e; font-size:11px; padding:18px 4px 0; }
      @media (max-width:800px) { .grid { grid-template-columns:repeat(2,1fr); } .two { grid-template-columns:1fr; } }
      @media (max-width:520px) { .grid { grid-template-columns:1fr 1fr; gap:8px; } .card { padding:13px; } .metric { font-size:24px; } .header { padding:18px; } .brand { align-items:flex-start; } .brand-title { font-size:22px; } .brand-subtitle { font-size:12px; } .logo-wrap { padding:6px 8px; } .logo { max-width:150px; height:46px; } }
    </style>
    """


def section_title(title, subtitle="", icon=""):
    heading = f"{icon} {esc(title)}".strip()
    extra = f'<div class="section-subtitle">{esc(subtitle)}</div>' if subtitle else ""
    return f'<h2>{heading}</h2>{extra}'


def table(rows, first_label="Elemento", second_label="Detecciones"):
    """Tabla simple con barra proporcional."""
    if not rows:
        return '<div class="empty">No se registraron datos para este período.</div>'
    max_value = max(int(row[1]) for row in rows) or 1
    body = []
    for name, count in rows:
        value = int(count)
        width = max(2, round((value / max_value) * 100))
        body.append(
            f'<tr><td>{esc(name)}</td><td class="num">{fmt_number(value)}'
            f'<div class="bar"><span style="width:{width}%"></span></div></td></tr>'
        )
    return (
        f'<table><thead><tr><th>{esc(first_label)}</th><th class="num">{esc(second_label)}</th></tr></thead>'
        f'<tbody>{"".join(body)}</tbody></table>'
    )


def agent_rows(agents, limit=10):
    """Convierte Counter[(agent_id, agent_name)] en filas usando solo el nombre."""
    rows = []
    for key, count in agents.most_common(limit):
        if isinstance(key, tuple) and len(key) >= 2:
            name = key[1]
        else:
            name = key
        rows.append((name, count))
    return rows


def rule_rows(categories, limit=12):
    """Agrega las reglas de todas las categorías usando el mismo conteo del reporte clásico."""
    counter = Counter()
    for info in categories.values():
        counter.update(info.get("rules") or {})

    rows = []
    for key, count in counter.most_common(limit):
        if isinstance(key, tuple) and len(key) >= 2:
            rule_id, description = key[0], key[1]
            name = f"{rule_id} · {description}"
        else:
            name = key
        rows.append((name, count))
    return rows


def ip_pills(source_ips, limit=60):
    """Muestra IPs observadas sin inventar un contador: load_events() entrega un set."""
    if not source_ips:
        return '<div class="empty">No se registraron IPs de origen válidas.</div>'
    items = []
    for ip in sorted(source_ips, key=str)[:limit]:
        items.append(f'<span class="pill">{esc(ip)}</span>')
    suffix = f'<div class="section-subtitle">Mostrando {min(len(source_ips), limit):,} de {len(source_ips):,} IPs observadas.</div>'
    return suffix + "".join(items)


def dashboard_html(report, summary, group, start, end, label, lang="es"):
    """Renderiza el mismo summary del reporte clásico con una presentación tipo dashboard."""
    security_count = summary["security_count"]
    critical_count = summary["critical_count"]
    source_ips = summary["source_ips"]
    agents = summary["agents"]
    categories = summary["categories"]
    firewall_rows = summary["firewall_rows"]
    firewall_ips = summary["firewall_ips"]

    period = f"{start.strftime('%d/%m/%Y %H:%M')} — {end.strftime('%d/%m/%Y %H:%M')}"
    now = datetime.now().astimezone().strftime("%d/%m/%Y %H:%M %Z")

    category_rows = [
        (CATEGORY_LABELS[key], categories[key]["count"])
        for key in CATEGORY_LABELS
        if categories.get(key, {}).get("count", 0)
    ]

    top_agents = agent_rows(agents, 10)
    top_rules = rule_rows(categories, 12)
    mitre_rows = report.mitre_rows(summary)
    firewall_attempts = sum(row["attempts"] for row in firewall_rows)
    firewall_table_rows = [
        (f"{row['agent_name']} · Regla {row['rule_id']} · {row['description']}", len(row['ips']))
        for row in firewall_rows
    ]

    html_doc = f"""<!doctype html>
<html lang="{'en' if lang == 'en' else 'es'}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">{css()}</head>
<body>
<div class="page">
  <div class="header">
    <div class="brand">
      <div class="logo-wrap">
        <img class="logo" src="{esc(LOGO_URL)}" alt="OrangeBox IT Services">
      </div>
      <div class="brand-copy">
        <div class="brand-title">Security Dashboard</div>
        <div class="brand-subtitle">Resumen visual de actividad y detecciones de Wazuh</div>
      </div>
    </div>
    <div class="period"><strong>Cliente / grupo:</strong> {esc(group)} &nbsp;·&nbsp; <strong>Período:</strong> {esc(label)}<br>{esc(period)}</div>
  </div>

  <div class="grid">
    <div class="card"><div class="metric-label">Eventos de seguridad</div><div class="metric">{fmt_number(security_count)}</div><div class="metric-note">Misma clasificación del reporte clásico</div></div>
    <div class="card"><div class="metric-label">Alta severidad</div><div class="metric">{fmt_number(critical_count)}</div><div class="metric-note">Alertas con nivel Wazuh ≥ 13</div></div>
    <div class="card"><div class="metric-label">IPs de origen</div><div class="metric">{fmt_number(len(source_ips))}</div><div class="metric-note">Direcciones válidas observadas</div></div>
    <div class="card"><div class="metric-label">Sistemas afectados</div><div class="metric">{fmt_number(len(agents))}</div><div class="metric-note">Agentes con detecciones</div></div>
  </div>

  <div class="two">
    <div class="section">
      {section_title('Actividad por categoría', 'Los mismos contadores generados por load_events() del reporte principal.')}
      {table(category_rows, 'Categoría', 'Eventos')}
    </div>
    <div class="section">
      {section_title('Sistemas más afectados', 'Ordenados por volumen de detecciones. Se muestra solo el nombre del sistema.')}
      {table(top_agents, 'Sistema', 'Alertas')}
    </div>
  </div>

  <div class="two">
    <div class="section">
      {section_title('Reglas más activas', 'Agregación directa de las reglas contadas por cada categoría del reporte.')}
      {table(top_rules, 'Regla', 'Alertas')}
    </div>
    <div class="section">
      {section_title('IPs de origen observadas', 'El reporte clásico conserva estas IPs como conjunto de direcciones válidas.')}
      {ip_pills(source_ips)}
    </div>
  </div>

  <div class="section">
    {section_title('Técnicas MITRE observadas', 'Misma correlación MITRE recopilada por el reporte clásico.')}
    {('<table><thead><tr><th>Técnica</th><th>Nombre</th><th>Descripción</th><th class="num">Detecciones</th></tr></thead><tbody>' + ''.join(f'<tr><td><b>{esc(mid)}</b></td><td>{esc(name)}</td><td>{esc(meaning)}</td><td class="num">{fmt_number(count)}</td></tr>' for mid, name, meaning, count in mitre_rows) + '</tbody></table>') if mitre_rows else '<div class="empty">No se encontraron técnicas MITRE ATT&CK en las alertas del período.</div>'}
  </div>

  <div class="section firewall">
    {section_title('Bloqueos automáticos', 'Eventos de Active Response firewall-drop registrados por el reporte clásico.', '🛡️')}
    {f'<div class="metric">{fmt_number(len(firewall_ips))}</div><div class="metric-note">IPs bloqueadas automáticamente · {fmt_number(firewall_attempts)} intentos asociados</div>' if firewall_ips else '<div class="good">No se registraron bloqueos automáticos con una IP de origen válida.</div>'}
    {table(firewall_table_rows, 'Sistema / regla', 'IPs bloqueadas') if firewall_rows else ''}
  </div>

  <div class="footer">OrangeBox IT Services · Dashboard generado {esc(now)} · Datos extraídos desde Wazuh</div>
</div>
</body></html>"""
    return html_doc


def send_email(subject, html_body, recipients, sender=DEFAULT_FROM):
    """Envía el mismo dashboard a todos los destinatarios."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText("OrangeBox Wazuh Security Dashboard.", "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
        smtp.sendmail(sender, recipients, msg.as_string())


def parser():
    p = argparse.ArgumentParser(description="OrangeBox Wazuh Security Dashboard")
    modes = p.add_mutually_exclusive_group(required=True)
    modes.add_argument("--today", action="store_true")
    modes.add_argument("--yesterday", action="store_true")
    modes.add_argument("--thisweek", action="store_true")
    modes.add_argument("--lastweek", action="store_true")
    modes.add_argument("--thismonth", action="store_true")
    modes.add_argument("--lastmonth", action="store_true")
    modes.add_argument("--thisyear", action="store_true")
    modes.add_argument("--lastyear", action="store_true")
    modes.add_argument("--date", metavar="YYYY-MM-DD")
    p.add_argument("--group", default="all", help="Grupo Wazuh o all")
    p.add_argument("--lang", choices=["es", "en"], default="es")
    p.add_argument("--output", help="Archivo HTML de salida")
    p.add_argument("--archive", action="store_true", help="Guardar también en /var/ossec/reports/archive")
    p.add_argument("--email", action="append", help="Destinatario. Puede repetirse o contener varias direcciones separadas por comas.")
    return p.parse_args()


def main():
    args = parser()
    report = load_report_module()

    mode = args.date and f"date:{args.date}" or next(
        name for name in (
            "today", "yesterday", "thisweek", "lastweek",
            "thismonth", "lastmonth", "thisyear", "lastyear",
        ) if getattr(args, name)
    )

    recipients = []
    for value in args.email or []:
        recipients.extend(item.strip() for item in value.split(",") if item.strip())
    for recipient in recipients:
        if not re.fullmatch(r"[^\s@]+@[^\s@]+", recipient):
            raise SystemExit(f"Dirección de correo inválida: {recipient}")

    now = datetime.now().astimezone()
    start, end, label = report.period_bounds(mode, now)
    allowed = report.group_members(args.group)

    # MISMA extracción del reporte clásico: no hay una segunda fuente de datos.
    summary = report.load_events(start, end, allowed)
    body = dashboard_html(report, summary, args.group, start, end, label, args.lang)

    safe_period = start.strftime("%Y%m%d")
    safe_group = "".join(c if c.isalnum() or c in "._-" else "_" for c in args.group)
    default_name = f"security-dashboard-{safe_group}-{safe_period}.html"
    output = Path(args.output) if args.output else Path("/tmp") / default_name
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(body, encoding="utf-8")

    if args.archive:
        ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
        archive_path = ARCHIVE_DIR / default_name
        archive_path.write_text(body, encoding="utf-8")
        print(f"Archivado: {archive_path}")

    if recipients:
        subject_prefix = {
            "today": "Dashboard Diario de Seguridad",
            "yesterday": "Dashboard Diario de Seguridad",
            "thisweek": "Dashboard Semanal de Seguridad",
            "lastweek": "Dashboard Semanal de Seguridad",
            "thismonth": "Dashboard Mensual de Seguridad",
            "lastmonth": "Dashboard Mensual de Seguridad",
            "thisyear": "Dashboard Anual de Seguridad",
            "lastyear": "Dashboard Anual de Seguridad",
        }
        subject = f"📊 [ORANGEBOX] {subject_prefix.get(mode, 'Dashboard de Seguridad')} — {args.group}"
        send_email(subject, body, recipients)
        print(f"Destinatarios enviados: {', '.join(recipients)}")

    print(f"Dashboard generado: {output}")


if __name__ == "__main__":
    main()
