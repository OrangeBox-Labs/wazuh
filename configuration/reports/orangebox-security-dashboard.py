#!/usr/bin/env python3
"""OrangeBox Wazuh Security Dashboard.

Reporte HTML adicional, orientado a dashboard ejecutivo/operacional.

IMPORTANTE:
- No reemplaza orangebox-security-report.py.
- Reutiliza directamente su mecanismo de extracción y clasificación de eventos.
- No duplica la lectura de alerts.json ni de los archivos históricos.
- Mantiene los mismos períodos, grupos de agentes y filtros del reporte existente.

Uso:
  ./orangebox-security-dashboard.py --yesterday --group production --email soporte@orangebox.cl
  ./orangebox-security-dashboard.py --lastweek --group all --email soporte@orangebox.cl --email cliente@example.com
  ./orangebox-security-dashboard.py --thismonth --group clientes --email soporte@orangebox.cl,cliente@example.com --output /tmp/dashboard.html
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


def load_report_module():
    """Carga el reporte existente para reutilizar toda su lógica de extracción."""
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
    """CSS autocontenido para que el dashboard viaje dentro del correo HTML."""
    return """
    <style>
      :root { color-scheme: light; }
      * { box-sizing: border-box; }
      body { margin:0; background:#eef1f5; color:#17202a; font-family:Arial,Helvetica,sans-serif; }
      .page { max-width:1180px; margin:0 auto; padding:24px 14px 36px; }
      .header { background:#17202a; border-radius:16px; padding:24px 26px; color:#fff; }
      .brand { display:flex; align-items:center; gap:16px; }
      .logo { max-width:190px; max-height:58px; object-fit:contain; background:#fff; padding:7px 10px; border-radius:8px; }
      h1 { margin:0; font-size:27px; line-height:1.15; }
      .subtitle { margin:8px 0 0; color:#cbd3db; font-size:14px; }
      .period { margin-top:18px; padding-top:14px; border-top:1px solid #46515d; font-size:13px; color:#e4e8ec; }
      .grid { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin:16px 0; }
      .card { background:#fff; border-radius:14px; padding:18px; box-shadow:0 2px 10px rgba(23,32,42,.08); }
      .metric-label { color:#68737d; font-size:12px; text-transform:uppercase; letter-spacing:.06em; }
      .metric { font-size:31px; font-weight:700; margin-top:6px; }
      .metric-note { margin-top:5px; color:#7b858e; font-size:12px; }
      .two { display:grid; grid-template-columns:1fr 1fr; gap:14px; margin:14px 0; }
      .section { background:#fff; border-radius:14px; padding:20px; box-shadow:0 2px 10px rgba(23,32,42,.08); }
      h2 { margin:0 0 15px; font-size:18px; }
      h3 { margin:18px 0 9px; font-size:14px; }
      table { width:100%; border-collapse:collapse; font-size:13px; }
      th { text-align:left; color:#68737d; font-size:11px; text-transform:uppercase; letter-spacing:.05em; border-bottom:2px solid #e7eaee; padding:8px; }
      td { border-bottom:1px solid #edf0f2; padding:9px 8px; vertical-align:top; }
      .num { text-align:right; font-weight:700; white-space:nowrap; }
      .bar { height:9px; background:#e9edf1; border-radius:20px; overflow:hidden; margin-top:7px; }
      .bar > span { display:block; height:100%; background:#e66a16; border-radius:20px; }
      .pill { display:inline-block; padding:4px 8px; border-radius:999px; background:#edf2f6; font-size:11px; }
      .empty { color:#7b858e; padding:12px 0; font-size:13px; }
      .footer { text-align:center; color:#7b858e; font-size:11px; padding:18px 4px 0; }
      @media (max-width:800px) { .grid { grid-template-columns:repeat(2,1fr); } .two { grid-template-columns:1fr; } }
      @media (max-width:520px) { .grid { grid-template-columns:1fr 1fr; gap:8px; } .card { padding:13px; } .metric { font-size:24px; } .header { padding:18px; } h1 { font-size:22px; } }
    </style>
    """


def section_title(title, subtitle=""):
    extra = f'<div class="subtitle">{esc(subtitle)}</div>' if subtitle else ""
    return f'<h2>{esc(title)}</h2>{extra}'


def find_count(summary, *keys):
    """Obtiene contadores sin asumir una única forma de serialización del reporte base."""
    for key in keys:
        value = summary.get(key)
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, (list, tuple, set, dict)):
            return len(value)
    return 0


def category_count(summary, category):
    """Cuenta una categoría desde el resumen generado por el reporte existente."""
    value = summary.get(category)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, (list, tuple, set, dict)):
        return len(value)
    return 0


def rows_from_value(value, limit=10):
    """Convierte contadores, listas o diccionarios del resumen en filas de dashboard."""
    if isinstance(value, Counter):
        return list(value.most_common(limit))
    if isinstance(value, dict):
        rows = []
        for key, item in value.items():
            if isinstance(item, (int, float)):
                rows.append((key, item))
            elif isinstance(item, dict):
                count = item.get("count", item.get("detections", item.get("total", 0)))
                if isinstance(count, (int, float)):
                    rows.append((key, count))
            elif isinstance(item, (list, tuple, set)):
                rows.append((key, len(item)))
        return sorted(rows, key=lambda item: item[1], reverse=True)[:limit]
    if isinstance(value, (list, tuple, set)):
        counter = Counter()
        for item in value:
            if isinstance(item, dict):
                name = item.get("agent_name") or item.get("name") or item.get("description") or item.get("rule_id") or "Evento"
            else:
                name = item
            counter[str(name)] += 1
        return counter.most_common(limit)
    return []


def table(rows, first_label="Elemento", second_label="Detecciones"):
    if not rows:
        return '<div class="empty">No se registraron datos para este período.</div>'
    max_value = max(int(row[1]) for row in rows) or 1
    body = []
    for name, count in rows:
        width = max(2, round((int(count) / max_value) * 100))
        body.append(
            f'<tr><td>{esc(name)}</td><td class="num">{fmt_number(count)}'
            f'<div class="bar"><span style="width:{width}%"></span></div></td></tr>'
        )
    return (
        f'<table><thead><tr><th>{esc(first_label)}</th><th class="num">{esc(second_label)}</th></tr></thead>'
        f'<tbody>{"".join(body)}</tbody></table>'
    )


def dashboard_html(report, summary, group, start, end, label, lang="es"):
    """Renderiza un dashboard a partir del mismo summary del reporte clásico."""
    categories = [
        ("authentication", "Autenticación"),
        ("web", "Web"),
        ("fim", "Integridad de archivos"),
        ("malware", "Malware / WebShell"),
        ("privilege", "Privilegios"),
        ("attack", "Ataques"),
        ("active_response", "Bloqueos automáticos"),
        ("other", "Otros"),
    ]

    total = find_count(summary, "total", "total_events", "security_events", "events", "alerts")
    high = find_count(summary, "high_alerts", "high", "high_severity")
    source_ips = find_count(summary, "source_ips", "ips", "unique_source_ips")
    systems = find_count(summary, "systems", "agents", "affected_agents")

    # Si el resumen no expone alguno de los cuatro KPIs con ese nombre, derivamos
    # lo posible desde las categorías ya calculadas por el reporte base.
    category_values = [(key, category_count(summary, key)) for key, _ in categories]
    if total == 0:
        total = sum(value for key, value in category_values if key != "other") + category_count(summary, "other")

    mitre = summary.get("mitre") or summary.get("mitre_techniques") or summary.get("techniques")
    agents = summary.get("agents") or summary.get("affected_agents") or summary.get("systems")
    rules = summary.get("rules") or summary.get("top_rules")
    ips = summary.get("source_ips") or summary.get("ips") or summary.get("top_ips")

    period_end = end.strftime("%d/%m/%Y %H:%M")
    period = f"{start.strftime('%d/%m/%Y %H:%M')} — {period_end}"
    now = datetime.now().astimezone().strftime("%d/%m/%Y %H:%M %Z")

    category_rows = [(name, count) for (key, name), (_, count) in zip(categories, category_values) if count]
    if not category_rows:
        category_rows = [(name, category_count(summary, key)) for key, name in categories]

    logo = getattr(report, "LOGO_URL", "")
    html_doc = f"""<!doctype html>
<html lang="{ 'en' if lang == 'en' else 'es' }">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">{css()}</head>
<body>
<div class="page">
  <div class="header">
    <div class="brand">
      {'<img class="logo" src="' + esc(logo) + '" alt="OrangeBox">' if logo else ''}
      <div>
        <h1>📊 OrangeBox Security Dashboard</h1>
        <div class="subtitle">Resumen visual de actividad y detecciones de Wazuh</div>
      </div>
    </div>
    <div class="period"><strong>Cliente / grupo:</strong> {esc(group)} &nbsp;·&nbsp; <strong>Período:</strong> {esc(label)}<br>{esc(period)}</div>
  </div>

  <div class="grid">
    <div class="card"><div class="metric-label">Eventos de seguridad</div><div class="metric">{fmt_number(total)}</div><div class="metric-note">Alertas procesadas</div></div>
    <div class="card"><div class="metric-label">Alta severidad</div><div class="metric">{fmt_number(high)}</div><div class="metric-note">Nivel alto / crítico según Wazuh</div></div>
    <div class="card"><div class="metric-label">IPs de origen</div><div class="metric">{fmt_number(source_ips)}</div><div class="metric-note">Direcciones válidas observadas</div></div>
    <div class="card"><div class="metric-label">Sistemas afectados</div><div class="metric">{fmt_number(systems)}</div><div class="metric-note">Agentes con actividad</div></div>
  </div>

  <div class="two">
    <div class="section">{section_title('Actividad por categoría', 'Distribución de las detecciones clasificadas por el motor del reporte.')}{table(category_rows, 'Categoría', 'Eventos')}</div>
    <div class="section">{section_title('Sistemas más afectados', 'Agentes con mayor volumen de alertas.')}{table(rows_from_value(agents), 'Sistema', 'Alertas')}</div>
  </div>

  <div class="two">
    <div class="section">{section_title('Reglas más activas', 'Reglas Wazuh con mayor cantidad de detecciones.')}{table(rows_from_value(rules), 'Regla', 'Alertas')}</div>
    <div class="section">{section_title('IPs de origen observadas', 'Principales direcciones IP presentes en las alertas.')}{table(rows_from_value(ips), 'IP', 'Alertas')}</div>
  </div>

  <div class="section">{section_title('Técnicas MITRE observadas', 'Asociaciones MITRE presentes en las alertas del período.')}{table(rows_from_value(mitre), 'Técnica', 'Detecciones')}</div>

  <div class="footer">OrangeBox IT Services · Dashboard generado {esc(now)} · Datos extraídos desde Wazuh</div>
</div>
</body></html>"""
    return html_doc


def send_email(subject, html_body, recipient, sender=DEFAULT_FROM):
    """Envía el dashboard HTML sin modificar el mecanismo de reportes existente."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    msg.attach(MIMEText(html_body, "html", "utf-8"))
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
        smtp.sendmail(sender, [recipient], msg.as_string())


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
    p.add_argument("--email", action="append", required=True, help="Destinatario. Puede repetirse o contener varias direcciones separadas por comas.")
    return p.parse_args()


def main():
    args = parser()
    recipients = []
    for value in args.email:
        recipients.extend(r.strip() for r in value.split(",") if r.strip())
    if not recipients:
        raise SystemExit("Debe especificar al menos un destinatario")
    for recipient in recipients:
        if not re.fullmatch(r"[^\s@]+@[^\s@]+", recipient):
            raise SystemExit(f"Dirección de correo inválida: {recipient}")

    report = load_report_module()
    mode = args.date and f"date:{args.date}" or next(
        name for name in (
            "today", "yesterday", "thisweek", "lastweek",
            "thismonth", "lastmonth", "thisyear", "lastyear",
        ) if getattr(args, name)
    )

    now = datetime.now().astimezone()
    start, end, label = report.period_bounds(mode, now)
    allowed = report.group_members(args.group)

    # ESTA es la misma extracción utilizada por el reporte clásico.
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
    sent = []
    failed = []
    for recipient in recipients:
        try:
            send_email(subject, body, recipient)
            sent.append(recipient)
        except Exception as exc:
            failed.append((recipient, exc))

    print(f"Destinatarios enviados: {', '.join(sent) if sent else 'ninguno'}")
    for recipient, exc in failed:
        print(f"ERROR enviando a {recipient}: {exc}")
    print(f"Dashboard generado: {output}")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
