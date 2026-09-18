#!/usr/bin/env python3
"""OrangeBox Wazuh Security Dashboard.

Dashboard adicional al informe ejecutivo. La fuente de datos es EXACTAMENTE
la misma: orangebox-security-report.py -> period_bounds(), group_members(),
load_events() y mitre_rows(). Este archivo cambia únicamente la presentación.

Diseño:
- Pensado como dashboard visual, no como un segundo informe tabular.
- KPIs grandes.
- Barras proporcionales para categorías, reglas, sistemas y MITRE.
- Pocos elementos textuales y sin listados extensos.
- HTML compatible con correo: tablas, estilos inline y sin JavaScript.
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

COLORS = {
    "page": "#eef2f5",
    "dark": "#182a33",
    "dark2": "#213b46",
    "orange": "#f58220",
    "orange_dark": "#d65d00",
    "text": "#263238",
    "muted": "#607d8b",
    "border": "#d7e0e4",
    "track": "#e7edef",
    "white": "#ffffff",
    "danger": "#c43d2b",
    "danger_dark": "#6b2923",
    "danger_bg": "#fff6f4",
    "good": "#147a4a",
}

CATEGORIES = {
    "authentication": ("🔐", "Autenticación"),
    "web": ("🌐", "Web"),
    "fim": ("📁", "Integridad de archivos"),
    "malware": ("🦠", "Malware / WebShell"),
    "privilege": ("🔑", "Privilegios"),
    "attack": ("🎯", "Ataques"),
}


def load_report_module():
    spec = importlib.util.spec_from_file_location("orangebox_security_report", REPORT_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit(f"No se pudo cargar {REPORT_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def esc(value):
    return html.escape(str(value), quote=True)


def num(value):
    try:
        return f"{int(value):,}".replace(",", ".")
    except (TypeError, ValueError):
        return esc(value)


def pct(value, total):
    if not total:
        return 0
    return max(0, min(100, round((int(value) / total) * 100)))


def kpi(label, value, note, accent="orange"):
    accent_color = COLORS["orange"] if accent == "orange" else COLORS["danger"]
    return (
        "<td width='25%' valign='top' style='padding:0 4px 8px;'>"
        f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='background:{COLORS['dark2']};border-bottom:4px solid {accent_color};'>"
        f"<tr><td align='center' style='padding:16px 4px 3px;color:{accent_color};font-size:29px;font-weight:bold;line-height:1.1;'>{num(value)}</td></tr>"
        f"<tr><td align='center' style='padding:0 5px 4px;color:{COLORS['white']};font-size:10px;font-weight:bold;text-transform:uppercase;'>{esc(label)}</td></tr>"
        f"<tr><td align='center' style='padding:0 5px 13px;color:#c8d7dc;font-size:9px;line-height:1.3;'>{esc(note)}</td></tr>"
        "</table></td>"
    )


def chart_section(title, subtitle, inner_html, icon=""):
    heading = esc(f"{icon} {title}".strip())
    return (
        "<tr><td style='padding:0 0 16px;'>"
        f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='background:{COLORS['white']};border:1px solid {COLORS['border']};'>"
        f"<tr><td style='background:#f1f5f7;border-left:4px solid {COLORS['orange']};padding:11px 13px;color:{COLORS['text']};font-size:16px;font-weight:bold;'>{heading}</td></tr>"
        f"<tr><td style='padding:8px 14px 4px;color:#667b85;font-size:11px;line-height:1.4;'>{esc(subtitle)}</td></tr>"
        f"<tr><td style='padding:2px 12px 12px;'>{inner_html}</td></tr>"
        "</table></td></tr>"
    )


def bar_chart(rows, max_rows=8, value_suffix="", show_values=True, small=False):
    rows = rows[:max_rows]
    if not rows:
        return f"<div style='padding:8px 2px;color:{COLORS['muted']};font-size:11px;'>Sin datos para el período.</div>"

    max_value = max(int(count) for _, count in rows) or 1
    parts = [
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>"
    ]

    for index, (label, count) in enumerate(rows):
        width = pct(count, max_value)
        if width < 2 and count:
            width = 2
        border_top = "" if index == 0 else f"border-top:1px solid #edf0f2;"
        label_size = "10px" if small else "11px"
        value_size = "10px" if small else "11px"
        value = f"{num(count)}{esc(value_suffix)}" if show_values else ""
        parts.append(
            f"<tr>"
            f"<td valign='middle' width='34%' style='{border_top}padding:8px 6px 8px 2px;font-size:{label_size};color:{COLORS['text']};overflow-wrap:anywhere;'><b>{esc(label)}</b></td>"
            f"<td valign='middle' width='52%' style='{border_top}padding:8px 7px;'>"
            f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr>"
            f"<td style='background:{COLORS['track']};height:9px;font-size:1px;line-height:9px;'>"
            f"<table role='presentation' cellpadding='0' cellspacing='0' border='0' width='{width}%'><tr><td style='background:{COLORS['orange']};height:9px;font-size:1px;line-height:9px;'>&nbsp;</td></tr></table>"
            f"</td></tr></table>"
            f"</td>"
            f"<td valign='middle' width='14%' align='right' style='{border_top}padding:8px 2px;font-size:{value_size};font-weight:bold;color:{COLORS['text']};white-space:nowrap;'>{value}</td>"
            f"</tr>"
        )

    parts.append("</table>")
    return "".join(parts)


def category_rows(categories):
    rows = []
    for key, (icon, label) in CATEGORIES.items():
        count = categories.get(key, {}).get("count", 0)
        if count:
            rows.append((f"{icon} {label}", count))
    return sorted(rows, key=lambda item: item[1], reverse=True)


def rules_rows(categories, limit=8):
    counter = Counter()
    for info in categories.values():
        counter.update(info.get("rules") or {})

    rows = []
    for key, count in counter.most_common(limit):
        if isinstance(key, tuple) and len(key) >= 2:
            rule_id, description = key[0], key[1]
            label = f"{rule_id} · {description}"
        else:
            label = str(key)
        rows.append((label, count))
    return rows


def agent_rows(agents, limit=8):
    rows = []
    for key, count in agents.most_common(limit):
        if isinstance(key, tuple) and len(key) >= 2:
            label = key[1]
        else:
            label = str(key)
        rows.append((label, count))
    return rows


def mitre_chart_rows(summary, report, limit=8):
    return [(f"{mid} · {name}", count) for mid, name, _meaning, count in report.mitre_rows(summary)[:limit]]


def big_stat(value, label, note="", accent="orange"):
    color = COLORS["orange"] if accent == "orange" else COLORS["danger"]
    return (
        f"<div style='font-size:34px;font-weight:bold;color:{color};line-height:1.0;'>{num(value)}</div>"
        f"<div style='font-size:11px;font-weight:bold;color:{COLORS['text']};text-transform:uppercase;margin-top:5px;'>{esc(label)}</div>"
        f"<div style='font-size:10px;color:{COLORS['muted']};margin-top:4px;'>{esc(note)}</div>"
    )


def dashboard_html(summary, group, start, end, label, report):
    categories = summary["categories"]
    security_count = summary["security_count"]
    critical_count = summary["critical_count"]
    source_ips = summary["source_ips"]
    agents = summary["agents"]
    firewall_ips = summary["firewall_ips"]
    firewall_data = summary["firewall_rows"]

    now = datetime.now().astimezone()
    period = (
        f"{start.strftime('%d/%m/%Y %H:%M')} — "
        f"{end.strftime('%d/%m/%Y %H:%M') if end <= now else 'ahora'}"
    )
    generated = now.strftime("%d/%m/%Y %H:%M %Z")

    category_data = category_rows(categories)
    rules_data = rules_rows(categories, 5)
    agents_data = agent_rows(agents, 5)
    mitre_data = mitre_chart_rows(summary, report, 5)

    firewall_attempts = sum(row["attempts"] for row in firewall_data)
    blocked_ips = len(firewall_ips)
    critical_pct = round((critical_count / security_count) * 100, 1) if security_count else 0

    category_total = sum(count for _label, count in category_data) or 1

    def compact_bars(rows, max_rows=5):
        rows = rows[:max_rows]
        if not rows:
            return (
                f"<div style='padding:12px 4px;color:{COLORS['muted']};"
                "font-size:10px;'>Sin datos para el período.</div>"
            )

        max_value = max(int(count) for _, count in rows) or 1
        parts = [
            "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>"
        ]
        for index, (label, count) in enumerate(rows):
            width = pct(count, max_value)
            if width < 3 and count:
                width = 3
            border = "" if index == 0 else "border-top:1px solid #edf0f2;"
            shown = label if len(str(label)) <= 34 else f"{str(label)[:31]}…"
            parts.append(
                f"<tr>"
                f"<td width='45%' valign='middle' style='{border}padding:7px 5px 7px 2px;"
                f"font-size:10px;color:{COLORS['text']};overflow-wrap:anywhere;'>"
                f"<b>{esc(shown)}</b></td>"
                f"<td width='40%' valign='middle' style='{border}padding:7px 5px;'>"
                f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>"
                f"<tr><td style='background:{COLORS['track']};height:7px;font-size:1px;line-height:7px;'>"
                f"<table role='presentation' cellpadding='0' cellspacing='0' border='0' width='{width}%'>"
                f"<tr><td style='background:{COLORS['orange']};height:7px;font-size:1px;line-height:7px;'>&nbsp;</td></tr>"
                f"</table></td></tr></table></td>"
                f"<td width='15%' align='right' valign='middle' style='{border}padding:7px 2px;"
                f"font-size:10px;font-weight:bold;color:{COLORS['text']};white-space:nowrap;'>"
                f"{num(count)}</td></tr>"
            )
        parts.append("</table>")
        return "".join(parts)

    category_chart = compact_bars(
        [
            (
                f"{icon} {label} · {pct(count, category_total)}%",
                count,
            )
            for label, count in category_data
            for icon, _display in [(next((v[0] for k, v in CATEGORIES.items() if v[1] == label), ""), label)]
        ],
        6,
    )

    # En este dashboard, las tarjetas inferiores contienen solo el Top 5.
    rules_chart = compact_bars(rules_data, 5)
    systems_chart = compact_bars(agents_data, 5)
    mitre_chart = compact_bars(mitre_data, 5)

    def panel(title, subtitle, inner, width="33.33%"):
        return (
            f"<td width='{width}' valign='top' style='padding:0 4px 8px;'>"
            f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' "
            f"style='height:100%;background:{COLORS['white']};border:1px solid {COLORS['border']};'>"
            f"<tr><td style='background:#f1f5f7;border-top:3px solid {COLORS['orange']};"
            f"padding:10px 10px 6px;color:{COLORS['text']};font-size:13px;font-weight:bold;'>"
            f"{esc(title)}</td></tr>"
            f"<tr><td style='padding:0 10px 4px;color:{COLORS['muted']};font-size:9px;'>"
            f"{esc(subtitle)}</td></tr>"
            f"<tr><td style='padding:0 8px 8px;'>{inner}</td></tr></table></td>"
        )

    if firewall_ips:
        firewall_card = (
            f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>"
            f"<tr>"
            f"<td width='50%' valign='top' style='padding:0 4px 0 0;'>"
            f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' "
            f"style='background:{COLORS['danger_dark']};'>"
            f"<tr><td align='center' style='padding:15px 5px 2px;color:#ffb39e;"
            f"font-size:30px;font-weight:bold;'>{num(blocked_ips)}</td></tr>"
            f"<tr><td align='center' style='padding:0 5px 3px;color:#fff;font-size:10px;"
            f"font-weight:bold;text-transform:uppercase;'>IPs atacantes bloqueadas</td></tr>"
            f"<tr><td align='center' style='padding:0 5px 13px;color:#ffdcd3;font-size:9px;'>"
            f"firewall-drop / Active Response</td></tr></table></td>"
            f"<td width='50%' valign='top' style='padding:0 0 0 4px;'>"
            f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' "
            f"style='background:#f7f0ee;border:1px solid #ead6d1;'>"
            f"<tr><td align='center' style='padding:15px 5px 2px;color:{COLORS['danger']};"
            f"font-size:30px;font-weight:bold;'>{num(firewall_attempts)}</td></tr>"
            f"<tr><td align='center' style='padding:0 5px 3px;color:{COLORS['text']};font-size:10px;"
            f"font-weight:bold;text-transform:uppercase;'>Intentos asociados</td></tr>"
            f"<tr><td align='center' style='padding:0 5px 13px;color:{COLORS['muted']};font-size:9px;'>"
            f"detectados antes del bloqueo</td></tr></table></td>"
            f"</tr></table>"
        )
    else:
        firewall_card = (
            f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' "
            f"style='background:#f6faf8;border:1px solid #dcebe3;'>"
            f"<tr><td align='center' style='padding:18px 10px;color:{COLORS['good']};"
            f"font-size:12px;font-weight:bold;'>Sin bloqueos automáticos en el período</td></tr>"
            f"</table>"
        )

    parts = [
        "<!DOCTYPE html><html lang='es'><head><meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1.0'></head>",
        f"<body style='margin:0;padding:0;background:{COLORS['page']};"
        "font-family:Arial,Helvetica,sans-serif;color:#263238;'>",
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>"
        "<tr><td align='center' style='padding:10px;'>",
        f"<table role='presentation' width='720' cellpadding='0' cellspacing='0' border='0' "
        f"style='width:100%;max-width:720px;background:{COLORS['white']};'>",

        # Header visual.
        f"<tr><td style='background:{COLORS['dark']};border-bottom:5px solid {COLORS['orange']};"
        "padding:15px 18px;'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr>"
        f"<td width='55%' valign='middle'><img src='{esc(LOGO_URL)}' alt='OrangeBox IT Services' "
        "width='190' style='display:block;width:190px;max-width:100%;height:auto;border:0;'></td>"
        f"<td width='45%' align='right' valign='middle' style='color:{COLORS['white']};padding-left:8px;'>"
        "<div style='font-size:20px;font-weight:bold;'>Security Dashboard</div>"
        "<div style='font-size:9px;color:#cbd7dc;padding-top:4px;'>WAZUH · SECURITY MONITORING</div>"
        f"</td></tr></table></td></tr>",

        # Context line.
        f"<tr><td style='padding:16px 18px 10px;'>"
        f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr>"
        f"<td valign='top'><div style='font-size:10px;font-weight:bold;letter-spacing:1px;"
        f"color:{COLORS['orange']};'>ORANGEBOX SECURITY · WAZUH</div>"
        f"<div style='font-size:23px;font-weight:bold;color:{COLORS['text']};padding-top:3px;'>"
        "Estado de seguridad</div>"
        f"<div style='font-size:11px;color:{COLORS['muted']};padding-top:3px;'>"
        "Resumen visual del período seleccionado</div></td>"
        f"<td align='right' valign='top' style='padding-left:10px;color:{COLORS['muted']};"
        "font-size:10px;line-height:1.5;'>"
        f"<b style='color:{COLORS['text']};'>Grupo</b><br>{esc(group)}<br>"
        f"<b style='color:{COLORS['text']};'>Período</b><br>{esc(label)}</td>"
        f"</tr></table>"
        f"<div style='margin-top:10px;background:#f4f7f8;border:1px solid #d9e3e7;"
        f"padding:8px 10px;font-size:10px;color:#526873;'>"
        f"{esc(period)}</div></td></tr>",

        # KPI row: four datos que se ven de inmediato.
        "<tr><td style='padding:0 10px 10px;'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr>",
        kpi("Eventos", security_count, "detecciones clasificadas"),
        kpi("Alta severidad", critical_count, "nivel Wazuh ≥ 13"),
        kpi("IPs atacantes", len(source_ips), "orígenes observados"),
        kpi("IPs bloqueadas", blocked_ips, "firewall-drop", "danger"),
        "</tr></table></td></tr>",

        # Gran bloque visual de categorías + respuesta automática.
        "<tr><td style='padding:0 10px 8px;'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr>",
        f"<td width='65%' valign='top' style='padding:0 4px 0 0;'>"
        f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' "
        f"style='background:{COLORS['white']};border:1px solid {COLORS['border']};'>"
        f"<tr><td style='background:#f1f5f7;border-left:4px solid {COLORS['orange']};"
        f"padding:11px 12px;color:{COLORS['text']};font-size:15px;font-weight:bold;'>"
        "Actividad por categoría</td></tr>"
        f"<tr><td style='padding:7px 12px 3px;color:{COLORS['muted']};font-size:9px;'>"
        "Distribución de las detecciones del período.</td></tr>"
        f"<tr><td style='padding:0 10px 10px;'>{category_chart}</td></tr></table></td>",

        f"<td width='35%' valign='top' style='padding:0 0 0 4px;'>"
        f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' "
        f"style='background:{COLORS['white']};border:1px solid {COLORS['border']};'>"
        f"<tr><td style='background:{COLORS['danger_dark']};border-bottom:3px solid {COLORS['danger']};"
        "padding:11px 10px;color:#fff;font-size:15px;font-weight:bold;'>"
        "Bloqueos automáticos</td></tr>"
        f"<tr><td style='padding:10px 8px 8px;'>{firewall_card}</td></tr>"
        f"<tr><td style='padding:2px 10px 11px;color:{COLORS['muted']};font-size:9px;line-height:1.4;'>"
        "IPs bloqueadas por las respuestas Active Response observadas en Wazuh.</td></tr>"
        "</table></td></tr></table></td></tr>",

        # Tres paneles compactos, estilo dashboard.
        "<tr><td style='padding:0 10px 0;'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr>",
        panel("Top 5 sistemas", f"{len(agents)} sistemas con actividad", systems_chart),
        panel("Top 5 reglas", "Reglas con mayor volumen", rules_chart),
        panel("Top 5 MITRE", "Técnicas más observadas", mitre_chart),
        "</tr></table></td></tr>",

        # Banda final de indicadores.
        "<tr><td style='padding:8px 10px 8px;'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr>"
        f"<td width='50%' style='padding:0 4px 0 0;'>"
        f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' "
        f"style='background:#f4f7f8;border:1px solid {COLORS['border']};'>"
        f"<tr><td style='padding:9px 11px;color:{COLORS['muted']};font-size:9px;text-transform:uppercase;'>"
        "Alta severidad sobre detecciones</td></tr>"
        f"<tr><td style='padding:0 11px 11px;color:{COLORS['text']};font-size:20px;font-weight:bold;'>"
        f"{critical_pct}%</td></tr></table></td>"
        f"<td width='50%' style='padding:0 0 0 4px;'>"
        f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' "
        f"style='background:#f4f7f8;border:1px solid {COLORS['border']};'>"
        f"<tr><td style='padding:9px 11px;color:{COLORS['muted']};font-size:9px;text-transform:uppercase;'>"
        "Sistemas activos</td></tr>"
        f"<tr><td style='padding:0 11px 11px;color:{COLORS['text']};font-size:20px;font-weight:bold;'>"
        f"{num(len(agents))}</td></tr></table></td>"
        "</tr></table></td></tr>",

        f"<tr><td style='background:{COLORS['dark']};border-top:4px solid {COLORS['orange']};"
        f"padding:12px 18px;color:#c7d2d7;font-size:9px;line-height:1.5;'>"
        f"<b style='color:#fff;'>ORANGEBOX IT SERVICES</b><br>"
        f"Security Dashboard · Generado {esc(generated)} · Datos extraídos desde Wazuh"
        "</td></tr>",
        "</table></td></tr></table></body></html>",
    ]
    return "".join(parts)

def send_email(subject, body, recipients, sender=DEFAULT_FROM):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"Wazuh SOC <{sender}>"
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText("OrangeBox Wazuh Security Dashboard.", "plain", "utf-8"))
    msg.attach(MIMEText(body, "html", "utf-8"))
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
        smtp.sendmail(sender, recipients, msg.as_string())


def main():
    parser = argparse.ArgumentParser(description="OrangeBox Wazuh Security Dashboard")
    modes = parser.add_mutually_exclusive_group(required=True)
    for name in ("today", "yesterday", "thisweek", "lastweek", "thismonth", "lastmonth", "thisyear", "lastyear"):
        modes.add_argument("--" + name, action="store_true")
    modes.add_argument("--date", metavar="YYYY-MM-DD")
    parser.add_argument("--group", required=True, help="Grupo Wazuh o all")
    parser.add_argument("--lang", choices=("es", "en"), default="es")
    parser.add_argument("--output", help="Archivo HTML de salida")
    parser.add_argument("--archive", action="store_true", help="Guardar también en /var/ossec/reports/archive")
    parser.add_argument("--email", action="append", help="Destinatario; puede repetirse o usar comas")
    args = parser.parse_args()

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

    # MISMA extracción del informe ejecutivo. No existe una segunda fuente de datos.
    summary = report.load_events(start, end, allowed)
    body = dashboard_html(summary, args.group, start, end, label, report)

    safe_group = "".join(c if c.isalnum() or c in "._-" else "_" for c in args.group)
    default_name = f"security-dashboard-{safe_group}-{start:%Y%m%d}.html"
    output = Path(args.output) if args.output else Path("/tmp") / default_name
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(body, encoding="utf-8")

    if args.archive:
        ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
        archive_path = ARCHIVE_DIR / default_name
        archive_path.write_text(body, encoding="utf-8")
        print(f"Archivado: {archive_path}")

    if recipients:
        prefixes = {
            "today": "Dashboard Diario de Seguridad",
            "yesterday": "Dashboard Diario de Seguridad",
            "thisweek": "Dashboard Semanal de Seguridad",
            "lastweek": "Dashboard Semanal de Seguridad",
            "thismonth": "Dashboard Mensual de Seguridad",
            "lastmonth": "Dashboard Mensual de Seguridad",
            "thisyear": "Dashboard Anual de Seguridad",
            "lastyear": "Dashboard Anual de Seguridad",
        }
        subject = f"📊 [ORANGEBOX] {prefixes.get(mode, 'Dashboard de Seguridad')} — {args.group}"
        sent, failed = [], []

        for recipient in recipients:
            try:
                send_email(subject, body, [recipient])
                sent.append(recipient)
            except Exception as exc:
                failed.append((recipient, exc))

        print(f"Destinatarios enviados: {', '.join(sent) if sent else 'ninguno'}")
        for recipient, exc in failed:
            print(f"ERROR enviando a {recipient}: {exc}")

        if failed:
            raise SystemExit(1)

    print(f"Dashboard generado: {output}")


if __name__ == "__main__":
    main()
