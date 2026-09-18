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
    accent_color = COLORS['orange'] if accent == "orange" else COLORS['danger']
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
    color = COLORS['orange'] if accent == "orange" else COLORS['danger']
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

    blocked_ips = len(firewall_ips)
    firewall_attempts = sum(row["attempts"] for row in firewall_data)
    critical_pct = round((critical_count / security_count) * 100, 1) if security_count else 0

    category_data = category_rows(categories)
    rules_data = rules_rows(categories, 5)
    systems_data = agent_rows(agents, 5)
    mitre_data = mitre_chart_rows(summary, report, 5)

    def visual_bar(count, max_value, height=8, color=None):
        color = color or COLORS['orange']
        width = pct(count, max_value)
        if width < 3 and count:
            width = 3
        return (
            f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>"
            f"<tr><td style='background:{COLORS['track']};height:{height}px;font-size:1px;line-height:{height}px;'>"
            f"<table role='presentation' cellpadding='0' cellspacing='0' border='0' width='{width}%'>"
            f"<tr><td style='background:{color};height:{height}px;font-size:1px;line-height:{height}px;'>&nbsp;</td></tr>"
            f"</table></td></tr></table>"
        )

    # Mantiene la lectura del informe, pero la presenta como tarjetas y gráficos.
    category_total = sum(count for _label, count in category_data) or 1
    max_category = max((count for _label, count in category_data), default=1)

    category_cards = []
    for label_text, count in category_data:
        share = round((count / category_total) * 100, 1) if category_total else 0
        category_cards.append(
            f"<td width='33.33%' valign='top' style='padding:3px;'>"
            f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' "
            f"style='background:#f7f9fa;border:1px solid {COLORS['border']};'>"
            f"<tr><td style='padding:10px 10px 3px;color:{COLORS['text']};font-size:11px;font-weight:bold;'>{esc(label_text)}</td></tr>"
            f"<tr><td style='padding:0 10px;color:{COLORS['orange']};font-size:21px;font-weight:bold;'>{num(count)}</td></tr>"
            f"<tr><td style='padding:3px 10px 4px;color:{COLORS['muted']};font-size:9px;'>{share}% del total</td></tr>"
            f"<tr><td style='padding:0 10px 10px;'>{visual_bar(count, max_category, 7)}</td></tr>"
            f"</table></td>"
        )

    def ranked_cards(rows, title_color=None):
        title_color = title_color or COLORS['orange']
        if not rows:
            return (
                f"<div style='padding:14px;color:{COLORS['muted']};font-size:10px;'>"
                "Sin datos para el período.</div>"
            )
        max_value = max(int(count) for _label, count in rows) or 1
        blocks = []
        for index, (label_text, count) in enumerate(rows):
            shown = str(label_text)
            if len(shown) > 31:
                shown = shown[:28] + "…"
            blocks.append(
                f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' "
                f"style='margin-bottom:5px;'>"
                f"<tr>"
                f"<td width='7%' style='padding:5px 3px;color:{title_color};font-size:11px;font-weight:bold;'>"
                f"{index + 1}</td>"
                f"<td width='61%' style='padding:5px 3px;color:{COLORS['text']};font-size:10px;overflow-wrap:anywhere;'>"
                f"<b>{esc(shown)}</b></td>"
                f"<td width='20%' style='padding:5px 4px;'>{visual_bar(count, max_value, 6, title_color)}</td>"
                f"<td width='12%' align='right' style='padding:5px 2px;color:{COLORS['text']};font-size:10px;font-weight:bold;'>"
                f"{num(count)}</td>"
                f"</tr></table>"
            )
        return "".join(blocks)

    def box(title, inner, width="50%", accent=None):
        accent = accent or COLORS['orange']
        return (
            f"<td width='{width}' valign='top' style='padding:4px;'>"
            f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' "
            f"style='background:{COLORS['white']};border:1px solid {COLORS['border']};'>"
            f"<tr><td style='border-top:4px solid {accent};padding:10px 11px 7px;"
            f"color:{COLORS['text']};font-size:14px;font-weight:bold;'>{esc(title)}</td></tr>"
            f"<tr><td style='padding:0 10px 10px;'>{inner}</td></tr>"
            "</table></td>"
        )

    # KPI principal: cuatro números, sin párrafos intermedios.
    # Se construye explícitamente como string para que parts[] nunca reciba un tuple.
    kpis = "".join((
        "<tr><td style='padding:0 6px 9px;'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr>",
        kpi("Eventos", security_count, "detecciones"),
        kpi("Alta severidad", critical_count, "nivel Wazuh ≥ 13"),
        kpi("IPs atacantes", len(source_ips), "orígenes observados"),
        kpi("IPs bloqueadas", blocked_ips, "firewall-drop", "danger"),
        "</tr></table></td></tr>"
    ))

    category_rows_html = (
        "<tr><td style='padding:0 6px 8px;'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr>"
        + "".join(category_cards[:3])
        + "</tr><tr>"
        + "".join(category_cards[3:6])
        + "</tr></table></td></tr>"
    )

    if blocked_ips:
        blocked_inner = (
            f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>"
            f"<tr><td align='center' style='padding:6px 4px 0;color:{COLORS['danger']};font-size:42px;font-weight:bold;line-height:1;'>"
            f"{num(blocked_ips)}</td></tr>"
            f"<tr><td align='center' style='padding:3px 4px 1px;color:{COLORS['text']};font-size:10px;font-weight:bold;text-transform:uppercase;'>"
            "IPs atacantes bloqueadas</td></tr>"
            f"<tr><td align='center' style='padding:0 4px 10px;color:{COLORS['muted']};font-size:9px;'>"
            f"{num(firewall_attempts)} intentos asociados · Active Response</td></tr>"
            "</table>"
        )
    else:
        blocked_inner = (
            f"<div style='padding:18px 5px;text-align:center;color:{COLORS['good']};font-size:12px;font-weight:bold;'>"
            "0 IPs bloqueadas en el período</div>"
        )

    posture_inner = (
        f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>"
        f"<tr><td width='50%' valign='top' style='padding:4px 8px 4px 0;'>"
        f"<div style='font-size:27px;font-weight:bold;color:{COLORS['orange']};'>{critical_pct}%</div>"
        f"<div style='font-size:9px;color:{COLORS['muted']};text-transform:uppercase;'>alta severidad</div>"
        f"</td><td width='50%' valign='top' style='padding:4px 0 4px 8px;'>"
        f"<div style='font-size:27px;font-weight:bold;color:{COLORS['text']};'>{num(len(agents))}</div>"
        f"<div style='font-size:9px;color:{COLORS['muted']};text-transform:uppercase;'>sistemas activos</div>"
        f"</td></tr></table>"
    )

    top_panels = (
        "<tr><td style='padding:0 6px 2px;'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr>"
        + box("Top 5 sistemas", ranked_cards(systems_data))
        + box("Top 5 reglas", ranked_cards(rules_data))
        + "</tr></table></td></tr>"
        "<tr><td style='padding:0 6px 8px;'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr>"
        + box("Top 5 MITRE ATT&CK", ranked_cards(mitre_data), "50%")
        + box("Indicadores de seguridad", posture_inner, "50%")
        + "</tr></table></td></tr>"
    )

    parts = [
        "<!DOCTYPE html><html lang='es'><head><meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1.0'></head>",
        f"<body style='margin:0;padding:0;background:{COLORS['page']};font-family:Arial,Helvetica,sans-serif;color:{COLORS['text']};'>",
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>"
        "<tr><td align='center' style='padding:8px;'>",
        f"<table role='presentation' width='720' cellpadding='0' cellspacing='0' border='0' "
        f"style='width:100%;max-width:720px;background:#0f171b;'>",

        # Header tipo dashboard.
        f"<tr><td style='background:{COLORS['dark']};border-bottom:5px solid {COLORS['orange']};padding:14px 17px;'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr>"
        f"<td width='54%' valign='middle'><img src='{esc(LOGO_URL)}' alt='OrangeBox IT Services' width='185' "
        "style='display:block;width:185px;max-width:100%;height:auto;border:0;'></td>"
        f"<td width='46%' align='right' valign='middle' style='color:{COLORS['white']};padding-left:8px;'>"
        "<div style='font-size:20px;font-weight:bold;line-height:1.0;'>Security Dashboard</div>"
        f"<div style='font-size:9px;color:#cbd7dc;padding-top:5px;'>{esc(label.upper())} · {esc(group)}</div>"
        "</td></tr></table></td></tr>",

        # Título mínimo.
        f"<tr><td style='background:#11191d;padding:13px 17px 8px;color:{COLORS['white']};'>"
        f"<div style='font-size:10px;color:{COLORS['orange']};font-weight:bold;letter-spacing:1.1px;'>ORANGEBOX SECURITY · WAZUH</div>"
        "<div style='font-size:24px;font-weight:bold;padding-top:3px;'>Resumen de seguridad</div>"
        f"<div style='font-size:10px;color:#aebec5;padding-top:3px;'>{esc(period)}</div>"
        "</td></tr>",

        kpis,

        # Categorías: tarjetas en lugar de una tabla de informe.
        f"<tr><td style='padding:2px 12px 7px;color:{COLORS['white']};font-size:16px;font-weight:bold;'>"
        f"<span style='color:{COLORS['orange']};'>▌</span> Actividad por categoría</td></tr>",
        category_rows_html,

        # Bloqueos + postura.
        "<tr><td style='padding:0 6px 2px;'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr>"
        + box("Bloqueos automáticos", blocked_inner, "50%", COLORS['danger'])
        + box("Estado general", posture_inner, "50%", COLORS['orange'])
        + "</tr></table></td></tr>",

        # Rankings.
        f"<tr><td style='padding:8px 12px 7px;color:{COLORS['white']};font-size:16px;font-weight:bold;'>"
        f"<span style='color:{COLORS['orange']};'>▌</span> Actividad destacada</td></tr>",
        top_panels,

        f"<tr><td style='padding:4px 12px 12px;color:#8fa2aa;font-size:8px;line-height:1.4;text-align:right;'>"
        f"Generado {esc(generated)} · Wazuh · OrangeBox IT Services</td></tr>",
        f"<tr><td style='background:{COLORS['dark']};border-top:4px solid {COLORS['orange']};padding:11px 17px;"
        "color:#c7d2d7;font-size:9px;line-height:1.4;'>"
        "<b style='color:#fff;'>ORANGEBOX IT SERVICES</b><br>Security Monitoring</td></tr>",
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
