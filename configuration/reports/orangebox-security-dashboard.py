#!/usr/bin/env python3
"""OrangeBox Wazuh Security Dashboard.

Dashboard adicional al informe ejecutivo. La fuente de datos es EXACTAMENTE
la misma: orangebox-security-report.py -> period_bounds(), group_members(),
load_events(), section_rows() y mitre_rows(). Solo cambia la presentación.

El HTML está diseñado para correo: tablas de presentación, estilos inline y
sin CSS Grid, Flexbox ni JavaScript, para evitar que Gmail rompa el layout.
"""
import argparse
import html
import importlib.util
import re
import smtplib
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


def section(title, subtitle="", icon=""):
    return (
        "<tr><td style='padding:0 0 16px;'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='background:#ffffff;border:1px solid #d7e0e4;'>"
        f"<tr><td style='background:#f1f5f7;border-left:4px solid #f58220;padding:11px 13px;color:#263238;font-size:16px;font-weight:bold;'>{esc((icon + ' ' + title).strip())}</td></tr>"
        + (f"<tr><td style='padding:8px 14px 6px;color:#667b85;font-size:11px;line-height:1.4;'>{esc(subtitle)}</td></tr>" if subtitle else "")
    )


def close_section():
    return "</table></td></tr>"


def metric(value, label, note):
    return (
        "<td width='25%' valign='top' style='padding:0 4px 8px;'>"
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='background:#18313b;border-bottom:4px solid #f58220;'>"
        f"<tr><td align='center' style='padding:13px 4px 3px;color:#f58220;font-size:25px;font-weight:bold;'>{num(value)}</td></tr>"
        f"<tr><td align='center' style='padding:0 4px 3px;color:#ffffff;font-size:10px;font-weight:bold;'>{esc(label)}</td></tr>"
        f"<tr><td align='center' style='padding:0 4px 11px;color:#c8d7dc;font-size:9px;line-height:1.3;'>{esc(note)}</td></tr>"
        "</table></td>"
    )


def category_summary(categories):
    total = sum(info["count"] for info in categories.values()) or 1
    body = []
    for key, (icon, label) in CATEGORIES.items():
        count = categories[key]["count"]
        pct = round((count / total) * 100) if count else 0
        body.append(
            f"<tr><td style='border-top:1px solid #e5eaed;padding:8px;font-size:11px;'>{icon} <b>{esc(label)}</b></td>"
            f"<td align='right' style='border-top:1px solid #e5eaed;padding:8px;font-size:11px;font-weight:bold;'>{num(count)}</td>"
            f"<td width='38%' style='border-top:1px solid #e5eaed;padding:8px;'>"
            f"<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='background:#e8edf0;'><tr>"
            f"<td width='{pct}%' style='background:#f58220;height:7px;font-size:1px;line-height:7px;'>&nbsp;</td>"
            f"<td style='height:7px;font-size:1px;line-height:7px;'>&nbsp;</td></tr></table></td></tr>"
        )
    return "".join(body)


def rules_rows(categories, limit=12):
    rows = []
    for info in categories.values():
        rows.extend(info["rules"].items())
    rows.sort(key=lambda item: item[1], reverse=True)
    if not rows:
        return "<tr><td colspan='2' style='padding:10px;color:#667b85;font-size:11px;'>Sin datos para el período.</td></tr>"
    body = []
    for (rule_id, description), count in rows[:limit]:
        body.append(
            f"<tr><td valign='top' style='border-top:1px solid #e3e9ec;padding:7px;font-size:10px;'><b style='color:#d65d00;font-family:monospace;'>{esc(rule_id)}</b><br><span style='color:#526873;'>{esc(description)}</span></td>"
            f"<td align='right' valign='top' style='border-top:1px solid #e3e9ec;padding:7px;font-size:10px;font-weight:bold;white-space:nowrap;'>{num(count)}</td></tr>"
        )
    return "<tr><td style='padding:0 7px 8px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr><td style='background:#29414c;color:#fff;padding:7px;font-size:10px;font-weight:bold;'>Regla</td><td style='background:#29414c;color:#fff;padding:7px;font-size:10px;font-weight:bold;'>Alertas</td></tr>" + "".join(body) + "</table></td></tr>"


def agents_rows(agents, limit=15):
    if not agents:
        return "<tr><td style='padding:10px;color:#147a4a;font-size:11px;'>Sin actividad relevante.</td></tr>"
    body = ["<tr><td style='background:#29414c;color:#fff;padding:7px;font-size:10px;font-weight:bold;'>Sistema</td><td style='background:#29414c;color:#fff;padding:7px;font-size:10px;font-weight:bold;'>Detecciones</td></tr>"]
    for (_agent_id, name), count in agents.most_common(limit):
        body.append(
            f"<tr><td style='border-top:1px solid #e3e9ec;padding:7px;font-size:10px;overflow-wrap:anywhere;'><b>{esc(name)}</b></td>"
            f"<td align='right' style='border-top:1px solid #e3e9ec;padding:7px;font-size:10px;font-weight:bold;white-space:nowrap;'>{num(count)}</td></tr>"
        )
    return "<tr><td style='padding:0 7px 8px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>" + "".join(body) + "</table></td></tr>"


def mitre_rows(summary, report):
    rows = report.mitre_rows(summary)
    if not rows:
        return "<tr><td style='padding:10px 14px;color:#667b85;font-size:11px;'>No se encontraron técnicas MITRE ATT&CK en las alertas del período.</td></tr>"
    body = ["<tr><td style='background:#29414c;color:#fff;padding:7px;font-size:10px;font-weight:bold;'>Técnica</td><td style='background:#29414c;color:#fff;padding:7px;font-size:10px;font-weight:bold;'>Nombre</td><td style='background:#29414c;color:#fff;padding:7px;font-size:10px;font-weight:bold;'>Qué significa</td><td style='background:#29414c;color:#fff;padding:7px;font-size:10px;font-weight:bold;'>Alertas</td></tr>"]
    for mid, name, meaning, count in rows:
        body.append(
            f"<tr><td valign='top' style='border-top:1px solid #e3e9ec;padding:7px;font-family:monospace;font-weight:bold;color:#d65d00;font-size:10px;'>{esc(mid)}</td>"
            f"<td valign='top' style='border-top:1px solid #e3e9ec;padding:7px;font-size:10px;'>{esc(name)}</td>"
            f"<td valign='top' style='border-top:1px solid #e3e9ec;padding:7px;font-size:10px;line-height:1.35;'>{esc(meaning)}</td>"
            f"<td align='right' valign='top' style='border-top:1px solid #e3e9ec;padding:7px;font-size:10px;font-weight:bold;white-space:nowrap;'>{num(count)}</td></tr>"
        )
    return "<tr><td style='padding:0 7px 8px;overflow-wrap:anywhere;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>" + "".join(body) + "</table></td></tr>"


def firewall_rows(summary):
    rows = summary["firewall_rows"]
    if not rows:
        return "<tr><td style='padding:10px 14px;color:#147a4a;font-size:11px;'>No se registraron bloqueos automáticos con una IP de origen válida.</td></tr>"
    attempts = sum(row["attempts"] for row in rows)
    body = [f"<tr><td colspan='3' style='padding:9px 14px;color:#8a3a30;font-size:11px;'><b>{num(len(summary['firewall_ips']))}</b> IPs bloqueadas automáticamente · <b>{num(attempts)}</b> intentos asociados.</td></tr>", "<tr><td style='background:#6b2923;color:#fff;padding:7px;font-size:10px;font-weight:bold;'>Sistema</td><td style='background:#6b2923;color:#fff;padding:7px;font-size:10px;font-weight:bold;'>Regla / motivo</td><td style='background:#6b2923;color:#fff;padding:7px;font-size:10px;font-weight:bold;'>IPs</td></tr>"]
    for row in rows:
        body.append(
            f"<tr><td valign='top' style='border-top:1px solid #ead8d5;padding:7px;font-size:10px;'><b>{esc(row['agent_name'])}</b></td>"
            f"<td valign='top' style='border-top:1px solid #ead8d5;padding:7px;font-size:10px;'><b style='color:#c43d2b;font-family:monospace;'>{esc(row['rule_id'])}</b><br>{esc(row['description'])}</td>"
            f"<td align='right' valign='top' style='border-top:1px solid #ead8d5;padding:7px;font-size:10px;font-weight:bold;'>{num(len(row['ips']))}</td></tr>"
        )
    return "<tr><td style='padding:0 7px 8px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>" + "".join(body) + "</table></td></tr>"


def dashboard_html(summary, group, start, end, label, report):
    period = f"{start.strftime('%d/%m/%Y %H:%M')} — {end.strftime('%d/%m/%Y %H:%M') if end <= datetime.now().astimezone() else 'ahora'}"
    generated = datetime.now().astimezone().strftime("%d/%m/%Y %H:%M %Z")
    categories = summary["categories"]
    parts = [
        "<!DOCTYPE html><html lang='es'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1.0'></head>",
        "<body style='margin:0;padding:0;background:#eef2f5;font-family:Arial,Helvetica,sans-serif;color:#263238;'>",
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr><td align='center' style='padding:10px;'>",
        "<table role='presentation' width='680' cellpadding='0' cellspacing='0' border='0' style='width:100%;max-width:680px;background:#ffffff;'>",
        "<tr><td style='background:#182a33;border-bottom:5px solid #f58220;padding:15px 18px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr>",
        f"<td width='52%' valign='middle'><img src='{esc(LOGO_URL)}' alt='OrangeBox IT Services' width='190' style='display:block;width:190px;max-width:100%;height:auto;border:0;'></td>",
        "<td width='48%' align='right' valign='middle' style='color:#ffffff;padding-left:8px;'><div style='font-size:20px;font-weight:bold;'>Security Dashboard</div><div style='font-size:9px;color:#cbd7dc;padding-top:4px;'>WAZUH · SECURITY MONITORING</div></td>",
        "</tr></table></td></tr>",
        f"<tr><td style='padding:19px 18px 11px;'><div style='font-size:10px;font-weight:bold;letter-spacing:1px;color:#f58220;'>ORANGEBOX SECURITY · WAZUH</div><div style='font-size:24px;font-weight:bold;color:#263238;padding-top:5px;'>Resumen de seguridad</div><div style='font-size:13px;color:#607d8b;padding-top:4px;'>Actividad y detecciones del período seleccionado.</div><div style='margin-top:12px;background:#f4f7f8;border:1px solid #d9e3e7;padding:9px 11px;font-size:11px;color:#526873;line-height:1.5;'><b>Grupo:</b> {esc(group)} &nbsp;·&nbsp; <b>Período:</b> {esc(label)}<br>{esc(period)}</div></td></tr>",
        "<tr><td style='padding:0 10px 9px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr>",
        metric(summary['security_count'], 'Eventos de seguridad', 'Alertas clasificadas'),
        metric(summary['critical_count'], 'Alta severidad', 'Nivel Wazuh ≥ 13'),
        metric(len(summary['source_ips']), 'IPs de origen', 'Direcciones válidas'),
        metric(len(summary['agents']), 'Sistemas', 'Agentes con detecciones'),
        "</tr></table></td></tr>",
        section("Actividad por categoría", "Los mismos contadores del informe ejecutivo; solo cambia la presentación.", "📊"),
        "<tr><td style='padding:0 7px 8px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr><td style='background:#29414c;color:#fff;padding:7px;font-size:10px;font-weight:bold;'>Categoría</td><td align='right' style='background:#29414c;color:#fff;padding:7px;font-size:10px;font-weight:bold;'>Eventos</td><td style='background:#29414c;color:#fff;padding:7px;font-size:10px;font-weight:bold;'>Proporción</td></tr>",
        category_summary(categories), "</table></td></tr>", close_section(),
        section("Reglas más activas", "Agregadas directamente desde las mismas estructuras del informe ejecutivo.", "⚙️"),
        rules_rows(categories), close_section(),
        section("Sistemas más afectados", "Se muestra solo el nombre del sistema; el ID de agente no se expone.", "🖥️"),
        agents_rows(summary['agents']), close_section(),
        section("Técnicas MITRE observadas", "Misma correlación MITRE y mismas descripciones del informe ejecutivo.", "🧭"),
        mitre_rows(summary, report), close_section(),
        section("Bloqueos automáticos", "Eventos de Active Response firewall-drop reconstruidos desde las alertas Wazuh.", "🛡️"),
        firewall_rows(summary), close_section(),
        "<tr><td style='padding:0 14px 15px;'><div style='background:#f7f9fa;border:1px solid #dce5e9;border-left:4px solid #f58220;padding:9px 11px;color:#526873;font-size:10px;line-height:1.5;'>Este dashboard utiliza la misma extracción y clasificación del informe ejecutivo. No mantiene una segunda fuente de datos.</div></td></tr>",
        f"<tr><td style='background:#182a33;border-top:4px solid #f58220;padding:13px 18px;color:#c7d2d7;font-size:9px;line-height:1.5;'><b style='color:#fff;'>ORANGEBOX IT SERVICES</b><br>Security Dashboard · Generado {esc(generated)} · Datos extraídos desde Wazuh</td></tr>",
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
    mode = args.date and f"date:{args.date}" or next(name for name in ("today","yesterday","thisweek","lastweek","thismonth","lastmonth","thisyear","lastyear") if getattr(args,name))
    recipients = []
    for value in args.email or []:
        recipients.extend(item.strip() for item in value.split(",") if item.strip())
    for recipient in recipients:
        if not re.fullmatch(r"[^\s@]+@[^\s@]+", recipient):
            raise SystemExit(f"Dirección de correo inválida: {recipient}")
    now = datetime.now().astimezone()
    start, end, label = report.period_bounds(mode, now)
    allowed = report.group_members(args.group)
    # MISMA extracción del informe ejecutivo. No hay una segunda implementación de load_events().
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
        prefixes = {"today":"Dashboard Diario de Seguridad","yesterday":"Dashboard Diario de Seguridad","thisweek":"Dashboard Semanal de Seguridad","lastweek":"Dashboard Semanal de Seguridad","thismonth":"Dashboard Mensual de Seguridad","lastmonth":"Dashboard Mensual de Seguridad","thisyear":"Dashboard Anual de Seguridad","lastyear":"Dashboard Anual de Seguridad"}
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
