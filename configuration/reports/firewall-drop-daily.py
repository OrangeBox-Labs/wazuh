#!/usr/bin/env python3

"""OrangeBox Wazuh - Reporte diario de firewall-drop."""

import argparse
import html
import ipaddress
import json
import os
import re
import smtplib
from collections import defaultdict
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
DEFAULT_TO = "soporte@orangebox.cl"
DEFAULT_FROM = "wazuh@orangebox.cl"
SMTP_HOST = "localhost"
SMTP_PORT = 25
ARCHIVE_DIR = "/var/ossec/reports/archive"
FIREWALL_DROP_RE = re.compile(r"active-response/bin/firewall-drop:\s*(\{.*\})$")
DURATIONS = {"5720": "3 minutos", "10006": "24 horas", "10026": "24 horas"}


def esc(value):
    return html.escape(str(value), quote=True)


def valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def parse_timestamp(value):
    if not value:
        return None
    try:
        value = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value)
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def extract_firewall_drop_payload(full_log):
    if not isinstance(full_log, str):
        return None
    match = FIREWALL_DROP_RE.search(full_log.strip())
    if not match:
        return None
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return None


def parse_alerts(path=ALERTS_FILE, report_date=None):
    events = []
    start = end = None
    if report_date:
        try:
            day = datetime.strptime(report_date, "%Y-%m-%d").date()
        except ValueError as exc:
            raise SystemExit(f"Fecha invalida: {report_date}. Use YYYY-MM-DD.") from exc
        start, end = day, day + timedelta(days=1)

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    outer = json.loads(line.strip())
                except (json.JSONDecodeError, AttributeError):
                    continue
                if str((outer.get("rule", {}) or {}).get("id")) != "651":
                    continue
                timestamp = parse_timestamp(outer.get("timestamp", ""))
                if report_date and (not timestamp or not (start <= timestamp.date() < end)):
                    continue
                inner = extract_firewall_drop_payload(outer.get("full_log", ""))
                if not inner or inner.get("command") != "add":
                    continue
                parameters = inner.get("parameters", {}) or {}
                if parameters.get("program") != "active-response/bin/firewall-drop":
                    continue
                alert = parameters.get("alert", {}) or {}
                rule = alert.get("rule", {}) or {}
                agent = alert.get("agent", {}) or {}
                data = alert.get("data", {}) or {}
                srcip = data.get("srcip") or alert.get("srcip")
                if not valid_ip(srcip):
                    continue
                events.append({
                    "agent_id": str(agent.get("id", "000")),
                    "agent_name": agent.get("name", "unknown"),
                    "rule_id": str(rule.get("id", "unknown")),
                    "description": rule.get("description", "Sin descripcion"),
                    "srcip": str(srcip),
                })
    except FileNotFoundError:
        raise SystemExit(f"No existe el archivo: {path}")
    return events


def group_events(events):
    grouped = defaultdict(set)
    for event in events:
        rule_id = event["rule_id"]
        duration = DURATIONS.get(rule_id, "Configurada en Active Response")
        key = (event["agent_id"], event["agent_name"], rule_id, event["description"], duration)
        grouped[key].add(event["srcip"])
    return grouped


def generate_html(events, report_date=None):
    report_date = report_date or datetime.now().strftime("%Y-%m-%d")
    grouped = group_events(events)
    agents = defaultdict(list)
    global_ips = set()
    rule_ips = defaultdict(set)
    total_blocks = 0

    for (agent_id, agent_name, rule_id, description, duration), ips in sorted(grouped.items()):
        ip_list = sorted(ips, key=lambda x: (ipaddress.ip_address(x).version, ipaddress.ip_address(x)))
        agents[(agent_id, agent_name)].append({
            "rule_id": rule_id, "description": description, "duration": duration,
            "ips": ip_list, "ip_count": len(ip_list),
        })
        global_ips.update(ips)
        rule_ips[(rule_id, description)].update(ips)
        total_blocks += len(ips)

    css = """
body{margin:0;padding:0;background:#eef2f5;font-family:Arial,Helvetica,sans-serif;color:#263238}
.container{max-width:920px;margin:20px auto;background:#fff;border:1px solid #d5dde2;border-radius:10px;overflow:hidden}
.top{background:#182a33;color:#fff;border-bottom:5px solid #f58220;padding:18px 26px;display:flex;justify-content:space-between;align-items:center}
.logo{display:flex;align-items:center;gap:12px}.cube{width:42px;height:42px;background:#f58220;clip-path:polygon(50% 0,100% 25%,100% 75%,50% 100%,0 75%,0 25%);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:900;font-size:15px}.wordmark{font-size:21px;font-weight:800;letter-spacing:1px}.wordmark span{color:#f58220}.submark{font-size:10px;color:#b8c5cb;letter-spacing:2px;margin-top:2px}.wazuh{font-size:19px;font-weight:bold;text-align:right}.wazuh small{display:block;color:#b8c5cb;font-size:10px;letter-spacing:1px}
.hero{padding:25px 28px 18px}.eyebrow{color:#f58220;font-size:12px;font-weight:bold;letter-spacing:1.5px;text-transform:uppercase}.hero h1{margin:5px 0 4px;font-size:27px;color:#263943}.hero p{margin:0;color:#607d8b;font-size:14px}.date{float:right;text-align:right;margin-top:-38px}.date strong{display:block;color:#f58220;font-size:20px}.date span{font-size:11px;color:#78909c}
.content{padding:0 28px 26px}.agent{margin:0 0 18px;border:1px solid #d6e0e5;border-radius:9px;overflow:hidden;background:#fff;box-shadow:0 2px 7px rgba(38,50,56,.05)}.agent-head{padding:13px 16px;background:#f4f7f8;display:flex;justify-content:space-between;align-items:center}.agent-name{font-size:17px;font-weight:bold;color:#263943}.agent-id{font-size:11px;color:#78909c;margin-top:2px}.badge{background:#dff6ea;color:#147a4a;border:1px solid #bdebd4;border-radius:16px;padding:7px 12px;font-size:12px;font-weight:bold;white-space:nowrap}.agent table{width:100%;border-collapse:collapse}.agent th{background:#29414c;color:#fff;text-align:left;padding:9px 12px;font-size:12px}.agent td{border-top:1px solid #e4eaed;padding:11px 12px;font-size:13px;vertical-align:top}.rule{font-family:monospace;font-weight:bold;background:#fff0e5;color:#d65d00;border:1px solid #ffd2b0;border-radius:5px;padding:4px 7px;display:inline-block}.count{text-align:center;font-weight:bold}.motivo{line-height:1.4}.motivo strong{color:#263943}
details{margin-top:8px}summary{cursor:pointer;color:#425d68;font-size:12px;font-weight:bold;list-style-position:inside}summary::marker{color:#f58220}.ipbox{margin-top:8px;background:#f7f9fa;border:1px solid #dce5e9;border-radius:6px;padding:8px 10px;font-family:monospace;font-size:12px;color:#455a64;line-height:1.65;word-break:break-all}.ip{display:inline-block;background:#fff;border:1px solid #d9e2e6;border-radius:4px;padding:2px 6px;margin:2px 3px}
.summary{margin-top:8px;background:#18313b;color:#fff;border-radius:9px;overflow:hidden}.summary-title{padding:13px 17px;font-size:16px;font-weight:bold}.metrics{display:flex;gap:10px;padding:0 12px 14px}.metric{flex:1;background:#274754;border:1px solid #3b5c68;border-radius:7px;text-align:center;padding:12px 6px}.metric b{display:block;color:#f58220;font-size:27px}.metric span{font-size:11px;color:#d3e0e5}.detail{background:#fff;color:#263238;margin:0 12px 14px;border-radius:7px;overflow:hidden}.detail table{width:100%;border-collapse:collapse}.detail th{background:#29414c;color:#fff;padding:9px;text-align:left;font-size:11px}.detail td{border-top:1px solid #e2e8eb;padding:9px;font-size:12px;vertical-align:top}.note{margin-top:16px;background:#edf6fb;border:1px solid #c9e3f0;border-left:4px solid #f58220;border-radius:7px;padding:12px 14px;color:#49616b;font-size:12px;line-height:1.5}.footer{background:#182a33;border-top:4px solid #f58220;color:#c7d2d7;padding:15px 26px;display:flex;justify-content:space-between;font-size:10px}.footer b{color:#fff}.clear{clear:both}
@media(max-width:700px){.container{margin:0;border-radius:0}.top,.footer{display:block}.wazuh{text-align:left;margin-top:12px}.date{float:none;text-align:left;margin:14px 0 0}.metrics{display:block}.metric{margin-bottom:7px}.content,.hero{padding-left:14px;padding-right:14px}.agent table{font-size:12px}.agent th,.agent td{padding:8px}.wordmark{font-size:18px}}
"""

    parts = ["<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>", f"<style>{css}</style></head><body>", "<div class='container'>"]
    parts.append("<div class='top'><div class='logo'><div class='cube'>OB</div><div><div class='wordmark'>ORANGE<span>BOX</span></div><div class='submark'>IT SERVICES</div></div></div><div class='wazuh'>Wazuh<small>SECURITY MONITORING</small></div></div>")
    parts.append(f"<div class='hero'><div class='eyebrow'>OrangeBox Security · Wazuh</div><h1>Reporte diario — Firewall Drop</h1><p>Bloqueos aplicados automáticamente por Wazuh Active Response</p><div class='date'><strong>{esc(report_date)}</strong><span>Período analizado: 00:00 — 23:59</span></div><div class='clear'></div></div><div class='content'>")

    if not agents:
        parts.append("<div class='note'>No se registraron bloqueos firewall-drop con IP válida durante el período.</div>")
    else:
        for (agent_id, agent_name), items in sorted(agents.items(), key=lambda x: x[0][1].lower()):
            count = sum(i["ip_count"] for i in items)
            parts.append(f"<div class='agent'><div class='agent-head'><div><div class='agent-name'>{esc(agent_name)}</div><div class='agent-id'>ID del agente: {esc(agent_id)}</div></div><div class='badge'>🛡 {count} IP{'s' if count != 1 else ''} bloqueada{'s' if count != 1 else ''}</div></div><table><thead><tr><th>Motivo</th><th>Regla</th><th>Duración</th><th>IPs únicas</th></tr></thead><tbody>")
            for item in items:
                ip_html = "".join(f"<span class='ip'>{esc(ip)}</span>" for ip in item["ips"])
                parts.append("<tr>")
                parts.append(f"<td class='motivo'><strong>ALERTA:</strong> {esc(item['description'].replace('ALERTA CRITICA: ', '').replace('ALERTA: ', ''))}<details><summary>Ver IPs bloqueadas ({item['ip_count']})</summary><div class='ipbox'>{ip_html}</div></details></td>")
                parts.append(f"<td><span class='rule'>{esc(item['rule_id'])}</span></td><td>{esc(item['duration'])}</td><td class='count'>{item['ip_count']}</td></tr>")
            parts.append("</tbody></table></div>")

    parts.append(f"<div class='summary'><div class='summary-title'>📊 Resumen del período</div><div class='metrics'><div class='metric'><b>{len(agents)}</b><span>Agentes con bloqueos</span></div><div class='metric'><b>{total_blocks}</b><span>Bloqueos efectivos</span></div><div class='metric'><b>{len(global_ips)}</b><span>IPs únicas globales</span></div></div><div class='detail'><table><thead><tr><th>Regla</th><th>Motivo</th><th>IPs únicas</th></tr></thead><tbody>")
    for (rule_id, description), ips in sorted(rule_ips.items()):
        parts.append(f"<tr><td><span class='rule'>{esc(rule_id)}</span></td><td>{esc(description)}</td><td class='count'>{len(ips)}</td></tr>")
    parts.append("</tbody></table></div></div>")
    parts.append("<div class='note'>ℹ Este reporte muestra los bloqueos aplicados automáticamente por Wazuh mediante la respuesta activa <b>firewall-drop</b>. Las IPs se mantienen ocultas hasta desplegar el detalle de cada servidor.</div></div>")
    parts.append("<div class='footer'><div><b>ORANGEBOX IT SERVICES</b><br>Infraestructura segura, negocios sin interrupciones</div><div style='text-align:right'><b>OrangeBox Security · Wazuh</b><br>Reporte generado automáticamente</div></div></div></body></html>")
    return "".join(parts)


def send_email(subject, html_body, recipient=DEFAULT_TO, sender=DEFAULT_FROM):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"Wazuh SOC <{sender}>"
    msg["To"] = recipient
    msg.attach(MIMEText("Reporte diario de firewall-drop de Wazuh.", "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
        smtp.sendmail(sender, [recipient], msg.as_string())


def archive_html(html_body, report_date):
    os.makedirs(ARCHIVE_DIR, mode=0o750, exist_ok=True)
    path = f"{ARCHIVE_DIR}/firewall-drop-{report_date}.html"
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_body)
    return path


def main():
    parser = argparse.ArgumentParser(description="Genera y opcionalmente envia reporte diario de firewall-drop")
    parser.add_argument("--file", default=ALERTS_FILE)
    parser.add_argument("--date", help="Fecha YYYY-MM-DD")
    parser.add_argument("--send", action="store_true", help="Enviar mediante Postfix local")
    parser.add_argument("--no-archive", action="store_true")
    args = parser.parse_args()
    report_date = args.date or ((datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d") if args.send else None)
    events = parse_alerts(args.file, report_date)
    body = generate_html(events, report_date)
    if not args.no_archive:
        archive_html(body, report_date or datetime.now().strftime("%Y-%m-%d"))
    if args.send:
        send_email(f"[OrangeBox SOC] Reporte diario Firewall Drop - {report_date}", body)
    else:
        print(body)


if __name__ == "__main__":
    main()
