#!/usr/bin/env python3

"""
OrangeBox Wazuh - Reporte diario de firewall-drop

Lee /var/ossec/logs/active-responses.log y genera un resumen HTML
agrupado por agente, regla/motivo y duracion.

No envia correos por si mismo en esta primera version: la funcion
principal genera el HTML y puede ser integrada posteriormente con
el mecanismo de correo definido para los reportes diarios.

El reporte NO lista IPs individualmente. Cuenta IPs unicas por:
    agente + rule_id + duracion

Los eventos sin una srcip valida no se consideran bloqueos efectivos.
"""

import html
import ipaddress
import json
import re
from collections import defaultdict
from datetime import datetime

ACTIVE_RESPONSE_LOG = "/var/ossec/logs/active-responses.log"

# Coincide con las lineas que contienen el JSON de Active Response.
JSON_LINE_RE = re.compile(
    r"^([^ ]+ [^ ]+) active-response/bin/firewall-drop: (\{.*\})$"
)


def esc(value):
    return html.escape(str(value), quote=True)


def valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def parse_log(path=ACTIVE_RESPONSE_LOG):
    """Devuelve eventos firewall-drop con srcip valida."""
    events = []

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                match = JSON_LINE_RE.match(line.rstrip("\n"))
                if not match:
                    continue

                log_timestamp, payload_text = match.groups()

                try:
                    payload = json.loads(payload_text)
                except json.JSONDecodeError:
                    continue

                if payload.get("command") != "add":
                    continue

                alert = payload.get("parameters", {}).get("alert", {})
                data = alert.get("data", {}) or {}
                rule = alert.get("rule", {}) or {}
                agent = alert.get("agent", {}) or {}

                srcip = data.get("srcip") or alert.get("srcip")

                if not valid_ip(srcip):
                    # firewall-drop no pudo recibir una IP valida.
                    continue

                events.append({
                    "log_timestamp": log_timestamp,
                    "alert_timestamp": alert.get("timestamp", ""),
                    "agent_id": agent.get("id", "000"),
                    "agent_name": agent.get("name", "unknown"),
                    "rule_id": str(rule.get("id", "unknown")),
                    "description": rule.get("description", "Sin descripcion"),
                    "srcip": srcip,
                    "alert_id": alert.get("id", ""),
                })

    except FileNotFoundError:
        raise SystemExit(f"No existe el archivo: {path}")

    return events


def parse_duration_from_rule(rule_id):
    """Duracion conocida segun la configuracion OrangeBox actual."""
    durations = {
        "5720": "3 minutos",
        "10006": "24 horas",
        "10026": "24 horas",
    }
    return durations.get(rule_id, "Configurada en Active Response")


def group_events(events):
    """Agrupa por agente + regla + duracion y cuenta IPs unicas."""
    grouped = defaultdict(set)

    for event in events:
        rule_id = event["rule_id"]
        duration = parse_duration_from_rule(rule_id)
        key = (
            event["agent_id"],
            event["agent_name"],
            rule_id,
            event["description"],
            duration,
        )
        grouped[key].add(event["srcip"])

    return grouped


def generate_html(events, report_date=None):
    """Genera el reporte HTML con el estilo visual de OrangeBox."""
    if report_date is None:
        report_date = datetime.now().strftime("%d/%m/%Y")

    grouped = group_events(events)

    agents = defaultdict(list)
    total_ips = set()
    total_blocks = 0
    rules_summary = defaultdict(set)

    for key, ips in sorted(grouped.items()):
        agent_id, agent_name, rule_id, description, duration = key
        item = {
            "rule_id": rule_id,
            "description": description,
            "duration": duration,
            "ip_count": len(ips),
            "ips": ips,
        }
        agents[(agent_id, agent_name)].append(item)
        total_ips.update((agent_id, ip) for ip in ips)
        total_blocks += len(ips)
        rules_summary[(rule_id, description)].update(ips)

    css = """
    body { margin:0; padding:0; background:#f4f6f8; font-family:Arial,Helvetica,sans-serif; color:#263238; }
    .container { max-width:900px; margin:30px auto; background:#ffffff; border:1px solid #d9dee3; border-radius:8px; overflow:hidden; }
    .header { background:#263238; color:#ffffff; padding:24px 28px; }
    .header .brand { color:#ff8c00; font-size:13px; font-weight:bold; letter-spacing:1px; text-transform:uppercase; }
    .header h1 { margin:7px 0 4px; font-size:23px; font-weight:600; }
    .header .date { color:#cfd8dc; font-size:13px; }
    .content { padding:24px 28px; }
    .agent { margin-bottom:28px; border:1px solid #d9dee3; border-radius:6px; overflow:hidden; }
    .agent-title { background:#eceff1; padding:12px 15px; font-size:15px; font-weight:bold; }
    table { width:100%; border-collapse:collapse; }
    th { background:#37474f; color:#ffffff; text-align:left; padding:10px; font-size:12px; }
    td { border-top:1px solid #e5e8eb; padding:10px; font-size:13px; vertical-align:top; }
    .count { font-weight:bold; text-align:center; white-space:nowrap; }
    .rule { font-family:monospace; font-weight:bold; }
    .summary { margin-top:28px; border:1px solid #d9dee3; border-radius:6px; overflow:hidden; }
    .summary-title { background:#263238; color:#ffffff; padding:12px 15px; font-weight:bold; }
    .summary-body { padding:15px; }
    .metric { display:inline-block; margin-right:35px; margin-bottom:10px; }
    .metric-value { font-size:22px; font-weight:bold; }
    .metric-label { display:block; color:#607d8b; font-size:12px; margin-top:2px; }
    .footer { padding:16px 28px; background:#fafbfc; border-top:1px solid #e5e8eb; color:#78909c; font-size:11px; }
    """

    parts = [
        "<!DOCTYPE html>",
        "<html><head><meta charset='UTF-8'>",
        f"<style>{css}</style></head><body>",
        "<div class='container'>",
        "<div class='header'>",
        "<div class='brand'>OrangeBox Security · Wazuh</div>",
        "<h1>Reporte diario — Firewall Drop</h1>",
        f"<div class='date'>Período: {esc(report_date)}</div>",
        "</div><div class='content'>",
    ]

    if not agents:
        parts.append("<p>No se registraron bloqueos firewall-drop con IP válida durante el período.</p>")
    else:
        for (agent_id, agent_name), items in sorted(agents.items(), key=lambda x: x[0][1]):
            parts.extend([
                "<div class='agent'>",
                f"<div class='agent-title'>{esc(agent_name)} <span style='font-weight:normal;color:#607d8b'>(ID {esc(agent_id)})</span></div>",
                "<table><thead><tr>",
                "<th>Motivo</th><th>Regla</th><th>Duración</th><th>IPs únicas</th>",
                "</tr></thead><tbody>",
            ])

            for item in items:
                parts.extend([
                    "<tr>",
                    f"<td>{esc(item['description'])}</td>",
                    f"<td class='rule'>{esc(item['rule_id'])}</td>",
                    f"<td>{esc(item['duration'])}</td>",
                    f"<td class='count'>{item['ip_count']}</td>",
                    "</tr>",
                ])

            parts.extend(["</tbody></table></div>"])

    parts.extend([
        "<div class='summary'>",
        "<div class='summary-title'>Resumen del período</div>",
        "<div class='summary-body'>",
        f"<div class='metric'><span class='metric-value'>{len(agents)}</span><span class='metric-label'>Agentes con bloqueos</span></div>",
        f"<div class='metric'><span class='metric-value'>{total_blocks}</span><span class='metric-label'>IPs bloqueadas (por agente/regla)</span></div>",
        f"<div class='metric'><span class='metric-value'>{len(total_ips)}</span><span class='metric-label'>IPs únicas globales</span></div>",
        "<table style='margin-top:15px'><thead><tr><th>Regla</th><th>Motivo</th><th>IPs únicas</th></tr></thead><tbody>",
    ])

    for (rule_id, description), ips in sorted(rules_summary.items()):
        parts.extend([
            "<tr>",
            f"<td class='rule'>{esc(rule_id)}</td>",
            f"<td>{esc(description)}</td>",
            f"<td class='count'>{len(ips)}</td>",
            "</tr>",
        ])

    parts.extend([
        "</tbody></table>",
        "</div></div>",
        "</div>",
        "<div class='footer'>OrangeBox IT Services · Reporte generado automáticamente desde Wazuh Active Response.</div>",
        "</div></body></html>",
    ])

    return "".join(parts)


def main():
    events = parse_log()
    print(generate_html(events))


if __name__ == "__main__":
    main()
