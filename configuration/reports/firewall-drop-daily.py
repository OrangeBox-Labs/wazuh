#!/usr/bin/env python3

"""
OrangeBox Wazuh - Reporte diario de firewall-drop

Lee /var/ossec/logs/alerts/alerts.json y reconstruye las ejecuciones
reales de Active Response firewall-drop a partir de las alertas 651.

No envia correos por si mismo: genera el HTML por stdout para ser
integrado posteriormente con el mecanismo de reportes diarios.

IMPORTANTE:
- No cuenta las alertas 10026 directamente como bloqueos.
- Solo considera alertas 651 cuyo full_log contiene una ejecucion
  firewall-drop con command=add.
- Los eventos sin una srcip valida no se consideran bloqueos efectivos.
- Una misma IP puede generar muchas ejecuciones de firewall-drop mientras
  una alerta de correlacion continua disparandose. Para el resumen se
  deduplica por agente + regla + srcip.
- Las IPs individuales no se muestran en el HTML.
"""

import argparse
import html
import ipaddress
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta

ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"

# El full_log de una alerta 651 contiene una linea como:
#   2026/... active-response/bin/firewall-drop: {JSON}
FIREWALL_DROP_RE = re.compile(
    r"active-response/bin/firewall-drop:\s*(\{.*\})$"
)


def esc(value):
    return html.escape(str(value), quote=True)


def valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def parse_timestamp(value):
    """Convierte timestamps Wazuh ISO-8601 a datetime con timezone."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def extract_firewall_drop_payload(full_log):
    """Extrae el JSON interno de firewall-drop desde alert.full_log."""
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
    """
    Lee alerts.json y devuelve ejecuciones efectivas de firewall-drop.

    report_date: fecha local Wazuh en formato YYYY-MM-DD. Si es None,
    procesa todo el archivo.
    """
    events = []

    start = end = None
    if report_date:
        try:
            day = datetime.strptime(report_date, "%Y-%m-%d").date()
        except ValueError as exc:
            raise SystemExit(
                f"Fecha invalida: {report_date}. Use YYYY-MM-DD."
            ) from exc
        start = day
        end = day + timedelta(days=1)

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    outer = json.loads(line)
                except json.JSONDecodeError:
                    continue

                rule = outer.get("rule", {}) or {}
                if str(rule.get("id")) != "651":
                    continue

                outer_timestamp = parse_timestamp(outer.get("timestamp", ""))
                if report_date and outer_timestamp:
                    if not (start <= outer_timestamp.date() < end):
                        continue
                elif report_date and not outer_timestamp:
                    continue

                inner = extract_firewall_drop_payload(outer.get("full_log", ""))
                if not inner:
                    continue

                if inner.get("program") != "active-response/bin/firewall-drop":
                    continue

                if inner.get("command") != "add":
                    continue

                alert = inner.get("parameters", {}).get("alert", {}) or {}
                inner_rule = alert.get("rule", {}) or {}
                agent = alert.get("agent", {}) or {}
                data = alert.get("data", {}) or {}

                srcip = data.get("srcip") or alert.get("srcip")
                if not valid_ip(srcip):
                    # firewall-drop no recibio una IP valida; no es un
                    # bloqueo efectivo para nuestro reporte.
                    continue

                events.append({
                    "timestamp": outer.get("timestamp", ""),
                    "alert_timestamp": alert.get("timestamp", ""),
                    "agent_id": str(agent.get("id", "000")),
                    "agent_name": agent.get("name", "unknown"),
                    "rule_id": str(inner_rule.get("id", "unknown")),
                    "description": inner_rule.get(
                        "description", "Sin descripcion"
                    ),
                    "srcip": str(srcip),
                    "alert_id": str(alert.get("id", "")),
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
    """
    Agrupa bloqueos por agente + regla + duracion y cuenta IPs unicas.

    La IP es el identificador de un bloqueo efectivo dentro de un grupo.
    Las multiples ejecuciones de firewall-drop para la misma IP no se
    contabilizan nuevamente.
    """
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
        report_date = datetime.now().strftime("%Y-%m-%d")

    grouped = group_events(events)

    agents = defaultdict(list)
    total_ips_global = set()
    total_blocks = 0
    rules_summary = defaultdict(set)

    for key, ips in sorted(grouped.items()):
        agent_id, agent_name, rule_id, description, duration = key
        item = {
            "rule_id": rule_id,
            "description": description,
            "duration": duration,
            "ip_count": len(ips),
        }
        agents[(agent_id, agent_name)].append(item)
        total_ips_global.update(ips)
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
        f"<div class='date'>Fecha: {esc(report_date)}</div>",
        "</div><div class='content'>",
    ]

    if not agents:
        parts.append(
            "<p>No se registraron bloqueos firewall-drop con IP válida durante el período.</p>"
        )
    else:
        for (agent_id, agent_name), items in sorted(
            agents.items(), key=lambda x: x[0][1]
        ):
            parts.extend([
                "<div class='agent'>",
                f"<div class='agent-title'>{esc(agent_name)} "
                f"<span style='font-weight:normal;color:#607d8b'>"
                f"(ID {esc(agent_id)})</span></div>",
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
        f"<div class='metric'><span class='metric-value'>{len(agents)}</span>"
        "<span class='metric-label'>Agentes con bloqueos</span></div>",
        f"<div class='metric'><span class='metric-value'>{total_blocks}</span>"
        "<span class='metric-label'>Bloqueos efectivos</span></div>",
        f"<div class='metric'><span class='metric-value'>{len(total_ips_global)}</span>"
        "<span class='metric-label'>IPs únicas globales</span></div>",
        "<table style='margin-top:15px'><thead><tr>"
        "<th>Regla</th><th>Motivo</th><th>IPs únicas</th>"
        "</tr></thead><tbody>",
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
    parser = argparse.ArgumentParser(
        description="Genera reporte HTML de firewall-drop desde Wazuh alerts.json"
    )
    parser.add_argument(
        "--file",
        default=ALERTS_FILE,
        help=f"Archivo alerts.json (default: {ALERTS_FILE})",
    )
    parser.add_argument(
        "--date",
        help="Procesar solo una fecha YYYY-MM-DD; por defecto procesa todo el archivo",
    )
    args = parser.parse_args()

    events = parse_alerts(args.file, args.date)
    print(generate_html(events, args.date))


if __name__ == "__main__":
    main()
