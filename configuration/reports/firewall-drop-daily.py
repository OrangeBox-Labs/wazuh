#!/usr/bin/env python3
"""OrangeBox Wazuh Security Activity Report.

Reads current and rotated JSON alert logs, filters by Wazuh agent group and
builds a professional HTML security activity report.

Periods: --today, --yesterday, --thisweek, --lastweek, --thismonth,
--lastmonth, --thisyear, --lastyear, or --date YYYY-MM-DD.

Examples:
  firewall-drop-daily.py --today --group all --email soporte@orangebox.cl
  firewall-drop-daily.py --yesterday --group CTS --email soporte@cts.cl
  firewall-drop-daily.py --lastmonth --group Nexit --email soporte@nexit.cl
"""

import argparse
import gzip
import html
import ipaddress
import json
import os
import re
import smtplib
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

ALERTS_ROOT = "/var/ossec/logs/alerts"
ALERTS_FILE = f"{ALERTS_ROOT}/alerts.json"
ARCHIVE_DIR = "/var/ossec/reports/archive"
DEFAULT_FROM = "wazuh@orangebox.cl"
SMTP_HOST = "localhost"
SMTP_PORT = 25
AGENT_GROUPS_BIN = "/var/ossec/bin/agent_groups"
FIREWALL_RULE = "651"
FIREWALL_RE = re.compile(r"active-response/bin/firewall-drop:\s*(\{.*\})$")

AUTH_RULES = {"5710","5712","5715","5716","5720","5760","5763","10001","10004","10005","10006","10007","10008","10009"}
WEB_RULES = {"31101","10023","10024","10025","10026"}
FIM_RULES = {"550","553","554","10060","10062","10063","10410","10432"}
MALWARE_RULES = {"10060","10062","10063","10410","10432"}
PRIV_RULES = {"10004","10005"}
AUTH_GROUPS = {"authentication","authentication_success","authentication_failed"}
WEB_GROUPS = {"web","orangebox_web"}
FIM_GROUPS = {"syscheck","syscheck_entry_added","syscheck_entry_modified","syscheck_entry_deleted","orangebox_temporary_executable"}
MALWARE_GROUPS = {"malware","webshell","orangebox_malware","orangebox_webshell"}
ATTACK_GROUPS = {"attack","brute_force","reconnaissance","credential_discovery","sensitive_file","lateral_movement"}


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
        value = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", str(value))
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def extract_firewall_payload(full_log):
    if not isinstance(full_log, str):
        return None
    m = FIREWALL_RE.search(full_log.strip())
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return None


def period_bounds(mode, now):
    today = now.date()
    if mode == "today":
        return datetime.combine(today, datetime.min.time(), now.tzinfo), now, "Hoy"
    if mode == "yesterday":
        d = today - timedelta(days=1)
        return datetime.combine(d, datetime.min.time(), now.tzinfo), datetime.combine(today, datetime.min.time(), now.tzinfo), "Ayer"
    monday = today - timedelta(days=today.weekday())
    if mode == "thisweek":
        return datetime.combine(monday, datetime.min.time(), now.tzinfo), now, "Semana actual"
    if mode == "lastweek":
        a = monday - timedelta(days=7)
        return datetime.combine(a, datetime.min.time(), now.tzinfo), datetime.combine(monday, datetime.min.time(), now.tzinfo), "Semana anterior"
    first = today.replace(day=1)
    if mode == "thismonth":
        return datetime.combine(first, datetime.min.time(), now.tzinfo), now, "Mes actual"
    if mode == "lastmonth":
        prev = first - timedelta(days=1)
        a = prev.replace(day=1)
        return datetime.combine(a, datetime.min.time(), now.tzinfo), datetime.combine(first, datetime.min.time(), now.tzinfo), "Mes anterior"
    year = today.replace(month=1, day=1)
    if mode == "thisyear":
        return datetime.combine(year, datetime.min.time(), now.tzinfo), now, "Año actual"
    if mode == "lastyear":
        a = year.replace(year=year.year - 1)
        return datetime.combine(a, datetime.min.time(), now.tzinfo), datetime.combine(year, datetime.min.time(), now.tzinfo), "Año anterior"
    if mode.startswith("date:"):
        d = datetime.strptime(mode[5:], "%Y-%m-%d").date()
        return datetime.combine(d, datetime.min.time(), now.tzinfo), datetime.combine(d + timedelta(days=1), datetime.min.time(), now.tzinfo), d.strftime("%Y-%m-%d")
    raise SystemExit("Período no válido")


def iter_log_files(start, end):
    paths = []
    d = start.date()
    last = (end - timedelta(microseconds=1)).date()
    while d <= last:
        base = Path(ALERTS_ROOT) / f"{d.year:04d}" / d.strftime("%b")
        paths += [base / f"ossec-alerts-{d.day:02d}.json.gz", base / f"ossec-alerts-{d.day:02d}.json"]
        d += timedelta(days=1)
    if start.date() <= datetime.now().date() <= last:
        paths.append(Path(ALERTS_FILE))
    seen = set()
    for path in paths:
        if path.exists() and str(path) not in seen:
            seen.add(str(path))
            yield path


def iter_json(path):
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    yield obj
            except json.JSONDecodeError:
                continue


def group_members(group):
    if group.lower() == "all":
        return None
    if not os.path.exists(AGENT_GROUPS_BIN):
        raise SystemExit(f"No existe {AGENT_GROUPS_BIN}")
    try:
        p = subprocess.run([AGENT_GROUPS_BIN, "-l", "-g", group], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"No se pudo consultar el grupo {group}: {exc}") from exc
    output = p.stdout + "\n" + p.stderr
    if p.returncode != 0:
        raise SystemExit(f"Grupo Wazuh inválido o no disponible: {group}\n{output.strip()}")
    ids = set(re.findall(r"\bID:\s*([0-9]+)\b", output))
    if ids:
        return ids
    if re.search(r"0\s+agent\(s\)", output, re.I):
        return set()
    raise SystemExit(f"No se pudieron obtener agentes del grupo {group}")


def classify(rule_id, groups, level):
    rid = str(rule_id)
    g = {str(x).lower() for x in (groups or [])}
    if rid == FIREWALL_RULE:
        return "active_response"
    if rid in MALWARE_RULES or g & MALWARE_GROUPS:
        return "malware"
    if rid in PRIV_RULES or g & {"privilege_escalation", "privilege_escalation_root", "sudo"}:
        return "privilege"
    if rid in AUTH_RULES or g & AUTH_GROUPS:
        return "authentication"
    if rid in WEB_RULES or g & WEB_GROUPS:
        return "web"
    if rid in FIM_RULES or g & FIM_GROUPS:
        return "fim"
    if g & ATTACK_GROUPS or int(level or 0) >= 12:
        return "attack"
    return "other"


def parse_event(outer):
    rule = outer.get("rule") or {}
    rid = str(rule.get("id", ""))
    timestamp = parse_timestamp(outer.get("timestamp"))
    if not timestamp:
        return None
    if rid == FIREWALL_RULE:
        inner = extract_firewall_payload(outer.get("full_log", ""))
        if not inner or inner.get("command") not in {"add", "delete"}:
            return None
        params = inner.get("parameters") or {}
        if params.get("program") != "active-response/bin/firewall-drop":
            return None
        alert = params.get("alert") or {}
        r = alert.get("rule") or {}
        agent = alert.get("agent") or {}
        data = alert.get("data") or {}
        src = data.get("srcip") or alert.get("srcip")
        return {"timestamp": parse_timestamp(alert.get("timestamp")) or timestamp,
                "outer_rule": rid, "rule_id": str(r.get("id", "unknown")),
                "description": r.get("description", "Firewall Drop"),
                "level": int(r.get("level", 0) or 0), "groups": r.get("groups") or [],
                "agent_id": str(agent.get("id", "000")), "agent_name": agent.get("name", "unknown"),
                "srcip": str(src) if valid_ip(src) else None, "command": inner.get("command"),
                "alert_id": str(alert.get("id", outer.get("id", ""))),
                "mitre": (r.get("mitre") or {}).get("id", []), "url": data.get("url")}
    agent = outer.get("agent") or {}
    data = outer.get("data") or {}
    return {"timestamp": timestamp, "outer_rule": rid, "rule_id": rid,
            "description": rule.get("description", "Sin descripción"),
            "level": int(rule.get("level", 0) or 0), "groups": rule.get("groups") or [],
            "agent_id": str(agent.get("id", "000")), "agent_name": agent.get("name", "unknown"),
            "srcip": str(data.get("srcip")) if valid_ip(data.get("srcip")) else None,
            "command": None, "alert_id": str(outer.get("id", "")),
            "mitre": (rule.get("mitre") or {}).get("id", []), "url": data.get("url")}


def load_events(start, end, allowed):
    files = list(iter_log_files(start, end))
    if not files:
        raise SystemExit("No se encontraron logs JSON para el período solicitado")
    events, seen = [], set()
    for path in files:
        for outer in iter_json(path):
            e = parse_event(outer)
            if not e or e["timestamp"] < start or e["timestamp"] >= end:
                continue
            if allowed is not None and e["agent_id"] not in allowed:
                continue
            key = e["alert_id"]
            if key and key in seen:
                continue
            if key:
                seen.add(key)
            e["category"] = classify(e["rule_id"], e["groups"], e["level"])
            events.append(e)
    return events


def duration(rule):
    return {"5720": "3 minutos", "10006": "24 horas", "10026": "24 horas"}.get(str(rule), "Configurada en Active Response")


def firewall_data(events):
    adds = [e for e in events if e["outer_rule"] == FIREWALL_RULE and e["command"] == "add"]
    deletes = [e for e in events if e["outer_rule"] == FIREWALL_RULE and e["command"] == "delete"]
    groups = defaultdict(set)
    for e in adds:
        if e["srcip"]:
            groups[(e["agent_id"], e["agent_name"], e["rule_id"], e["description"], duration(e["rule_id"]))].add(e["srcip"])
    rows = [(k[0], k[1], k[2], k[3], k[4], sorted(v, key=lambda x: (ipaddress.ip_address(x).version, ipaddress.ip_address(x)))) for k,v in groups.items()]
    return adds, deletes, sorted(rows, key=lambda x: x[1].lower())


def section_rows(events):
    c = Counter((e["rule_id"], e["description"]) for e in events)
    rows = []
    for (rid, desc), count in c.most_common(12):
        names = sorted({e["agent_name"] for e in events if e["rule_id"] == rid and e["description"] == desc})
        rows.append((rid, desc, count, names))
    return rows


def generate_html(events, title, subtitle, period, group):
    security = [e for e in events if e["category"] != "other"]
    critical = [e for e in security if e["level"] >= 13]
    cats = {c: [e for e in security if e["category"] == c] for c in ("authentication","web","fim","malware","privilege","attack")}
    fw_add, fw_del, fw_rows = firewall_data(events)
    fw_ips = {e["srcip"] for e in fw_add if e["srcip"]}
    all_ips = {e["srcip"] for e in security if e["srcip"]}
    agents = Counter((e["agent_id"], e["agent_name"]) for e in security)
    mitre = Counter(mid for e in security for mid in (e.get("mitre") or []))
    css = """
body{margin:0;padding:0;background:#eef2f5;font-family:Arial,Helvetica,sans-serif;color:#263238}.container{max-width:980px;margin:20px auto;background:#fff;border:1px solid #d5dde2;border-radius:10px;overflow:hidden}.top{background:#182a33;color:#fff;border-bottom:5px solid #f58220;padding:18px 26px;display:flex;justify-content:space-between}.logo{display:flex;gap:12px;align-items:center}.cube{width:42px;height:42px;background:#f58220;display:flex;align-items:center;justify-content:center;color:#fff;font-weight:900}.wordmark{font-size:21px;font-weight:800}.wordmark span{color:#f58220}.submark{font-size:9px;color:#b8c5cb;letter-spacing:2px}.wazuh{font-size:19px;font-weight:bold;text-align:right}.wazuh small{display:block;color:#b8c5cb;font-size:10px}.hero{padding:25px 28px 18px}.eyebrow{color:#f58220;font-size:12px;font-weight:bold;letter-spacing:1.5px;text-transform:uppercase}.hero h1{margin:5px 0;font-size:27px}.hero p{margin:0;color:#607d8b;font-size:14px}.period{margin-top:14px;background:#f4f7f8;border:1px solid #dbe4e8;border-radius:7px;padding:10px 12px;font-size:12px;color:#526873}.content{padding:0 28px 28px}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px}.metric{background:#18313b;color:#fff;border-radius:8px;padding:13px;text-align:center;border-bottom:3px solid #f58220}.metric b{display:block;color:#f58220;font-size:25px}.metric span{font-size:10px;color:#d3e0e5;text-transform:uppercase}.section{margin-bottom:18px;border:1px solid #d6e0e5;border-radius:9px;overflow:hidden}.section-title{padding:12px 15px;background:#f4f7f8;font-size:16px;font-weight:bold;border-left:4px solid #f58220}.section-sub{padding:0 15px 10px;color:#78909c;font-size:11px}.table{width:100%;border-collapse:collapse}.table th{background:#29414c;color:#fff;text-align:left;padding:9px 11px;font-size:11px}.table td{border-top:1px solid #e3e9ec;padding:9px 11px;font-size:12px;vertical-align:top}.count{text-align:center;font-weight:bold}.rule{font-family:monospace;font-weight:bold;background:#fff0e5;color:#d65d00;border:1px solid #ffd2b0;border-radius:5px;padding:3px 6px}.tag{display:inline-block;background:#edf6fb;border:1px solid #c9e3f0;color:#486775;border-radius:12px;padding:3px 7px;font-size:10px}details{margin-top:6px}summary{cursor:pointer;color:#425d68;font-size:11px;font-weight:bold}.ipbox{margin-top:7px;background:#f7f9fa;border:1px solid #dce5e9;border-radius:6px;padding:8px;font-family:monospace;font-size:11px;line-height:1.6;word-break:break-all}.ip{display:inline-block;background:#fff;border:1px solid #d9e2e6;border-radius:4px;padding:2px 5px;margin:2px}.note{margin:12px 0;background:#edf6fb;border:1px solid #c9e3f0;border-left:4px solid #f58220;border-radius:7px;padding:11px 13px;color:#49616b;font-size:11px;line-height:1.5}.ok{color:#147a4a}.footer{background:#182a33;border-top:4px solid #f58220;color:#c7d2d7;padding:15px 26px;display:flex;justify-content:space-between;font-size:10px}.footer b{color:#fff}@media(max-width:700px){.container{margin:0;border-radius:0}.top,.footer{display:block}.wazuh{text-align:left;margin-top:12px}.content,.hero{padding-left:14px;padding-right:14px}.grid{grid-template-columns:repeat(2,1fr)}}"""
    p=["<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>",f"<style>{css}</style></head><body><div class='container'>"]
    p.append("<div class='top'><div class='logo'><div class='cube'>OB</div><div><div class='wordmark'>ORANGE<span>BOX</span></div><div class='submark'>IT SERVICES</div></div></div><div class='wazuh'>Wazuh<small>SECURITY MONITORING</small></div></div>")
    p.append(f"<div class='hero'><div class='eyebrow'>OrangeBox Security · Wazuh</div><h1>{esc(title)}</h1><p>{esc(subtitle)}</p><div class='period'><b>Grupo:</b> {esc(group)} &nbsp; · &nbsp; <b>Período:</b> {esc(period)}</div></div><div class='content'>")
    p.append(f"<div class='grid'><div class='metric'><b>{len(security)}</b><span>Eventos seguridad</span></div><div class='metric'><b>{len(critical)}</b><span>Alertas críticas</span></div><div class='metric'><b>{len(all_ips)}</b><span>IPs únicas</span></div><div class='metric'><b>{len(agents)}</b><span>Agentes afectados</span></div></div>")
    p.append("<div class='section'><div class='section-title'>🛡 Active Response · Firewall Drop</div><div class='section-sub'>Acciones automatizadas de defensa.</div>")
    if fw_rows:
        p.append("<table class='table'><thead><tr><th>Agente</th><th>Motivo</th><th>Regla</th><th>Duración</th><th>IPs</th></tr></thead><tbody>")
        for aid,name,rid,desc,dur,ips in fw_rows:
            iphtml=''.join(f"<span class='ip'>{esc(x)}</span>" for x in ips)
            p.append(f"<tr><td><b>{esc(name)}</b><br><small>ID {esc(aid)}</small></td><td>{esc(desc)}<details><summary>Ver IPs ({len(ips)})</summary><div class='ipbox'>{iphtml}</div></details></td><td><span class='rule'>{esc(rid)}</span></td><td>{esc(dur)}</td><td class='count'>{len(ips)}</td></tr>")
        p.append("</tbody></table>")
    else:p.append("<div class='note ok'>No se registraron bloqueos firewall-drop con IP válida.</div>")
    p.append(f"<div class='note'><b>{len(fw_add)}</b> acciones add · <b>{len(fw_ips)}</b> IPs únicas · <b>{len(fw_del)}</b> acciones delete.</div></div>")

    labels=[("🔐 Authentication & Access","authentication"),("🌐 Web Security & Reconnaissance","web"),("📁 File Integrity & Critical Changes","fim"),("🦠 Malware / WebShell / Suspicious Files","malware"),("🔑 Privilege Escalation / Sudo / SU","privilege"),("🎯 Attack Activity","attack")]
    for label,cat in labels:
        subset=cats[cat]
        p.append(f"<div class='section'><div class='section-title'>{label}</div>")
        if not subset:
            p.append("<div class='note ok'>No se registraron eventos de esta categoría durante el período.</div></div>");continue
        p.append(f"<div class='section-sub'><b>{len(subset)}</b> eventos · <b>{len({e['srcip'] for e in subset if e['srcip']})}</b> IPs únicas · <b>{len({e['agent_id'] for e in subset})}</b> agentes</div><table class='table'><thead><tr><th>Regla</th><th>Descripción</th><th>Eventos</th><th>Agentes</th></tr></thead><tbody>")
        for rid,desc,count,names in section_rows(subset):
            shown=', '.join(names[:5])+(' …' if len(names)>5 else '')
            p.append(f"<tr><td><span class='rule'>{esc(rid)}</span></td><td>{esc(desc)}</td><td class='count'>{count}</td><td>{esc(shown)}</td></tr>")
        p.append("</tbody></table></div>")

    p.append("<div class='section'><div class='section-title'>🚨 Top Security Events</div>")
    top=section_rows(security)
    if top:
        p.append("<table class='table'><thead><tr><th>Regla</th><th>Descripción</th><th>Eventos</th></tr></thead><tbody>")
        for rid,desc,count,_ in top:p.append(f"<tr><td><span class='rule'>{esc(rid)}</span></td><td>{esc(desc)}</td><td class='count'>{count}</td></tr>")
        p.append("</tbody></table>")
    else:p.append("<div class='note ok'>No se registraron eventos de seguridad relevantes.</div>")
    p.append("</div>")

    p.append("<div class='section'><div class='section-title'>🧭 MITRE ATT&CK Activity</div>")
    mitre=Counter(mid for e in security for mid in (e.get('mitre') or []))
    if mitre:
        p.append("<table class='table'><thead><tr><th>Técnica</th><th>Eventos</th></tr></thead><tbody>")
        for mid,count in mitre.most_common(20):p.append(f"<tr><td><span class='tag'>{esc(mid)}</span></td><td class='count'>{count}</td></tr>")
        p.append("</tbody></table>")
    else:p.append("<div class='note'>Las alertas del período no contienen técnicas MITRE ATT&CK.</div>")
    p.append("</div>")

    p.append("<div class='section'><div class='section-title'>🖥️ Agents Most Affected</div><table class='table'><thead><tr><th>Agente</th><th>Eventos de seguridad</th></tr></thead><tbody>")
    for (aid,name),count in agents.most_common(15):p.append(f"<tr><td><b>{esc(name)}</b><br><small>ID {esc(aid)}</small></td><td class='count'>{count}</td></tr>")
    if not agents:p.append("<tr><td colspan='2' class='ok'>Sin actividad relevante.</td></tr>")
    p.append("</tbody></table></div>")
    p.append("<div class='note'>Este informe consolida detecciones OrangeBox/Wazuh y acciones automatizadas de Active Response. Los datos históricos se leen directamente de los logs JSON rotados; las IPs se muestran dentro de detalles desplegables.</div></div>")
    p.append("<div class='footer'><div><b>ORANGEBOX IT SERVICES</b><br>Infraestructura segura, negocios sin interrupciones</div><div style='text-align:right'><b>OrangeBox Security · Wazuh</b><br>Security Activity Report</div></div></div></body></html>")
    return ''.join(p)


def send_email(subject, body, recipient):
    msg=MIMEMultipart('alternative')
    msg['Subject']=subject
    msg['From']=f'Wazuh SOC <{DEFAULT_FROM}>'
    msg['To']=recipient
    msg.attach(MIMEText('OrangeBox Wazuh Security Activity Report.','plain','utf-8'))
    msg.attach(MIMEText(body,'html','utf-8'))
    with smtplib.SMTP(SMTP_HOST,SMTP_PORT,timeout=30) as smtp:
        smtp.sendmail(DEFAULT_FROM,[recipient],msg.as_string())


def archive_html(body,label):
    os.makedirs(ARCHIVE_DIR,mode=0o750,exist_ok=True)
    safe=re.sub(r'[^A-Za-z0-9_.-]+','_',label)
    path=f'{ARCHIVE_DIR}/security-report-{safe}.html'
    with open(path,'w',encoding='utf-8') as fh:fh.write(body)
    return path


def main():
    parser=argparse.ArgumentParser(description='OrangeBox Wazuh Security Activity Report')
    modes=parser.add_mutually_exclusive_group(required=True)
    for name in ('today','yesterday','thisweek','lastweek','thismonth','lastmonth','thisyear','lastyear'):modes.add_argument('--'+name,action='store_true')
    modes.add_argument('--date',help='Día específico YYYY-MM-DD')
    parser.add_argument('--group',required=True,help='Grupo Wazuh o all')
    parser.add_argument('--email',required=True,help='Destinatario')
    args=parser.parse_args()
    mode=args.date and f'date:{args.date}' or next(x for x in ('today','yesterday','thisweek','lastweek','thismonth','lastyear','thisyear','lastmonth') if getattr(args,x))
    now=datetime.now().astimezone()
    start,end,label=period_bounds(mode,now)
    allowed=group_members(args.group)
    events=load_events(start,end,allowed)
    period=f"{start.strftime('%d/%m/%Y %H:%M')} — {end.strftime('%d/%m/%Y %H:%M') if end < now else 'ahora'}"
    body=generate_html(events,'Security Activity Report','Actividad de seguridad, detecciones y acciones automatizadas de Wazuh',period,args.group)
    archive=archive_html(body,f'{args.group}-{mode.replace(":","-")}-{start:%Y%m%d}-{end:%Y%m%d}')
    send_email(f'[OrangeBox SOC] {label} — {args.group}',body,args.email)
    security=sum(1 for e in events if e['category']!='other')
    print(f'Reporte enviado a {args.email}')
    print(f'Grupo: {args.group}')
    print(f'Periodo: {period}')
    print(f'Eventos de seguridad: {security}')
    print(f'Archivo: {archive}')

if __name__=='__main__':main()
