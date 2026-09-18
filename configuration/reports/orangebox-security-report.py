#!/usr/bin/env python3
"""OrangeBox Wazuh Security Activity Report.

Genera reportes HTML portables a partir de las alertas JSON de Wazuh.
El HTML usa tablas e estilos inline para funcionar en Thunderbird, webmail y móvil.
"""
import argparse
import gzip
import html
try:
    import orjson
except ImportError:
    orjson = None
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
LOGO_URL = "https://www.orangebox.cl/obox/img/logo-dark.png"

AUTH_RULES = {"5710", "5712", "5715", "5716", "5720", "5760", "5763", "10001", "10004", "10005", "10006", "10007", "10008", "10009"}
WEB_RULES = {"31101", "10023", "10024", "10025", "10026"}
FIM_RULES = {"550", "553", "554", "10060", "10062", "10063", "10410", "10432"}
MALWARE_RULES = {"10060", "10062", "10063", "10410", "10432"}
PRIV_RULES = {"10004", "10005"}
AUTH_GROUPS = {"authentication", "authentication_success", "authentication_failed"}
WEB_GROUPS = {"web", "orangebox_web"}
FIM_GROUPS = {"syscheck", "syscheck_entry_added", "syscheck_entry_modified", "syscheck_entry_deleted", "orangebox_temporary_executable"}
MALWARE_GROUPS = {"malware", "webshell", "orangebox_malware", "orangebox_webshell"}
ATTACK_GROUPS = {"attack", "brute_force", "reconnaissance", "credential_discovery", "sensitive_file", "lateral_movement"}

MITRE_DESCRIPTIONS = {
    "T1110": "Fuerza bruta: intentos repetidos para obtener acceso mediante credenciales.",
    "T1110.001": "Intentos repetidos de acceso probando contraseñas.",
    "T1021": "Acceso remoto a otro sistema mediante un servicio de red.",
    "T1021.004": "Acceso remoto a sistemas mediante SSH.",
    "T1078": "Uso de una cuenta o credencial válida para intentar acceder.",
    "T1565.001": "Modificación de información almacenada para alterar su contenido o comportamiento.",
    "T1070.004": "Eliminación de archivos para borrar rastros de actividad.",
    "T1485": "Destrucción de datos para provocar pérdida o interrupción de información.",
    "T1548.003": "Uso de sudo para ejecutar acciones con privilegios elevados.",
    "T1055": "Intento de ejecutar código dentro de otro proceso para evadir controles.",
    "T1190": "Intento de aprovechar una aplicación o servicio expuesto a Internet.",
    "T1498": "Intento de saturar un servicio mediante un volumen elevado de tráfico.",
    "T1595.002": "Reconocimiento activo para identificar servicios o sistemas accesibles.",
    "T1083": "Búsqueda de archivos y directorios para conocer qué existe en el sistema.",
    "T1552": "Búsqueda de información sensible almacenada de forma insegura.",
    "T1098": "Modificación de cuentas para mantener o ampliar el acceso.",
    "T1059": "Uso de una consola o intérprete para ejecutar comandos.",
    "T1059.004": "Ejecución de comandos mediante una consola Unix o Linux.",
    "T1105": "Descarga o transferencia de archivos desde una ubicación remota.",
    "T1505.003": "Intento de instalar o utilizar un componente web malicioso, como un webshell.",
}

LABELS_ES = {
    "report": "Informe de Actividad de Seguridad", "subtitle": "Actividad de seguridad, detecciones y acciones automatizadas de Wazuh", "security_events": "Eventos de seguridad", "high_alerts": "Alertas de alta severidad", "source_ips": "IPs de origen observadas", "systems": "Sistemas afectados", "firewall": "Respuesta automática · Firewall Drop", "firewall_sub": "Intentos detectados y direcciones IP bloqueadas automáticamente.", "agent": "Sistema", "reason": "Motivo", "rule": "Regla", "blocked_ips": "IPs bloqueadas", "attempts": "Intentos detectados", "access": "Intentos de acceso", "web": "Intentos de acceso y exploración web", "fim": "Cambios detectados en archivos", "malware": "Detecciones de malware y archivos sospechosos", "priv": "Escalamiento de privilegios", "attack": "Detecciones clasificadas como intentos de ataque", "mitre": "Técnicas MITRE observadas en las alertas", "technique": "Técnica", "meaning": "Qué significa", "detections": "Alertas asociadas", "agents": "Servidores afectados", "no_firewall": "No se registraron bloqueos automáticos con una IP de origen válida.", "no_activity": "No se registraron detecciones de esta categoría durante el período.", "attack_note": "Esta sección incluye únicamente alertas que el informe clasificó explícitamente como actividad de ataque. Que una técnica MITRE aparezca más abajo no significa por sí sola que exista un ataque confirmado.", "mitre_note": "El contador indica cuántas alertas de Wazuh fueron asociadas a cada técnica MITRE durante el período. No representa necesariamente accesos exitosos, conexiones individuales ni compromisos confirmados.", "firewall_note": "Los intentos detectados son detecciones Wazuh asociadas a las IP que fueron bloqueadas; no equivalen necesariamente a la cantidad bruta de conexiones o solicitudes originales.", "technical_note": "Los identificadores y descripciones de las reglas corresponden al motor de detección Wazuh. La detección de un intento no implica por sí sola que el sistema haya sido comprometido.",
}
LABELS_EN = {
    "report": "Security Activity Report", "subtitle": "Security activity, detections and automated Wazuh responses", "security_events": "Security events", "high_alerts": "High-severity alerts", "source_ips": "Observed source IPs", "systems": "Affected systems", "firewall": "Automated response · Firewall Drop", "firewall_sub": "Detected attempts and IP addresses blocked automatically.", "agent": "System", "reason": "Reason", "rule": "Rule", "blocked_ips": "Blocked IPs", "attempts": "Detected attempts", "access": "Access attempts", "web": "Web access and reconnaissance attempts", "fim": "Detected file changes", "malware": "Malware and suspicious file detections", "priv": "Privilege escalation", "attack": "Detections classified as attack attempts", "mitre": "MITRE techniques observed in alerts", "technique": "Technique", "meaning": "What it means", "detections": "Associated alerts", "agents": "Most affected systems", "no_firewall": "No automatic blocks with a valid source IP were recorded.", "no_activity": "No detections were recorded for this category during the period.", "attack_note": "This section includes only alerts explicitly classified by the report as attack activity. The appearance of a MITRE technique below does not by itself mean that a confirmed attack occurred.", "mitre_note": "The counter shows how many Wazuh alerts were associated with each MITRE technique during the period. It does not necessarily represent successful logins, individual connections, or confirmed compromises.", "firewall_note": "Detected attempts are Wazuh detections associated with the IPs that were blocked; they do not necessarily equal the raw number of original connections or requests.", "technical_note": "Rule identifiers and descriptions come from the Wazuh detection engine. Detecting an attempt does not by itself mean that the system was compromised.",
}

def labels(lang): return LABELS_EN if lang == "en" else LABELS_ES
def esc(value): return html.escape(str(value), quote=True)
def valid_ip(value):
    try: ipaddress.ip_address(value); return True
    except (ValueError, TypeError): return False

def parse_timestamp(value):
    if not value: return None
    try:
        value = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", str(value)); return datetime.fromisoformat(value)
    except (TypeError, ValueError): return None

def extract_firewall_payload(full_log):
    if not isinstance(full_log, str): return None
    match = FIREWALL_RE.search(full_log.strip())
    if not match: return None
    try: return json.loads(match.group(1))
    except json.JSONDecodeError: return None

def period_bounds(mode, now):
    today = now.date()
    if mode == "today": return datetime.combine(today, datetime.min.time(), now.tzinfo), now, "Hoy"
    if mode == "yesterday":
        day = today - timedelta(days=1); return datetime.combine(day, datetime.min.time(), now.tzinfo), datetime.combine(today, datetime.min.time(), now.tzinfo), "Ayer"
    monday = today - timedelta(days=today.weekday())
    if mode == "thisweek": return datetime.combine(monday, datetime.min.time(), now.tzinfo), now, "Semana actual"
    if mode == "lastweek":
        start = monday - timedelta(days=7); return datetime.combine(start, datetime.min.time(), now.tzinfo), datetime.combine(monday, datetime.min.time(), now.tzinfo), "Semana anterior"
    first = today.replace(day=1)
    if mode == "thismonth": return datetime.combine(first, datetime.min.time(), now.tzinfo), now, "Mes actual"
    if mode == "lastmonth":
        previous = first - timedelta(days=1); start = previous.replace(day=1); return datetime.combine(start, datetime.min.time(), now.tzinfo), datetime.combine(first, datetime.min.time(), now.tzinfo), "Mes anterior"
    year = today.replace(month=1, day=1)
    if mode == "thisyear": return datetime.combine(year, datetime.min.time(), now.tzinfo), now, "Año actual"
    if mode == "lastyear":
        start = year.replace(year=year.year - 1); return datetime.combine(start, datetime.min.time(), now.tzinfo), datetime.combine(year, datetime.min.time(), now.tzinfo), "Año anterior"
    if mode.startswith("date:"):
        day = datetime.strptime(mode[5:], "%Y-%m-%d").date(); return datetime.combine(day, datetime.min.time(), now.tzinfo), datetime.combine(day + timedelta(days=1), datetime.min.time(), now.tzinfo), day.strftime("%Y-%m-%d")
    raise SystemExit("Período no válido")

def iter_log_files(start, end):
    paths=[]; day=start.date(); last=(end-timedelta(microseconds=1)).date()
    while day <= last:
        base=Path(ALERTS_ROOT)/f"{day.year:04d}"/day.strftime("%b"); paths += [base/f"ossec-alerts-{day.day:02d}.json.gz", base/f"ossec-alerts-{day.day:02d}.json"]; day += timedelta(days=1)
    if start.date() <= datetime.now().date() <= last: paths.append(Path(ALERTS_FILE))
    seen=set()
    for path in paths:
        if path.exists() and str(path) not in seen: seen.add(str(path)); yield path

def iter_json(path):
    opener=gzip.open if str(path).endswith(".gz") else open
    with opener(path,"rb") as handle:
        for line in handle:
            try:
                obj=orjson.loads(line) if orjson is not None else json.loads(line)
                if isinstance(obj,dict): yield obj
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError): continue

def group_members(group):
    if group.lower()=="all": return None
    if not os.path.exists(AGENT_GROUPS_BIN): raise SystemExit(f"No existe {AGENT_GROUPS_BIN}")
    try: process=subprocess.run([AGENT_GROUPS_BIN,"-l","-g",group],capture_output=True,text=True,timeout=15)
    except (OSError,subprocess.SubprocessError) as exc: raise SystemExit(f"No se pudo consultar el grupo {group}: {exc}") from exc
    output=process.stdout+"\n"+process.stderr
    if process.returncode!=0: raise SystemExit(f"Grupo Wazuh inválido o no disponible: {group}\n{output.strip()}")
    ids=set(re.findall(r"\bID:\s*([0-9]+)\b",output))
    if ids: return ids
    if re.search(r"0\s+agent\(s\)",output,re.I): return set()
    raise SystemExit(f"No se pudieron obtener agentes del grupo {group}")

def classify(rule_id, groups, level):
    rid=str(rule_id); group_set={str(value).lower() for value in (groups or [])}
    if rid==FIREWALL_RULE: return "active_response"
    if rid in MALWARE_RULES or group_set & MALWARE_GROUPS: return "malware"
    if rid in PRIV_RULES or group_set & {"privilege_escalation","privilege_escalation_root","sudo"}: return "privilege"
    if rid in AUTH_RULES or group_set & AUTH_GROUPS: return "authentication"
    if rid in WEB_RULES or group_set & WEB_GROUPS: return "web"
    if rid in FIM_RULES or group_set & FIM_GROUPS: return "fim"
    if group_set & ATTACK_GROUPS or int(level or 0)>=12: return "attack"
    return "other"

def parse_event(outer):
    rule=outer.get("rule") or {}; rule_id=str(rule.get("id","")); timestamp=parse_timestamp(outer.get("timestamp"))
    if not timestamp: return None
    if rule_id==FIREWALL_RULE:
        # Wazuh 4.x decodes active-responses.log into data.command +
        # data.parameters. The previous parser expected the raw JSON payload
        # in full_log, which made valid firewall-drop executions invisible.
        data=outer.get("data") or {}
        command=data.get("command")
        params=data.get("parameters") or {}

        # En Wazuh 4.x, el evento 651 mezcla dos representaciones:
        # command/parameters vienen estructurados en data, mientras que
        # "program" y el payload completo de firewall-drop pueden permanecer
        # únicamente dentro de full_log. Por eso no debemos exigir program
        # dentro de data.parameters.
        payload=extract_firewall_payload(outer.get("full_log",""))
        if isinstance(payload,dict):
            if command not in {"add","delete"}:
                command=payload.get("command")
            raw_params=payload.get("parameters") or {}
            if raw_params:
                merged_params=dict(raw_params)
                merged_params.update(params)
                params=merged_params
            elif payload.get("program") and "program" not in params:
                params=dict(params)
                params["program"]=payload.get("program")

        if command not in {"add","delete"}:
            return None

        program=params.get("program")
        if program not in {
            "active-response/bin/firewall-drop",
            "/var/ossec/active-response/bin/firewall-drop",
        }:
            # El programa puede estar sólo dentro del JSON anidado de
            # full_log; usarlo como última comprobación.
            program=isinstance(payload,dict) and payload.get("program")
            if program not in {
                "active-response/bin/firewall-drop",
                "/var/ossec/active-response/bin/firewall-drop",
            }:
                return None

        alert=params.get("alert") or {}
        if not alert and isinstance(payload,dict):
            alert=(payload.get("parameters") or {}).get("alert") or {}
        alert_rule=alert.get("rule") or {}
        agent=alert.get("agent") or {}
        alert_data=alert.get("data") or {}
        src=alert_data.get("srcip") or data.get("srcip") or alert.get("srcip")
        mitre=alert_rule.get("mitre") or {}
        return {
            "timestamp":parse_timestamp(alert.get("timestamp")) or timestamp,
            "outer_rule":rule_id,
            "rule_id":str(alert_rule.get("id","unknown")),
            "description":alert_rule.get("description","Firewall Drop"),
            "level":int(alert_rule.get("level",0) or 0),
            "groups":alert_rule.get("groups") or [],
            "agent_id":str(agent.get("id","000")),
            "agent_name":agent.get("name","unknown"),
            "srcip":str(src) if valid_ip(src) else None,
            "command":command,
            "alert_id":str(alert.get("id",outer.get("id",""))),
            "mitre":mitre.get("id",[]),
            "techniques":mitre.get("technique",[]),
            "url":alert_data.get("url"),
        }
    agent=outer.get("agent") or {}; data=outer.get("data") or {}; mitre=rule.get("mitre") or {}
    return {
        "timestamp":timestamp,
        "outer_rule":rule_id,
        "rule_id":rule_id,
        "description":rule.get("description","Sin descripción"),
        "level":int(rule.get("level",0) or 0),
        "groups":rule.get("groups") or [],
        "agent_id":str(agent.get("id","000")),
        "agent_name":agent.get("name","unknown"),
        "srcip":str(data.get("srcip")) if valid_ip(data.get("srcip")) else None,
        "command":None,
        "alert_id":str(outer.get("id","")),
        "mitre":mitre.get("id",[]),
        "techniques":mitre.get("technique",[]),
        "url":data.get("url"),
    }

def load_events(start,end,allowed):
    files=list(iter_log_files(start,end))
    if not files: raise SystemExit("No se encontraron logs JSON para el período solicitado")
    security_count=0; critical_count=0; source_ips=set(); agents=Counter()
    agent_stats=defaultdict(lambda: {"events":0, "high":0, "ips":set(), "attacks":0})
    categories={name:{"count":0,"ips":set(),"agents":set(),"rules":Counter(),"rule_agents":defaultdict(set)} for name in ("authentication","web","fim","malware","privilege","attack")}
    mitre_counts=Counter(); mitre_names={}; firewall_ips=set(); firewall_rows=defaultdict(set); firewall_attempts=Counter(); timeline=Counter()
    seen_day=None; seen=set(); today=datetime.now().date()
    for path in files:
        if path == Path(ALERTS_FILE): file_day=today
        else:
            try: file_day=datetime.strptime(f"{path.name[13:15]} {path.parent.name} {path.parent.parent.name}","%d %b %Y").date()
            except (ValueError, IndexError): file_day=None
        if file_day != seen_day: seen_day=file_day; seen=set()
        for outer in iter_json(path):
            rule=outer.get("rule") or {}; outer_rule=str(rule.get("id",""))
            if outer_rule != FIREWALL_RULE:
                outer_ts=parse_timestamp(outer.get("timestamp"))
                if not outer_ts or outer_ts<start or outer_ts>=end: continue
            event=parse_event(outer)
            if not event or event["timestamp"]<start or event["timestamp"]>=end: continue
            if allowed is not None and event["agent_id"] not in allowed: continue
            key=event["alert_id"]
            if key:
                if key in seen: continue
                seen.add(key)
            category=classify(event["rule_id"],event["groups"],event["level"]); event_agent=(event["agent_id"],event["agent_name"])
            if event["outer_rule"]==FIREWALL_RULE:
                if event["command"]=="add" and event["srcip"]:
                    row_key=(event["agent_id"],event["agent_name"],event["rule_id"],event["description"]); firewall_rows[row_key].add(event["srcip"]); firewall_ips.add(event["srcip"])
                continue
            if event["srcip"]: firewall_attempts[(event["agent_id"],event["rule_id"],event["srcip"])] += 1
            if category=="other": continue
            security_count += 1
            timeline[event["timestamp"].date()] += 1
            if event["level"]>=13: critical_count += 1
            if event["srcip"]: source_ips.add(event["srcip"])
            agents[event_agent] += 1
            agent_info=agent_stats[event_agent]
            agent_info["events"] += 1
            if event["level"] >= 13: agent_info["high"] += 1
            if event["srcip"]: agent_info["ips"].add(event["srcip"])
            if category == "attack": agent_info["attacks"] += 1
            info=categories[category]; info["count"] += 1
            if event["srcip"]: info["ips"].add(event["srcip"])
            info["agents"].add(event["agent_id"])
            rule_key=(event["rule_id"],event["description"]); info["rules"][rule_key] += 1; info["rule_agents"][rule_key].add(event["agent_name"])
            techniques=event.get("techniques") or []
            for index,mitre_id in enumerate(event.get("mitre") or []):
                mitre_counts[mitre_id] += 1
                if index<len(techniques) and techniques[index]: mitre_names[mitre_id]=techniques[index]
    firewall_result=[]
    for key,ips in firewall_rows.items():
        agent_id,agent_name,rule_id,description=key; attempts=sum(firewall_attempts[(agent_id,rule_id,ip)] for ip in ips)
        if attempts==0: attempts=len(ips)
        firewall_result.append({"agent_id":agent_id,"agent_name":agent_name,"rule_id":rule_id,"description":description,"ips":sorted(ips,key=lambda v:(ipaddress.ip_address(v).version,ipaddress.ip_address(v))),"attempts":attempts})
    return {"security_count":security_count,"critical_count":critical_count,"source_ips":source_ips,"agents":agents,"agent_stats":agent_stats,"categories":categories,"mitre_counts":mitre_counts,"mitre_names":mitre_names,"firewall_ips":firewall_ips,"firewall_rows":sorted(firewall_result,key=lambda r:r["agent_name"].lower()),"timeline":timeline}

def section_rows(info):
    rows=[]
    for (rule_id,description),count in info["rules"].most_common(12): rows.append((rule_id,description,count,sorted(info["rule_agents"][(rule_id,description)])))
    return rows

def mitre_rows(summary):
    counts=summary["mitre_counts"]; names=summary["mitre_names"]
    return [(mid,names.get(mid,"Técnica MITRE ATT&CK"),MITRE_DESCRIPTIONS.get(mid,"Comportamiento asociado a una técnica de ataque o intrusión; Wazuh la vinculó con esta detección."),count) for mid,count in counts.most_common()]

def generate_html(summary,title,subtitle,period,group,lang="es"):
    L=labels(lang); security_count=summary["security_count"]; critical_count=summary["critical_count"]; all_ips=summary["source_ips"]; agents=summary["agents"]; agent_stats=summary["agent_stats"]; categories=summary["categories"]; firewall_rows=summary["firewall_rows"]; firewall_ips=summary["firewall_ips"]
    bg="#eef2f5"; dark="#182a33"; orange="#f58220"; text="#263238"; muted="#607d8b"; border="#d6e0e5"; page=[f"<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1.0'></head><body style='margin:0;padding:0;background:{bg};font-family:Arial,Helvetica,sans-serif;color:{text};'>"]
    page.append("<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='width:100%;'><tr><td align='center' style='padding:12px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='width:90%;background:#ffffff;border:1px solid #d5dde2;'>")
    page.append(f"<tr><td style='background:{dark};border-bottom:5px solid {orange};padding:16px 20px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr><td valign='middle'><img src='{LOGO_URL}' alt='OrangeBox IT Services' style='display:block;max-width:210px;height:auto;max-height:55px;border:0;'></td><td align='right' valign='middle' style='padding-left:10px;color:#fff;font-size:18px;font-weight:bold;'>Wazuh<div style='font-size:9px;color:#b8c5cb;'>SECURITY MONITORING</div></td></tr></table></td></tr>")
    page.append(f"<tr><td style='padding:24px 22px 14px;'><div style='color:{orange};font-size:11px;font-weight:bold;letter-spacing:1.4px;'>ORANGEBOX SECURITY · WAZUH</div><div style='font-size:26px;font-weight:bold;margin-top:5px;color:{text};'>{esc(title)}</div><div style='font-size:14px;color:{muted};padding-top:5px;'>{esc(subtitle)}</div><div style='margin-top:14px;background:#f4f7f8;border:1px solid #dbe4e8;padding:9px 11px;font-size:13px;color:#526873;'><b>Grupo:</b> {esc(group)} &nbsp; · &nbsp; <b>Período:</b> {esc(period)}</div></td></tr>")
    page.append("<tr><td style='padding:0 14px 18px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='8' border='0'><tr>")
    metrics=[(security_count,L["security_events"]),(critical_count,L["high_alerts"]),(len(all_ips),L["source_ips"]),(len(agents),L["systems"])]
    for value,label in metrics: page.append(f"<td width='25%' valign='top' align='center' style='background:#18313b;border-bottom:3px solid {orange};padding:12px 5px;color:#fff;'><div style='color:{orange};font-size:24px;font-weight:bold;'>{value:,}</div><div style='font-size:10px;color:#d3e0e5;text-transform:uppercase;'>{esc(label)}</div></td>")
    page.append("</tr></table></td></tr>")
    def section_open(icon,heading,sub=None):
        section=f"<tr><td style='padding:0 14px 18px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='border:1px solid {border};'><tr><td style='background:#f4f7f8;border-left:4px solid {orange};padding:11px 13px;font-size:16px;font-weight:bold;color:{text};'>{icon} {esc(heading)}</td></tr>"
        if sub: section+=f"<tr><td style='padding:8px 14px 5px;color:#78909c;font-size:12px;'>{esc(sub)}</td></tr>"
        return section
    def section_close(): return "</table></td></tr>"
    page.append(section_open("🛡",L["firewall"],L["firewall_sub"]))
    if firewall_rows:
        # Agrupa las ejecuciones reales de firewall-drop por motivo de bloqueo.
        # Una IP cuenta una sola vez dentro de cada motivo, aunque haya más de
        # una ejecución/alerta asociada al mismo bloqueo.
        firewall_by_reason=defaultdict(lambda: {"ips":set(), "attempts":0, "rules":set()})
        for row in firewall_rows:
            reason_key=(row["rule_id"],row["description"])
            firewall_by_reason[reason_key]["ips"].update(row["ips"])
            firewall_by_reason[reason_key]["attempts"] += row["attempts"]
            firewall_by_reason[reason_key]["rules"].add(row["rule_id"])
        firewall_reasons=sorted(firewall_by_reason.items(), key=lambda item:(-len(item[1]["ips"]), -item[1]["attempts"], item[0][0]))

        page.append("<tr><td style='padding:0 8px 8px;overflow-wrap:anywhere;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>")
        page.append(f"<tr><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>{esc(L['reason'])}</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>{esc(L['rule'])}</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>{esc(L['blocked_ips'])}</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>{esc(L['attempts'])}</td></tr>")
        for (rule_id,description),data in firewall_reasons:
            page.append(f"<tr><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:12px;overflow-wrap:anywhere;'>{esc(description)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-family:monospace;font-weight:bold;color:#d65d00;font-size:12px;'>{esc(rule_id)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;text-align:center;font-weight:bold;font-size:12px;'>{len(data['ips']):,}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;text-align:center;font-weight:bold;font-size:12px;'>{data['attempts']:,}</td></tr>")
        page.append("</table></td></tr>")
    else: page.append(f"<tr><td style='padding:10px 14px;color:#147a4a;font-size:12px;'>{esc(L['no_firewall'])}</td></tr>")
    page.append(f"<tr><td style='background:#edf6fb;border-left:4px solid {orange};padding:10px 13px;color:#49616b;font-size:12px;'><b>{len(firewall_ips):,}</b> {esc(L['blocked_ips'].lower())} automáticamente · <b>{sum(row['attempts'] for row in firewall_rows):,}</b> {esc(L['attempts'].lower())} asociados a estos bloqueos.</td></tr><tr><td style='padding:0 14px 12px;color:#78909c;font-size:11px;'>{esc(L['firewall_note'])}</td></tr>")
    page.append(section_close())
    section_labels=[("🔐",L["access"],"authentication"),("🌐",L["web"],"web"),("📁",L["fim"],"fim"),("🦠",L["malware"],"malware"),("🔑",L["priv"],"privilege"),("🎯",L["attack"],"attack")]
    for icon,label,category in section_labels:
        info=categories[category]; page.append(section_open(icon,label))
        if not info["count"]: page.append(f"<tr><td style='padding:10px 14px;color:#147a4a;font-size:12px;'>{esc(L['attack_note'] if category=='attack' else L['no_activity'])}</td></tr>")
        else:
            page.append(f"<tr><td style='padding:0 8px 8px;color:#78909c;font-size:11px;'><b>{info['count']:,}</b> detecciones · <b>{len(info['ips']):,}</b> IPs · <b>{len(info['agents']):,}</b> sistemas</td></tr><tr><td style='padding:0 8px 8px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>Regla</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>Descripción</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>Detecciones</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>Sistemas</td></tr>")
            for rule_id,description,count,names in section_rows(info):
                shown=", ".join(names[:5])+(" …" if len(names)>5 else ""); page.append(f"<tr><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-family:monospace;font-weight:bold;color:#d65d00;font-size:11px;'>{esc(rule_id)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:11px;overflow-wrap:anywhere;'>{esc(description)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;text-align:center;font-weight:bold;font-size:11px;'>{count:,}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:11px;overflow-wrap:anywhere;'>{esc(shown)}</td></tr>")
            page.append("</table></td></tr>")
        if category=="attack": page.append(f"<tr><td style='padding:0 14px 10px;color:#78909c;font-size:11px;'>{esc(L['attack_note'])}</td></tr>")
        page.append(section_close())
    page.append(section_open("🧭",L["mitre"],"MITRE ATT&CK")); page.append(f"<tr><td style='padding:8px 14px 5px;color:#78909c;font-size:11px;'>{esc(L['mitre_note'])}</td></tr>"); mitre=mitre_rows(summary)
    if mitre:
        page.append("<tr><td style='padding:0 8px 8px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>"); page.append(f"<tr><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>{esc(L['technique'])}</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>Nombre</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>{esc(L['meaning'])}</td><td style='background:#29414c;color:#fff;padding:8px;font-size:11px;font-weight:bold;'>{esc(L['detections'])}</td></tr>")
        for mitre_id,name,meaning,count in mitre: page.append(f"<tr><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-family:monospace;font-weight:bold;color:#d65d00;font-size:11px;'>{esc(mitre_id)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:11px;'>{esc(name)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:11px;line-height:1.35;'>{esc(meaning)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;text-align:center;font-weight:bold;font-size:11px;'>{count:,}</td></tr>")
        page.append("</table></td></tr>")
    else: page.append("<tr><td style='padding:10px 14px;color:#78909c;font-size:12px;'>No se encontraron técnicas MITRE ATT&CK en las alertas del período.</td></tr>")
    page.append(f"<tr><td style='padding:10px 14px 18px;'><div style='background:#f7f9fa;border:1px solid #dce5e9;border-left:4px solid {orange};padding:10px 12px;font-size:11px;line-height:1.5;color:#526873;'>{esc(L['technical_note'])}</div></td></tr><tr><td style='background:{dark};border-top:4px solid {orange};padding:14px 20px;color:#c7d2d7;font-size:10px;'><b style='color:#fff;'>ORANGEBOX IT SERVICES</b><br>Monitoreo y seguridad de infraestructura</td></tr></table></td></tr></table></body></html>")
    return "".join(page)

def send_email(subject,body,recipient):
    msg=MIMEMultipart("alternative"); msg["Subject"]=subject; msg["From"]=f"Wazuh SOC <{DEFAULT_FROM}>"; msg["To"]=recipient; msg.attach(MIMEText("OrangeBox Wazuh Security Activity Report.","plain","utf-8")); msg.attach(MIMEText(body,"html","utf-8"))
    with smtplib.SMTP(SMTP_HOST,SMTP_PORT,timeout=30) as smtp: smtp.sendmail(DEFAULT_FROM,[recipient],msg.as_string())

def archive_html(body,label):
    os.makedirs(ARCHIVE_DIR,mode=0o750,exist_ok=True); safe=re.sub(r"[^A-Za-z0-9_.-]+","_",label); path=f"{ARCHIVE_DIR}/security-report-{safe}.html"
    with open(path,"w",encoding="utf-8") as handle: handle.write(body)
    return path

def main():
    parser=argparse.ArgumentParser(description="OrangeBox Wazuh Security Activity Report"); modes=parser.add_mutually_exclusive_group(required=True)
    for name in ("today","yesterday","thisweek","lastweek","thismonth","lastmonth","thisyear","lastyear"): modes.add_argument("--"+name,action="store_true")
    modes.add_argument("--date",help="Día específico YYYY-MM-DD"); parser.add_argument("--group",required=True,help="Grupo Wazuh o all")
    parser.add_argument("--email",action="append",required=True,help="Destinatario. Puede repetirse o contener varias direcciones separadas por comas."); parser.add_argument("--lang",choices=("es","en"),default="es",help="Idioma del informe: es o en"); args=parser.parse_args()
    recipients=[]
    for value in args.email: recipients.extend(r.strip() for r in value.split(",") if r.strip())
    if not recipients: raise SystemExit("Debe especificar al menos un destinatario")
    for recipient in recipients:
        if not re.fullmatch(r"[^\s@]+@[^\s@]+",recipient): raise SystemExit(f"Dirección de correo inválida: {recipient}")
    mode=args.date and f"date:{args.date}" or next(name for name in ("today","yesterday","thisweek","lastweek","thismonth","lastmonth","thisyear","lastyear") if getattr(args,name))
    now=datetime.now().astimezone(); start,end,label=period_bounds(mode,now); allowed=group_members(args.group); summary=load_events(start,end,allowed); period=f"{start.strftime('%d/%m/%Y %H:%M')} — {end.strftime('%d/%m/%Y %H:%M') if end < now else 'ahora'}"; L=labels(args.lang); body=generate_html(summary,L["report"],L["subtitle"],period,args.group,args.lang); archive=archive_html(body,f"{args.group}-{mode.replace(':','-')}-{start:%Y%m%d}-{end:%Y%m%d}")
    subject_prefix={
        "today": "Reporte Diario de Seguridad",
        "yesterday": "Reporte Diario de Seguridad",
        "thisweek": "Reporte Semanal de Seguridad",
        "lastweek": "Reporte Semanal de Seguridad",
        "thismonth": "Reporte Mensual de Seguridad",
        "lastmonth": "Reporte Mensual de Seguridad",
        "thisyear": "Reporte Anual de Seguridad",
        "lastyear": "Reporte Anual de Seguridad",
    }
    subject=f"📊 [ORANGEBOX] {subject_prefix.get(mode, 'Reporte de Seguridad')} — {args.group}"; sent=[]; failed=[]
    for recipient in recipients:
        try: send_email(subject,body,recipient); sent.append(recipient)
        except Exception as exc: failed.append((recipient,exc))
    security=summary["security_count"]; print(f"Destinatarios enviados: {', '.join(sent) if sent else 'ninguno'}")
    for recipient,exc in failed: print(f"ERROR enviando a {recipient}: {exc}")
    print(f"Grupo: {args.group}"); print(f"Periodo: {period}"); print(f"Eventos de seguridad: {security}"); print(f"Archivo: {archive}")
    if failed: raise SystemExit(1)

if __name__=="__main__": main()
