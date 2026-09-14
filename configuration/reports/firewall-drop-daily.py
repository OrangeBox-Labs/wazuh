#!/usr/bin/env python3
"""OrangeBox Wazuh Security Activity Report.

Generates a portable HTML email report from Wazuh JSON alert logs.
The report is designed for desktop, webmail and mobile mail clients.
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

# Short, client-friendly explanations for the MITRE techniques currently used
# by the OrangeBox/Wazuh environment. Wazuh supplies the official ID, tactic
# and technique name in each alert; these explanations are deliberately short.
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
    "report": "Informe de Actividad de Seguridad", "subtitle": "Actividad de seguridad, detecciones y acciones automatizadas de Wazuh",
    "security_events": "Eventos de seguridad", "high_alerts": "Alertas de alta severidad", "source_ips": "IPs de origen observadas", "systems": "Sistemas afectados",
    "firewall": "Respuesta automática · Firewall Drop", "firewall_sub": "Intentos detectados y direcciones IP bloqueadas automáticamente.",
    "agent": "Sistema", "reason": "Motivo", "rule": "Regla", "blocked_ips": "IPs bloqueadas", "attempts": "Intentos detectados", "first": "Primera detección", "last": "Última detección",
    "access": "Intentos de acceso", "web": "Intentos de acceso y exploración web", "fim": "Cambios detectados en archivos", "malware": "Detecciones de malware y archivos sospechosos",
    "priv": "Escalamiento de privilegios", "attack": "Intentos de ataque detectados", "mitre": "Técnicas asociadas a intentos de ataque", "technique": "Técnica", "meaning": "Qué significa", "detections": "Detecciones",
    "agents": "Sistemas más afectados", "validation": "Validación del sistema", "validation_text": "Este informe incluye eventos de validación generados durante pruebas controladas de las reglas y controles de seguridad de OrangeBox. Estos registros permiten comprobar que las detecciones y mecanismos de respuesta están funcionando correctamente.",
    "details": "Ver IPs", "no_firewall": "No se registraron bloqueos automáticos con una IP de origen válida.", "no_activity": "No se registraron detecciones de esta categoría durante el período.",
    "technical_note": "Los identificadores y descripciones de las reglas corresponden al motor de detección Wazuh. La detección de un intento no implica por sí sola que el sistema haya sido comprometido.",
}
LABELS_EN = {
    "report": "Security Activity Report", "subtitle": "Security activity, detections and automated Wazuh responses", "security_events": "Security events", "high_alerts": "High-severity alerts", "source_ips": "Observed source IPs", "systems": "Affected systems",
    "firewall": "Automated response · Firewall Drop", "firewall_sub": "Detected attempts and IP addresses blocked automatically.", "agent": "System", "reason": "Reason", "rule": "Rule", "blocked_ips": "Blocked IPs", "attempts": "Detected attempts", "first": "First detection", "last": "Last detection",
    "access": "Access attempts", "web": "Web access and reconnaissance attempts", "fim": "Detected file changes", "malware": "Malware and suspicious file detections", "priv": "Privilege escalation", "attack": "Detected attack attempts", "mitre": "Techniques associated with attack attempts", "technique": "Technique", "meaning": "What it means", "detections": "Detections", "agents": "Most affected systems", "validation": "System validation",
    "validation_text": "This report includes validation events generated during controlled tests of OrangeBox security rules and controls. These records verify that detections and response mechanisms are working correctly.", "details": "View IPs", "no_firewall": "No automatic blocks with a valid source IP were recorded.", "no_activity": "No detections were recorded for this category during the period.", "technical_note": "Rule identifiers and descriptions come from the Wazuh detection engine. Detecting an attempt does not by itself mean that the system was compromised.",
}

def labels(lang):
    return LABELS_EN if lang == "en" else LABELS_ES

def esc(value): return html.escape(str(value), quote=True)

def valid_ip(value):
    try: ipaddress.ip_address(value); return True
    except (ValueError, TypeError): return False

def parse_timestamp(value):
    if not value: return None
    try:
        value = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", str(value))
        return datetime.fromisoformat(value)
    except (TypeError, ValueError): return None

def extract_firewall_payload(full_log):
    if not isinstance(full_log, str): return None
    m = FIREWALL_RE.search(full_log.strip())
    if not m: return None
    try: return json.loads(m.group(1))
    except json.JSONDecodeError: return None

def period_bounds(mode, now):
    today = now.date()
    if mode == "today": return datetime.combine(today, datetime.min.time(), now.tzinfo), now, "Hoy"
    if mode == "yesterday":
        d = today - timedelta(days=1); return datetime.combine(d, datetime.min.time(), now.tzinfo), datetime.combine(today, datetime.min.time(), now.tzinfo), "Ayer"
    monday = today - timedelta(days=today.weekday())
    if mode == "thisweek": return datetime.combine(monday, datetime.min.time(), now.tzinfo), now, "Semana actual"
    if mode == "lastweek":
        a = monday - timedelta(days=7); return datetime.combine(a, datetime.min.time(), now.tzinfo), datetime.combine(monday, datetime.min.time(), now.tzinfo), "Semana anterior"
    first = today.replace(day=1)
    if mode == "thismonth": return datetime.combine(first, datetime.min.time(), now.tzinfo), now, "Mes actual"
    if mode == "lastmonth":
        prev = first - timedelta(days=1); a = prev.replace(day=1); return datetime.combine(a, datetime.min.time(), now.tzinfo), datetime.combine(first, datetime.min.time(), now.tzinfo), "Mes anterior"
    year = today.replace(month=1, day=1)
    if mode == "thisyear": return datetime.combine(year, datetime.min.time(), now.tzinfo), now, "Año actual"
    if mode == "lastyear":
        a = year.replace(year=year.year - 1); return datetime.combine(a, datetime.min.time(), now.tzinfo), datetime.combine(year, datetime.min.time(), now.tzinfo), "Año anterior"
    if mode.startswith("date:"):
        d = datetime.strptime(mode[5:], "%Y-%m-%d").date(); return datetime.combine(d, datetime.min.time(), now.tzinfo), datetime.combine(d + timedelta(days=1), datetime.min.time(), now.tzinfo), d.strftime("%Y-%m-%d")
    raise SystemExit("Período no válido")

def iter_log_files(start, end):
    paths=[]; d=start.date(); last=(end-timedelta(microseconds=1)).date()
    while d <= last:
        base=Path(ALERTS_ROOT)/f"{d.year:04d}"/d.strftime("%b")
        paths += [base/f"ossec-alerts-{d.day:02d}.json.gz", base/f"ossec-alerts-{d.day:02d}.json"]; d += timedelta(days=1)
    if start.date() <= datetime.now().date() <= last: paths.append(Path(ALERTS_FILE))
    seen=set()
    for path in paths:
        if path.exists() and str(path) not in seen: seen.add(str(path)); yield path

def iter_json(path):
    opener=gzip.open if str(path).endswith(".gz") else open
    with opener(path,"rt",encoding="utf-8",errors="replace") as fh:
        for line in fh:
            try:
                obj=json.loads(line)
                if isinstance(obj,dict): yield obj
            except json.JSONDecodeError: continue

def group_members(group):
    if group.lower()=="all": return None
    if not os.path.exists(AGENT_GROUPS_BIN): raise SystemExit(f"No existe {AGENT_GROUPS_BIN}")
    try: p=subprocess.run([AGENT_GROUPS_BIN,"-l","-g",group],capture_output=True,text=True,timeout=15)
    except (OSError,subprocess.SubprocessError) as exc: raise SystemExit(f"No se pudo consultar el grupo {group}: {exc}") from exc
    output=p.stdout+"\n"+p.stderr
    if p.returncode!=0: raise SystemExit(f"Grupo Wazuh inválido o no disponible: {group}\n{output.strip()}")
    ids=set(re.findall(r"\bID:\s*([0-9]+)\b",output))
    if ids: return ids
    if re.search(r"0\s+agent\(s\)",output,re.I): return set()
    raise SystemExit(f"No se pudieron obtener agentes del grupo {group}")

def classify(rule_id, groups, level):
    rid=str(rule_id); g={str(x).lower() for x in (groups or [])}
    if rid==FIREWALL_RULE: return "active_response"
    if rid in MALWARE_RULES or g&MALWARE_GROUPS: return "malware"
    if rid in PRIV_RULES or g&{"privilege_escalation","privilege_escalation_root","sudo"}: return "privilege"
    if rid in AUTH_RULES or g&AUTH_GROUPS: return "authentication"
    if rid in WEB_RULES or g&WEB_GROUPS: return "web"
    if rid in FIM_RULES or g&FIM_GROUPS: return "fim"
    if g&ATTACK_GROUPS or int(level or 0)>=12: return "attack"
    return "other"

def parse_event(outer):
    rule=outer.get("rule") or {}; rid=str(rule.get("id","")); timestamp=parse_timestamp(outer.get("timestamp"))
    if not timestamp: return None
    if rid==FIREWALL_RULE:
        inner=extract_firewall_payload(outer.get("full_log",""))
        if not inner or inner.get("command") not in {"add","delete"}: return None
        params=inner.get("parameters") or {}
        if params.get("program")!="active-response/bin/firewall-drop": return None
        alert=params.get("alert") or {}; r=alert.get("rule") or {}; agent=alert.get("agent") or {}; data=alert.get("data") or {}; src=data.get("srcip") or alert.get("srcip")
        return {"timestamp":parse_timestamp(alert.get("timestamp")) or timestamp,"outer_rule":rid,"rule_id":str(r.get("id","unknown")),"description":r.get("description","Firewall Drop"),"level":int(r.get("level",0) or 0),"groups":r.get("groups") or [],"agent_id":str(agent.get("id","000")),"agent_name":agent.get("name","unknown"),"srcip":str(src) if valid_ip(src) else None,"command":inner.get("command"),"alert_id":str(alert.get("id",outer.get("id",""))),"mitre":(r.get("mitre") or {}).get("id",[]),"techniques":(r.get("mitre") or {}).get("technique",[]),"url":data.get("url")}
    agent=outer.get("agent") or {}; data=outer.get("data") or {}
    return {"timestamp":timestamp,"outer_rule":rid,"rule_id":rid,"description":rule.get("description","Sin descripción"),"level":int(rule.get("level",0) or 0),"groups":rule.get("groups") or [],"agent_id":str(agent.get("id","000")),"agent_name":agent.get("name","unknown"),"srcip":str(data.get("srcip")) if valid_ip(data.get("srcip")) else None,"command":None,"alert_id":str(outer.get("id","")),"mitre":(rule.get("mitre") or {}).get("id",[]),"techniques":(rule.get("mitre") or {}).get("technique",[]),"url":data.get("url")}

def load_events(start,end,allowed):
    files=list(iter_log_files(start,end))
    if not files: raise SystemExit("No se encontraron logs JSON para el período solicitado")
    events=[]; seen=set()
    for path in files:
        for outer in iter_json(path):
            e=parse_event(outer)
            if not e or e["timestamp"]<start or e["timestamp"]>=end: continue
            if allowed is not None and e["agent_id"] not in allowed: continue
            key=e["alert_id"]
            if key and key in seen: continue
            if key: seen.add(key)
            e["category"]=classify(e["rule_id"],e["groups"],e["level"]); events.append(e)
    return events

def firewall_data(events):
    adds=[e for e in events if e["outer_rule"]==FIREWALL_RULE and e["command"]=="add"]
    deletes=[e for e in events if e["outer_rule"]==FIREWALL_RULE and e["command"]=="delete"]
    rows=defaultdict(lambda:{"ips":set(),"times":[],"attempts":0}); security=[e for e in events if e["outer_rule"]!=FIREWALL_RULE]
    for e in adds:
        key=(e["agent_id"],e["agent_name"],e["rule_id"],e["description"])
        if e["srcip"]: rows[key]["ips"].add(e["srcip"])
        rows[key]["times"].append(e["timestamp"])
    for key,row in rows.items():
        aid,_,rid,_=key; ips=row["ips"]; row["attempts"]=sum(1 for e in security if e["agent_id"]==aid and e["rule_id"]==rid and e["srcip"] in ips)
        if row["attempts"]==0: row["attempts"]=len(ips)
    result=[]
    for key,row in rows.items():
        times=row["times"]; result.append({"agent_id":key[0],"agent_name":key[1],"rule_id":key[2],"description":key[3],"ips":sorted(row["ips"],key=lambda x:(ipaddress.ip_address(x).version,ipaddress.ip_address(x))),"attempts":row["attempts"],"first":min(times) if times else None,"last":max(times) if times else None})
    return adds,deletes,sorted(result,key=lambda x:x["agent_name"].lower())

def section_rows(events):
    c=Counter((e["rule_id"],e["description"]) for e in events); rows=[]
    for (rid,desc),count in c.most_common(12):
        names=sorted({e["agent_name"] for e in events if e["rule_id"]==rid and e["description"]==desc}); rows.append((rid,desc,count,names))
    return rows

def fmt_dt(value): return value.astimezone().strftime("%d/%m %H:%M") if value else "—"

def mitre_rows(events):
    counts=Counter(); names={}
    for e in events:
        ids=e.get("mitre") or []; tech=e.get("techniques") or []
        for i,mid in enumerate(ids):
            counts[mid]+=1
            if i<len(tech) and tech[i]: names[mid]=tech[i]
    return [(mid,names.get(mid,"Técnica MITRE ATT&CK"),MITRE_DESCRIPTIONS.get(mid,"Comportamiento asociado a una técnica de ataque o intrusión; Wazuh la vinculó con esta detección."),count) for mid,count in counts.most_common()]

def generate_html(events,title,subtitle,period,group,lang="es"):
    L=labels(lang); security=[e for e in events if e["category"]!="other"]; critical=[e for e in security if e["level"]>=13]
    cats={c:[e for e in security if e["category"]==c] for c in ("authentication","web","fim","malware","privilege","attack")}; fw_add,fw_del,fw_rows=firewall_data(events); fw_ips={e["srcip"] for e in fw_add if e["srcip"]}; all_ips={e["srcip"] for e in security if e["srcip"]}; agents=Counter((e["agent_id"],e["agent_name"]) for e in security)
    bg="#eef2f5"; dark="#182a33"; orange="#f58220"; text="#263238"; muted="#607d8b"; border="#d6e0e5"
    p=["<!DOCTYPE html><html><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1.0'></head><body style='margin:0;padding:0;background:%s;font-family:Arial,Helvetica,sans-serif;color:%s;'>"%(bg,text)]
    p.append("<table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='width:100%;'><tr><td align='center' style='padding:12px;'>")
    p.append("<table role='presentation' width='640' cellpadding='0' cellspacing='0' border='0' style='width:100%;max-width:640px;background:#ffffff;border:1px solid #d5dde2;'>")
    p.append(f"<tr><td style='background:{dark};border-bottom:5px solid {orange};padding:16px 20px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr><td valign='middle'><table role='presentation' cellpadding='0' cellspacing='0' border='0'><tr><td style='width:42px;height:42px;background:{orange};color:#fff;font-size:17px;font-weight:bold;text-align:center;vertical-align:middle;'>OB</td><td style='padding-left:10px;color:#fff;font-size:20px;font-weight:bold;'>ORANGE<span style='color:{orange};'>BOX</span><div style='font-size:8px;letter-spacing:2px;color:#b8c5cb;font-weight:normal;'>IT SERVICES</div></td></tr></table></td><td align='right' valign='middle' style='color:#fff;font-size:18px;font-weight:bold;'>Wazuh<div style='font-size:9px;color:#b8c5cb;'>SECURITY MONITORING</div></td></tr></table></td></tr>")
    p.append(f"<tr><td style='padding:24px 22px 14px;'><div style='color:{orange};font-size:11px;font-weight:bold;letter-spacing:1.4px;'>ORANGEBOX SECURITY · WAZUH</div><div style='font-size:26px;font-weight:bold;margin-top:5px;color:{text};'>{esc(title)}</div><div style='font-size:14px;color:{muted};padding-top:5px;'>{esc(subtitle)}</div><div style='margin-top:14px;background:#f4f7f8;border:1px solid #dbe4e8;padding:9px 11px;font-size:12px;color:#526873;'><b>Grupo:</b> {esc(group)} &nbsp; · &nbsp; <b>Período:</b> {esc(period)}</div></td></tr>")
    p.append("<tr><td style='padding:0 14px 18px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='8' border='0'><tr>")
    metrics=[(len(security),L["security_events"]),(len(critical),L["high_alerts"]),(len(all_ips),L["source_ips"]),(len(agents),L["systems"])]
    for value,label in metrics: p.append(f"<td width='25%' valign='top' align='center' style='background:#18313b;border-bottom:3px solid {orange};padding:12px 5px;color:#fff;'><div style='color:{orange};font-size:24px;font-weight:bold;'>{value:,}</div><div style='font-size:9px;color:#d3e0e5;text-transform:uppercase;'>{esc(label)}</div></td>")
    p.append("</tr></table></td></tr>")
    def section_open(icon,heading,sub=None):
        s=f"<tr><td style='padding:0 14px 18px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='border:1px solid {border};'><tr><td style='background:#f4f7f8;border-left:4px solid {orange};padding:11px 13px;font-size:16px;font-weight:bold;color:{text};'>{icon} {esc(heading)}</td></tr>"
        if sub: s+=f"<tr><td style='padding:8px 14px 5px;color:#78909c;font-size:11px;'>{esc(sub)}</td></tr>"
        return s
    def section_close(): return "</table></td></tr>"
    p.append(section_open("🛡",L["firewall"],L["firewall_sub"]))
    if fw_rows:
        p.append("<tr><td style='padding:0 8px 8px;overflow-wrap:anywhere;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>")
        p.append(f"<tr><td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:bold;'>{esc(L['agent'])}</td><td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:bold;'>{esc(L['reason'])}</td><td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:bold;'>{esc(L['rule'])}</td><td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:bold;'>{esc(L['attempts'])}</td><td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:bold;'>{esc(L['blocked_ips'])}</td></tr>")
        for row in fw_rows:
            ips_html=''.join(f"<span style='display:inline-block;background:#fff;border:1px solid #d9e2e6;padding:2px 5px;margin:2px;font-family:monospace;font-size:10px;'>{esc(ip)}</span>" for ip in row['ips'])
            detail=f"<details style='margin-top:5px;'><summary style='cursor:pointer;color:#425d68;font-size:10px;font-weight:bold;'>{esc(L['details'])} ({len(row['ips'])})</summary><div style='margin-top:6px;background:#f7f9fa;border:1px solid #dce5e9;padding:7px;overflow-wrap:anywhere;'>{ips_html}</div></details>"
            p.append(f"<tr><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:11px;'><b>{esc(row['agent_name'])}</b><br><span style='font-size:9px;color:#607d8b;'>ID {esc(row['agent_id'])}</span></td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:11px;'>{esc(row['description'])}{detail}<br><span style='font-size:9px;color:#78909c;'>Primera: {esc(fmt_dt(row['first']))} · Última: {esc(fmt_dt(row['last']))}</span></td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-family:monospace;font-weight:bold;color:#d65d00;font-size:11px;'>{esc(row['rule_id'])}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;text-align:center;font-weight:bold;font-size:11px;'>{row['attempts']:,}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;text-align:center;font-weight:bold;font-size:11px;'>{len(row['ips']):,}</td></tr>")
        p.append("</table></td></tr>")
    else: p.append(f"<tr><td style='padding:10px 14px;color:#147a4a;font-size:11px;'>{esc(L['no_firewall'])}</td></tr>")
    p.append(f"<tr><td style='background:#edf6fb;border-left:4px solid {orange};padding:10px 13px;color:#49616b;font-size:11px;'><b>{len(fw_ips):,}</b> {esc(L['blocked_ips'].lower())} · detecciones correlacionadas con los bloqueos: <b>{sum(r['attempts'] for r in fw_rows):,}</b></td></tr>")
    p.append(section_close())
    section_labels=[("🔐",L["access"],"authentication"),("🌐",L["web"],"web"),("📁",L["fim"],"fim"),("🦠",L["malware"],"malware"),("🔑",L["priv"],"privilege"),("🎯",L["attack"],"attack")]
    for icon,label,cat in section_labels:
        subset=cats[cat]; p.append(section_open(icon,label))
        if not subset: p.append(f"<tr><td style='padding:10px 14px;color:#147a4a;font-size:11px;'>{esc(L['no_activity'])}</td></tr>")
        else:
            p.append(f"<tr><td style='padding:0 8px 8px;color:#78909c;font-size:10px;'><b>{len(subset):,}</b> detecciones · <b>{len({e['srcip'] for e in subset if e['srcip']}):,}</b> IPs · <b>{len({e['agent_id'] for e in subset}):,}</b> sistemas</td></tr>")
            p.append("<tr><td style='padding:0 8px 8px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>")
            p.append("<tr><td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:bold;'>Regla</td><td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:bold;'>Descripción</td><td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:bold;'>Detecciones</td><td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:bold;'>Sistemas</td></tr>")
            for rid,desc,count,names in section_rows(subset):
                shown=', '.join(names[:5])+(' …' if len(names)>5 else '')
                p.append(f"<tr><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-family:monospace;font-weight:bold;color:#d65d00;font-size:10px;'>{esc(rid)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:10px;overflow-wrap:anywhere;'>{esc(desc)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;text-align:center;font-weight:bold;font-size:10px;'>{count:,}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:10px;overflow-wrap:anywhere;'>{esc(shown)}</td></tr>")
            p.append("</table></td></tr>")
        p.append(section_close())
    p.append(section_open("🎯",L["mitre"],"MITRE ATT&CK"))
    mr=mitre_rows(security)
    if mr:
        p.append("<tr><td style='padding:0 8px 8px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'>")
        p.append(f"<tr><td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:bold;'>{esc(L['technique'])}</td><td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:bold;'>Nombre</td><td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:bold;'>{esc(L['meaning'])}</td><td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:bold;'>{esc(L['detections'])}</td></tr>")
        for mid,name,meaning,count in mr: p.append(f"<tr><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-family:monospace;font-weight:bold;color:#d65d00;font-size:10px;'>{esc(mid)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:10px;'>{esc(name)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;font-size:10px;line-height:1.35;'>{esc(meaning)}</td><td valign='top' style='border-top:1px solid #e3e9ec;padding:8px;text-align:center;font-weight:bold;font-size:10px;'>{count:,}</td></tr>")
        p.append("</table></td></tr>")
    else: p.append("<tr><td style='padding:10px 14px;color:#78909c;font-size:11px;'>No se encontraron técnicas MITRE ATT&CK en las alertas del período.</td></tr>")
    p.append(section_close())
    p.append(section_open("🖥",L["agents"]))
    p.append("<tr><td style='padding:0 8px 8px;'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0'><tr><td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:bold;'>Sistema</td><td style='background:#29414c;color:#fff;padding:8px;font-size:10px;font-weight:bold;'>Detecciones</td></tr>")
    for (aid,name),count in agents.most_common(15): p.append(f"<tr><td style='border-top:1px solid #e3e9ec;padding:8px;font-size:10px;'><b>{esc(name)}</b><br><span style='color:#78909c;font-size:9px;'>ID {esc(aid)}</span></td><td style='border-top:1px solid #e3e9ec;padding:8px;text-align:center;font-weight:bold;font-size:10px;'>{count:,}</td></tr>")
    if not agents: p.append("<tr><td colspan='2' style='padding:10px;color:#147a4a;'>Sin actividad relevante.</td></tr>")
    p.append("</table></td></tr>"); p.append(section_close())
    p.append(section_open("🧪",L["validation"]))
    p.append(f"<tr><td style='padding:11px 14px;font-size:11px;line-height:1.5;color:#49616b;'>{esc(L['validation_text'])}</td></tr>"); p.append(section_close())
    p.append(f"<tr><td style='padding:10px 14px 18px;'><div style='background:#f7f9fa;border:1px solid #dce5e9;border-left:4px solid {orange};padding:10px 12px;font-size:10px;line-height:1.5;color:#526873;'>{esc(L['technical_note'])}</div></td></tr>")
    p.append(f"<tr><td style='background:{dark};border-top:4px solid {orange};padding:14px 20px;color:#c7d2d7;font-size:9px;'><b style='color:#fff;'>ORANGEBOX IT SERVICES</b><br>Infraestructura segura, negocios sin interrupciones</td></tr>")
    p.append("</table></td></tr></table></body></html>")
    return ''.join(p)

def send_email(subject,body,recipient):
    msg=MIMEMultipart('alternative'); msg['Subject']=subject; msg['From']=f'Wazuh SOC <{DEFAULT_FROM}>'; msg['To']=recipient
    msg.attach(MIMEText('OrangeBox Wazuh Security Activity Report.','plain','utf-8')); msg.attach(MIMEText(body,'html','utf-8'))
    with smtplib.SMTP(SMTP_HOST,SMTP_PORT,timeout=30) as smtp: smtp.sendmail(DEFAULT_FROM,[recipient],msg.as_string())

def archive_html(body,label):
    os.makedirs(ARCHIVE_DIR,mode=0o750,exist_ok=True); safe=re.sub(r'[^A-Za-z0-9_.-]+','_',label); path=f'{ARCHIVE_DIR}/security-report-{safe}.html'
    with open(path,'w',encoding='utf-8') as fh: fh.write(body)
    return path

def main():
    parser=argparse.ArgumentParser(description='OrangeBox Wazuh Security Activity Report'); modes=parser.add_mutually_exclusive_group(required=True)
    for name in ('today','yesterday','thisweek','lastweek','thismonth','lastmonth','thisyear','lastyear'): modes.add_argument('--'+name,action='store_true')
    modes.add_argument('--date',help='Día específico YYYY-MM-DD'); parser.add_argument('--group',required=True,help='Grupo Wazuh o all'); parser.add_argument('--email',required=True,help='Destinatario'); parser.add_argument('--lang',choices=('es','en'),default='es',help='Idioma del informe: es o en')
    args=parser.parse_args(); mode=args.date and f'date:{args.date}' or next(x for x in ('today','yesterday','thisweek','lastweek','thismonth','lastmonth','thisyear','lastyear') if getattr(args,x)); now=datetime.now().astimezone(); start,end,label=period_bounds(mode,now); allowed=group_members(args.group); events=load_events(start,end,allowed); period=f"{start.strftime('%d/%m/%Y %H:%M')} — {end.strftime('%d/%m/%Y %H:%M') if end < now else 'ahora'}"; L=labels(args.lang); body=generate_html(events,L['report'],L['subtitle'],period,args.group,args.lang); archive=archive_html(body,f'{args.group}-{mode.replace(":","-")}-{start:%Y%m%d}-{end:%Y%m%d}'); send_email(f'[OrangeBox SOC] {label} — {args.group}',body,args.email); security=sum(1 for e in events if e['category']!='other')
    print(f'Reporte enviado a {args.email}'); print(f'Grupo: {args.group}'); print(f'Periodo: {period}'); print(f'Eventos de seguridad: {security}'); print(f'Archivo: {archive}')

if __name__=='__main__': main()
