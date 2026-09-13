#!/usr/bin/env python3
import sys
import json
import smtplib
import os
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Configuracion de tiempos para el Buffer de Agrupacion (en segundos)
WINDOW_SECONDS = 30
BUFFER_DIR = "/tmp/wazuh_email_buffer"

# LISTA BLANCA: Reglas criticas que jamas esperan y se envian al segundo 0 de forma individual
IMMEDIATE_RULES = ["5715"] 

# Leer argumentos de Wazuh correctamente
alert_file = sys.argv[1]
recipient = sys.argv[3]

# Cargar el JSON de la alerta actual
with open(alert_file, 'r') as f:
    alert_json = json.load(f)

# Extraer los datos base indispensables
rule_id = alert_json.get('rule', {}).get('id', 'N/A')
rule_level = int(alert_json.get('rule', {}).get('level', 0))
description = alert_json.get('rule', {}).get('description', 'Sin descripcion')
agent_id = alert_json.get('agent', {}).get('id', '000')
agent_name = alert_json.get('agent', {}).get('name', 'Wazuh Manager')
agent_ip = alert_json.get('agent', {}).get('ip', 'Local')
location = alert_json.get('location', 'N/A')
timestamp = alert_json.get('timestamp', 'N/A')
full_log = alert_json.get('full_log', 'No log fragment attached.')
groups = ", ".join(alert_json.get('rule', {}).get('groups', []))

# Extraer informacion avanzada de integridad de archivos (FIM / Syscheck)
syscheck_data = alert_json.get('syscheck', {})
file_path = syscheck_data.get('path', '')
file_diff = syscheck_data.get('diff', '')
file_size = syscheck_data.get('size_after', 'N/A')
file_uname = syscheck_data.get('uname_after', 'N/A')

current_event = {
    "timestamp": timestamp,
    "level": rule_level,
    "full_log": full_log,
    "file_path": file_path,
    "file_diff": file_diff,
    "file_size": file_size,
    "file_uname": file_uname
}

# Evaluar si la regla requiere procesamiento inmediato por Lista Blanca
if rule_id in IMMEDIATE_RULES:
    total_alerts = 1
    highest_level = rule_level
    final_data = {
        "agent_name": agent_name,
        "agent_ip": agent_ip,
        "agent_id": agent_id,
        "rule_id": rule_id,
        "description": description,
        "location": location,
        "groups": groups,
        "events": [current_event]
    }
else:
    # Agrupacion ESTANDAR: Clave unica combinando estrictamente Agente + Regla especifica
    buffer_key = f"buffer_{agent_id}_{rule_id}.json"
    buffer_path = os.path.join(BUFFER_DIR, buffer_key)

    if not os.path.exists(BUFFER_DIR):
        os.makedirs(BUFFER_DIR, exist_ok=True)

    if not os.path.exists(buffer_path):
        buffer_data = {
            "first_seen": time.time(),
            "agent_name": agent_name,
            "agent_ip": agent_ip,
            "agent_id": agent_id,
            "rule_id": rule_id,
            "description": description,
            "location": location,
            "groups": groups,
            "max_level": rule_level,
            "events": [current_event]
        }
        with open(buffer_path, 'w') as f:
            json.dump(buffer_data, f)
        
        time.sleep(WINDOW_SECONDS)
        
        with open(buffer_path, 'r') as f:
            final_data = json.load(f)
        
        try:
            os.remove(buffer_path)
        except FileNotFoundError:
            pass
    else:
        try:
            with open(buffer_path, 'r+') as f:
                data = json.load(f)
                data["events"].append(current_event)
                if rule_level > data["max_level"]:
                    data["max_level"] = rule_level
                f.seek(0)
                json.dump(data, f)
                f.truncate()
        except Exception:
            pass
        sys.exit(0)

    total_alerts = len(final_data["events"])
    highest_level = final_data["max_level"]

# Determinar color y texto de cabecera (Estilo Zabbix dinamico)
if highest_level >= 12:
    status_color = "#dc2626"
    status_text = "CRITICO"
elif highest_level >= 7:
    status_color = "#f97316"
    status_text = "ADVERTENCIA"
else:
    status_color = "#4b5563"
    status_text = "INFORMACION"

# COMPORTAMIENTO INTELIGENTE DEL ENCABEZADO
if rule_id in IMMEDIATE_RULES or total_alerts == 1:
    subtitulo_header = f"Alerta de Seguridad: Nivel {highest_level} ({status_text})"
    texto_contador = "1 Alerta registrada (Evento unico)"
else:
    subtitulo_header = f"Maximo Nivel de Alerta en Rafaga: {highest_level} ({status_text})"
    texto_contador = f"{total_alerts} Alertas registradas (Eventos consolidados)"

# Construccion de los bloques de logs e historial de cambios
log_history_html = ""
fim_details_html = ""

# Si el ultimo evento contiene datos de FIM/Syscheck, extraemos el detalle estructurado del archivo
last_event = final_data["events"][-1]
if last_event.get("file_path"):
    diff_content = last_event.get("file_diff", "").strip()
    if not diff_content:
        diff_content = "No se adjuntaron diferencias de contenido en el evento."
    
    fim_details_html = f"""
    <tr>
        <td colspan="2" style="padding: 12px 16px; background-color: #f1f5f9; font-size: 13px; font-weight: 700; color: #1e293b; border-bottom: 1px solid #cbd5e1;">
            Auditoria de Integridad (FIM) - Archivo Afectado:
        </td>
    </tr>
    <tr>
        <td style="width: 35%; padding: 10px 16px; border-bottom: 1px solid #e2e8f0; font-size: 13px; font-weight: 700; color: #475569;">Ruta del Archivo</td>
        <td style="width: 65%; padding: 10px 16px; border-bottom: 1px solid #e2e8f0; font-size: 13px; color: #0f172a; font-family: monospace; font-weight: bold;">{last_event.get('file_path')}</td>
    </tr>
    <tr>
        <td style="width: 35%; padding: 10px 16px; border-bottom: 1px solid #e2e8f0; font-size: 13px; font-weight: 700; color: #475569;">Propietario / Tamano</td>
        <td style="width: 65%; padding: 10px 16px; border-bottom: 1px solid #e2e8f0; font-size: 13px; color: #0f172a;">{last_event.get('file_uname')} ({last_event.get('file_size')} bytes)</td>
    </tr>
    <tr>
        <td colspan="2" style="padding: 12px 16px; background-color: #f8fafc; font-size: 13px; font-weight: 700; color: #334155; border-bottom: 1px solid #cbd5e1;">
            Modificaciones Exactas en el Contenido (Diff):
        </td>
    </tr>
    <tr>
        <td colspan="2" style="padding: 14px; background-color: #1e293b;">
            <pre style="margin: 0; color: #38bdf8; font-family: monospace; white-space: pre-wrap; font-size: 12px; line-height: 1.5; text-align: left;">{diff_content}</pre>
        </td>
    </tr>
    """

# Renderizar logs estandar o de auditoria
for idx, ev in enumerate(final_data["events"], start=1):
    log_history_html += f"""
    <div style="margin-bottom: 12px; border-bottom: 1px dashed #cbd5e1; padding-bottom: 10px;">
        <span style="color: #475569; font-weight: bold;">[{idx}/{total_alerts}] ({ev['timestamp']}):</span><br/>
        <pre style="margin: 5px 0 0 0; color: #b91c1c; font-family: monospace; white-space: pre-wrap; font-size: 13px; line-height: 1.4;">{ev['full_log']}</pre>
    </div>
    """

# Enlace dinamico directo al agente en el modulo Threat Hunting
wazuh_url = f"https://wazuh.orangebox.cl/app/threat-hunting#/overview/?tab=general&tabView=events&agentId={final_data['agent_id']}&_a=(filters:!(('$state':(store:appState),meta:(alias:'-%20Level%2012%20or%20above%20alerts',disabled:!f,index:'wazuh-alerts-*',key:query,negate:!f,type:custom,value:'%7B%22bool%22:%7B%22must%22%3A%5B%5D,%22filter%22%3A%5B%7B%22bool%22%3A%7B%22should%22%3A%5B%7B%22range%22%3A%7B%22rule.level%22%3A%7B%22gte%22%3A12%7D%7D%7D%5D,%22minimum_should_match%22%3A1%7D%7D%5D,%22should%22%3A%5B%5D,%22must_not%22%3A%5B%5D%7D%7D'),query:(bool:(filter:!((bool:(minimum_should_match:1,should:!((range:(rule.level:(gte:12))))))),must:!(),must_not:!(),should:!())))),query:(language:kuery,query:''))&_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-24h,to:now))"

# PLANTILLA HTML CORPORATIVA ORANGEBOX
html_template = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Alerta Wazuh: Nivel {highest_level} en {final_data['agent_name']}</title>
</head>
<body style="margin: 0; padding: 20px; background-color: #1e2a3e; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0" border="0" align="center" style="background-color: #1e2a3e; width: 100%;">
        <tr>
            <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" border="0" align="center" style="width: 100%; max-width: 600px; background-color: #1e2a3e;">
                    <tr>
                        <td>
                            <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #2d3a4e; border-radius: 20px; overflow: hidden; box-shadow: 0 20px 35px -10px rgba(0,0,0,0.3);">
                                
                                <!-- HEADER -->
                                <tr style="background-color: #2d3a4e;">
                                    <td style="padding: 30px 20px 20px 20px; text-align: center;">
                                        <div style="margin-bottom: 10px;">
                                            <img src="https://www.orangebox.cl/obox/img/logo-dark.png" alt="OrangeBox" style="max-height: 55px; width: auto; display: inline-block;" onerror="this.src='https://www.orangebox.cl/favicon.ico'">
                                        </div>
                                        <div style="color: #ffffff; font-size: 20px; font-weight: 700; letter-spacing: -0.3px;">
                                            OrangeBox <span style="color: #f97316;">Seguridad</span>
                                        </div>
                                        <div style="display: inline-block; font-size: 13px; font-weight: 700; padding: 4px 14px; border-radius: 30px; margin-top: 12px; background-color: rgba(255,255,255,0.1); color: #cbd5e1;">
                                            {subtitulo_header}
                                        </div>
                                    </td>
                                </tr>

                                <tr>
                                    <td style="padding: 0 20px;">
                                        <table width="100%" cellpadding="0" cellspacing="0" border="0" style="margin: 5px 0 0 0; background-color: #eef2ff; border-radius: 12px; overflow: hidden;">
                                            <tr style="background-color: {status_color};">
                                                <td colspan="2" style="padding: 14px 16px; text-align: center;">
                                                    <div style="font-size: 15px; font-weight: 800; color: #ffffff; line-height: 1.4;">ID Regla {final_data['rule_id']}: {final_data['description']}</div>
                                                </td>
                                            </tr>
                                            <tr>
                                                <td style="width: 35%; padding: 12px 16px; border-bottom: 1px solid #cbd5e1; font-size: 13px; font-weight: 700; color: #334155;">Agente afectado</td>
                                                <td style="width: 65%; padding: 12px 16px; border-bottom: 1px solid #cbd5e1; font-size: 14px; color: #0f172a; font-weight: 600;">{final_data['agent_name']} ({final_data['agent_ip']})</td>
                                            </tr>
                                            <tr>
                                                <td style="width: 35%; padding: 12px 16px; border-bottom: 1px solid #cbd5e1; font-size: 13px; font-weight: 700; color: #334155;">Origen / Ubicacion</td>
                                                <td style="width: 65%; padding: 12px 16px; border-bottom: 1px solid #cbd5e1; font-size: 14px; color: #0f172a; font-family: monospace;">{final_data['location']}</td>
                                            </tr>
                                            <tr>
                                                <td style="width: 35%; padding: 12px 16px; border-bottom: 1px solid #cbd5e1; font-size: 13px; font-weight: 700; color: #334155;">Categoria / Grupo</td>
                                                <td style="width: 65%; padding: 12px 16px; border-bottom: 1px solid #cbd5e1; font-size: 14px; color: #0f172a;">{final_data['groups']}</td>
                                            </tr>
                                            <tr>
                                                <td style="width: 35%; padding: 12px 16px; border-bottom: 1px solid #cbd5e1; font-size: 13px; font-weight: 700; color: #334155;">Estado del Evento</td>
                                                <td style="width: 65%; padding: 12px 16px; border-bottom: 1px solid #cbd5e1; font-size: 14px; color: #0f172a; font-weight: bold;">{texto_contador}</td>
                                            </tr>
                                            
                                            {fim_details_html}
                                            
                                            <tr>
                                                <td colspan="2" style="padding: 12px 16px; background-color: #f8fafc; font-size: 13px; font-weight: 700; color: #334155; border-bottom: 1px solid #cbd5e1;">
                                                    Historial de Logs Crudos de Wazuh:
                                                </td>
                                            </tr>
                                            <tr>
                                                <td colspan="2" style="padding: 16px; background-color: #ffffff; max-height: 200px; overflow-y: auto;">
                                                    {log_history_html}
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>

                                <tr>
                                    <td style="padding: 25px 20px; text-align: center;">
                                        <a href="{wazuh_url}" style="display: inline-block; background-color: #f97316; color: #ffffff; text-decoration: none; font-weight: 700; padding: 12px 30px; border-radius: 40px; font-size: 15px; box-shadow: 0 2px 6px rgba(249,115,22,0.3);">Investigar Agente en Wazuh Dashboard</a>
                                    </td>
                                </tr>

                                <tr>
                                    <td style="background-color: #2d3a4e; padding: 16px 20px; text-align: center; border-top: 1px solid #4a5a6e;">
                                        <div style="font-size: 12px; color: #cbd5e1;">Mensaje automatizado de <strong>OrangeBox SOC & CyberSecurity</strong></div>
                                        <div style="font-size: 12px; color: #cbd5e1;">Por favor, no responda a este correo de alerta.</div>
                                        <div style="font-size: 11px; color: #94a3b8; margin-top: 8px;">Alertas procesadas por Wazuh SIEM.</div>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>"""

# Preparar y despachar el correo electrónico
msg = MIMEMultipart('alternative')
subject_prefix = f"[{total_alerts} EVENTOS] " if total_alerts > 1 else ""
msg['Subject'] = f"{subject_prefix}Wazuh Alert Lvl {highest_level} - {final_data['agent_name']} ({final_data['description'][:35]})"
msg['From'] = "Wazuh SOC <soporte@orangebox.cl>"
msg['To'] = recipient

msg.attach(MIMEText(html_template, 'html'))

try:
    s = smtplib.SMTP('localhost')
    s.sendmail(msg['From'], [msg['To']], msg.as_string())
    s.quit()
except Exception as e:
    with open('/var/ossec/logs/integrations.log', 'a') as logf:
        logf.write(f"Error enviando correo en custom-orangebox-email: {str(e)}\n")
