#!/usr/bin/env python3

import sys
import json
import smtplib
import os
import time
import fcntl
import html

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


# ============================================================
# CONFIGURACION
# ============================================================

# Ventana de agrupacion para alertas no inmediatas.
# 600 segundos = 10 minutos.
WINDOW_SECONDS = 600

# Directorio donde se almacenan temporalmente las alertas agrupadas.
BUFFER_DIR = "/tmp/wazuh_email_buffer"

# Estado persistente para controlar deduplicacion diaria de SSH.
STATE_DIR = "/var/ossec/logs/orangebox_email_state"
SSH_STATE_FILE = os.path.join(STATE_DIR, "ssh_notifications.json")


# ============================================================
# REGLAS DE ENVIO INMEDIATO
# ============================================================

# Estas reglas no pasan por el buffer.
#
# 5715 = SSH login exitoso
# 10001 = regla OrangeBox hija de 5715
# 10004 = SU hacia root
# 10008 = SUDO exitoso
# 10009 = SUDO exitoso
#
# IMPORTANTE:
# 5715 y 10001 tienen una deduplicacion adicional por IP
# origen/dia porque representan el mismo evento de SSH.
#
# Cualquier regla que incluya el grupo:
#
#     privilege_escalation_root
#
# se considera automaticamente inmediata.
#
# Esto permite que futuras reglas de escalamiento exitoso
# hacia ROOT no tengan que agregarse manualmente a esta lista.
#
IMMEDIATE_RULES = {
    "5715",
    "10001",
    "10004",
    "10008",
    "10009",
}

IMMEDIATE_GROUPS = {
    "privilege_escalation_root",
}


# ============================================================
# FUNCIONES AUXILIARES
# ============================================================

def ensure_directories():
    """
    Crea los directorios necesarios si no existen.
    """

    os.makedirs(BUFFER_DIR, exist_ok=True)
    os.makedirs(STATE_DIR, exist_ok=True)


def safe_int(value, default=0):
    """
    Convierte un valor a entero sin provocar excepciones.
    """

    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def esc(value):
    """
    Escapa contenido para HTML.

    Esto es importante porque full_log, diff, rutas, etc.
    pueden contener caracteres especiales.
    """

    if value is None:
        return ""

    return html.escape(str(value))


def load_json_file(path):
    """
    Carga un JSON desde disco.
    """

    with open(path, "r") as f:
        return json.load(f)


def save_json_file(path, data):
    """
    Guarda un JSON de forma segura.
    """

    with open(path, "w") as f:
        json.dump(data, f, indent=2)


# ============================================================
# DEDUPLICACION SSH
# ============================================================

def ssh_already_notified(agent_id, srcip, event_timestamp):
    """
    Determina si ya se envio un correo por SSH desde la misma
    IP origen hacia el mismo agente durante el mismo dia.

    Clave logica:

        agent_id + srcip + fecha

    Por lo tanto:

        mismo agente + misma IP + mismo dia
            -> NO enviar nuevamente

        mismo agente + IP diferente
            -> enviar

        mismo agente + misma IP al dia siguiente
            -> enviar

        agente diferente + misma IP
            -> enviar

    Se utiliza flock para evitar carreras cuando llegan varios
    SSH simultaneamente.
    """

    if not srcip:
        # Si no existe IP origen, no aplicamos deduplicacion.
        return False

    event_date = str(event_timestamp)[:10]

    try:
        os.makedirs(STATE_DIR, exist_ok=True)

        with open(SSH_STATE_FILE, "a+") as f:

            fcntl.flock(f.fileno(), fcntl.LOCK_EX)

            f.seek(0)

            try:
                state = json.load(f)
            except (json.JSONDecodeError, ValueError):
                state = {}

            key = f"{agent_id}|{srcip}|{event_date}"

            if key in state:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                return True

            state[key] = {
                "agent_id": agent_id,
                "srcip": srcip,
                "date": event_date,
                "timestamp": event_timestamp,
            }

            # Limpiar entradas antiguas.
            #
            # No necesitamos conservar historico indefinidamente.
            # Se mantienen solamente los ultimos 7 dias.
            current_time = time.time()

            cleaned_state = {}

            for state_key, state_value in state.items():

                timestamp_value = state_value.get("timestamp", "")

                try:
                    parsed_time = time.strptime(
                        timestamp_value[:19],
                        "%Y-%m-%dT%H:%M:%S"
                    )

                    entry_epoch = time.mktime(parsed_time)

                    if current_time - entry_epoch <= 7 * 86400:
                        cleaned_state[state_key] = state_value

                except Exception:
                    # Si no podemos interpretar la fecha,
                    # conservamos la entrada.
                    cleaned_state[state_key] = state_value

            f.seek(0)
            f.truncate()

            json.dump(cleaned_state, f, indent=2)

            f.flush()
            os.fsync(f.fileno())

            fcntl.flock(f.fileno(), fcntl.LOCK_UN)

        return False

    except Exception as e:

        # Ante un problema con el mecanismo de deduplicacion,
        # preferimos enviar el correo antes que perder una alerta.
        try:
            with open(
                "/var/ossec/logs/integrations.log",
                "a"
            ) as logf:

                logf.write(
                    "WARNING SSH deduplication error: "
                    f"{str(e)}\n"
                )

        except Exception:
            pass

        return False


# ============================================================
# BUFFER AGRUPADO
# ============================================================

def append_event_to_buffer(buffer_path, current_event,
                           agent_name, agent_ip, agent_id,
                           rule_id, description, location,
                           groups, rule_level):
    """
    Agrega un evento a un buffer existente utilizando bloqueo
    exclusivo para evitar corrupcion cuando llegan eventos
    simultaneos.
    """

    with open(buffer_path, "r+") as f:

        fcntl.flock(f.fileno(), fcntl.LOCK_EX)

        try:
            data = json.load(f)

        except (json.JSONDecodeError, ValueError):

            # Si el buffer esta corrupto, reconstruimos el buffer
            # usando el evento actual.
            data = {
                "first_seen": time.time(),
                "agent_name": agent_name,
                "agent_ip": agent_ip,
                "agent_id": agent_id,
                "rule_id": rule_id,
                "description": description,
                "location": location,
                "groups": groups,
                "max_level": rule_level,
                "events": []
            }

        data.setdefault("events", [])

        # ----------------------------------------------------
        # EVITAR DUPLICADOS
        # ----------------------------------------------------
        #
        # Cada alerta de Wazuh tiene un ID unico.
        # Si la misma alerta vuelve a ser procesada por la
        # integracion, no la agregamos nuevamente.
        #
        # No usamos file_path porque el mismo archivo puede
        # generar eventos legitimos diferentes.
        # ----------------------------------------------------

        current_alert_id = current_event.get("alert_id", "")

        if current_alert_id:

            already_exists = any(
                str(event.get("alert_id", "")) == current_alert_id
                for event in data["events"]
            )

            if already_exists:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                return

        data["events"].append(current_event)

        if rule_level > safe_int(data.get("max_level", 0)):
            data["max_level"] = rule_level

        f.seek(0)
        json.dump(data, f, indent=2)
        f.truncate()

        f.flush()
        os.fsync(f.fileno())

        fcntl.flock(f.fileno(), fcntl.LOCK_UN)


# ============================================================
# CREACION ATOMICA DEL BUFFER
# ============================================================

def create_first_buffer(buffer_path, buffer_data):
    """
    Intenta convertirse en el proceso propietario del buffer.

    O_CREAT | O_EXCL garantiza que solamente UN proceso puede
    crear el archivo.

    Esto elimina el problema anterior donde 25 alertas
    simultaneas podian generar 25 procesos que creian ser
    el primer proceso y terminaban enviando 25 correos.
    """

    fd = os.open(
        buffer_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600
    )

    try:

        with os.fdopen(fd, "w") as f:
            json.dump(buffer_data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())

    except Exception:

        try:
            os.unlink(buffer_path)
        except FileNotFoundError:
            pass

        raise


# ============================================================
# LECTURA DE ARGUMENTOS WAZUH
# ============================================================

if len(sys.argv) < 4:

    with open(
        "/var/ossec/logs/integrations.log",
        "a"
    ) as logf:

        logf.write(
            "ERROR custom-orangebox-email: "
            "argumentos insuficientes.\n"
        )

    sys.exit(1)


alert_file = sys.argv[1]
recipient = sys.argv[3]


# ============================================================
# CARGAR ALERTA
# ============================================================

try:

    with open(alert_file, "r") as f:
        alert_json = json.load(f)

except Exception as e:

    with open(
        "/var/ossec/logs/integrations.log",
        "a"
    ) as logf:

        logf.write(
            "ERROR custom-orangebox-email leyendo alerta: "
            f"{str(e)}\n"
        )

    sys.exit(1)


# ============================================================
# DATOS PRINCIPALES
# ============================================================

rule_id = str(
    alert_json.get("rule", {}).get("id", "N/A")
)

rule_level = safe_int(
    alert_json.get("rule", {}).get("level", 0)
)

description = alert_json.get(
    "rule", {}
).get(
    "description",
    "Sin descripcion"
)

agent_id = str(
    alert_json.get("agent", {}).get("id", "000")
)

agent_name = alert_json.get(
    "agent", {}
).get(
    "name",
    "Wazuh Manager"
)

agent_ip = alert_json.get(
    "agent", {}
).get(
    "ip",
    "Local"
)

location = alert_json.get(
    "location",
    "N/A"
)

timestamp = alert_json.get(
    "timestamp",
    "N/A"
)

full_log = alert_json.get(
    "full_log",
    "No log fragment attached."
)

groups = ", ".join(
    alert_json.get(
        "rule", {}
    ).get(
        "groups",
        []
    )
)


# ============================================================
# DATOS FIM / SYSCHECK
# ============================================================

# IMPORTANTE:
#
# Antes solamente guardabamos:
#
#   path
#   diff
#   size_after
#   uname_after
#
# Eso podia perder informacion importante entregada por Wazuh.
#
# Ahora conservamos TODO el objeto syscheck.

syscheck_data = alert_json.get(
    "syscheck",
    {}
)

if not isinstance(syscheck_data, dict):
    syscheck_data = {}


# ============================================================
# EVENTO COMPLETO PARA EL BUFFER
# ============================================================

alert_id = str(
    alert_json.get("id", "")
)

current_event = {
    "alert_id": alert_id,
    "timestamp": timestamp,
    "level": rule_level,
    "full_log": full_log,

    # Conservamos el objeto FIM COMPLETO.
    "syscheck": syscheck_data,

    # Estos campos adicionales mantienen compatibilidad con
    # cualquier procesamiento existente.
    "file_path": syscheck_data.get("path", ""),
    "file_diff": syscheck_data.get("diff", ""),
    "file_size": syscheck_data.get("size_after", "N/A"),
    "file_uname": syscheck_data.get("uname_after", "N/A"),

    # Conservamos tambien el JSON original del evento.
    # Esto permite recuperar informacion futura sin tener
    # que modificar nuevamente la estructura del buffer.
    "alert": alert_json,
}


# ============================================================
# ENVIO INMEDIATO
# ============================================================

send_immediately = (
    rule_id in IMMEDIATE_RULES
    or bool(
        IMMEDIATE_GROUPS.intersection(
            set(alert_json.get("rule", {}).get("groups", []))
        )
    )
)


# ------------------------------------------------------------
# DEDUPLICACION PARA SSH
# ------------------------------------------------------------
#
# 5715 = regla nativa de SSH exitoso.
# 10001 = regla OrangeBox hija de 5715.
#
# Ambas representan el mismo evento de autenticacion SSH.
#
# La deduplicacion se realiza por:
#     agente + IP origen + dia calendario
#
# Esto NO afecta:
#     10004 = SU
#     10008 = SUDO
#     10009 = SUDO
#
# Esas reglas siguen enviandose siempre.
# ------------------------------------------------------------

if rule_id in {"5715", "10001"}:

    srcip = (
        alert_json
        .get("data", {})
        .get("srcip", "")
    )

    if ssh_already_notified(
        agent_id,
        srcip,
        timestamp
    ):

        # SSH repetido desde la misma IP durante el mismo dia.
        #
        # La alerta SI queda registrada en Wazuh.
        # Simplemente no enviamos otro correo.
        sys.exit(0)


# ============================================================
# PREPARAR DATOS FINALES
# ============================================================

if send_immediately:

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
        "events": [
            current_event
        ]
    }

else:

    # ========================================================
    # AGRUPACION
    # ========================================================
    #
    # La clave sigue siendo:
    #
    #       agent_id + rule_id
    #
    # Nunca se mezclan:
    #
    #   agente A + regla 10410
    #   agente B + regla 10410
    #
    # ni:
    #
    #   agente A + regla 10410
    #   agente A + regla 10030
    #
    # ========================================================

    buffer_key = (
        f"buffer_{agent_id}_{rule_id}.json"
    )

    buffer_path = os.path.join(
        BUFFER_DIR,
        buffer_key
    )

    os.makedirs(
        BUFFER_DIR,
        exist_ok=True
    )

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
        "events": [
            current_event
        ]
    }

    # --------------------------------------------------------
    # Intentamos crear el buffer de forma atomica.
    #
    # Si tenemos exito:
    #   somos el primer evento
    #   esperamos 10 minutos
    #   enviamos el correo.
    #
    # Si falla porque ya existe:
    #   otro proceso ya es propietario
    #   simplemente agregamos el evento.
    # --------------------------------------------------------

    try:

        create_first_buffer(
            buffer_path,
            buffer_data
        )

        # ----------------------------------------------------
        # SOMOS EL PRIMER EVENTO.
        #
        # IMPORTANTE:
        #
        # NO debemos hacer sleep() directamente en este
        # proceso porque Wazuh puede serializar la ejecucion
        # de la integracion.
        #
        # Creamos un proceso hijo que esperara la ventana
        # de agrupacion mientras este proceso padre termina.
        #
        # De esta forma:
        #
        #   evento 1 -> crea buffer -> proceso hijo espera
        #   evento 2 -> agrega al buffer
        #   evento 3 -> agrega al buffer
        #   evento 4 -> agrega al buffer
        #   ...
        #
        # Al cumplirse WINDOW_SECONDS, el hijo envia el correo.
        # ----------------------------------------------------

        pid = os.fork()

        if pid > 0:

            # ------------------------------------------------
            # PROCESO PADRE
            #
            # Termina inmediatamente para no bloquear nuevas
            # ejecuciones de la integracion Wazuh.
            # ------------------------------------------------

            sys.exit(0)

        # ----------------------------------------------------
        # PROCESO HIJO
        # ----------------------------------------------------
        #
        # Nos independizamos de la sesion del proceso padre.
        # ----------------------------------------------------

        os.setsid()

        time.sleep(WINDOW_SECONDS)

        # ----------------------------------------------------
        # Leer el buffer completo.
        # ----------------------------------------------------

        try:

            with open(
                buffer_path,
                "r"
            ) as f:

                final_data = json.load(f)

        except Exception as e:

            with open(
                "/var/ossec/logs/integrations.log",
                "a"
            ) as logf:

                logf.write(
                    "ERROR leyendo buffer "
                    f"{buffer_path}: {str(e)}\n"
                )

            try:
                os.remove(buffer_path)
            except FileNotFoundError:
                pass

            sys.exit(1)

        # ----------------------------------------------------
        # Eliminar buffer.
        # ----------------------------------------------------

        try:
            os.remove(buffer_path)

        except FileNotFoundError:
            pass

    except FileExistsError:

        # ----------------------------------------------------
        # Otro proceso ya creo el buffer.
        #
        # Simplemente agregamos el evento actual.
        # ----------------------------------------------------

        try:

            append_event_to_buffer(
                buffer_path,
                current_event,
                agent_name,
                agent_ip,
                agent_id,
                rule_id,
                description,
                location,
                groups,
                rule_level
            )

        except Exception as e:

            with open(
                "/var/ossec/logs/integrations.log",
                "a"
            ) as logf:

                logf.write(
                    "ERROR agregando evento al buffer "
                    f"{buffer_path}: {str(e)}\n"
                )

        # Este proceso NO envia correo.
        sys.exit(0)

    except Exception as e:

        with open(
            "/var/ossec/logs/integrations.log",
            "a"
        ) as logf:

            logf.write(
                "ERROR creando buffer "
                f"{buffer_path}: {str(e)}\n"
            )

        sys.exit(1)

    total_alerts = len(
        final_data.get("events", [])
    )

    highest_level = safe_int(
        final_data.get("max_level", 0)
    )


# ============================================================
# COLOR Y TEXTO DE CABECERA
# ============================================================

if highest_level >= 12:

    status_color = "#dc2626"
    status_text = "CRITICO"

elif highest_level >= 7:

    status_color = "#f97316"
    status_text = "ADVERTENCIA"

else:

    status_color = "#4b5563"
    status_text = "INFORMACION"


# ============================================================
# ENCABEZADO
# ============================================================

if (
    send_immediately
    or total_alerts == 1
):

    subtitulo_header = (
        f"Alerta de Seguridad: Nivel "
        f"{highest_level} ({status_text})"
    )

    texto_contador = (
        "1 Alerta registrada "
        "(Evento unico)"
    )

else:

    subtitulo_header = (
        f"Maximo Nivel de Alerta en Rafaga: "
        f"{highest_level} ({status_text})"
    )

    texto_contador = (
        f"{total_alerts} Alertas registradas "
        "(Eventos consolidados)"
    )


# ============================================================
# CONSTRUCCION DEL HISTORIAL FIM
# ============================================================

log_history_html = ""
fim_details_html = ""


# ============================================================
# FIM:
#
# AHORA SE MUESTRAN TODOS LOS EVENTOS.
#
# Antes solamente:
#
#     last_event = events[-1]
#
# Por eso un correo con 25 archivos mostraba solamente
# el ultimo archivo.
#
# Ahora cada evento tiene:
#
#   archivo
#   propietario
#   tamaño
#   atributos modificados
#   hashes
#   diff si existe
#   log crudo
#
# ============================================================

fim_event_counter = 0

for idx, ev in enumerate(
    final_data.get("events", []),
    start=1
):

    syscheck = ev.get(
        "syscheck",
        {}
    )

    if not isinstance(syscheck, dict):
        syscheck = {}

    file_path = syscheck.get(
        "path",
        ev.get("file_path", "")
    )

    if not file_path:
        continue

    fim_event_counter += 1

    file_diff = syscheck.get(
        "diff",
        ev.get("file_diff", "")
    )

    file_diff = str(
        file_diff or ""
    ).strip()

    file_size = syscheck.get(
        "size_after",
        ev.get("file_size", "N/A")
    )

    file_uname = syscheck.get(
        "uname_after",
        ev.get("file_uname", "N/A")
    )

    changed_fields = syscheck.get(
        "changed_attributes",
        syscheck.get(
            "changed_fields",
            ""
        )
    )

    # --------------------------------------------------------
    # Algunos eventos FIM pueden traer informacion de hashes
    # aunque no tengan diff de contenido.
    # --------------------------------------------------------

    hash_rows = ""

    for hash_name in (
        "md5_after",
        "sha1_after",
        "sha256_after"
    ):

        if hash_name in syscheck:

            hash_rows += f"""
            <tr>
                <td style="width: 35%; padding: 8px 16px;
                    border-bottom: 1px solid #e2e8f0;
                    font-size: 12px; font-weight: 700;
                    color: #475569;">
                    {esc(hash_name)}
                </td>
                <td style="width: 65%; padding: 8px 16px;
                    border-bottom: 1px solid #e2e8f0;
                    font-size: 12px; color: #0f172a;
                    font-family: monospace;
                    word-break: break-all;">
                    {esc(syscheck.get(hash_name))}
                </td>
            </tr>
            """

    # --------------------------------------------------------
    # Atributos modificados.
    # --------------------------------------------------------

    changed_html = ""

    if isinstance(changed_fields, list):

        changed_text = ", ".join(
            str(x)
            for x in changed_fields
        )

    else:

        changed_text = str(
            changed_fields or ""
        )

    if changed_text:

        changed_html = f"""
        <tr>
            <td style="width: 35%; padding: 8px 16px;
                border-bottom: 1px solid #e2e8f0;
                font-size: 12px; font-weight: 700;
                color: #475569;">
                Atributos modificados
            </td>
            <td style="width: 65%; padding: 8px 16px;
                border-bottom: 1px solid #e2e8f0;
                font-size: 12px; color: #0f172a;
                font-family: monospace;">
                {esc(changed_text)}
            </td>
        </tr>
        """

    # --------------------------------------------------------
    # Diff.
    #
    # Si existe, se muestra exactamente.
    #
    # Si no existe, NO decimos que Wazuh "no adjunto"
    # diferencias. Indicamos que el evento no contiene
    # diff de contenido.
    # --------------------------------------------------------

    if file_diff:

        diff_html = f"""
        <pre style="margin: 0; color: #38bdf8;
            font-family: monospace;
            white-space: pre-wrap;
            font-size: 12px;
            line-height: 1.5;
            text-align: left;">{esc(file_diff)}</pre>
        """

    else:

        diff_html = """
        <div style="color: #94a3b8;
            font-family: monospace;
            font-size: 12px;">
            Este evento FIM no contiene un diff de contenido.
            Se muestran los atributos y hashes disponibles.
        </div>
        """

    fim_details_html += f"""
    <tr>
        <td colspan="2"
            style="padding: 12px 16px;
            background-color: #f1f5f9;
            font-size: 13px;
            font-weight: 700;
            color: #1e293b;
            border-bottom: 1px solid #cbd5e1;">

            Auditoria de Integridad (FIM)
            - Evento {idx}/{total_alerts}

        </td>
    </tr>

    <tr>
        <td style="width: 35%;
            padding: 10px 16px;
            border-bottom: 1px solid #e2e8f0;
            font-size: 13px;
            font-weight: 700;
            color: #475569;">
            Ruta del Archivo
        </td>

        <td style="width: 65%;
            padding: 10px 16px;
            border-bottom: 1px solid #e2e8f0;
            font-size: 13px;
            color: #0f172a;
            font-family: monospace;
            font-weight: bold;">
            {esc(file_path)}
        </td>
    </tr>

    <tr>
        <td style="width: 35%;
            padding: 10px 16px;
            border-bottom: 1px solid #e2e8f0;
            font-size: 13px;
            font-weight: 700;
            color: #475569;">
            Propietario / Tamaño
        </td>

        <td style="width: 65%;
            padding: 10px 16px;
            border-bottom: 1px solid #e2e8f0;
            font-size: 13px;
            color: #0f172a;">
            {esc(file_uname)}
            ({esc(file_size)} bytes)
        </td>
    </tr>

    {changed_html}

    {hash_rows}

    <tr>
        <td colspan="2"
            style="padding: 12px 16px;
            background-color: #f8fafc;
            font-size: 13px;
            font-weight: 700;
            color: #334155;
            border-bottom: 1px solid #cbd5e1;">

            Modificaciones Exactas en el Contenido (Diff):

        </td>
    </tr>

    <tr>
        <td colspan="2"
            style="padding: 14px;
            background-color: #1e293b;">

            {diff_html}

        </td>
    </tr>
    """


# ============================================================
# HISTORIAL DE LOGS CRUDOS
# ============================================================

for idx, ev in enumerate(
    final_data.get("events", []),
    start=1
):

    log_history_html += f"""
    <div style="
        margin-bottom: 12px;
        border-bottom: 1px dashed #cbd5e1;
        padding-bottom: 10px;
    ">

        <span style="
            color: #475569;
            font-weight: bold;
        ">
            [{idx}/{total_alerts}]
            ({esc(ev.get('timestamp', 'N/A'))}):
        </span>

        <br/>

        <pre style="
            margin: 5px 0 0 0;
            color: #b91c1c;
            font-family: monospace;
            white-space: pre-wrap;
            font-size: 13px;
            line-height: 1.4;
        ">{esc(ev.get('full_log', ''))}</pre>

    </div>
    """


# ============================================================
# URL DINAMICA WAZUH
# ============================================================

wazuh_url = (
    "https://wazuh.orangebox.cl/app/threat-hunting"
    "#/overview/?tab=general&tabView=events"
    f"&agentId={final_data['agent_id']}"
    "&_a=(filters:!(('$state':(store:appState),"
    "meta:(alias:'-%20Level%2012%20or%20above%20alerts',"
    "disabled:!f,index:'wazuh-alerts-*',key:query,"
    "negate:!f,type:custom,value:"
    "'%7B%22bool%22:%7B%22must%22:%5B%5D,"
    "%22filter%22:%5B%7B%22bool%22:%7B"
    "%22should%22:%5B%7B%22range%22:%7B"
    "%22rule.level%22:%7B%22gte%22:12%7D%7D%7D%5D,"
    "%22minimum_should_match%22:1%7D%7D%5D,"
    "%22should%22:%5B%5D,%22must_not%22:%5B%5D%7D%7D'),"
    "query:(bool:(filter:!((bool:"
    "(minimum_should_match:1,should:!((range:"
    "(rule.level:(gte:12))))))),must:!(),"
    "must_not:!(),should:!())))),"
    "query:(language:kuery,query:''))"
    "&_g=(filters:!(),refreshInterval:"
    "(pause:!t,value:0),time:(from:now-24h,to:now))"
)


# ============================================================
# PLANTILLA HTML CORPORATIVA ORANGEBOX
# ============================================================

html_template = f"""<!DOCTYPE html>
<html>

<head>

    <meta charset="UTF-8">

    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>
        Alerta Wazuh: Nivel {highest_level}
        en {esc(final_data['agent_name'])}
    </title>

</head>

<body style="
    margin: 0;
    padding: 20px;
    background-color: #1e2a3e;
    font-family: -apple-system, BlinkMacSystemFont,
                 'Segoe UI', Roboto,
                 'Helvetica Neue', Arial, sans-serif;
">

<table width="100%"
       cellpadding="0"
       cellspacing="0"
       border="0"
       align="center"
       style="
           background-color: #1e2a3e;
           width: 100%;
       ">

<tr>

<td align="center">

<table width="600"
       cellpadding="0"
       cellspacing="0"
       border="0"
       align="center"
       style="
           width: 100%;
           max-width: 600px;
           background-color: #1e2a3e;
       ">

<tr>

<td>

<table width="100%"
       cellpadding="0"
       cellspacing="0"
       border="0"
       style="
           background-color: #2d3a4e;
           border-radius: 20px;
           overflow: hidden;
           box-shadow:
             0 20px 35px -10px
             rgba(0,0,0,0.3);
       ">


<!-- ======================================================
     HEADER
     ====================================================== -->

<tr style="background-color: #2d3a4e;">

<td style="
    padding: 30px 20px 20px 20px;
    text-align: center;
">

<div style="margin-bottom: 10px;">

<img src="https://www.orangebox.cl/obox/img/logo-dark.png"
     alt="OrangeBox"
     style="
         max-height: 55px;
         width: auto;
         display: inline-block;
     "
     onerror="
         this.src='https://www.orangebox.cl/favicon.ico'
     ">

</div>

<div style="
    color: #ffffff;
    font-size: 20px;
    font-weight: 700;
    letter-spacing: -0.3px;
">

OrangeBox
<span style="color: #f97316;">
Seguridad
</span>

</div>

<div style="
    display: inline-block;
    font-size: 13px;
    font-weight: 700;
    padding: 4px 14px;
    border-radius: 30px;
    margin-top: 12px;
    background-color: rgba(255,255,255,0.1);
    color: #cbd5e1;
">

{subtitulo_header}

</div>

</td>

</tr>


<!-- ======================================================
     INFORMACION PRINCIPAL
     ====================================================== -->

<tr>

<td style="padding: 0 20px;">

<table width="100%"
       cellpadding="0"
       cellspacing="0"
       border="0"
       style="
           margin: 5px 0 0 0;
           background-color: #eef2ff;
           border-radius: 12px;
           overflow: hidden;
       ">


<tr style="
    background-color: {status_color};
">

<td colspan="2"
    style="
        padding: 14px 16px;
        text-align: center;
    ">

<div style="
    font-size: 15px;
    font-weight: 800;
    color: #ffffff;
    line-height: 1.4;
">

ID Regla {esc(final_data['rule_id'])}:
{esc(final_data['description'])}

</div>

</td>

</tr>


<tr>

<td style="
    width: 35%;
    padding: 12px 16px;
    border-bottom: 1px solid #cbd5e1;
    font-size: 13px;
    font-weight: 700;
    color: #334155;
">

Agente afectado

</td>

<td style="
    width: 65%;
    padding: 12px 16px;
    border-bottom: 1px solid #cbd5e1;
    font-size: 14px;
    color: #0f172a;
    font-weight: 600;
">

{esc(final_data['agent_name'])}
({esc(final_data['agent_ip'])})

</td>

</tr>


<tr>

<td style="
    width: 35%;
    padding: 12px 16px;
    border-bottom: 1px solid #cbd5e1;
    font-size: 13px;
    font-weight: 700;
    color: #334155;
">

Origen / Ubicacion

</td>

<td style="
    width: 65%;
    padding: 12px 16px;
    border-bottom: 1px solid #cbd5e1;
    font-size: 14px;
    color: #0f172a;
    font-family: monospace;
">

{esc(final_data['location'])}

</td>

</tr>


<tr>

<td style="
    width: 35%;
    padding: 12px 16px;
    border-bottom: 1px solid #cbd5e1;
    font-size: 13px;
    font-weight: 700;
    color: #334155;
">

Categoria / Grupo

</td>

<td style="
    width: 65%;
    padding: 12px 16px;
    border-bottom: 1px solid #cbd5e1;
    font-size: 14px;
    color: #0f172a;
">

{esc(final_data['groups'])}

</td>

</tr>


<tr>

<td style="
    width: 35%;
    padding: 12px 16px;
    border-bottom: 1px solid #cbd5e1;
    font-size: 13px;
    font-weight: 700;
    color: #334155;
">

Estado del Evento

</td>

<td style="
    width: 65%;
    padding: 12px 16px;
    border-bottom: 1px solid #cbd5e1;
    font-size: 14px;
    color: #0f172a;
    font-weight: bold;
">

{texto_contador}

</td>

</tr>


<!-- ======================================================
     FIM
     ====================================================== -->

{fim_details_html}


<!-- ======================================================
     LOGS CRUDOS
     ====================================================== -->

<tr>

<td colspan="2"
    style="
        padding: 12px 16px;
        background-color: #f8fafc;
        font-size: 13px;
        font-weight: 700;
        color: #334155;
        border-bottom: 1px solid #cbd5e1;
    ">

Historial de Logs Crudos de Wazuh:

</td>

</tr>


<tr>

<td colspan="2"
    style="
        padding: 16px;
        background-color: #ffffff;
        max-height: 200px;
        overflow-y: auto;
    ">

{log_history_html}

</td>

</tr>


</table>

</td>

</tr>


<!-- ======================================================
     BOTON WAZUH
     ====================================================== -->

<tr>

<td style="
    padding: 25px 20px;
    text-align: center;
">

<a href="{wazuh_url}"
   style="
       display: inline-block;
       background-color: #f97316;
       color: #ffffff;
       text-decoration: none;
       font-weight: 700;
       padding: 12px 30px;
       border-radius: 40px;
       font-size: 15px;
       box-shadow:
           0 2px 6px
           rgba(249,115,22,0.3);
   ">

Investigar Agente en Wazuh Dashboard

</a>

</td>

</tr>


<!-- ======================================================
     FOOTER
     ====================================================== -->

<tr>

<td style="
    background-color: #2d3a4e;
    padding: 16px 20px;
    text-align: center;
    border-top: 1px solid #4a5a6e;
">

<div style="
    font-size: 12px;
    color: #cbd5e1;
">

Mensaje automatizado de
<strong>
OrangeBox SOC & CyberSecurity
</strong>

</div>

<div style="
    font-size: 12px;
    color: #cbd5e1;
">

Por favor, no responda a este correo de alerta.

</div>

<div style="
    font-size: 11px;
    color: #94a3b8;
    margin-top: 8px;
">

Alertas procesadas por Wazuh SIEM.

</div>

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
</html>
"""


# ============================================================
# PREPARAR CORREO
# ============================================================

msg = MIMEMultipart("alternative")

subject_prefix = (
    f"[{total_alerts} EVENTOS] "
    if total_alerts > 1
    else ""
)

msg["Subject"] = (
    f"{subject_prefix}"
    f"Wazuh Alert Lvl {highest_level} - "
    f"{final_data['agent_name']} "
    f"({final_data['description'][:35]})"
)

msg["From"] = (
    "Wazuh SOC <soporte@orangebox.cl>"
)

msg["To"] = recipient

msg.attach(
    MIMEText(
        html_template,
        "html"
    )
)


# ============================================================
# ENVIO SMTP
# ============================================================

try:

    s = smtplib.SMTP("localhost")

    s.sendmail(
        msg["From"],
        [msg["To"]],
        msg.as_string()
    )

    s.quit()

except Exception as e:

    try:

        with open(
            "/var/ossec/logs/integrations.log",
            "a"
        ) as logf:

            logf.write(
                "Error enviando correo en "
                "custom-orangebox-email: "
                f"{str(e)}\n"
            )

    except Exception:
        pass
