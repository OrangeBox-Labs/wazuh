#!/usr/bin/env python3

"""
OrangeBox Wazuh - TEST HARNESS
================================

Este archivo NO reemplaza ni modifica custom-orangebox-email.py.

El harness lee la integracion original instalada en:

    /var/ossec/integrations/custom-orangebox-email.py

inyecta solamente la logica experimental para correlacionar:

    alerta Wazuh -> firewall-drop -> bloqueo confirmado

y luego ejecuta la integracion resultante en memoria.

Esto permite probar el correo sin tocar el archivo original ni cambiar
el <integration> activo del manager.

Uso manual de prueba:

    custom-orangebox-email-test.py ALERT_JSON HOOK_URL RECIPIENT --test-immediate

El flag --test-immediate solamente permite probar manualmente una alerta
que normalmente pasaria por el buffer.
"""

from pathlib import Path
import sys


ORIGINAL_SCRIPT = Path(
    "/var/ossec/integrations/custom-orangebox-email.py"
)


# --------------------------------------------------------------------
# Fragmentos de codigo inyectados en la copia EN MEMORIA.
# --------------------------------------------------------------------

FIREWALL_CONFIG = r'''ACTIVE_RESPONSES_LOG = "/var/ossec/logs/active-responses.log"
FIREWALL_DROP_WAIT_SECONDS = 3
FIREWALL_DROP_POLL_SECONDS = 0.25
FIREWALL_DROP_READ_BYTES = 2 * 1024 * 1024

FIREWALL_DROP_TIMEOUTS = {
    "5720": "180 segundos",
    "10006": "24 horas",
    "10025": "24 horas",
    "10026": "24 horas",
    "10453": "1 hora",
    "10454": "1 hora",
}

FIREWALL_DROP_RULES = set(FIREWALL_DROP_TIMEOUTS)
'''


FIREWALL_FUNCTION = r'''def find_firewall_drop_for_alerts(alert_ids, wait_seconds=FIREWALL_DROP_WAIT_SECONDS):
    """
    Busca ejecuciones reales de firewall-drop asociadas a las alertas.

    Solo considera BLOQUEO CONFIRMADO cuando active-responses.log contiene
    una ejecucion "add" de active-response/bin/firewall-drop cuyo alert.id
    coincide con la alerta original.
    """

    wanted = {str(x) for x in alert_ids if x}

    if not wanted:
        return {}

    deadline = time.monotonic() + wait_seconds
    found = {}

    while True:

        try:
            with open(
                ACTIVE_RESPONSES_LOG,
                "r",
                encoding="utf-8",
                errors="replace"
            ) as f:

                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - FIREWALL_DROP_READ_BYTES), os.SEEK_SET)
                content = f.read()

        except (FileNotFoundError, OSError):
            return {}

        marker = "active-response/bin/firewall-drop:"

        for line in reversed(content.splitlines()):

            if marker not in line:
                continue

            try:
                payload = json.loads(
                    line.split(marker, 1)[1].strip()
                )
            except (IndexError, json.JSONDecodeError):
                continue

            if payload.get("command") != "add":
                continue

            alert = (
                payload
                .get("parameters", {})
                .get("alert", {})
            )

            current_alert_id = str(alert.get("id", ""))

            if current_alert_id not in wanted:
                continue

            response_timestamp = line.split(marker, 1)[0].strip()

            found[current_alert_id] = {
                "action": "firewall-drop",
                "status": "BLOQUEO CONFIRMADO",
                "timestamp": response_timestamp,
                "alert": alert,
            }

        if wanted.issubset(found) or time.monotonic() >= deadline:
            return found

        time.sleep(FIREWALL_DROP_POLL_SECONDS)
'''


FIREWALL_HTML = r'''# ============================================================
# RESUMEN DE BLOQUEO FIREWALL
# ============================================================

firewall_block_html = ""

if firewall_blocked:

    block_rows = []

    for alert_id, block in firewall_blocks.items():

        blocked_alert = block.get("alert", {})
        blocked_rule = blocked_alert.get("rule", {})
        blocked_agent = blocked_alert.get("agent", {})
        blocked_data = blocked_alert.get("data", {})

        blocked_rule_id = str(blocked_rule.get("id", ""))
        blocked_srcip = str(blocked_data.get("srcip", ""))

        if not blocked_srcip:
            blocked_srcip = str(
                blocked_alert.get("srcip", "")
                or blocked_agent.get("ip", "")
            )

        timeout_text = FIREWALL_DROP_TIMEOUTS.get(
            blocked_rule_id,
            "Configurado por Active Response"
        )

        block_rows.append(f"""
<tr>
<td style="padding: 8px 12px; border-bottom: 1px solid #fecaca; font-size: 12px; font-weight: 700; color: #7f1d1d;">
    firewall-drop
</td>
<td style="padding: 8px 12px; border-bottom: 1px solid #fecaca; font-size: 12px; color: #450a0a;">
    <strong>BLOQUEO CONFIRMADO</strong><br>
    IP: {esc(blocked_srcip)}<br>
    Regla: {esc(blocked_rule_id)}<br>
    Duracion configurada: {esc(timeout_text)}<br>
    Ejecutado: {esc(block.get("timestamp", "N/A"))}
</td>
</tr>
""")

    firewall_block_html = f"""
<tr>
<td style="padding: 0 20px 12px 20px;">
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #fef2f2; border: 2px solid #ef4444; border-radius: 12px; overflow: hidden;">
<tr style="background-color: #991b1b;">
<td colspan="2" style="padding: 13px 16px; text-align: center; color: #ffffff; font-size: 15px; font-weight: 800;">
    🛡️ ATAQUE DETECTADO Y BLOQUEADO AUTOMATICAMENTE
</td>
</tr>
{''.join(block_rows)}
</table>
</td>
</tr>
"""
'''


def transform(source):
    """Aplica cambios estrictamente sobre la fuente original."""

    anchor = 'SSH_STATE_FILE = os.path.join(STATE_DIR, "ssh_notifications.json")\n\n\n# ============================================================\n# REGLAS DE ENVIO INMEDIATO'
    if anchor not in source:
        raise RuntimeError("No se encontro el ancla de configuracion del script original.")
    source = source.replace(
        anchor,
        'SSH_STATE_FILE = os.path.join(STATE_DIR, "ssh_notifications.json")\n\n'
        + FIREWALL_CONFIG
        + '\n\n# ============================================================\n# REGLAS DE ENVIO INMEDIATO',
        1,
    )

    anchor = '''def save_json_file(path, data):
    """
    Guarda un JSON de forma segura.
    """

    with open(path, "w") as f:
        json.dump(data, f, indent=2)


# ============================================================
# DEDUPLICACION SSH'''
    if anchor not in source:
        raise RuntimeError("No se encontro el ancla de funciones del script original.")
    source = source.replace(
        anchor,
        anchor.replace("\n\n# ============================================================\n# DEDUPLICACION SSH", "\n\n" + FIREWALL_FUNCTION + "\n\n# ============================================================\n# DEDUPLICACION SSH"),
        1,
    )

    anchor = '''alert_file = sys.argv[1]
recipient = sys.argv[3]


# ============================================================
# CARGAR ALERTA'''
    if anchor not in source:
        raise RuntimeError("No se encontro el ancla de argumentos del script original.")
    source = source.replace(
        anchor,
        '''alert_file = sys.argv[1]
recipient = sys.argv[3]

# Solo para esta copia de prueba.
FORCE_IMMEDIATE_TEST = "--test-immediate" in sys.argv


# ============================================================
# CARGAR ALERTA''',
        1,
    )

    anchor = '''send_immediately = (
    rule_id in IMMEDIATE_RULES
    or bool(
        IMMEDIATE_GROUPS.intersection(
            set(alert_json.get("rule", {}).get("groups", []))
        )
    )
)'''
    if anchor not in source:
        raise RuntimeError("No se encontro la logica send_immediately del script original.")
    source = source.replace(
        anchor,
        '''send_immediately = (
    FORCE_IMMEDIATE_TEST
    or rule_id in IMMEDIATE_RULES
    or bool(
        IMMEDIATE_GROUPS.intersection(
            set(alert_json.get("rule", {}).get("groups", []))
        )
    )
)''',
        1,
    )

    anchor = '''# ============================================================
# COLOR Y TEXTO DE CABECERA
# ============================================================

if highest_level >= 12:'''
    if anchor not in source:
        raise RuntimeError("No se encontro el ancla de color del script original.")
    source = source.replace(
        anchor,
        '''# ============================================================
# CORRELACION FINAL CON ACTIVE RESPONSE
# ============================================================

alert_ids = [
    str(ev.get("alert_id", ""))
    for ev in final_data.get("events", [])
    if ev.get("alert_id")
]

if rule_id in FIREWALL_DROP_RULES or FORCE_IMMEDIATE_TEST:
    firewall_blocks = find_firewall_drop_for_alerts(alert_ids)
else:
    firewall_blocks = {}

firewall_blocked = bool(firewall_blocks)


# ============================================================
# COLOR Y TEXTO DE CABECERA
# ============================================================

if firewall_blocked:

    status_color = "#991b1b"
    status_text = "ATAQUE BLOQUEADO"

elif highest_level >= 12:''',
        1,
    )

    anchor = '''# ============================================================
# CONSTRUCCION DEL HISTORIAL FIM
# ============================================================

log_history_html = ""'''
    if anchor not in source:
        raise RuntimeError("No se encontro el ancla de la plantilla del script original.")
    source = source.replace(
        anchor,
        FIREWALL_HTML + '''

# ============================================================
# CONSTRUCCION DEL HISTORIAL FIM
# ============================================================

log_history_html = ""''',
        1,
    )

    anchor = '''<!-- ======================================================
     INFORMACION PRINCIPAL
     ====================================================== -->

<tr>'''
    if anchor not in source:
        raise RuntimeError("No se encontro el ancla HTML de informacion principal.")
    source = source.replace(
        anchor,
        '''<!-- ======================================================
     INFORMACION PRINCIPAL
     ====================================================== -->

{firewall_block_html}

<tr>''',
        1,
    )

    anchor = '''msg["Subject"] = (
    f"{subject_prefix}"
    f"Wazuh Alert Lvl {highest_level} - "'''
    if anchor not in source:
        raise RuntimeError("No se encontro el ancla del asunto del correo.")
    source = source.replace(
        anchor,
        '''if firewall_blocked:
    subject_prefix = "[BLOQUEADO] "

msg["Subject"] = (
    f"{subject_prefix}"
    f"Wazuh Alert Lvl {highest_level} - "''',
        1,
    )

    return source


def main():
    if not ORIGINAL_SCRIPT.exists():
        print(
            f"ERROR: no existe la integracion original: {ORIGINAL_SCRIPT}",
            file=sys.stderr,
        )
        return 1

    try:
        source = ORIGINAL_SCRIPT.read_text(encoding="utf-8")
        source = transform(source)
    except Exception as exc:
        print(f"ERROR preparando copia de prueba: {exc}", file=sys.stderr)
        return 1

    # Mantener exactamente los argumentos entregados al harness.
    # El script original recibira tambien --test-immediate cuando se use.
    namespace = {
        "__name__": "__main__",
        "__file__": str(ORIGINAL_SCRIPT),
        "__package__": None,
    }

    try:
        exec(
            compile(source, str(ORIGINAL_SCRIPT), "exec"),
            namespace,
            namespace,
        )
    except SystemExit as exc:
        return int(exc.code or 0)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
