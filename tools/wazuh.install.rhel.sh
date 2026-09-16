#!/bin/bash

# OrangeBox - Wazuh Agent / Firewall Logging
# Compatible: CentOS 6/7/8 and AlmaLinux 8/9/10.
# Idempotent: existing correct settings are preserved; missing settings are added;
# unexpected existing settings cause an error instead of guessing.

set -u

WAZUH_VERSION="4.14.7"
DEFAULT_MANAGER="wazuh.orangebox.cl"
DEFAULT_GROUP="OrangeBox"
DEFAULT_AGENT_NAME="$HOSTNAME"

FIREWALL_LOG="/var/log/orangebox-firewall.log"
LOGROTATE_FILE="/etc/logrotate.d/orangebox-firewall"

fail() { echo "ERROR: $*" >&2; exit 1; }
ok() { echo "OK: $*"; }
warn() { echo "AVISO: $*" >&2; }
has() { command -v "$1" >/dev/null 2>&1; }

yesno() {
    local a
    while true; do
        read -r -p "$1 (s/N): " a
        case "$a" in
            s|S) return 0 ;;
            n|N|"") return 1 ;;
            *) echo "Responde s o n." ;;
        esac
    done
}

[ "$(id -u)" -eq 0 ] || fail "Debes ejecutar como root."

# ---------------------------------------------------------------------------
# 1. Wazuh Agent
# ---------------------------------------------------------------------------

agent_installed() {
    rpm -q wazuh-agent >/dev/null 2>&1 || [ -x /var/ossec/bin/wazuh-control ]
}

agent_version() {
    rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\n' wazuh-agent 2>/dev/null || echo "desconocida"
}

install_agent() {
    AGENT_NAME="${WAZUH_AGENT_NAME:-$DEFAULT_AGENT_NAME}"
    MANAGER="${WAZUH_MANAGER:-$DEFAULT_MANAGER}"
    GROUP="${WAZUH_AGENT_GROUP:-$DEFAULT_GROUP}"
    PASSWORD="${WAZUH_REGISTRATION_PASSWORD:-}"

    echo
    echo "=== DATOS DE ENROLAMIENTO ==="
    echo "Nombre : $AGENT_NAME"
    echo "Manager: $MANAGER"
    echo "Grupo  : $GROUP"
    [ -n "$PASSWORD" ] && echo "Password: [definida por entorno]" || echo "Password: [no definida]"

    if ! yesno "¿Los datos están correctos?"; then
        read -r -p "Nombre [$AGENT_NAME]: " v; [ -n "$v" ] && AGENT_NAME="$v"
        read -r -p "Manager [$MANAGER]: " v; [ -n "$v" ] && MANAGER="$v"
        read -r -p "Grupo [$GROUP]: " v; [ -n "$v" ] && GROUP="$v"
    fi

    if [ -z "$PASSWORD" ]; then
        read -r -s -p "Password de enrolamiento: " PASSWORD
        echo
    fi
    [ -n "$PASSWORD" ] || fail "La password de enrolamiento está vacía."

    echo
    echo "=== CONFIRMACIÓN ==="
    echo "Nombre : $AGENT_NAME"
    echo "Manager: $MANAGER"
    echo "Grupo  : $GROUP"
    echo "Password: [oculta]"
    yesno "¿Proceder?" || fail "Instalación cancelada."

    # /var/ossec se prepara solamente para instalaciones nuevas.
    if ! mountpoint -q /var/ossec 2>/dev/null && [ -d /var/ossec ] && [ "$(ls -A /var/ossec 2>/dev/null)" ]; then
        fail "/var/ossec contiene archivos pero no está montado. No se tocará."
    fi

    local rpm_file="wazuh-agent-$WAZUH_VERSION-1.x86_64.rpm"
    local url="https://packages.wazuh.com/4.x/yum/$rpm_file"

    has curl || fail "curl no está instalado."
    info="Descargando $rpm_file..."
    echo "==> $info"
    curl -fL -o "/tmp/$rpm_file" "$url" || fail "Falló la descarga."

    if has yum; then
        WAZUH_MANAGER="$MANAGER" WAZUH_REGISTRATION_SERVER="$MANAGER"         WAZUH_REGISTRATION_PASSWORD="$PASSWORD" WAZUH_AGENT_NAME="$AGENT_NAME"         WAZUH_AGENT_GROUP="$GROUP" yum localinstall -y "/tmp/$rpm_file"         || fail "Falló yum."
    elif has dnf; then
        WAZUH_MANAGER="$MANAGER" WAZUH_REGISTRATION_SERVER="$MANAGER"         WAZUH_REGISTRATION_PASSWORD="$PASSWORD" WAZUH_AGENT_NAME="$AGENT_NAME"         WAZUH_AGENT_GROUP="$GROUP" dnf install -y "/tmp/$rpm_file"         || fail "Falló dnf."
    else
        fail "No existe yum ni dnf."
    fi

    rm -f "/tmp/$rpm_file"
    agent_installed || fail "Wazuh Agent no quedó instalado."
    [ -s /var/ossec/etc/client.keys ] || fail "No se generó client.keys."
    ok "Wazuh Agent instalado: $(agent_version)"
}

restart_agent() {
    if has systemctl; then
        systemctl enable wazuh-agent >/dev/null 2>&1 || true
        systemctl restart wazuh-agent || fail "No se pudo reiniciar wazuh-agent."
        systemctl is-active --quiet wazuh-agent || fail "wazuh-agent no está activo."
    else
        chkconfig wazuh-agent on >/dev/null 2>&1 || true
        service wazuh-agent restart || fail "No se pudo reiniciar wazuh-agent."
        service wazuh-agent status >/dev/null 2>&1 || fail "No se pudo validar wazuh-agent."
    fi
    ok "wazuh-agent activo."
}

# ---------------------------------------------------------------------------
# 2. Firewall: firewalld si está activo, si no iptables
# ---------------------------------------------------------------------------

iptables_input_rule_exists() {
    iptables -C INPUT         -p tcp --tcp-flags SYN SYN         ! -s 127.0.0.0/8         -j ORANGEBOX-FW >/dev/null 2>&1
}

iptables_log_rule_exists() {
    iptables -C ORANGEBOX-FW         -m limit --limit 20/second --limit-burst 40         -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 4 >/dev/null 2>&1
}

iptables_return_rule_exists() {
    iptables -C ORANGEBOX-FW -j RETURN >/dev/null 2>&1
}

iptables_config_ok() {
    iptables_input_rule_exists &&
    iptables_log_rule_exists &&
    iptables_return_rule_exists
}

configure_iptables() {
    has iptables || fail "iptables no está instalado."

    if ! iptables -L ORANGEBOX-FW -n >/dev/null 2>&1; then
        echo "==> Creando cadena ORANGEBOX-FW..."
        iptables -N ORANGEBOX-FW || fail "No se pudo crear ORANGEBOX-FW."
    fi

    if ! iptables_log_rule_exists; then
        echo "==> Agregando LOG a ORANGEBOX-FW..."
        iptables -A ORANGEBOX-FW             -m limit --limit 20/second --limit-burst 40             -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 4             || fail "No se pudo agregar LOG a ORANGEBOX-FW."
    fi

    if ! iptables_return_rule_exists; then
        echo "==> Agregando RETURN a ORANGEBOX-FW..."
        iptables -A ORANGEBOX-FW -j RETURN             || fail "No se pudo agregar RETURN a ORANGEBOX-FW."
    fi

    if ! iptables_input_rule_exists; then
        echo "==> Conectando INPUT con ORANGEBOX-FW..."
        iptables -I INPUT 1             -p tcp --tcp-flags SYN SYN             ! -s 127.0.0.0/8             -j ORANGEBOX-FW             || fail "No se pudo conectar INPUT con ORANGEBOX-FW."
    fi

    iptables_config_ok || fail "La configuración ORANGEBOX-FW no quedó completa o correcta."

    if [ -f /etc/sysconfig/iptables ]; then
        if has service && service iptables save >/dev/null 2>&1; then
            ok "Configuración iptables persistida."
        else
            iptables-save > /etc/sysconfig/iptables                 || warn "No se pudo persistir la configuración iptables."
        fi
    else
        warn "No existe /etc/sysconfig/iptables; no se fuerza persistencia."
    fi

    ok "Configuración ORANGEBOX-FW de iptables validada."
}

configure_firewalld() {
    has firewall-cmd || fail "firewalld está activo pero firewall-cmd no existe."

    local r='-p tcp --tcp-flags SYN SYN ! -s 127.0.0.0/8 -m limit --limit 20/second --limit-burst 40 -j LOG --log-prefix "ORANGEBOX-FW: " --log-level 4'

    if firewall-cmd --direct --get-all-rules 2>/dev/null | grep -F -- "$r" >/dev/null 2>&1; then
        ok "Regla ORANGEBOX-FW ya existe en firewalld."
    else
        echo "==> Agregando regla ORANGEBOX-FW a firewalld..."
        firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 "$r"             || fail "No se pudo agregar la regla a firewalld."
        firewall-cmd --reload || fail "No se pudo recargar firewalld."
        firewall-cmd --direct --get-all-rules 2>/dev/null | grep -F -- "$r" >/dev/null 2>&1             || fail "No se pudo validar la regla firewalld."
        ok "Regla ORANGEBOX-FW instalada en firewalld."
    fi
}

configure_firewall() {
    if has firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
        ok "firewalld activo."
        configure_firewalld
    else
        ok "firewalld no activo; usando iptables."
        configure_iptables
    fi
}

# ---------------------------------------------------------------------------
# 3. rsyslog
# ---------------------------------------------------------------------------

rsyslog_rule_exists() {
    [ -f /etc/rsyslog.conf ] &&
    grep -Fq ':msg, contains, "ORANGEBOX-FW:"' /etc/rsyslog.conf &&
    grep -Fq '/var/log/orangebox-firewall.log' /etc/rsyslog.conf &&
    grep -Fxq 'stop' /etc/rsyslog.conf
}

configure_rsyslog() {
    has rsyslogd || fail "rsyslogd no está instalado."

    touch "$FIREWALL_LOG"
    chmod 640 "$FIREWALL_LOG"
    chown root:root "$FIREWALL_LOG"

    if ! rsyslog_rule_exists; then
        local line
        line="$(grep -n -E '^\*\.info;mail\.none;authpriv\.none;cron\.none[[:space:]].*/var/log/messages' /etc/rsyslog.conf | head -n1 | cut -d: -f1)"
        [ -n "$line" ] || fail "No se encontró la regla de /var/log/messages."

        cp -p /etc/rsyslog.conf "/etc/rsyslog.conf.orangebox-backup.$(date +%Y%m%d%H%M%S)"             || fail "No se pudo respaldar rsyslog.conf."

        awk -v n="$line" 'NR == n { print ":msg, contains, \"ORANGEBOX-FW:\" -/var/log/orangebox-firewall.log"; print "stop" } { print }' /etc/rsyslog.conf > /etc/rsyslog.conf.orangebox.tmp || fail "No se pudo preparar el filtro de rsyslog."
        mv /etc/rsyslog.conf.orangebox.tmp /etc/rsyslog.conf || fail "No se pudo actualizar rsyslog.conf."
    fi

    rsyslog_rule_exists || fail "No se pudo validar la regla rsyslog."
    rsyslogd -N1 >/dev/null 2>&1 || fail "rsyslogd rechazó la configuración."

    if has systemctl; then
        systemctl restart rsyslog || fail "No se pudo reiniciar rsyslog."
    else
        service rsyslog restart || fail "No se pudo reiniciar rsyslog."
    fi

    local marker="ORANGEBOX-RSYSLOG-TEST-$(date +%s)"
    logger -p kern.info "$marker ORANGEBOX-FW: test"
    sleep 1

    grep -Fq "$marker" "$FIREWALL_LOG" || fail "El test rsyslog no llegó al log dedicado."
    grep -Fq "$marker" /var/log/messages && fail "El test rsyslog también llegó a messages."

    ok "rsyslog validado."
}

# ---------------------------------------------------------------------------
# 4. logrotate
# ---------------------------------------------------------------------------

configure_logrotate() {
    has logrotate || fail "logrotate no está instalado."

    cat > "$LOGROTATE_FILE" <<'EOF'
/var/log/orangebox-firewall.log {
    daily
    rotate 0
    missingok
    notifempty
    copytruncate
}
EOF

    chmod 644 "$LOGROTATE_FILE"
    logrotate -d "$LOGROTATE_FILE" >/dev/null 2>&1 || fail "logrotate rechazó la configuración."

    grep -Fq 'daily' "$LOGROTATE_FILE" || fail "Falta daily."
    grep -Fq 'rotate 0' "$LOGROTATE_FILE" || fail "Falta rotate 0."
    grep -Fq 'copytruncate' "$LOGROTATE_FILE" || fail "Falta copytruncate."

    ok "logrotate validado."
}

# ---------------------------------------------------------------------------
# 5. Ejecución
# ---------------------------------------------------------------------------

echo
echo "============================================================"
echo " OrangeBox - Wazuh Agent / Firewall Logging"
echo "============================================================"

if agent_installed; then
    ok "Wazuh Agent ya instalado: $(agent_version)"
else
    warn "Wazuh Agent no está instalado."
    install_agent
fi

restart_agent
configure_firewall
configure_rsyslog
configure_logrotate

agent_installed || fail "Verificación final: Wazuh Agent ausente."
[ -s /var/ossec/etc/client.keys ] || fail "Verificación final: client.keys ausente."
[ -f "$FIREWALL_LOG" ] || fail "Verificación final: log ausente."
[ -f "$LOGROTATE_FILE" ] || fail "Verificación final: logrotate ausente."

ok "Configuración OrangeBox completada."
