# `wazuh.install.rhel.sh` — Documentación técnica

## Propósito

Script interactivo para preparar `/var/ossec` en un volumen lógico dedicado e instalar el agente Wazuh.

El motivo principal es aislar `/var/ossec` cuando `/var` puede tener políticas restrictivas, especialmente `noexec`. El script crea un LV propio y lo monta con `defaults,nosuid,nodev`.

**Estado:** esta documentación describe exactamente la versión actual. El deploy será rehecho posteriormente cuando incorporemos los logs de firewall y el soporte necesario para `firewall-drop` asociado a escaneo de puertos y DDoS.

## Flujo actual

```text
verificar /var/ossec
        ↓
detectar LV/VG de /var
        ↓
comprobar espacio
        ↓
crear LV wazuh de 100 MB
        ↓
formatear ext4
        ↓
montar /var/ossec
        ↓
actualizar fstab
        ↓
confirmar datos del agente
        ↓
instalar RPM Wazuh
        ↓
habilitar e iniciar wazuh-agent
```

## Funciones actuales

### Almacenamiento

- Comprueba si `/var/ossec` ya está montado.
- Si existe un montaje, solicita autorización antes de desmontarlo.
- Si el directorio contiene archivos sin estar montado, solicita autorización antes de eliminarlos.
- Detecta el LV y VG de `/var` mediante LVM.
- Comprueba que existan al menos 100 MB libres.
- Crea el LV `wazuh` de 100 MB.
- Formatea como ext4.
- Monta en `/var/ossec`.
- Registra el montaje en `/etc/fstab`.
- Si `mount -a` falla, elimina la entrada problemática y aborta.

### Seguridad del montaje

La entrada actual usa:

```text
defaults,nosuid,nodev
```

`nosuid` evita efectos SUID/SGID y `nodev` impide dispositivos especiales en el filesystem. No se usa `noexec` porque Wazuh necesita ejecutar componentes desde `/var/ossec`.

### Configuración del agente

Solicita:

- nombre del agente, proponiendo el hostname;
- IP del Manager, por defecto `192.168.200.160`;
- grupo, por defecto `OrangeBox`;
- confirmación final.

### Instalación

Actualmente descarga e instala:

```text
wazuh-agent-4.14.5-1.x86_64.rpm
```

Pasa al instalador:

```text
WAZUH_MANAGER
WAZUH_AGENT_NAME
WAZUH_AGENT_GROUP
```

### Servicio

Con systemd utiliza `systemctl enable --now wazuh-agent`. Si no existe systemd, intenta el camino SysV mediante `chkconfig`/`update-rc.d` y `service`.

### Manejo de errores

Utiliza `set -e` y comprobaciones explícitas para las operaciones críticas. La intención es detener la instalación ante errores de almacenamiento, filesystem, instalación o servicio.

## Por qué es interactivo

El script modifica almacenamiento, `/etc/fstab` y la instalación del agente. Por eso exige confirmaciones antes de operaciones potencialmente destructivas y antes de instalar.

No fue diseñado como un `curl | bash` ciego.

## Validación posterior

```bash
mount | grep /var/ossec
systemctl status wazuh-agent
journalctl -u wazuh-agent -f
```

También debe verificarse desde el Manager que el agente aparece correctamente y pertenece al grupo esperado.

## Limitaciones conocidas

El script **todavía no configura**:

- logs de firewall;
- fuentes de eventos necesarias para auditar `firewall-drop`;
- detecciones de escaneo de puertos;
- detecciones DDoS;
- cualquier otra función que decidamos incorporar al nuevo deploy.

Esto es intencional: primero terminaremos el diseño de detección/Active Response y después reharemos el deploy para instalar el conjunto completo de capacidades.

## Próximo rediseño

Cuando llegue ese momento habrá que revisar conjuntamente:

1. versión del agente;
2. distribución soportada;
3. montaje de `/var/ossec`;
4. `agent.conf`;
5. logs del firewall real de cada host;
6. compatibilidad de `firewall-drop`;
7. persistencia y expiración de bloqueos;
8. logging de Active Response;
9. comportamiento después de reinicio;
10. validación automática post-instalación.

No se adelantan aquí decisiones que todavía no hemos tomado.

## Advertencias

Este script **formatea un LV nuevo**. Debe revisarse el VG antes de ejecutarlo en producción.

La documentación antigua de `tools/README.md` mencionaba nombres y variables que ya no coinciden exactamente con el script. Esta página debe considerarse la referencia documental del comportamiento actual del archivo versionado.
