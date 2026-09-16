# wazuh.install.rhel.sh

Script idempotente para instalar y mantener Wazuh Agent y el logging de red OrangeBox.

## Compatibilidad

Objetivo:

- CentOS 6, 7 y 8
- AlmaLinux 8, 9 y 10

Para sistemas sin systemd utiliza SysV init.

## Principio

El script se puede ejecutar repetidamente:

- Si Wazuh Agent ya existe, no reinstala ni toca /var/ossec.
- Si falta un componente, lo agrega.
- Si ya existe y está correcto, lo conserva.
- Si encuentra un estado inesperado, informa y termina.
- Cada cambio importante tiene una validación.

## Wazuh Agent

Valores iniciales:

```text
Manager : 192.168.200.160
Grupo   : OrangeBox
Nombre  : $HOSTNAME
```

El script pregunta si están correctos y permite modificarlos.

La contraseña de enrolamiento no se guarda en Git. Puede entregarse con:

```bash
WAZUH_REGISTRATION_PASSWORD='PASSWORD' ./wazuh.install.rhel.sh
```

o introducirse de forma interactiva. Nunca se muestra.

La instalación usa las variables de despliegue documentadas por Wazuh, incluyendo `WAZUH_MANAGER`, `WAZUH_REGISTRATION_SERVER`, `WAZUH_REGISTRATION_PASSWORD`, `WAZUH_AGENT_NAME` y `WAZUH_AGENT_GROUP`. citeturn519500search1turn519500search4

Después se comprueba:

- paquete instalado;
- `client.keys`;
- servicio activo.

## /var/ossec

La funcionalidad histórica de crear un LV de 100 MB se mantiene en el flujo de instalación nueva.

El script nunca borra contenido existente de `/var/ossec`.

## Firewall

Primero detecta firewalld.

Si está activo:

- usa `firewall-cmd --direct`;
- agrega la regla TCP SYN OrangeBox;
- la marca como permanente;
- recarga y valida.

Si firewalld no está activo:

- usa iptables;
- evita localhost;
- aplica limitación de 20 eventos/s y burst 40;
- intenta persistir en `/etc/sysconfig/iptables`.

La regla solamente registra; no bloquea.

## rsyslog

Se utiliza el prefijo:

```text
ORANGEBOX-FW:
```

y el archivo:

```text
/var/log/orangebox-firewall.log
```

El filtro se inserta antes de la regla estándar de `/var/log/messages`.

El script realiza un test con `logger` y exige:

- evento presente en el log dedicado;
- evento ausente de `messages`.

Se usa sintaxis clásica de rsyslog para mantener compatibilidad con CentOS antiguos.

## logrotate

Archivo:

```text
/etc/logrotate.d/orangebox-firewall
```

Configuración:

```text
daily
rotate 0
missingok
notifempty
copytruncate
```

No se conservan logs rotados.

## Wazuh y la detección de red

El agente consume:

```text
/var/log/orangebox-firewall.log
```

Las reglas OrangeBox asociadas están en:

```text
configuration/rules/orangebox-firewall.xml
```

Actualmente:

- `10450`: señal de TCP SYN usada para correlación sin generar alertas individuales.
- `10453`: 12 SYN en 90 segundos, misma IP origen y diferentes puertos destino.

## Futuros componentes

Toda nueva dependencia del agente para Wazuh se incorpora a este script siguiendo el mismo patrón:

```text
detectar -> agregar si falta -> validar -> informar error
```

Mantener el script simple es una prioridad.

## Regla de oro

**No duplicar. No adivinar. Validar cada cambio.**
