# agent.conf — Documentación técnica

## Propósito

`agent.conf` define la política FIM distribuida a los agentes mediante la configuración compartida de Wazuh.

El objetivo es concentrar FIM realtime en zonas donde un cambio puede representar compromiso, persistencia, modificación de controles de seguridad o alteración de componentes críticos, evitando vigilar indiscriminadamente todo el sistema.

## Categorías monitorizadas

### Zonas temporales

```text
/dev/shm
/tmp
/var/tmp
/opt/zimbra/data/tmp
/opt/zextras/data/tmp
```

Se monitorizan en realtime y `alert_new_files=yes` permite detectar archivos nuevos. Son rutas de especial interés para staging, ejecución temporal y carga de webshells o malware.

### Root y controles de identidad

`/root`, SSH, sudoers, PAM, Polkit y los archivos de identidad (`passwd`, `shadow`, `group`, `gshadow`) utilizan realtime + `report_changes=yes` cuando corresponde. La intención es conservar evidencia útil del cambio y no solamente saber que ocurrió.

### Binarios autorizados para sudo → root

Se monitorizan individualmente los ejecutables que actualmente forman parte de la whitelist de `orangebox-auth.xml` para Zimbra. Esto es deliberado: modificar un binario legítimo incluido en una whitelist puede convertir una ruta autorizada de administración en una vía de escalamiento.

No se monitoriza indiscriminadamente todo `/opt/zimbra/libexec` o `/opt/zimbra/common/sbin`; se protege el conjunto actualmente autorizado.

### Red, firewall y seguridad

Se vigilan configuraciones de resolución, hosts, montaje, Shorewall, firewalld, UFW, CSF, iptables, nftables e Imunify360.

`/etc/sysconfig/iptables` se interpreta mediante reglas específicas que distinguen cambios reales de reglas respecto de modificaciones de timestamps o contadores.

### Web y PHP

Se vigilan configuraciones de Apache, Nginx, cPanel y PHP/PHP-FPM, evitando deliberadamente convertir logs dinámicos en una fuente permanente de ruido FIM.

### Bases de datos

Se vigilan configuraciones de MySQL/MariaDB y PostgreSQL.

### Persistencia

Se vigilan systemd, cron, módulos e inetd/xinetd para detectar mecanismos de persistencia o carga automática de código.

### Binarios y librerías

Se vigilan `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin`, librerías y certificados críticos en realtime, pero sin `report_changes=yes`. En estos árboles interesa principalmente detectar aparición, modificación o eliminación sin generar el volumen de datos que implicaría guardar diffs de todos los binarios.

## Decisiones de diseño

### Realtime

Se utiliza donde el tiempo de detección es importante, especialmente en temporales, autenticación, persistencia, firewall y componentes críticos.

### `report_changes=yes`

Se reserva para configuraciones y archivos donde conocer exactamente el cambio aporta valor operativo o forense.

### Alcance acotado

La configuración evita el error clásico de FIM: monitorizar demasiado y producir tanto ruido que las modificaciones realmente importantes pierdan prioridad.

## Relación con el ruleset

`agent.conf` recopila eventos; las reglas OrangeBox los interpretan.

```text
agent.conf
   ↓
FIM
   ↓
554 / 550 / 553
   ↓
regla OrangeBox
   ↓
alerta
   ↓
email / Active Response
```

No se crea automáticamente una regla por cada ruta FIM: primero se analiza el evento nativo que genera Wazuh y luego se decide si necesita una detección específica.

## Pendiente

El futuro deploy de agentes deberá incorporar la configuración de logs de firewall necesaria para las futuras detecciones de escaneo de puertos y DDoS. Esa funcionalidad todavía no forma parte de este archivo.
