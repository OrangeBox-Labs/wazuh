# firewall-drop-daily.py

Motor de reportes **OrangeBox Wazuh Security Activity Report**.

Aunque conserva su nombre histórico `firewall-drop-daily.py`, el script ahora genera reportes diarios, semanales, mensuales y anuales, globales o filtrados por grupo Wazuh.

## Fuente de datos

El script utiliza los logs JSON de alertas de Wazuh:

```text
/var/ossec/logs/alerts/alerts.json
/var/ossec/logs/alerts/YYYY/Mon/ossec-alerts-DD.json.gz
/var/ossec/logs/alerts/YYYY/Mon/ossec-alerts-DD.json
```

Los históricos `.json.gz` se leen directamente con `gzip`, sin descomprimirlos a disco. Esto permite reconstruir períodos largos usando los logs rotados de Wazuh.

No se utiliza `active-responses.log` como fuente histórica principal. Las ejecuciones de `firewall-drop` se reconstruyen desde las alertas `651`, cuyo `full_log` contiene el JSON de Active Response.

## Períodos

Los períodos de calendario están definidos de forma inequívoca:

| Opción | Período |
|---|---|
| `--today` | Hoy 00:00 hasta el momento de ejecución |
| `--yesterday` | Día calendario anterior completo |
| `--thisweek` | Lunes 00:00 hasta el momento de ejecución |
| `--lastweek` | Semana calendario anterior completa |
| `--thismonth` | Día 1 del mes hasta el momento de ejecución |
| `--lastmonth` | Mes calendario anterior completo |
| `--thisyear` | 1 de enero hasta el momento de ejecución |
| `--lastyear` | Año calendario anterior completo |
| `--date YYYY-MM-DD` | Día específico completo |

`--thisweek` comienza siempre el lunes.

## Grupos Wazuh

El filtro `--group` utiliza la pertenencia real de los agentes a grupos Wazuh mediante:

```text
/var/ossec/bin/agent_groups -l -g <grupo>
```

Por tanto, no existe una lista manual de agentes dentro del script.

Ejemplos:

```bash
--group all
--group Nexit
--group CloudLatam
--group JHG
--group OLC
--group CTS
--group CasaPiedra
```

`all` incluye todos los agentes. Un grupo específico incluye únicamente los agentes que Wazuh reporta como miembros de ese grupo.

## Envío

El destinatario se entrega explícitamente con `--email` y es obligatorio.

Ejemplos:

```bash
firewall-drop-daily.py --yesterday --group all --email soporte@orangebox.cl
firewall-drop-daily.py --lastmonth --group Nexit --email soporte@nexit.cl
firewall-drop-daily.py --thismonth --group CTS --email soporte@cts.cl
firewall-drop-daily.py --lastyear --group all --email soporte@orangebox.cl
```

El correo se entrega mediante Postfix/SMTP local (`localhost:25`) y utiliza:

```text
From: Wazuh SOC <wazuh@orangebox.cl>
```

El HTML generado se archiva bajo:

```text
/var/ossec/reports/archive/
```

## Contenido del Security Activity Report

El reporte ya no se limita a `firewall-drop`. Consolida las categorías de seguridad relevantes presentes en Wazuh:

### Active Response / Firewall Drop

- ejecuciones `651` de `firewall-drop`;
- acciones `add` y `delete`;
- regla que originó la acción;
- duración conocida de Active Response;
- IPs únicas;
- detalle de IPs desplegable por agente/regla.

Duraciones conocidas actualmente:

| Regla | Duración |
|---|---|
| 5720 | 3 minutos |
| 10006 | 24 horas |
| 10026 | 24 horas |

### Authentication & Access

Incluye reglas nativas y OrangeBox como:

```text
5710, 5712, 5715, 5716, 5720, 5760, 5763
10001, 10004, 10005, 10006, 10007, 10008, 10009
```

Permite visualizar fallos de autenticación, fuerza bruta, accesos SSH exitosos y escalaciones de privilegios.

### Web Security & Reconnaissance

Incluye:

```text
31101, 10023, 10024, 10025, 10026
```

Permite resumir HTTP 401/403, reconocimiento de archivos sensibles y fuerza bruta web.

### File Integrity & Critical Changes

Incluye eventos FIM y reglas OrangeBox:

```text
550, 553, 554
10060, 10062, 10063
10410, 10432
```

### Malware / WebShell / Suspicious Files

Incluye las reglas OrangeBox asociadas a malware, webshells y ejecutables sospechosos.

### Privilege Escalation

Incluye reglas de `sudo`, `su` y elevación a root, incluyendo la detección OrangeBox `10005`.

### Attack Activity

Incluye eventos asociados a grupos como:

```text
attack
brute_force
reconnaissance
credential_discovery
sensitive_file
lateral_movement
```

### Top Security Events

Presenta las reglas con mayor cantidad de eventos relevantes durante el período.

### MITRE ATT&CK

Cuando las alertas contienen información MITRE, el reporte consolida las técnicas detectadas y su cantidad de eventos.

### Agents Most Affected

Muestra los agentes con mayor cantidad de eventos de seguridad relevantes durante el período.

## Qué se considera evento de seguridad

El motor clasifica las alertas mediante sus IDs y grupos Wazuh. Los eventos que no pertenecen a una categoría de seguridad conocida se mantienen fuera del resumen principal para evitar que ruido operacional domine el informe.

Las categorías consideradas son:

```text
active_response
authentication
web
fim
malware
privilege
attack
```

## Cron recomendado

Ejemplo de reporte diario global a las 10:00:

```cron
0 10 * * * root /var/ossec/reports/firewall-drop-daily.py --yesterday --group all --email soporte@orangebox.cl
```

Reporte mensual global el día 1 a las 10:00:

```cron
0 10 1 * * root /var/ossec/reports/firewall-drop-daily.py --lastmonth --group all --email soporte@orangebox.cl
```

Reporte mensual de un cliente:

```cron
0 10 1 * * root /var/ossec/reports/firewall-drop-daily.py --lastmonth --group Nexit --email soporte@nexit.cl
```

Agregar o retirar un reporte de cliente consiste únicamente en agregar o eliminar una línea de cron.

## Seguridad y aislamiento por cliente

El correo del cliente no se define dentro del código. Cron entrega el destinatario y el grupo en cada ejecución.

Esto permite que un reporte como:

```bash
--group Nexit --email soporte@nexit.cl
```

contenga exclusivamente agentes que Wazuh identifica como pertenecientes a `Nexit`.

No se deben utilizar listas manuales de agentes dentro del script para reemplazar la pertenencia oficial a grupos Wazuh.
