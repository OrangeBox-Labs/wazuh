# firewall-drop-daily.py

Motor de reportes **OrangeBox Wazuh Security Activity Report**.

Aunque conserva su nombre histórico `firewall-drop-daily.py`, el script genera reportes diarios, semanales, mensuales y anuales, globales o filtrados por grupo Wazuh.

## Fuente de datos

El script utiliza los logs JSON de alertas de Wazuh:

```text
/var/ossec/logs/alerts/alerts.json
/var/ossec/logs/alerts/YYYY/Mon/ossec-alerts-DD.json.gz
/var/ossec/logs/alerts/YYYY/Mon/ossec-alerts-DD.json
```

Los históricos `.json.gz` se leen directamente con `gzip`, sin descomprimirlos a disco.

No se utiliza `active-responses.log` como fuente histórica principal. Las ejecuciones de `firewall-drop` se reconstruyen desde las alertas `651`, cuyo `full_log` contiene el JSON de Active Response.

## Períodos

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

## Grupos Wazuh

El filtro `--group` utiliza la pertenencia real de los agentes a grupos Wazuh mediante:

```text
/var/ossec/bin/agent_groups -l -g <grupo>
```

`all` incluye todos los agentes. Un grupo específico incluye únicamente los agentes que Wazuh reporta como miembros de ese grupo.

## Envío e idioma

El destinatario se entrega explícitamente con `--email` y es obligatorio.

El idioma por defecto es español. Los títulos y etiquetas del informe están traducidos; las descripciones técnicas de Wazuh se conservan para no perder información útil al investigar una detección.

```bash
firewall-drop-daily.py --yesterday --group all --email soporte@orangebox.cl
firewall-drop-daily.py --lastmonth --group Nexit --email soporte@nexit.cl
firewall-drop-daily.py --thismonth --group CTS --email soporte@cts.cl --lang es
firewall-drop-daily.py --lastyear --group all --email soporte@orangebox.cl --lang en
```

El correo se entrega mediante Postfix/SMTP local (`localhost:25`) y utiliza:

```text
From: Wazuh SOC <wazuh@orangebox.cl>
```

El HTML generado se archiva bajo:

```text
/var/ossec/reports/archive/
```

## Diseño para correo electrónico

El renderer utiliza HTML orientado específicamente a clientes de correo:

- layout basado en tablas HTML;
- estilos críticos inline;
- sin `flex`, CSS Grid ni JavaScript;
- ancho máximo de aproximadamente 640 px;
- contenido adaptable a pantallas pequeñas;
- `<details>` para mantener las listas largas de IPs contraídas cuando el cliente lo soporta.

Esto evita depender de características CSS que funcionan bien en Thunderbird de escritorio pero pueden ser eliminadas o interpretadas de forma diferente por webmail y clientes móviles.

## Contenido del informe

El orden del informe está pensado para comenzar con una visión ejecutiva y terminar con información técnica.

### Resumen

Presenta:

- eventos de seguridad;
- alertas de alta severidad;
- IPs de origen observadas;
- sistemas afectados.

### Respuesta automática · Firewall Drop

Esta sección correlaciona la detección que originó `firewall-drop` con las IPs que fueron bloqueadas.

Para cada sistema y regla muestra:

- motivo de la detección;
- regla Wazuh que originó el bloqueo;
- cantidad de intentos/detecciones correlacionados con las IP bloqueadas;
- cantidad de IPs bloqueadas;
- primera y última detección;
- lista de IPs en un menú desplegable.

No se muestra la duración configurada en Active Response porque describe la configuración del mecanismo, no la actividad observada. Tampoco se presenta la cantidad de ejecuciones `add` como una métrica de seguridad, ya que varias ejecuciones pueden corresponder a la misma IP.

La correlación de intentos se realiza usando el mismo agente, regla e IP de origen. De esta manera, el informe puede responder a una pregunta útil para el cliente: **cuántos intentos fueron detectados y cuántas IPs terminaron bloqueadas automáticamente**.

### Intentos de acceso

Resume autenticación, SSH, fuerza bruta y otras detecciones relacionadas con acceso.

### Intentos de acceso y exploración web

Resume reconocimiento y solicitudes HTTP asociadas a actividad sospechosa o intentos de acceso no autorizado.

### Cambios detectados en archivos

Resume actividad de File Integrity Monitoring y cambios relevantes detectados por Wazuh.

### Detecciones de malware y archivos sospechosos

Incluye reglas OrangeBox asociadas a malware, webshells y ejecutables sospechosos.

### Escalamiento de privilegios

Incluye reglas de `sudo`, `su` y elevación a root, incluyendo la detección OrangeBox `10005`.

### Intentos de ataque detectados

Agrupa detecciones asociadas a grupos como:

```text
attack
brute_force
reconnaissance
credential_discovery
sensitive_file
lateral_movement
```

El término **intento de ataque** se utiliza para destacar que la actividad presenta características compatibles con una acción ofensiva, sin afirmar que el atacante haya conseguido comprometer el sistema.

### Técnicas asociadas a intentos de ataque · MITRE ATT&CK

Wazuh incorpora en las alertas los identificadores MITRE ATT&CK, junto con el nombre de la técnica y la táctica cuando están disponibles. El informe conserva el identificador técnico y añade una explicación corta pensada para personas no especialistas.

El script mantiene las explicaciones dentro del propio archivo para que el reporte sea portable y no dependa de una consulta externa durante su ejecución.

Las explicaciones incorporadas cubren las técnicas MITRE que aparecen actualmente en los reportes OrangeBox, entre ellas:

```text
T1110       Fuerza bruta
T1110.001   Password Guessing
T1021       Remote Services
T1021.004   SSH
T1078       Valid Accounts
T1565.001   Stored Data Manipulation
T1070.004   File Deletion
T1485       Data Destruction
T1548.003   Sudo and Sudo Caching
T1055       Process Injection
T1190       Exploit Public-Facing Application
T1498       Network Denial of Service
T1595.002   Vulnerability Scanning
T1083       File and Directory Discovery
T1552       Unsecured Credentials
T1098       Account Manipulation
T1059       Command and Scripting Interpreter
T1059.004   Unix Shell
T1105       Ingress Tool Transfer
T1505.003   Web Shell
```

Wazuh documenta que las reglas pueden asociarse a IDs MITRE y que las alertas resultantes incluyen el ID, táctica y técnica. La lista puede crecer cuando el ruleset de Wazuh incorpore nuevas detecciones.

### Sistemas más afectados

Muestra los sistemas con mayor cantidad de detecciones relevantes durante el período.

### Validación del sistema

Los eventos de prueba controlada OrangeBox se mantienen en el informe. La sección de validación explica que estas cifras corresponden también a pruebas realizadas para comprobar que las reglas y mecanismos de respuesta funcionan correctamente.

## Qué se considera evento de seguridad

El motor clasifica las alertas mediante sus IDs y grupos Wazuh. Los eventos que no pertenecen a una categoría de seguridad conocida se mantienen fuera del resumen principal para evitar que el ruido operacional domine el informe.

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

Reporte diario global a las 10:00:

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

Por ejemplo:

```bash
--group Nexit --email soporte@nexit.cl
```

contendrá exclusivamente agentes que Wazuh identifica como pertenecientes a `Nexit`.

No se deben utilizar listas manuales de agentes dentro del script para reemplazar la pertenencia oficial a grupos Wazuh.
