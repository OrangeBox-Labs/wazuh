# firewall-drop-daily.py

Genera el reporte diario HTML de ejecuciones efectivas de `firewall-drop` registradas en:

```text
/var/ossec/logs/alerts/alerts.json
```

## Fuente de datos

El script **no utiliza `active-responses.log`** como fuente principal.

Wazuh registra las ejecuciones de Active Response como alertas `651`. El detalle de la ejecución queda dentro de `full_log` como un JSON que contiene:

- `command=add`;
- agente que ejecutó Active Response;
- regla que originó la acción;
- `srcip` recibida por `firewall-drop`.

El script reconstruye esos eventos desde `alerts.json`.

## Qué se considera un bloqueo efectivo

Solo se consideran eventos que cumplan simultáneamente:

1. regla externa `651`;
2. `full_log` correspondiente a `active-response/bin/firewall-drop`;
3. `command=add`;
4. `srcip` válida.

Los eventos sin IP válida no se consideran bloqueos efectivos, porque `firewall-drop` no pudo realizar un bloqueo sobre una IP.

Las alertas `10026` **no se cuentan directamente como bloqueos**. Una misma IP puede generar muchas alertas `10026` y múltiples ejecuciones `firewall-drop` durante una misma campaña.

## Deduplicación

Los bloqueos se agrupan por:

```text
agente + rule_id + duración
```

Dentro de cada grupo se cuentan **IPs únicas**.

Por ejemplo, 27 ejecuciones de `firewall-drop` para la misma IP no se convierten en 27 bloqueos: representan un único bloqueo efectivo para el resumen.

## Duraciones conocidas

La primera versión reconoce las duraciones actualmente utilizadas por OrangeBox:

| Regla | Duración |
|---|---|
| 5720 | 3 minutos |
| 10006 | 24 horas |
| 10026 | 24 horas |

Las demás reglas muestran `Configurada en Active Response` hasta que se agreguen explícitamente.

## Filtrado por fecha

El script permite generar el reporte de una fecha específica:

```bash
python3 firewall-drop-daily.py --date 2026-09-14
```

Si no se entrega `--date`, procesa todos los registros disponibles en `alerts.json`.

## Formato

El HTML utiliza el mismo lenguaje visual general de las alertas HTML de OrangeBox/Wazuh:

- encabezado OrangeBox Security · Wazuh;
- tablas;
- bloques por agente;
- resumen global;
- diseño compacto para correo electrónico;
- no muestra las IPs individuales.

El resumen incluye:

- agentes con bloqueos;
- bloqueos efectivos;
- IPs únicas globales;
- resumen por regla/motivo.

## Ejecución

Actualmente el script genera el HTML por stdout:

```bash
python3 /var/ossec/reports/firewall-drop-daily.py --date 2026-09-14
```

La programación diaria y el envío SMTP se implementarán posteriormente, manteniendo este reporte independiente del integrador de alertas.
