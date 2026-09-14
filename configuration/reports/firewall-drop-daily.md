# firewall-drop-daily.py

Genera el reporte diario HTML de ejecuciones de `firewall-drop` registradas en:

```text
/var/ossec/logs/active-responses.log
```

## Objetivo

El reporte está separado del integrador `custom-orangebox-email.py` y del resto de alertas individuales.

Su objetivo es entregar un resumen diario compacto de los bloqueos realizados por Active Response, evitando listar cientos o miles de IPs individualmente.

## Agrupación

Los eventos se agrupan por:

```text
agente + rule_id + duración
```

Para cada grupo se informa:

- agente;
- ID de regla;
- descripción/motivo de la regla;
- duración del bloqueo;
- cantidad de IPs únicas.

Las IPs individuales no se incluyen en el correo.

## IPs válidas

Solo se contabilizan eventos `command=add` que contengan una dirección `srcip` válida.

Los eventos donde `firewall-drop` no pudo obtener una IP válida no se consideran bloqueos efectivos.

## Formato

El HTML utiliza el mismo lenguaje visual general de las alertas HTML de OrangeBox/Wazuh:

- encabezado OrangeBox Security · Wazuh;
- tablas;
- bloques por agente;
- resumen final;
- diseño compacto para correo electrónico.

## Duraciones conocidas

La primera versión reconoce las duraciones actualmente utilizadas por OrangeBox:

| Regla | Duración |
|---|---|
| 5720 | 3 minutos |
| 10006 | 24 horas |
| 10026 | 24 horas |

Las demás reglas muestran `Configurada en Active Response` hasta que se agreguen explícitamente.

## Ejecución

Actualmente el script genera el HTML por stdout:

```bash
python3 /var/ossec/reports/firewall-drop-daily.py
```

La programación diaria y el envío SMTP se implementarán posteriormente, manteniendo este reporte independiente del integrador de alertas.
