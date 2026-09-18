# `custom-orangebox-email.py`

## Qué hace

Es la integración de correo HTML de OrangeBox para Wazuh.

Wazuh entrega la alerta en JSON y este script decide si:

- la envía inmediatamente;
- la agrupa durante una ventana de 10 minutos;
- evita duplicados;
- conserva el detalle FIM;
- genera el correo HTML;
- lo entrega al SMTP local.

La razón de tener un script propio es que el correo nativo de Wazuh no entrega el formato ni el comportamiento de agrupación que necesitamos.

## Envío inmediato

Estas reglas se consideran inmediatas:

- `5715` - login SSH exitoso nativo.
- `10001` - login SSH exitoso OrangeBox.
- `10004` - `su` hacia root.
- `10008` - sudo exitoso.
- `10007` - ráfaga de fallos SSH desde red interna / posible movimiento lateral.
- `10009` - sudo exitoso.

Además, cualquier alerta que pertenezca al grupo `privilege_escalation_root` se envía inmediatamente.

La regla `10007` utiliza intencionalmente este mecanismo para que un posible movimiento lateral no espere la ventana de agrupación de 10 minutos.

La decisión de usar el grupo para escalamiento es importante: una futura regla de elevación a root no necesita obligatoriamente modificar este script para empezar a recibir tratamiento inmediato.

## El problema de 5715 / 10001

`5715` y `10001` pueden representar el mismo login SSH.

Por eso existe una deduplicación específica para SSH usando:

```text
agent_id + srcip + fecha
```

Mismo agente + misma IP + mismo día = no mandar otro correo.

Esto **no elimina la alerta de Wazuh**. Solamente evita llenar el buzón con copias del mismo evento.

Si no existe `srcip`, no se aplica la deduplicación. En ese caso es preferible un correo de más antes que perder una alerta.

## Agrupación de alertas

Las alertas que no son inmediatas se agrupan durante `600` segundos.

La clave del buffer es:

```text
agent_id + rule_id
```

Esto evita mezclar cosas que no tienen relación.

Por ejemplo:

```text
agente A + regla 10410
agente A + regla 10030
```

usan buffers diferentes.

También quedan separados dos agentes aunque tengan la misma regla.

### Por qué existe el proceso hijo

El primer evento crea el buffer y genera un proceso hijo que espera los 10 minutos.

El proceso principal termina inmediatamente. Esto es importante porque no queremos que Wazuh quede esperando un `sleep()` mientras la integración está procesando eventos.

Además, la creación del buffer usa `O_EXCL`. Así, cuando llegan muchas alertas simultáneamente, solamente un proceso puede declararse dueño del buffer.

Esto corrige el problema clásico de:

```text
25 alertas simultáneas
        ↓
25 procesos creen que son el primero
        ↓
25 correos
```

## Protección contra duplicados

Cada evento conserva el `alert_id` de Wazuh.

Si el mismo evento vuelve a entrar al buffer, no se agrega nuevamente.

No usamos la ruta del archivo como identificador porque el mismo archivo puede generar eventos legítimos distintos.

## FIM: conservar la evidencia completa

El script conserva el objeto `syscheck` completo.

Además mantiene algunos campos individuales por compatibilidad:

- ruta;
- diff;
- tamaño;
- propietario;
- hashes;
- atributos modificados.

Esto se hizo porque una versión anterior guardaba solamente algunos campos y podía perder información entregada por Wazuh.

Para seguridad esto importa bastante: cuando estamos investigando un cambio de archivo, queremos ver la evidencia que Wazuh realmente recibió, no una versión recortada porque al script le dio flojera guardarla. 😎

También se conserva el JSON completo de la alerta dentro del evento. Eso permite recuperar información adicional en el futuro sin rediseñar nuevamente el buffer.

## HTML

El correo se genera directamente en HTML y contiene:

- nivel de alerta;
- regla;
- agente;
- origen/ubicación;
- grupos;
- cantidad de eventos;
- detalles FIM;
- hashes disponibles;
- diff;
- logs crudos;
- enlace directo al Dashboard de Wazuh.

Los datos variables pasan por `html.escape()` antes de insertarse en el HTML. Esto evita que contenido proveniente del log o del diff termine interpretándose como HTML.

## Niveles visuales

El encabezado clasifica visualmente el correo según el nivel máximo:

- `>= 12` → CRITICO
- `>= 7` → ADVERTENCIA
- menor → INFORMACION

No cambia el nivel real de Wazuh; solamente cambia la presentación del correo.

## SMTP

El script entrega el correo a:

```text
localhost
```

El relay SMTP local se encarga de la entrega posterior.

El remitente usado por el HTML es:

```text
Wazuh SOC <soporte@orangebox.cl>
```

## Integración con `ossec.conf`

`ossec.conf` llama esta integración con:

- formato `json`;
- nivel `12`;
- destinatario configurado en `hook_url`.

El correo nativo de Wazuh queda con `email_alert_level=16`, evitando que una misma alerta termine saliendo por dos caminos.

## Manejo de errores

Si falla la deduplicación SSH, el script prefiere **enviar la alerta** antes que perderla.

Los errores se escriben en:

```text
/var/ossec/logs/integrations.log
```

La filosofía es simple: un mecanismo de control de duplicados nunca debe convertirse en un mecanismo para perder alertas.

## Archivos utilizados

```text
/tmp/wazuh_email_buffer/
```

Buffers temporales de agrupación.

```text
/var/ossec/logs/orangebox_email_state/ssh_notifications.json
```

Estado persistente de deduplicación SSH.

El estado SSH se limpia conservando solamente aproximadamente los últimos 7 días.

## Decisiones que no deben cambiarse a la ligera

### No usar `sleep()` en el proceso principal

Bloquear el proceso de integración puede afectar el procesamiento de alertas.

### No deduplicar todo por regla

Dos alertas iguales en texto pueden representar incidentes distintos. La deduplicación agresiva puede esconder evidencia.

### No deduplicar FIM por ruta

Un mismo archivo puede ser creado, modificado y eliminado. Son eventos distintos y deben conservarse.

### No confiar en que `full_log` sea seguro para HTML

Los logs son datos externos. Siempre deben escaparse antes de insertarlos en el correo.

## Dependencias

- Python 3.
- Wazuh Manager.
- SMTP local en `localhost`.
- Permisos para escribir en `/tmp/wazuh_email_buffer` y `/var/ossec/logs/orangebox_email_state`.
- Integración JSON configurada en `ossec.conf`.

## Nota

Este script forma parte de la política de alertamiento OrangeBox. Las reglas deciden **qué pasó**; este script decide **cómo avisarnos sin convertir el correo en una ametralladora de spam**.
