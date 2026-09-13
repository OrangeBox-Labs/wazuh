# OrangeBox Wazuh Rules

Este directorio contiene las reglas y firmas personalizadas de OrangeBox para Wazuh.

## Arquitectura

Las reglas se separan conceptualmente en:

- `10000–19999`: detecciones y correlaciones OrangeBox.
- `20000–29999`: excepciones y whitelists.

Las excepciones se mantienen al final de los XML cuando su función es modificar el comportamiento de una detección anterior.

## Criterio de diseño

No se crean reglas simplemente porque exista un evento nativo. Primero se identifica qué regla oficial de Wazuh produce el evento, qué datos decodifica y qué comportamiento adicional queremos detectar.

Cuando una regla nativa ya entrega una señal útil, OrangeBox normalmente construye una regla hija mediante `if_sid`, en vez de duplicar el decoder o volver a analizar el log desde cero.

Las correlaciones utilizan condiciones como `if_matched_sid` y `same_source_ip` cuando necesitamos relacionar eventos anteriores con el evento actual.

## Archivos

### `orangebox-auth.xml`

Autenticación, escalamiento de privilegios y correlaciones SSH/SUDO/SU.

Incluye, entre otras, la detección de login SSH exitoso `10001` y la correlación `10006` de múltiples fallos SSH seguidos de un login exitoso desde la misma IP.

### `orangebox-hardening.xml`

Detecciones relacionadas con modificaciones de componentes y configuraciones críticas del sistema.

### `orangebox-temporary-executable.xml`

Detecciones sobre ejecutables o scripts creados en ubicaciones temporales o de alto riesgo.

### `orangebox-web.xml`

Detecciones HTTP/Apache orientadas a reconocimiento, autenticación web y abuso de recursos sensibles.

### Firmas YARA

- `orangebox-webshell-core.yar`
- `orangebox-webshell-extended.yar`
- `webshells_index.yar`

Estas firmas complementan las reglas XML para identificar contenido compatible con webshells.

## Ingeniería y pruebas

Cada regla importante debe documentar:

1. evento nativo que la dispara;
2. razón para no utilizar directamente la regla nativa;
3. condiciones específicas añadidas;
4. falsos positivos observados;
5. alternativas probadas y descartadas;
6. prueba realizada;
7. relación con email y Active Response;
8. dependencias de otras reglas.

Un ejemplo importante es `10001`: inicialmente heredaba demasiado de `5715`, porque `5715` también podía coincidir con mensajes auxiliares como `Accepted key ... found at ...`. Se terminó utilizando una expresión PCRE2 específica para `Accepted publickey`, `password` o `keyboard-interactive/pam`.

Otro ejemplo es `10006`: se evaluó la correlación con reglas nativas SSH, se probó una regla temporal `19999` y se comprobó en el sistema real que `5763 → 10001` con `same_source_ip` funciona. Por eso la versión final utiliza `if_matched_sid 5763`.

## Relación con Active Response

Las reglas de detección no implican automáticamente bloqueo. Cada acción debe evaluarse según:

- disponibilidad de `srcip`;
- riesgo de falso positivo;
- severidad;
- posibilidad de afectar servicios legítimos;
- duración del bloqueo;
- capacidad del agente para ejecutar y registrar la acción.

El futuro soporte de `firewall-drop` para escaneo de puertos y DDoS requerirá actualizar también el deploy de agentes para garantizar que los logs del firewall estén disponibles.

## Regla de oro

**Detectar primero, probar después, automatizar la contención al final.**
