# Manager

Configuración global del Wazuh Manager.

## Archivos

- **`ossec.conf`** — configuración principal del Manager, incluyendo alertas, correo, módulos, syscheck, indexer, autenticación de agentes e integraciones.
- **`ossec.md`** — documentación técnica del archivo y de las decisiones de configuración.

## Criterio

El Manager es el punto donde convergen los eventos de los agentes, los decoders/reglas nativos y las reglas OrangeBox. Su configuración debe mantenerse separada de la política distribuida de agentes y de la lógica de detección.

Cuando una funcionalidad requiere cambios tanto en Manager como en agentes, la documentación debe describir explícitamente esa dependencia.
