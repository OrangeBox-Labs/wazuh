# Agents

Configuraciones distribuidas para los agentes Wazuh.

## Perfiles

- **`default/`** — política base de FIM y monitoreo de integridad utilizada como configuración compartida.

Cada perfil debe mantener su archivo funcional acompañado de documentación técnica. La documentación debe explicar el alcance de FIM, el motivo de cada categoría monitorizada y cualquier relación con reglas del Manager.

## Criterio

La configuración de agentes debe recopilar la evidencia necesaria para las reglas sin convertir el FIM en una fuente indiscriminada de ruido.

Las detecciones futuras que dependan de logs locales, como escaneo de puertos, DDoS y `firewall-drop`, deberán incorporarse coordinadamente con el despliegue de agentes.
