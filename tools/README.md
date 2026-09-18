# Herramientas de Wazuh

[← Volver al README principal](../README.md)

Este directorio contiene herramientas operativas para desplegar o administrar componentes de Wazuh.

## Instalador actual

- [`wazuh.install.rhel.sh`](wazuh.install.rhel.sh) — instala el agente y prepara un filesystem dedicado para `/var/ossec`.
- [`wazuh.install.rhel.md`](wazuh.install.rhel.md) — documentación técnica del comportamiento actual y de las decisiones de diseño.

> **Estado actual:** el instalador ya incorpora el logging de firewall de OrangeBox, con precedencia `Shorewall > firewalld > iptables`, y usa rsyslog + logrotate en EL6 y journald en EL7+. En EL7+ las reglas iptables administradas por OrangeBox se cargan y retiran mediante `orangebox-iptables.service`, ligado al ciclo de vida de `wazuh-agent`.

## Criterio del directorio

Los scripts de despliegue deben contener automatización operativa. La documentación técnica detallada de cada script se mantiene junto al archivo para registrar no solamente su uso, sino también sus limitaciones y decisiones de diseño.

## Estado

Este directorio está en evolución junto con el proyecto OrangeBox Wazuh. Las capacidades de detección y respuesta deben implementarse primero en el ruleset/configuración y luego reflejarse en el deploy de agentes cuando corresponda.
