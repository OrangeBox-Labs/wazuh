# Configuration

Este directorio contiene los componentes versionados que forman la configuración de Wazuh utilizada por OrangeBox.

## Estructura

```text
configuration/
├── agents/
│   └── default/
│       ├── agent.conf
│       └── agent.md
├── integrations/
│   ├── custom-orangebox-email.py
│   └── custom-orangebox-email.md
├── manager/
│   ├── ossec.conf
│   └── ossec.md
├── reports/
│   ├── orangebox-security-report.py
│   └── orangebox-security-report.md
├── rules/
│   ├── *.xml
│   ├── *.yar
│   └── *.md
└── scripts/
```

## Criterio de organización

La separación no es solamente estética. Cada componente tiene una responsabilidad distinta:

- **`agents/`**: política distribuida que reciben los agentes, principalmente FIM, Who-Data y monitoreo de integridad.
- **`integrations/`**: código que conecta Wazuh con servicios externos o con el mecanismo de alertamiento OrangeBox.
- **`manager/`**: configuración del Wazuh Manager y sus módulos globales.
- **`reports/`**: generación de reportes de actividad a partir de las alertas de Wazuh.
- **`rules/`**: interpretación y correlación de eventos mediante reglas XML y firmas YARA.
- **`scripts/`**: automatizaciones auxiliares que no pertenecen directamente al ruleset ni a la configuración del Manager.

## Documentación

Cada archivo funcional debe tener su documentación técnica asociada usando el mismo nombre base cuando sea posible. La documentación debe explicar no solamente qué hace el archivo, sino también por qué existe, qué decisiones de diseño contiene, qué falsos positivos se encontraron, qué alternativas fueron descartadas y cómo fue probado.

Los `README.md` de directorio se reservan para explicar la arquitectura y servir como índice. La documentación detallada de un archivo debe permanecer junto a ese archivo.

## Flujo general

```text
agent.conf
    ↓
telemetría / FIM / logs / Who-Data
    ↓
reglas XML / YARA
    ↓
alerta Wazuh
    ↓
integraciones / Active Response
```

El objetivo es poder reconstruir el sistema entendiendo tanto la configuración actual como las razones históricas que llevaron a ella.

## Estado actual

La configuración ya incorpora detecciones de reconocimiento de red mediante logs de firewall, correlación de port scan, detección de SYN flood y posible DoS distribuido, además de `firewall-drop` donde corresponde.

La capa de FIM también utiliza Who-Data en rutas críticas para conservar información del usuario y proceso que realizó modificaciones, y vigila artefactos relevantes para persistencia de credenciales SSH.

## Pendientes de evolución

El proyecto seguirá evolucionando. Entre los próximos trabajos están:

- conectar completamente las firmas YARA al pipeline de detección FIM;
- revisar la política preventiva de puertos del firewall;
- mejorar el envío de alertas por grupo y cliente;
- ampliar pruebas automatizadas del ruleset y de las integraciones.

No se agregan cambios por deporte: cada componente debe probarse antes de convertirse en parte de la configuración base.
