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
├── rules/
│   ├── *.xml
│   ├── *.yar
│   └── *.md
└── scripts/
```

## Criterio de organización

La separación no es solamente estética. Cada componente tiene una responsabilidad distinta:

- **`agents/`**: política distribuida que reciben los agentes, principalmente FIM y monitoreo de integridad.
- **`integrations/`**: código que conecta Wazuh con servicios externos o con el mecanismo de alertamiento OrangeBox.
- **`manager/`**: configuración del Wazuh Manager y sus módulos globales.
- **`rules/`**: interpretación y correlación de eventos mediante reglas XML y firmas YARA.
- **`scripts/`**: automatizaciones auxiliares que no pertenecen directamente al ruleset ni a la configuración del Manager.

## Documentación

Cada archivo funcional debe tener su documentación técnica asociada usando el mismo nombre base cuando sea posible. La documentación debe explicar no solamente qué hace el archivo, sino también por qué existe, qué decisiones de diseño contiene, qué falsos positivos se encontraron, qué alternativas fueron descartadas y cómo fue probado.

Los `README.md` de directorio se reservan para explicar la arquitectura y servir como índice. La documentación detallada de un archivo debe permanecer junto a ese archivo.

## Flujo general

```text
agent.conf
    ↓
telemetría / FIM / logs
    ↓
reglas XML / YARA
    ↓
alerta Wazuh
    ↓
integraciones / Active Response
```

El objetivo es poder reconstruir el sistema entendiendo tanto la configuración actual como las razones históricas que llevaron a ella.

## Cambios futuros

El diseño seguirá evolucionando. En particular, la incorporación de detecciones de escaneo de puertos y DDoS mediante logs de firewall y `firewall-drop` implicará cambios coordinados en agentes, reglas, Active Response y documentación. No se adelantan esos cambios en los archivos actuales hasta que la nueva arquitectura sea definida y probada.
