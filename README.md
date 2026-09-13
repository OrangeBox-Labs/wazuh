# OrangeBox Wazuh

Configuraciones, reglas, integraciones y herramientas para desplegar y administrar **Wazuh** en entornos Linux empresariales.

Este repositorio pertenece a **OrangeBox Labs** y está orientado a mantener de forma versionada y reproducible las configuraciones utilizadas en infraestructura Linux.

## Estructura

```text
wazuh/
├── README.md
├── configuration/
│   ├── agents/
│   ├── integrations/
│   ├── manager/
│   ├── rules/
│   └── scripts/
│
└── tools/
    ├── README.md
    └── wazuh.install.rhel.sh
```

### `configuration/`

Contiene los componentes de configuración de Wazuh, separados por función:

- **`agents/`** — configuraciones y archivos destinados a los agentes Wazuh.
- **`integrations/`** — integraciones externas y scripts utilizados por Wazuh.
- **`manager/`** — configuración del Wazuh Manager.
- **`rules/`** — reglas personalizadas y grupos de reglas.
- **`scripts/`** — scripts auxiliares asociados a la configuración y operación de Wazuh.

### `tools/`

Contiene herramientas independientes para facilitar la instalación y administración.

Actualmente incluye un script para la instalación de agentes Wazuh en sistemas RHEL/CentOS:

- **`wazuh.install.rhel.sh`** — instalación automatizada del agente Wazuh, incluyendo soporte para entornos donde `/var` se encuentra montado con restricciones como `noexec`.

La documentación específica de esta herramienta se encuentra en [`tools/README.md`](tools/README.md).

## Objetivos

- Mantener la configuración de Wazuh bajo control de versiones.
- Separar claramente configuración, reglas, integraciones y herramientas.
- Facilitar la recuperación y reconstrucción de un Wazuh Manager.
- Mantener reglas personalizadas documentadas y reproducibles.
- Evitar configuraciones manuales difíciles de auditar.
- Permitir reutilizar componentes en nuevos servidores o instalaciones.

## Seguridad

Este repositorio puede contener configuraciones de seguridad y reglas utilizadas en infraestructura real.

**No se deben almacenar en GitHub:**

- Contraseñas.
- Tokens o API keys.
- Claves privadas.
- Certificados privados.
- Credenciales SMTP.
- Secretos de integraciones.
- Información sensible específica de una infraestructura.

Los valores dependientes del entorno deben mantenerse como variables, placeholders o archivos gestionados fuera del repositorio cuando corresponda.

## Estado del proyecto

El repositorio se encuentra en desarrollo activo. La estructura inicial está preparada para incorporar progresivamente la configuración del Wazuh Manager, reglas personalizadas, integraciones, configuraciones de agentes y scripts auxiliares.

---

**OrangeBox Enterprise Infrastructure** — Infraestructura Linux Enterprise, Seguridad y Alta Disponibilidad en Chile.

[🌐 www.orangebox.cl](https://www.orangebox.cl/)
