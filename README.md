# OrangeBox Wazuh

Configuraciones, reglas, integraciones y herramientas para desplegar y administrar **Wazuh** en entornos Linux empresariales.

Este repositorio pertenece a **OrangeBox Labs** y mantiene bajo control de versiones componentes utilizados para construir, operar y documentar una plataforma Wazuh reproducible.

## Filosofía

El repositorio no pretende ser solamente un lugar para guardar XML y scripts. Cada componente debe conservar también el contexto técnico que explica **por qué fue diseñado así**.

Cuando una decisión nace de una prueba real, un falso positivo, una limitación de Wazuh o una alternativa descartada, esa información debe quedar documentada junto al componente correspondiente.

> **Detectar primero, probar después, automatizar la contención al final.**

## Estructura

```text
wazuh/
├── README.md
├── configuration/
│   ├── README.md
│   ├── agents/
│   │   ├── README.md
│   │   └── default/
│   │       ├── agent.conf
│   │       └── agent.md
│   ├── integrations/
│   │   ├── README.md
│   │   ├── custom-orangebox-email.py
│   │   └── custom-orangebox-email.md
│   ├── manager/
│   │   ├── README.md
│   │   ├── ossec.conf
│   │   └── ossec.md
│   ├── reports/
│   │   ├── orangebox-security-report.py
│   │   └── orangebox-security-report.md
│   ├── rules/
│   │   ├── README.md
│   │   ├── *.xml
│   │   ├── *.yar
│   │   └── *.md
│   └── scripts/
│       └── README.md
│
└── tools/
    ├── README.md
    ├── wazuh.install.rhel.sh
    └── wazuh.install.rhel.md
```

## `configuration/`

Componentes que forman parte de la arquitectura Wazuh.

- **`agents/`** — configuración distribuida de agentes, principalmente FIM, Who-Data y monitoreo de integridad.
- **`integrations/`** — integraciones propias, como el correo HTML de OrangeBox.
- **`manager/`** — configuración global del Wazuh Manager.
- **`reports/`** — generación de reportes periódicos a partir de las alertas almacenadas.
- **`rules/`** — reglas de detección/correlación y firmas YARA.
- **`scripts/`** — espacio reservado para automatizaciones auxiliares relacionadas con la configuración u operación.

Cada directorio tiene un `README.md` que funciona como índice. Los archivos funcionales tienen documentación técnica asociada con el mismo nombre base cuando corresponde.

## `tools/`

Herramientas independientes para instalación y administración.

Actualmente incluye:

- **`wazuh.install.rhel.sh`** — instalador interactivo del agente Wazuh para sistemas RHEL/CentOS, incluyendo la preparación de `/var/ossec` en un volumen separado cuando corresponde.
- **`wazuh.install.rhel.md`** — documentación del instalador y de sus decisiones actuales.

El instalador también prepara el logging de firewall de OrangeBox de forma idempotente según la generación de Enterprise Linux: EL6 utiliza rsyslog + logrotate y EL7+ utiliza journald.

## Reglas OrangeBox

Las reglas personalizadas utilizan IDs propios y aprovechan, cuando es posible, los eventos y SIDs nativos de Wazuh.

La arquitectura actual incluye detecciones para:

- autenticación SSH, SUDO y SU;
- fuerza bruta y correlación de login exitoso;
- cambios críticos de configuración;
- firewall y reconocimiento de red;
- escaneo TCP, SYN flood y posible DoS distribuido;
- ataques y reconocimiento web;
- archivos temporales y ejecutables sospechosos;
- reglas y firmas experimentales para investigación de webshells.

Las reglas y sus decisiones de diseño están documentadas individualmente en `configuration/rules/`.

## Alertamiento

La arquitectura de alertamiento separa detección y entrega:

```text
evento
  ↓
Wazuh / ruleset nativo
  ↓
regla OrangeBox
  ↓
alerta
  ├── correo HTML personalizado
  └── Active Response cuando corresponde
```

La integración de correo conserva evidencia FIM, agrupa alertas no inmediatas y aplica deduplicación específica para determinados eventos SSH.

Las reglas pertenecientes al grupo `privilege_escalation_root` se consideran alertas inmediatas y no esperan la ventana de agrupación.

## Seguridad del repositorio

Este repositorio puede contener configuraciones de seguridad utilizadas en infraestructura real.

**Nunca almacenar en GitHub:**

- contraseñas;
- tokens o API keys;
- claves privadas;
- certificados privados;
- credenciales SMTP;
- secretos de integraciones;
- información sensible específica de una infraestructura.

Los valores dependientes del entorno deben mantenerse como variables, placeholders o archivos gestionados fuera del repositorio cuando corresponda.

## Documentación como historial de ingeniería

La documentación de cada componente debe intentar conservar:

1. propósito;
2. arquitectura;
3. comportamiento actual;
4. razón de cada decisión importante;
5. dependencias;
6. falsos positivos encontrados;
7. alternativas probadas y descartadas;
8. pruebas realizadas;
9. relación con otras reglas, correo y Active Response;
10. limitaciones conocidas;
11. cambios futuros previstos.

Esto permite que el repositorio sirva tanto para desplegar como para entender la evolución de la solución.

## Estado del proyecto

Proyecto en desarrollo activo. La base actual corresponde a una configuración real que está siendo consolidada y probada antes de convertirla en una plataforma más automatizada y reutilizable.

---

**OrangeBox Enterprise Infrastructure** — Infraestructura Linux Enterprise, Seguridad y Alta Disponibilidad en Chile.

[🌐 www.orangebox.cl](https://www.orangebox.cl/)
