---
title: "Wazuh: cómo crear una regla desde cero (sin inventar la rueda)"
description: "Una guía práctica para entender qué hace Wazuh, cómo fluye un evento desde un agente hasta una alerta y cómo construir y probar una regla personalizada."
date: 2026-09-19
tags: ["wazuh", "seguridad", "linux", "deteccion", "reglas", "logtest"]
categories: ["seguridad", "monitoreo"]
---

# Wazuh: cómo crear una regla desde cero (sin inventar la rueda)

Cuando uno empieza con Wazuh, tarde o temprano aparece esta pregunta:

> "Ya tengo los logs. ¿Y ahora cómo hago para que Wazuh detecte lo que me importa?"

La respuesta está en las reglas.

Pero antes de crear una, conviene entender qué estamos construyendo. Una regla no es simplemente un XML con una regex: es una condición que le dice a Wazuh **qué evento nos interesa, qué tan importante es y qué contexto queremos darle**.

Y cuando esa regla coincide, puede convertirse en el disparador de todo lo que viene después: una alerta, una entrada en el dashboard, una integración, un correo o una acción automática como <code>firewall-drop</code>, según cómo configuremos el Manager.

La idea de este artículo es hacerlo con peras y manzanas: entender primero cómo llega un evento a Wazuh y después construir una regla real.

---

## ¿Qué problema resuelve Wazuh?

En una infraestructura real tienes logs por todas partes:

~~~text
SSH
Apache
Nginx
Postfix
MariaDB
systemd / journald
firewalld
iptables
aplicaciones
Windows Event Log
etc.
~~~

El problema es que un log por sí solo es solamente información.

Este mensaje:

~~~text
Failed password for root from 192.168.1.50 port 54321 ssh2
~~~

te dice que algo pasó.

Pero alguien tiene que decidir:

- ¿esto es normal o sospechoso?
- ¿es un evento aislado o forma parte de un ataque?
- ¿qué severidad tiene?
- ¿debo avisarle a alguien?
- ¿debo bloquear el origen?
- ¿debo relacionarlo con otros eventos?

Ahí entra Wazuh.

Wazuh recopila información de endpoints, aplicaciones y dispositivos de red, la centraliza en el servidor y la analiza mediante **decoders y reglas**. Esa capacidad permite convertir miles de líneas de logs en eventos de seguridad que podemos buscar, investigar y automatizar.

---

## ¿Qué hace el Wazuh Agent?

El **Wazuh Agent** es el componente que instalamos en el servidor que queremos vigilar.

Su trabajo no es "decidir si hubo un ataque". Su trabajo principal es **recopilar información del sistema y enviarla al Wazuh Manager**.

Por ejemplo, podemos configurarlo para leer:

~~~text
/var/log/secure
/var/log/httpd/access_log
/var/log/httpd/error_log
~~~

o directamente:

~~~text
journald
~~~

También puede generar información propia mediante otros módulos, como FIM, inventario, SCA o detección de vulnerabilidades.

En términos simples:

~~~text
SERVIDOR
┌───────────────────────────────┐
│ SSH / Apache / systemd / etc. │
│             ↓                 │
│        Wazuh Agent            │
└──────────────┬────────────────┘
               │
               │ eventos
               ↓
        Wazuh Manager
~~~

El Agent hace de **sensor y transportista**.

No necesitamos entrar servidor por servidor para revisar manualmente todos sus logs. El agente los recopila y los envía al punto central de análisis.

Y no todo requiere Agent: Wazuh también puede recibir logs por otros mecanismos, como syslog o integraciones con APIs.

---

## ¿Qué hace el Wazuh Manager?

El **Wazuh Manager** es donde ocurre la parte interesante.

Recibe los eventos de los agentes y los pasa por una cadena de análisis:

~~~text
Evento
  ↓
Pre-decoding
  ↓
Decoder
  ↓
Reglas
  ↓
Alerta
  ↓
Integraciones / Active Response / Dashboard / Reportes
~~~

### 1. Pre-decoding

Primero Wazuh identifica información básica del mensaje:

~~~text
fecha
hostname
programa
evento completo
~~~

### 2. Decoder

Después intenta entender la estructura del evento y separar información útil.

Por ejemplo, de esto:

~~~text
Failed password for root from 192.168.1.50 port 54321 ssh2
~~~

podemos terminar con campos como:

~~~text
user     = root
srcip    = 192.168.1.50
srcport  = 54321
~~~

El decoder convierte texto en información que las reglas pueden utilizar.

### 3. Rules

Ahora sí entra nuestra estrella.

Una regla evalúa el evento y pregunta:

~~~text
¿Esto coincide con lo que quiero detectar?
~~~

Puede utilizar texto, campos decodificados, IDs de otras reglas, grupos y condiciones de correlación.

Una regla también puede asignar un **nivel de severidad**, describir el evento, asociarlo a grupos o MITRE ATT&CK y servir como condición para acciones posteriores.

Por ejemplo:

~~~text
1 fallo SSH
      ↓
evento detectado

20 fallos desde la misma IP
      ↓
regla de fuerza bruta
      ↓
alerta nivel 11
      ↓
Active Response
      ↓
firewall-drop
~~~

La regla no necesariamente tiene que bloquear nada por sí sola. En Wazuh, el **Active Response se configura en el Manager** y puede usar una regla o conjunto de reglas como disparador.

---

## ¿Qué es entonces una regla Wazuh?

Pensemos en una regla como una pregunta.

Por ejemplo:

> "¿Este evento corresponde a un fallo SSH?"

O algo más interesante:

> "¿La misma IP produjo muchos fallos SSH en poco tiempo?"

O incluso:

> "¿Se creó un archivo PHP sospechoso en /tmp?"

La regla convierte esa pregunta en condiciones que Wazuh puede evaluar.

Por eso una regla puede ser tan sencilla como:

~~~text
si aparece este texto → alerta
~~~

o bastante más inteligente:

~~~text
si la regla 5712 coincide
y la IP es de nuestra red interna
→ generar una nueva alerta
~~~

o:

~~~text
si la misma IP
genera 12 eventos
en 90 segundos
tocando puertos diferentes
→ posible escaneo de puertos
~~~

Ahí es donde Wazuh deja de ser simplemente un colector de logs y empieza a comportarse como un sistema de detección.

---

## ¿Cómo sabemos qué regla necesitamos?

Acá viene la primera regla de oro:

## No empieces escribiendo XML.

Empieza por **el evento real**.

Supongamos que queremos detectar algo relacionado con SSH.

Primero tenemos que preguntarnos:

~~~text
¿qué está ocurriendo realmente?
~~~

Buscamos el log en el agente.

Por ejemplo:

~~~text
Sep 19 03:50:01 servidor sshd[12345]: Failed password for invalid user prueba from 192.168.1.50 port 54321 ssh2
~~~

Ahora no inventamos una regex.

Primero queremos saber:

> "¿Wazuh ya entiende este evento?"

---

## <code>wazuh-logtest</code>: nuestro mejor amigo

En el Wazuh Manager ejecutamos:

~~~bash
/var/ossec/bin/wazuh-logtest
~~~

Y pegamos exactamente el evento real.

Wazuh nos muestra tres fases.

### Phase 1: ¿cómo entra el log?

Aquí vemos información básica:

~~~text
timestamp
hostname
program_name
full event
~~~

Es simplemente la forma en que Wazuh recibe el mensaje.

### Phase 2: ¿qué entendió?

Aquí vemos el resultado del decoder.

Por ejemplo:

~~~text
name: 'sshd'
user: 'prueba'
srcip: '192.168.1.50'
~~~

Esta fase nos dice si Wazuh ya sabe separar lo que necesitamos.

Y esto es importantísimo.

Si el decoder ya nos entrega <code>srcip</code>, no tiene sentido hacer una regex gigantesca para volver a extraer la IP.

Aprovechamos lo que Wazuh ya sabe.

### Phase 3: ¿alguna regla coincide?

Aquí Wazuh nos muestra qué reglas terminaron haciendo match.

Por ejemplo:

~~~text
id: '5712'
level: '5'
description: 'sshd: authentication failed.'
~~~

¡Bingo!

Eso significa que **ya existe una regla que reconoce este evento**.

Y esa información nos ahorra bastante trabajo.

---

## Antes de crear una regla: busca si ya existe

Esta es probablemente la costumbre más útil para empezar con Wazuh:

**no reinventes una detección que Wazuh ya tiene.**

Si <code>wazuh-logtest</code> te muestra:

~~~text
id: '5712'
~~~

puedes buscar la definición:

~~~bash
grep -Rni '<rule id="5712"' /var/ossec/ruleset/rules/
~~~

También puedes buscar por descripción o por alguna cadena característica:

~~~bash
grep -Rni 'authentication failed' /var/ossec/ruleset/rules/
~~~

Las reglas oficiales están en:

~~~text
/var/ossec/ruleset/rules/
~~~

Ese directorio sirve para **leer y estudiar** las reglas que Wazuh ya trae.

No conviene editar esos archivos directamente porque las actualizaciones pueden reemplazarlos.

Para nuestras reglas usamos:

~~~text
/var/ossec/etc/rules/
~~~

En este proyecto, además, las mantenemos versionadas en Git.

---

## ¿Y si ya existe una regla que hace casi lo que necesito?

Perfecto.

Ese suele ser el mejor escenario.

En lugar de crear otra detección desde cero, hacemos una **regla hija** y agregamos la condición que nos falta.

Por ejemplo, Wazuh ya sabe detectar:

~~~text
5712 = fallo SSH
~~~

Pero nosotros queremos algo más específico:

> "Quiero detectar una ráfaga de fallos SSH proveniente de nuestras redes internas."

Nuestra regla OrangeBox <code>10007</code> hace exactamente eso:

~~~xml
<rule id="10007" level="13">
    <if_sid>5712</if_sid>
    <match>from 192.168.|from 10.8.</match>
    <description>ALERTA: Posible movimiento lateral. Rafaga de fallos SSH desde la red interna.</description>
    <group>authentication_failed,lateral_movement,attack,orangebox_auth,privilege_escalation_root,</group>
</rule>
~~~

Traducida a lenguaje humano:

~~~text
Si Wazuh detectó un fallo SSH (5712)
        +
el evento viene de 192.168.x.x o 10.8.x.x
        ↓
genera la alerta OrangeBox 10007
~~~

Eso es una regla hija.

No reemplazamos <code>5712</code>.

No duplicamos toda la detección SSH.

Simplemente agregamos **nuestro criterio de seguridad** sobre una detección que Wazuh ya sabe hacer.

---

## ¿Qué hace cada parte?

Vamos por partes:

~~~xml
<rule id="10007" level="13">
~~~

<code>id</code> identifica nuestra regla.

<code>level</code> determina la severidad que tendrá el evento cuando haga match.

Luego:

~~~xml
<if_sid>5712</if_sid>
~~~

significa:

> "Esta regla depende de que primero haya coincidido la regla 5712."

Después:

~~~xml
<match>from 192.168.|from 10.8.</match>
~~~

agrega nuestra condición.

Finalmente:

~~~xml
<description>...</description>
~~~

es la descripción que veremos en la alerta.

Y:

~~~xml
<group>...</group>
~~~

clasifica la alerta para poder utilizar esos grupos posteriormente en consultas, reportes, integraciones y lógica de automatización.

No hace falta memorizar todas las etiquetas el primer día.

Lo importante es entender la idea:

~~~text
evento
  ↓
condiciones
  ↓
regla
  ↓
alerta
~~~

---

## ¿Dónde guardamos la regla?

En nuestro Manager:

~~~text
/var/ossec/etc/rules/orangebox-auth.xml
~~~

En nuestro repositorio:

~~~text
configuration/
└── rules/
    └── orangebox-auth.xml
~~~

Nuestro <code>ossec.conf</code> carga las reglas personalizadas desde:

~~~xml
<rule_dir>etc/rules</rule_dir>
~~~

La separación es deliberada:

~~~text
/var/ossec/ruleset/     → reglas oficiales de Wazuh
/var/ossec/etc/rules/   → reglas personalizadas
~~~

Así nuestras reglas quedan separadas del ruleset que entrega Wazuh.

---

## ¿Cuándo necesito un decoder?

Esta pregunta aparece mucho al empezar.

La respuesta sencilla:

**si el evento llega en un formato que Wazuh no sabe interpretar, puede que necesites un decoder.**

Por ejemplo, si una aplicación escribe:

~~~text
MAGICAPP user=felipe action=login src=10.20.30.40 result=failed
~~~

y Wazuh no sabe extraer:

~~~text
user
action
src
result
~~~

primero podemos crear un decoder.

Después hacemos una regla sobre esos campos.

La relación es:

~~~text
log
 ↓
decoder
 ↓
campos
 ↓
regla
 ↓
alerta
~~~

Si el decoder ya existe, perfecto: saltamos ese paso.

---

## Probar, probar y volver a probar

Una regla no está terminada porque el XML "se vea bonito".

La probamos con:

~~~bash
/var/ossec/bin/wazuh-logtest
~~~

y usamos **el log real**.

Para nuestro ejemplo queremos terminar en algo parecido a:

~~~text
**Phase 3: Completed filtering (rules).

id: '10007'
level: '13'
description: 'ALERTA: Posible movimiento lateral. Rafaga de fallos SSH desde la red interna.'
~~~

Si termina en <code>5712</code> y nunca llega a <code>10007</code>, nuestra condición adicional no está coincidiendo.

Si no hay decoder útil, tenemos otro problema.

Si aparece una regla diferente, hay que mirar por qué esa regla hizo match.

<code>wazuh-logtest</code> utiliza las mismas reglas del motor de análisis, por lo que es una herramienta muy útil para escribir y depurar reglas y decoders.

---

## ¿Y después qué?

Cuando <code>logtest</code> entrega exactamente lo que esperábamos, recién ahí aplicamos el cambio al Manager:

~~~bash
systemctl restart wazuh-manager
~~~

A partir de ese momento, los eventos reales serán analizados con la nueva regla.

Y recién entonces podemos decidir qué hacer con esa alerta:

~~~text
Regla
 ↓
alerta
 ├── Dashboard
 ├── correo
 ├── integración
 ├── reporte
 └── Active Response
       ↓
    firewall-drop
~~~

Una regla puede detectar.

La configuración del resto del stack decide **qué hacemos con esa detección**.

---

## La receta completa

Cuando tengas una necesidad nueva, piensa así:

~~~text
1. ¿Qué quiero detectar?
2. ¿Dónde ocurre ese evento?
3. ¿El Wazuh Agent está recopilando ese log?
4. ¿Tengo un evento real para probar?
5. ¿Qué muestra Phase 1?
6. ¿Qué decoder aparece en Phase 2?
7. ¿Existe una regla que ya reconoce el evento?
8. Si existe, ¿puedo usarla como base?
9. Si no existe, ¿necesito una regla nueva o un decoder?
10. Creo la regla en /var/ossec/etc/rules/.
11. La pruebo con wazuh-logtest.
12. Cuando funciona, reinicio el Manager.
13. Recién después agrego automatización, correo o Active Response.
~~~

Y con eso ya tienes la idea fundamental.

Wazuh no consiste en llenar una carpeta de XML hasta que aparezca una alerta.

Consiste en tomar **eventos reales**, entender cómo Wazuh los interpreta y construir detecciones sobre esa información.

Primero hacemos que Wazuh entienda el evento.

Después hacemos que lo detecte.

Y finalmente decidimos qué hacer con él.

Porque escribir una regex es fácil.

**Conseguir que Wazuh detecte exactamente lo que querías detectar, y no cualquier cosa que se parezca, es la verdadera pega.** 😈

---

## Documentación oficial

- [Data analysis](https://documentation.wazuh.com/current/user-manual/ruleset/index.html)
- [Log data collection](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html)
- [How log data collection works](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/how-it-works.html)
- [Custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [Rules syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [Testing decoders and rules](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)
- [wazuh-logtest](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
