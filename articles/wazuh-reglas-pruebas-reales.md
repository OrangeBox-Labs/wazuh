---
title: "Wazuh: cómo crear una regla desde un log real"
description: "Tutorial práctico para entender el flujo de un evento, encontrar reglas existentes, crear una regla personalizada y probarla con wazuh-logtest."
date: 2026-09-19
tags: ["wazuh", "seguridad", "linux", "deteccion", "reglas"]
categories: ["seguridad", "monitoreo"]
---

# Wazuh: cómo crear una regla desde un log real

La forma más fácil de crear una regla Wazuh es **no empezar por la regla**.

Primero miramos qué está ocurriendo en un agente, encontramos el log real y dejamos que Wazuh nos muestre qué entiende de ese evento.

La película completa es:

```text
Agente
  ↓
log de la aplicación / sistema
  ↓
Wazuh Agent lo recopila
  ↓
Wazuh Manager recibe el evento
  ↓
decoder
  ↓
reglas
  ↓
alerta
```

Wazuh no adivina lo que pasa en el servidor. El agente tiene que estar configurado para recopilar esa fuente de logs, por ejemplo un archivo, journald o el log de una aplicación. citeturn407285search8turn407285search11

## 1. Empieza por el evento, no por el XML

Supongamos que encontramos en un servidor este evento:

```text
Sep 19 03:50:01 argos.jhg.cl systemd[1105281]: pam_unix(systemd-user:session): session opened for user apache(uid=48) by apache(uid=0)
```

La pregunta no es todavía "¿cómo hago la regex?".

La primera pregunta es:

**¿Qué hace Wazuh con este log?**

Para averiguarlo usamos:

```bash
/var/ossec/bin/wazuh-logtest
```

Pegamos exactamente el log real. Wazuh lo procesa en tres fases y nos muestra qué pudo extraer y qué reglas coincidieron. citeturn407285search0turn407285search1

## 2. Phase 1, Phase 2 y Phase 3: las tres pistas

### Phase 1: ¿Wazuh entiende la cabecera?

Aquí vemos cosas básicas como:

```text
timestamp
hostname
program_name
```

Por ejemplo:

```text
program_name: 'systemd'
```

No estamos creando reglas todavía. Solo estamos viendo cómo entra el evento.

### Phase 2: ¿qué decoder lo entiende?

Aquí Wazuh intenta convertir el texto del log en información utilizable: usuario, IP, programa, puerto y otros campos. Los decoders existen precisamente para separar el log en esos campos. citeturn407285search3turn407285search5

Esta fase es importante porque una regla puede trabajar sobre campos ya decodificados en vez de hacer una regex gigantesca sobre todo el log.

### Phase 3: ¿ya existe una regla para esto?

Acá está la pregunta que nos ahorra trabajo.

Podemos recibir algo como:

```text
id: '40101'
level: '12'
description: 'System user successfully logged to the system.'
```

Perfecto: **Wazuh ya tiene una regla que reconoce este evento**.

En ese caso no partimos de cero. Buscamos la definición de esa regla:

```bash
grep -Rni '<rule id="40101"' /var/ossec/ruleset/rules/
```

También podemos buscar por el texto de la regla o por alguna cadena característica del log:

```bash
grep -Rni 'System user successfully logged to the system' /var/ossec/ruleset/rules/
```

Las reglas oficiales y decoders de Wazuh están bajo `/var/ossec/ruleset/`. **No los editamos ahí**, porque el contenido de ese directorio puede cambiar con las actualizaciones. Para nuestras reglas usamos `/var/ossec/etc/`. citeturn407285search8turn407285search2

## 3. ¿Y si no existe una regla que haga lo que necesitamos?

Hay tres escenarios.

**Ya existe una regla útil:** hacemos una regla hija y agregamos nuestra condición.

**Existe el decoder, pero no una regla útil:** aprovechamos los campos que ya entrega el decoder y creamos nuestra regla.

**No existe un decoder útil:** primero creamos un decoder y después la regla.

Por eso conviene probar el log con `wazuh-logtest` **antes de escribir XML**. La propia documentación de Wazuh recomienda comprobar primero el decoder y las reglas actuales. citeturn407285search3

## 4. Nuestro ejemplo real: la regla 20006

En OrangeBox tuvimos un falso positivo con la regla nativa `40101`.

El log era:

```text
session opened for user apache(uid=48) by apache(uid=0)
```

Wazuh lo clasificaba como `40101`, nivel 12.

Pero en este caso el evento correspondía a una sesión `systemd-user` automática de Apache utilizada por procesos programados de Nextcloud.

No queríamos desactivar `40101`. Queríamos **excluir solamente este caso concreto**.

Ahí nace la regla personalizada `20006`:

```xml
<rule id="20006" level="0">
    <if_sid>40101</if_sid>
    <user>apache</user>
    <match>systemd-user:session</match>
    <regex type="pcre2">session opened for user apache(?:\(uid=\d+\))? by (?:apache)?\(uid=0\)</regex>
    <description>EXCEPCION: Sesion systemd-user automatica de Apache para procesos programados de Nextcloud.</description>
    <group>authentication_success,orangebox_exception,orangebox_whitelist,nextcloud,</group>
</rule>
```

Acá la regla dice, en castellano:

```text
Si primero coincidió 40101
Y el usuario es apache
Y el evento es systemd-user:session
Y el mensaje tiene este patrón
→ entonces este caso es una excepción y queda en nivel 0
```

El `<if_sid>40101</if_sid>` es la parte importante: **no estamos reemplazando la regla nativa**. Estamos agregando una condición más específica sobre un evento que Wazuh ya sabe reconocer.

## 5. ¿Dónde se guarda nuestra regla?

En el servidor:

```text
/var/ossec/etc/rules/orangebox-auth.xml
```

En nuestro repositorio:

```text
configuration/
└── rules/
    └── orangebox-auth.xml
```

Nuestro Manager carga las reglas personalizadas desde `etc/rules`. citeturn407285search2

La idea es mantener separado:

```text
/var/ossec/ruleset/   → reglas oficiales de Wazuh
/var/ossec/etc/rules/ → reglas nuestras
```

Así una actualización de Wazuh no debería comerse nuestras modificaciones. citeturn407285search8

## 6. Probar la regla: el paso que evita la magia negra

Guardamos el archivo y volvemos a ejecutar:

```bash
/var/ossec/bin/wazuh-logtest
```

Pegamos **el mismo evento real**.

Si todo está bien, Phase 3 debería terminar en:

```text
id: '20006'
level: '0'
description: 'EXCEPCION: Sesion systemd-user automatica de Apache para procesos programados de Nextcloud.'
```

Eso nos confirma que la regla coincide.

Y acá aparece una diferencia importante:

**que `wazuh-logtest` funcione no significa todavía que el Manager de producción haya cargado el cambio.**

Para probar reglas alcanza con guardar los archivos. Para que el Manager genere alertas usando la modificación hay que reiniciarlo:

```bash
systemctl restart wazuh-manager
```

Eso está documentado por Wazuh. citeturn407285search2

## La receta para cualquier regla

Cuando aparezca una necesidad nueva:

```text
1. Mira el log real en el agente.
2. Confirma que el agente esté recopilando esa fuente.
3. Pasa el evento exacto por wazuh-logtest.
4. Mira Phase 2: ¿hay decoder y campos útiles?
5. Mira Phase 3: ¿ya existe una regla que lo reconoce?
6. Si existe, úsala como base en vez de inventar otra desde cero.
7. Si no existe, crea la regla o el decoder que falte.
8. Guarda la regla en /var/ossec/etc/rules/.
9. Prueba otra vez con wazuh-logtest.
10. Cuando el resultado sea el esperado, reinicia el Manager.
```

Y recién después de eso vienen el correo, Active Response, dashboards, reportes y toda la parafernalia.

Primero **hacer que Wazuh entienda correctamente el evento**.

Después hacemos que haga cosas con él.

Porque escribir XML a tontas y a locas es fácil.

**Hacer que Wazuh detecte exactamente lo que querías y nada más... ahí está la gracia.** 😈

---

**Documentación oficial:**

- [Data analysis](https://documentation.wazuh.com/current/user-manual/ruleset/index.html)
- [Custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [Rules syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [Testing decoders and rules](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)
- [wazuh-logtest](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
