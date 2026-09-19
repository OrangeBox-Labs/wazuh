---
title: "Wazuh: cómo crear una regla sin inventar la rueda"
description: "Tutorial corto y práctico para construir, probar y desplegar una regla personalizada de Wazuh usando un caso real."
date: 2026-09-19
tags: ["wazuh", "seguridad", "linux", "deteccion", "reglas"]
categories: ["seguridad", "monitoreo"]
---

# Wazuh: cómo crear una regla sin inventar la rueda

Crear una regla de Wazuh no parte por abrir un XML y rezarle a los regex. 😈

El camino correcto es:

```text
evento real
   ↓
ver qué regla nativa lo detecta
   ↓
crear una regla hija
   ↓
probar con wazuh-logtest
   ↓
desplegar
```

Vamos a hacerlo con una regla real de OrangeBox.

## 1. Primero busca qué está detectando Wazuh

Supongamos que queremos detectar **fallos SSH desde nuestra red interna**.

Antes de escribir nada, buscamos qué regla nativa procesa esos eventos:

```bash
grep -Rni '<rule id="5712"' /var/ossec/ruleset/rules/
```

La idea es encontrar la definición de la regla nativa y entender qué evento produce, qué campos decodifica y qué podemos reutilizar.

También podemos buscar por texto:

```bash
grep -Rni 'Failed password' /var/ossec/ruleset/rules/
```

No editamos nada dentro de `/var/ossec/ruleset/`. Es el ruleset oficial de Wazuh y una actualización puede sobrescribirlo.

La documentación oficial recomienda colocar las reglas personalizadas en:

```text
/var/ossec/etc/rules/
```

En nuestro caso además las mantenemos versionadas en Git.

## 2. Construimos la regla

La regla OrangeBox que usamos para este caso es la **10007**:

```xml
<rule id="10007" level="13">
    <if_sid>5712</if_sid>
    <match>from 192.168.|from 10.8.</match>
    <description>ALERTA: Posible movimiento lateral. Rafaga de fallos SSH desde la red interna.</description>
    <group>authentication_failed,lateral_movement,attack,orangebox_auth,privilege_escalation_root,</group>
</rule>
```

La gracia está en entender cada pieza:

- `id="10007"`: ID de nuestra regla.
- `level="13"`: severidad que tendrá la alerta.
- `if_sid>5712</if_sid>`: solo se evalúa si antes coincidió la regla SSH 5712.
- `match`: agregamos nuestra condición: el evento debe venir de `192.168.x.x` o `10.8.x.x`.
- `description`: qué verá el operador.
- `group`: categorías que podremos usar posteriormente para reportes, integraciones y correlaciones.

No estamos reemplazando la regla 5712. Estamos construyendo una **regla hija** que agrega contexto a un evento que Wazuh ya sabe reconocer.

## 3. ¿Dónde ponemos el archivo?

En nuestro proyecto:

```text
configuration/
└── rules/
    └── orangebox-auth.xml
```

En el Wazuh Manager:

```text
/var/ossec/etc/rules/orangebox-auth.xml
```

Nuestro `ossec.conf` carga explícitamente ese directorio:

```xml
<rule_dir>etc/rules</rule_dir>
```

Así mantenemos separadas las reglas oficiales de Wazuh de las reglas propias de OrangeBox.

## 4. Probamos antes de reiniciar nada

Acá entra el amigo que evita horas de puteadas:

```bash
/var/ossec/bin/wazuh-logtest
```

Pegamos **el evento real**, no uno inventado:

```text
Sep 19 03:50:01 servidor sshd[12345]: Failed password for invalid user prueba from 192.168.1.50 port 54321 ssh2
```

Y miramos las tres fases.

La importante para nosotros es la tercera:

```text
**Phase 3: Completed filtering (rules).
    id: '10007'
    level: '13'
    description: 'ALERTA: Posible movimiento lateral. Rafaga de fallos SSH desde la red interna.'
```

Si termina en 5712 y nunca llega a 10007, la regla no está haciendo lo que pensamos.

Si devuelve otra regla, tampoco hay que adivinar: volvemos a mirar el evento y la cadena de reglas.

## 5. ¿Y si uso regex?

Primero prueba si `match`, `field`, `user`, `srcip` u otra condición simple resuelve el problema.

Cuando necesitas una expresión más compleja, ahí sí entra `pcre2`:

```xml
<regex type="pcre2">...</regex>
```

No metas un regex de 14 líneas porque te dio confianza después del tercer café. 😂

Primero haz que coincida con el evento real y después endureces la condición.

## 6. Cuando logtest funciona, recién desplegamos

Guardar el archivo es suficiente para probarlo con `wazuh-logtest`.

Para que el `wazuh-manager` que procesa producción cargue la modificación:

```bash
systemctl restart wazuh-manager
```

Después volvemos a provocar o esperar el evento real y verificamos que la alerta generada tenga:

- el ID correcto;
- el nivel correcto;
- la descripción esperada;
- los grupos esperados;
- y, si corresponde, la respuesta automática configurada.

## La receta corta

Cuando tengas que crear una regla nueva:

```text
1. Consigue el evento real.
2. Ejecuta wazuh-logtest.
3. Averigua qué decoder y regla nativa lo procesan.
4. Busca la definición en /var/ossec/ruleset/rules/.
5. Crea tu regla en /var/ossec/etc/rules/.
6. Hazla hija de la regla existente cuando corresponda.
7. Prueba otra vez con wazuh-logtest.
8. Recién entonces reinicia wazuh-manager.
```

Eso es todo.

La parte difícil viene después, cuando descubres que el log que tenías:

```text
by (uid=0)
```

en producción era:

```text
by apache(uid=0)
```

y pasas una hora mirando el regex preguntándote por qué Wazuh te odia. 🤣

Pero esa es otra historia.

---

**Documentación oficial:**

- [Custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)
- [Rules syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [Testing decoders and rules](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html)
- [wazuh-logtest](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)
