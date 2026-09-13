# OrangeBox Auth

Documentación de `orangebox-auth.xml`.

## Para qué sirve

Estas reglas cubren eventos de autenticación que merecen más atención que las reglas nativas de Wazuh:

- login SSH exitoso;
- `su` a `root`;
- `sudo` hacia `root` fuera de la whitelist;
- fuerza bruta SSH que termina en login exitoso;
- ráfagas de fallos SSH desde redes internas.

La idea es simple: **no reemplazar Wazuh, sino agregar contexto a eventos que ya detecta**.

## Reglas

### 10001 — Login SSH exitoso

Parte de la regla nativa `5715`, pero no acepta cualquier mensaje que empiece con `Accepted`.

Durante las pruebas apareció un falso positivo importante:

```text
Accepted key RSA SHA256:... found at authorized_keys:1
```

Ese mensaje no significa que alguien haya abierto una sesión. Por eso `10001` busca explícitamente los formatos de login:

- `Accepted publickey for ...`
- `Accepted password for ...`
- `Accepted keyboard-interactive/pam for ...`

Se usa PCRE2 con `<regex>` porque necesitamos alternativas y el texto a buscar está dentro del `full_log`. Intentar usar `srcip` como `<field>` tampoco sirve: `srcip` es un campo estático de Wazuh.

**Nivel 13:** un login SSH exitoso es un evento que queremos ver, aunque no sea necesariamente malicioso.

### 10004 — `su` a root

Parte de `5501` y busca una sesión `su` cuyo usuario sea `root`.

No intenta decidir si el `su` era legítimo. Solo marca la elevación para que quede visible y pueda ser correlacionada por la integración de correo.

### 10005 — `sudo` a root fuera de whitelist

Parte de `5402`, que contiene el comando ejecutado.

La whitelist está dentro de la propia condición mediante `negate="yes"`. Esto es intencional: una regla posterior con `level=0` no deshace una alerta que `10005` ya generó.

La whitelist se controla por **comando**, no por UID, usuario ni proceso. Esto evita confiar en que una cuenta concreta sea siempre segura.

Los comandos autorizados corresponden a los binarios observados en la política sudo de Zimbra. `zmstat-fd` permite argumentos porque así está definido en sudoers; el resto se mantiene exacto.

### 10006 — Brute force SSH seguido de login exitoso

Esta es una correlación, no otra detección de fuerza bruta.

La secuencia que se validó en el entorno real fue:

```text
5760 → 5763 → 10001 → 10006
```

`5763` representa la detección efectiva de múltiples fallos de autenticación usada en las pruebas. Se consideró `5720`, pero no es la ruta que se disparó con los fallos probados.

`10006` exige:

- que el evento actual sea `10001`;
- que exista previamente `5763`;
- que sea la misma IP de origen.

El resultado es la alerta que realmente importa: **alguien probó varias credenciales y después consiguió entrar**.

La correlación fue validada primero con una regla temporal `19999`. Una vez comprobada, se reemplazó por `10006`.

### 10007 — Posible movimiento lateral

Parte de `5712`, que detecta una ráfaga de intentos contra usuarios inexistentes.

Solo se eleva cuando el origen pertenece a las redes internas contempladas actualmente:

- `192.168.*`
- `10.8.*`

La razón es operacional: muchos ataques SSH externos son ruido habitual de Internet. Una ráfaga equivalente desde dentro de la infraestructura merece otra lectura.

## Whitelist

Las excepciones usan IDs `20000–29999` y están al final del archivo.

Actualmente existen excepciones para logins SSH legítimos desde servidores BackupPC y para el SFTP automatizado de `certcoopeuch`.

No existe una whitelist por UID para Zimbra. Esa decisión fue reemplazada por la whitelist por comando de `10005`.

## Convención

- `10000–19999`: detecciones OrangeBox.
- `20000–29999`: excepciones/whitelists.
- Las reglas nativas de Wazuh no se modifican.
- Cuando es posible, OrangeBox se engancha como regla hija de una regla nativa.

## Dependencias

Las reglas dependen de eventos nativos de Wazuh, principalmente `5712`, `5715`, `5501`, `5402` y `5763`.

Si Wazuh cambia esas reglas en una futura versión, hay que revisar las correlaciones antes de actualizar producción.
