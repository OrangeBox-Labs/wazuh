# OrangeBox Hardening

Documentación de `orangebox-hardening.xml`.

## Para qué sirve

Estas reglas usan Wazuh FIM para detectar cambios o eliminaciones en archivos que pueden afectar identidad, autenticación, persistencia, red o escalamiento de privilegios.

No intentan reemplazar FIM: **FIM detecta el cambio y estas reglas deciden cuándo ese cambio merece una alerta OrangeBox**.

## Cambios detectados

### 10030–10036 — Configuración crítica

Estas reglas cubren modificaciones en:

- identidad: `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` y archivos asociados;
- SSH;
- SUDO;
- PAM;
- SYSTEMD;
- CRON/ANACRON;
- red, DNS y montajes.

Todas parten del evento FIM `550` (archivo modificado).

### 10037 — Firewall

Detecta cambios en configuraciones de Shorewall, firewalld, UFW, CSF, nftables y otras rutas de firewall contempladas.

`/etc/sysconfig/iptables` queda fuera porque necesita un tratamiento distinto.

### 10038 — Cambio real en iptables

`iptables-save` puede modificar `/etc/sysconfig/iptables` aunque nadie haya cambiado una regla: pueden variar timestamps y contadores de paquetes.

Eso generaba ruido. La regla actual mira `changed_content` y solo alerta cuando el diff contiene líneas de reglas iptables (`-A`, `-C`, `-D`, `-I`, `-R`, `-F`, `-N`, `-X`, `-P`).

Así se diferencia entre:

```text
guardar el firewall
```

y

```text
cambiar el firewall
```

Se probó específicamente este comportamiento antes de dejar la regla.

### 10046–10047 — Integridad de comandos sudo autorizados

Los comandos incluidos en la whitelist de `orangebox-auth.xml` son una superficie de escalamiento: si un atacante modifica uno de esos binarios, el comando podría seguir pareciendo autorizado ante sudo.

Por eso:

- `10046` alerta cuando uno de esos archivos es modificado (`550`);
- `10047` alerta cuando es eliminado (`553`).

La misma política se aplica a los componentes equivalentes bajo:

- `/opt/zimbra`;
- `/opt/zextras` para Carbonio CE.

Ambas reglas son nivel 15 y pertenecen a `privilege_escalation_root` para que la integración de correo las trate como críticas.

La lista debe mantenerse sincronizada con la whitelist de comandos de `10005`.

### 10048–10049 — Persistencia de credenciales SSH

Estas reglas vigilan `authorized_keys` bajo:

```text
/root/.ssh/authorized_keys
/home/<usuario>/.ssh/authorized_keys
```

El agente monitoriza los directorios `.ssh` con `whodata="yes"` y sin `report_changes`, por lo que podemos conservar la atribución de usuario/proceso sin mandar el contenido de las claves en el diff.

- `10048` detecta modificación de `authorized_keys` (`550`);
- `10049` detecta eliminación de `authorized_keys` (`553`).

El objetivo no es asumir que toda modificación es maliciosa. Una clave puede cambiar legítimamente. La regla existe para que ese cambio quede claramente identificado como un evento de persistencia de credenciales y pueda correlacionarse con el contexto de autenticación correspondiente.

## Eliminaciones

Las reglas `10040–10045` cubren la eliminación de los mismos grupos de configuración protegidos mediante el evento FIM `553`.

Eliminar un archivo crítico se trata con mayor severidad que modificarlo, porque puede dejar el control de acceso, autenticación o persistencia directamente inutilizado.

## Por qué no hay whitelist actualmente

No se agregaron excepciones solo para hacer desaparecer alertas. Si una operación legítima genera ruido, primero se valida qué cambió y por qué.

Cuando realmente sea necesaria una excepción, debe usar un ID `20000–29999`, ser específica y quedar al final del archivo.

## Decisiones importantes

### No filtrar por UID o proceso

El cambio relevante es el archivo y su contenido, no quién lo modificó. Filtrar por UID o proceso podría ocultar una modificación maliciosa realizada desde una cuenta o proceso comprometido.

Who-Data se utiliza justamente para **observar y atribuir**, no para convertir el origen en una whitelist.

### FIM primero, regla después

Estas reglas aprovechan los eventos nativos `550` y `553`. No se crea otro mecanismo paralelo para vigilar los mismos archivos.

## Dependencias

- Wazuh FIM/syscheck.
- Evento `550`: archivo modificado.
- Evento `553`: archivo eliminado.
- Who-Data para las rutas críticas configuradas en `agent.conf`.

Si cambia el formato de los eventos FIM en una futura versión de Wazuh, estas reglas deben volver a probarse.
