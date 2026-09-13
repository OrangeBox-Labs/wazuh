# `wazuh.install.rhel.sh`

## Qué hace

Script interactivo para preparar `/var/ossec` en un volumen lógico dedicado e instalar el agente Wazuh.

El motivo principal no es "instalar Wazuh porque sí". Está pensado para servidores donde `/var` puede tener políticas de montaje restrictivas, especialmente `noexec`, y necesitamos aislar `/var/ossec` en su propio filesystem.

## Flujo

```text
verificar /var/ossec
        ↓
detectar VG de /var
        ↓
comprobar espacio
        ↓
crear LV wazuh de 100 MB
        ↓
formatear ext4
        ↓
montar /var/ossec
        ↓
actualizar fstab
        ↓
confirmar datos del agente
        ↓
instalar RPM Wazuh
        ↓
habilitar e iniciar wazuh-agent
```

## Antes de tocar el disco

El script primero comprueba si `/var/ossec` ya está montado.

Si lo está, pregunta explícitamente si debe desmontarlo.

También comprueba si el directorio existe pero contiene archivos sin estar montado. En ese caso pregunta antes de eliminar contenido.

Esto es importante porque aquí ya no estamos hablando de editar un XML: estamos tocando almacenamiento. Un `rm -rf` sin confirmación sería una idea bastante mala.

## LVM

El script busca el LV que contiene `/var` y obtiene su Volume Group.

Después exige espacio libre suficiente y crea:

```text
LV: wazuh
Tamaño: 100 MB
Filesystem: ext4
Mountpoint: /var/ossec
```

El tamaño está fijado actualmente en el script. No existe una variable `LV_SIZE` separada aunque la documentación histórica del directorio `tools` la mencione.

## Opciones de montaje

La entrada agregada a `/etc/fstab` utiliza:

```text
defaults,nosuid,nodev
```

Esto mantiene dos restricciones de seguridad útiles:

- `nosuid`: evita que archivos con SUID/SGID en ese filesystem tengan efecto de elevación.
- `nodev`: impide utilizar dispositivos especiales almacenados allí.

La decisión es mantener estas restricciones sin usar `noexec` en `/var/ossec`, porque Wazuh necesita ejecutar componentes desde su instalación.

## Rollback básico

Si `mount -a` falla, el script elimina la entrada que acaba de agregar a `/etc/fstab` y aborta.

No intenta inventar una recuperación mágica del almacenamiento. Si falla algo más serio, se detiene y deja el problema para revisión.

## Datos del agente

Antes de instalar el RPM pregunta por:

- nombre del agente;
- IP del Manager;
- grupo del agente;
- confirmación final.

Valores por defecto actuales:

```text
Manager: 192.168.200.160
Grupo:   OrangeBox
Versión: 4.14.5-1.x86_64
```

El nombre del agente propone el hostname del servidor.

## Instalación

Descarga directamente el RPM oficial de Wazuh:

```text
wazuh-agent-4.14.5-1.x86_64.rpm
```

La instalación recibe las variables `WAZUH_MANAGER`, `WAZUH_AGENT_NAME` y `WAZUH_AGENT_GROUP` mediante el entorno del proceso `rpm`.

## Servicio

El script soporta dos escenarios:

- sistemas con `systemd`;
- sistemas antiguos que utilizan SysV init.

Con systemd utiliza:

```text
systemctl enable --now wazuh-agent
```

Sin systemd intenta utilizar `chkconfig` o `update-rc.d` y después reinicia el servicio.

## Por qué es interactivo

Este script modifica almacenamiento, `/etc/fstab` y la instalación del agente.

No se diseñó como un script ciego para ejecutarlo con `curl | bash` mientras uno mira para otro lado.

Las confirmaciones permiten revisar el hostname, Manager, grupo y operación completa antes de hacer cambios.

## Validación posterior

Después de instalar se recomienda comprobar:

```bash
mount | grep /var/ossec
systemctl status wazuh-agent
journalctl -u wazuh-agent -f
```

Y validar desde el Manager que el agente aparece en el grupo esperado.

## Dependencias

El servidor debe disponer, como mínimo, de:

- acceso root;
- LVM (`lvm2`);
- un LV para `/var`;
- al menos 100 MB libres en el VG;
- `mkfs.ext4`;
- herramientas de montaje;
- `curl`;
- RPM;
- systemd o SysV init según el sistema.

## Advertencias

Este script **formatea un LV nuevo**.

No ejecutarlo en un servidor de producción sin revisar primero qué contiene el VG y qué ocurre con `/var/ossec`.

También hay una diferencia importante entre este script y la documentación antigua de `tools/README.md`: el nombre real del archivo es `wazuh.install.rhel.sh`, y los valores de tamaño/versión están actualmente definidos directamente en el script.

La documentación de este archivo describe el comportamiento real del script versionado, no el comportamiento que alguna versión antigua del README dice que debería tener.
