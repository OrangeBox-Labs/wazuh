# Scripts de Instalación y Configuración de Wazuh Agent

Este repositorio contiene scripts automatizados para la instalación y configuración del agente de Wazuh en entornos Linux con políticas de seguridad restrictivas (como /var montado con noexec).

## Requisitos Previos

- Sistema Operativo: CentOS 7 / RHEL 7 o superior
- Arquitectura: x86_64
- Permisos: Acceso root o sudo
- LVM: El directorio /var debe residir en un Volumen Lógico (LVM)
- Espacio: Al menos 100 MB libres en el Volume Group de /var

## Scripts Disponibles

### install-wazuh-agent.sh

Script principal que automatiza todo el proceso:

1. Verifica si /var/ossec ya está montado (evita conflictos)
2. Crea un volumen lógico dedicado de 100 MB para Wazuh
3. Formatea el volumen como ext4
4. Monta el volumen en /var/ossec con opciones seguras (defaults,nosuid,nodev)
5. Agrega la entrada correspondiente en /etc/fstab
6. Solicita confirmación para el nombre del agente y la IP del manager
7. Descarga e instala el agente Wazuh desde los repositorios oficiales
8. Habilita e inicia el servicio wazuh-agent

### Características de Seguridad

- Validación pre-montaje: Verifica que no exista un montaje previo en /var/ossec
- Controles de error: Cada paso crítico valida su ejecución y aborta en caso de fallo
- Rollback automático: Si mount -a falla, elimina la entrada problemática de /etc/fstab
- Confirmación interactiva: Solicita confirmación antes de proceder con la instalación

## Uso Rápido
```
git clone https://github.com/OrangeBox-Labs/wazuh/wazuh-agent-installer.git
cd wazuh-agent-installer
chmod +x install-wazuh-agent.sh
./install-wazuh-agent.sh
```

## Configuración Personalizada

El script solicitará interactivamente:

- Nombre del agente: Identificador del equipo en Wazuh (por defecto: hostname del sistema)
- IP del Manager: Dirección del servidor Wazuh central (por defecto: 192.168.200.160)

## Estructura del Script
```
install-wazuh-agent.sh
├── Verificación de montaje previo
├── Detección del VG/LV de /var
├── Creación de LV dedicado (100 MB)
├── Formateo ext4
├── Montaje en /var/ossec
├── Configuración de fstab
├── Validación post-montaje
├── Configuración del agente
├── Descarga e instalación del RPM
└── Habilitación del servicio
```
## Parámetros Configurables

Puedes modificar las siguientes variables dentro del script:

- LV_NAME: Nombre del volumen lógico (por defecto: wazuh)
- LV_SIZE: Tamaño del volumen (por defecto: 100M)
- MANAGER_IP: IP por defecto del Wazuh manager
- AGENT_VERSION: Versión del paquete a instalar

## Solución de Problemas

Error: "No se pudo identificar un volumen lógico para /var"

Causa: /var no está en un volumen LVM.
Solución: El script requiere LVM. Verifica con lsblk o lvdisplay.

Error: "Espacio insuficiente en el VG"

Causa: El Volume Group no tiene al menos 100 MB libres.
Solución: Libera espacio o extiende el VG.

Error: "mount -a falló"

Causa: La entrada en /etc/fstab es incorrecta.
Solución: El script elimina automáticamente la entrada. Verifica manualmente con mount -a.

## Verificación Post-Instalación

mount | grep /var/ossec
systemctl status wazuh-agent
journalctl -u wazuh-agent -f

## Notas Importantes

- CentOS 7: Este script ha sido probado en CentOS 7.6+
- noexec: Resuelve el problema de noexec en /var aislando Wazuh en su propia partición
- Persistencia: El montaje en /var/ossec es persistente entre reinicios gracias a la entrada en /etc/fstab

## Desinstalación

systemctl stop wazuh-agent
systemctl disable wazuh-agent
umount /var/ossec
sed -i '/\/var\/ossec/d' /etc/fstab
lvremove -f /dev/$(vgdisplay -c | cut -d: -f1 | head -1)/wazuh


## Contribuciones

Las contribuciones son bienvenidas. Por favor, abre un issue primero para discutir los cambios propuestos.

---

Advertencia: Este script modifica la configuración de almacenamiento del sistema (LVM, fstab). Se recomienda probar en un entorno no productivo antes de usar en producción.
