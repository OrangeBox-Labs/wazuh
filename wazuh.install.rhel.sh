#!/bin/bash

# ==========================================
# Script: crear_lv_wazuh.sh
# Descripción: Crea un LV de 100MB para Wazuh en el VG de /var,
#              lo formatea, monta en /var/ossec, añade al fstab,
#              instala el agente Wazuh y habilita el servicio.
# ==========================================

set -e # Detiene el script si cualquier comando falla

# Colores para mensajes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# ==========================================
# 0. Verificar si /var/ossec ya está montado
# ==========================================
MOUNT_POINT="/var/ossec"

# Verificar si el directorio está montado
if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
  echo -e "${RED}❌ ERROR: Ya existe un montaje en $MOUNT_POINT${NC}"
  echo -e "${RED}   Ejecuta 'mount | grep $MOUNT_POINT' para ver los detalles.${NC}"
  echo -e "${YELLOW}   ¿Deseas desmontarlo y continuar? (s/N): ${NC}"
  read -p "" DESMONTAR
  if [[ "$DESMONTAR" =~ ^[Ss]$ ]]; then
    if umount "$MOUNT_POINT" 2>/dev/null; then
      echo -e "${GREEN}==> Montaje desmontado exitosamente.${NC}"
      # Eliminar entrada del fstab si existe
      sed -i "\|$MOUNT_POINT|d" /etc/fstab 2>/dev/null
    else
      echo -e "${RED}❌ ERROR: No se pudo desmontar $MOUNT_POINT${NC}"
      echo -e "${RED}   Abortando instalación.${NC}"
      exit 1
    fi
  else
    echo -e "${RED}Abortando instalación.${NC}"
    exit 1
  fi
fi

# Verificar si el directorio existe y tiene contenido (montaje previo no desmontado correctamente)
if [ -d "$MOUNT_POINT" ] && [ "$(ls -A $MOUNT_POINT 2>/dev/null)" ]; then
  echo -e "${YELLOW}⚠️  Advertencia: El directorio $MOUNT_POINT no está montado pero contiene archivos.${NC}"
  read -p "¿Deseas eliminar el contenido y continuar? (s/N): " ELIMINAR
  if [[ "$ELIMINAR" =~ ^[Ss]$ ]]; then
    rm -rf "${MOUNT_POINT:?}"/*
    echo -e "${GREEN}==> Contenido eliminado.${NC}"
  else
    echo -e "${RED}Abortando instalación.${NC}"
    exit 1
  fi
fi

# ==========================================
# 1. Obtener información del VG y LV de /var
# ==========================================
echo -e "${YELLOW}==> Obteniendo información del volumen de /var...${NC}"
VAR_LV=$(lvdisplay -c | grep -w "var" | cut -d: -f1 | head -n1)
if [ -z "$VAR_LV" ]; then
  echo -e "${RED}ERROR: No se pudo identificar un volumen lógico para /var.${NC}"
  echo "Asegúrate de que /var esté en un LV y que lvm2 esté instalado."
  exit 1
fi

# Extraer el Grupo de Volúmenes (VG) del LV de /var
VG_NAME=$(lvdisplay -c | grep -w "$VAR_LV" | cut -d: -f2)

echo -e "${GREEN}==> LV de /var encontrado en: $VAR_LV ${NC}"
echo -e "${GREEN}==> Grupo de Volúmenes (VG) identificado: $VG_NAME ${NC}"

# ==========================================
# 2. Verificar espacio libre en el VG
# ==========================================
FREE_PE=$(vgdisplay "$VG_NAME" -c | cut -d: -f16)
if [ "$FREE_PE" -lt 25 ]; then
  echo -e "${RED}ERROR: Espacio insuficiente en el VG '$VG_NAME'. Se requieren al menos 100MB libres.${NC}"
  exit 1
fi
echo -e "${GREEN}==> Espacio libre confirmado en $VG_NAME.${NC}"

# ==========================================
# 3. Crear el LV wazuh de 100MB
# ==========================================
LV_NAME="wazuh"
echo -e "${YELLOW}==> Creando LV '$LV_NAME' de 100MB en VG '$VG_NAME'...${NC}"
if ! lvcreate -L 100M -n "$LV_NAME" "$VG_NAME" 2>/dev/null; then
  echo -e "${RED}❌ ERROR: No se pudo crear el LV '$LV_NAME'.${NC}"
  echo -e "${RED}   Puede que ya exista o no haya suficiente espacio.${NC}"
  echo -e "${RED}   Abortando instalación.${NC}"
  exit 1
fi
echo -e "${GREEN}==> LV '$LV_NAME' creado.${NC}"

# ==========================================
# 4. Formatear como ext4
# ==========================================
echo -e "${YELLOW}==> Formateando /dev/$VG_NAME/$LV_NAME como ext4...${NC}"
if ! mkfs.ext4 -F "/dev/$VG_NAME/$LV_NAME" >/dev/null 2>&1; then
  echo -e "${RED}❌ ERROR: No se pudo formatear /dev/$VG_NAME/$LV_NAME.${NC}"
  echo -e "${RED}   Abortando instalación.${NC}"
  exit 1
fi
echo -e "${GREEN}==> Formateo completado.${NC}"

# ==========================================
# 5. Crear punto de montaje /var/ossec (si no existe)
# ==========================================
if [ ! -d "$MOUNT_POINT" ]; then
  echo -e "${YELLOW}==> Creando directorio $MOUNT_POINT...${NC}"
  if ! mkdir -p "$MOUNT_POINT" 2>/dev/null; then
    echo -e "${RED}❌ ERROR: No se pudo crear el directorio $MOUNT_POINT.${NC}"
    echo -e "${RED}   Abortando instalación.${NC}"
    exit 1
  fi
fi

# ==========================================
# 6. Montar temporalmente
# ==========================================
echo -e "${YELLOW}==> Montando temporalmente /dev/$VG_NAME/$LV_NAME en $MOUNT_POINT...${NC}"
if ! mount "/dev/$VG_NAME/$LV_NAME" "$MOUNT_POINT" 2>/dev/null; then
  echo -e "${RED}❌ ERROR: No se pudo montar /dev/$VG_NAME/$LV_NAME en $MOUNT_POINT.${NC}"
  echo -e "${RED}   Abortando instalación.${NC}"
  exit 1
fi
echo -e "${GREEN}==> Montaje temporal exitoso.${NC}"

# ==========================================
# 7. Añadir entrada al fstab
# ==========================================
FSTAB_ENTRY="/dev/$VG_NAME/$LV_NAME $MOUNT_POINT            ext4    defaults,nosuid,nodev 1 2"
echo -e "${YELLOW}==> Añadiendo entrada a /etc/fstab...${NC}"
echo "$FSTAB_ENTRY" >>/etc/fstab

# ==========================================
# 8. Verificar que el montaje automático funciona
# ==========================================
echo -e "${YELLOW}==> Verificando montaje automático (mount -a)...${NC}"
if ! mount -a 2>/dev/null; then
  echo -e "${RED}❌ ERROR: 'mount -a' falló. La entrada en fstab puede ser incorrecta.${NC}"
  echo -e "${RED}   Eliminando entrada problemática de /etc/fstab...${NC}"
  sed -i "/$MOUNT_POINT/d" /etc/fstab
  echo -e "${RED}   Abortando instalación.${NC}"
  exit 1
fi
echo -e "${GREEN}==> Verificación exitosa.${NC}"

echo -e "${GREEN}✅ Preparación del volumen completada exitosamente.${NC}"
echo "Resumen de la operación:"
echo "  - LV creado: /dev/$VG_NAME/$LV_NAME (100MB)"
echo "  - Formato: ext4"
echo "  - Montado en: $MOUNT_POINT"
echo "  - Entrada en fstab: $FSTAB_ENTRY"

# ==========================================
# 9. Obtener nombre del agente
# ==========================================
CURRENT_HOSTNAME=$(hostname)
echo -e "\n${YELLOW}==> Nombre de host detectado: $CURRENT_HOSTNAME${NC}"
read -p "¿Deseas usar este nombre para el agente? (s/N): " CONFIRMAR_HOSTNAME
if [[ "$CONFIRMAR_HOSTNAME" =~ ^[Ss]$ ]]; then
  AGENT_NAME="$CURRENT_HOSTNAME"
else
  read -p "Ingresa el nombre personalizado para el agente: " AGENT_NAME
fi

# ==========================================
# 10. Configurar IP del Manager
# ==========================================
MANAGER_IP="192.168.200.160"
echo -e "${YELLOW}==> IP del Wazuh Manager configurada: $MANAGER_IP${NC}"
read -p "¿Deseas usar esta IP? (s/N): " CONFIRMAR_IP
if [[ ! "$CONFIRMAR_IP" =~ ^[Ss]$ ]]; then
  read -p "Ingresa la IP correcta del Wazuh Manager: " MANAGER_IP
fi

# ==========================================
# 11. Configurar Grupo del agente
# ==========================================
DEFAULT_GROUP="OrangeBox"
echo -e "${YELLOW}==> Grupo por defecto: $DEFAULT_GROUP${NC}"
read -p "¿Deseas usar este grupo para el agente? (s/N): " CONFIRMAR_GRUPO
if [[ "$CONFIRMAR_GRUPO" =~ ^[Ss]$ ]]; then
  AGENT_GROUP="$DEFAULT_GROUP"
else
  read -p "Ingresa el nombre del grupo para el agente: " AGENT_GROUP
fi

# ==========================================
# 12. Confirmar datos antes de proceder
# ==========================================
echo -e "\n${GREEN}=== RESUMEN DE INSTALACIÓN ===${NC}"
echo "  • Nombre del agente: $AGENT_NAME"
echo "  • IP del Manager: $MANAGER_IP"
echo "  • Grupo del agente: $AGENT_GROUP"
echo "  • Versión del agente: 4.14.5-1.x86_64"
echo -e "${YELLOW}===============================${NC}"
read -p "¿Proceder con la instalación? (s/N): " CONFIRMAR_TODO
if [[ ! "$CONFIRMAR_TODO" =~ ^[Ss]$ ]]; then
  echo -e "${RED}Instalación cancelada por el usuario.${NC}"
  exit 0
fi

# ==========================================
# 13. Descargar e instalar el agente Wazuh
# ==========================================
echo -e "${YELLOW}==> Descargando e instalando Wazuh agent...${NC}"
if ! curl -o wazuh-agent-4.14.5-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.14.5-1.x86_64.rpm 2>/dev/null; then
  echo -e "${RED}❌ ERROR: Falló la descarga del paquete Wazuh.${NC}"
  echo -e "${RED}   Verifica la conexión a internet.${NC}"
  exit 1
fi

if ! WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$AGENT_NAME" WAZUH_AGENT_GROUP="$AGENT_GROUP" rpm -ihv wazuh-agent-4.14.5-1.x86_64.rpm 2>/dev/null; then
  echo -e "${RED}❌ ERROR: Falló la instalación del paquete Wazuh.${NC}"
  echo -e "${RED}   Puede que ya esté instalado o haya conflictos.${NC}"
  exit 1
fi
echo -e "${GREEN}✅ Instalación del agente completada.${NC}"

# ==========================================
# 14. Habilitar e iniciar el servicio
# ==========================================
echo -e "${YELLOW}==> Habilitando e iniciando wazuh-agent...${NC}"
if ! systemctl enable --now wazuh-agent 2>/dev/null; then
  echo -e "${RED}❌ ERROR: No se pudo habilitar/iniciar el servicio wazuh-agent.${NC}"
  echo -e "${RED}   Revisa los logs con: journalctl -u wazuh-agent${NC}"
  exit 1
fi

echo -e "${GREEN}✅ Servicio wazuh-agent habilitado e iniciado.${NC}"
echo -e "${GREEN}🎉 Instalación completada exitosamente.${NC}"
