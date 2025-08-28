#!/bin/bash

# ======================================================================
# CONFIGURACIÓN DEL PREFIJO DE LA COMPAÑÍA
# ======================================================================
# Modifica esta línea para configurar tu prefijo personalizado
COMPANY_PREFIX="VALORH2"  # <-- CAMBIA ESTE VALOR POR TU PREFIJO
# ======================================================================

# Verificar si se ejecuta con permisos de root o sudo
if [[ $EUID -ne 0 ]]; then
    echo "🔴 Este script requiere permisos de administrador. Ejecutándolo con sudo..." >&2
    exec sudo bash "$0" "$@"
    exit 1
fi

echo "✅ Verificando e instalando auditd..."

# Detectar el gestor de paquetes y verificar si auditd está instalado
if command -v apt &>/dev/null; then
    PKG_MANAGER="apt"
    INSTALL_CMD="apt install -y"
    CHECK_CMD="dpkg -l | grep -q auditd"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    INSTALL_CMD="yum install -y"
    CHECK_CMD="rpm -q audit"
else
    echo "⚠️ No se encontró un gestor de paquetes compatible. Instala auditd manualmente."
    exit 1
fi

# Instalar auditd si no está instalado
if ! eval "$CHECK_CMD"; then
    echo "📥 Instalando auditd..."
    eval "$INSTALL_CMD auditd"
    systemctl enable auditd
    systemctl start auditd
else
    echo "✅ auditd ya está instalado."
fi

# ======================================================================
# FUNCIONES DE CONFIGURACIÓN DE AUDITORÍA COMPLETA
# ======================================================================

# Función para detectar la distribución Linux
detect_linux_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "$ID"
    elif [[ -f /etc/redhat-release ]]; then
        echo "rhel"
    elif [[ -f /etc/debian_version ]]; then
        echo "debian"
    else
        echo "unknown"
    fi
}

# Función para configurar reglas de auditoría completas
configure_audit_rules() {
    echo "🔧 Configurando reglas de auditoría del sistema..."
    
    AUDIT_RULES_FILE="/etc/audit/rules.d/soc-t-audit.rules"
    
    cat > "$AUDIT_RULES_FILE" << 'EOF'
# Reglas de auditoría completas para Linux

# Eliminar reglas existentes
-D

# Buffer de eventos de auditoría
-b 8192

# Fallos de auditoría (2 = panic, 1 = printk, 0 = silent)
-f 1

# === AUDITORÍA DE ARCHIVOS CRÍTICOS DEL SISTEMA ===
# Archivos de autenticación y autorización
-w /etc/passwd -p wa -k identity_changes
-w /etc/group -p wa -k identity_changes
-w /etc/gshadow -p wa -k identity_changes
-w /etc/shadow -p wa -k identity_changes
-w /etc/security/opasswd -p wa -k identity_changes
-w /etc/sudoers -p wa -k privilege_changes
-w /etc/sudoers.d/ -p wa -k privilege_changes

# Configuración de red
-w /etc/hosts -p wa -k network_config
-w /etc/network/ -p wa -k network_config
-w /etc/netplan/ -p wa -k network_config
-w /etc/sysconfig/network-scripts/ -p wa -k network_config

# Configuración del sistema
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/issue -p wa -k system_config
-w /etc/issue.net -p wa -k system_config
-w /etc/hosts.allow -p wa -k system_config
-w /etc/hosts.deny -p wa -k system_config

# Logs críticos
-w /var/log/auth.log -p wa -k log_tampering
-w /var/log/secure -p wa -k log_tampering
-w /var/log/messages -p wa -k log_tampering
-w /var/log/audit/ -p wa -k log_tampering

# === AUDITORÍA DE COMANDOS PRIVILEGIADOS ===
# Comandos de administración
-w /usr/bin/sudo -p x -k privilege_escalation
-w /usr/bin/su -p x -k privilege_escalation
-w /bin/su -p x -k privilege_escalation

# Comandos de gestión de usuarios
-w /usr/sbin/useradd -p x -k user_management
-w /usr/sbin/userdel -p x -k user_management
-w /usr/sbin/usermod -p x -k user_management
-w /usr/sbin/groupadd -p x -k group_management
-w /usr/sbin/groupdel -p x -k group_management
-w /usr/sbin/groupmod -p x -k group_management

# Comandos de cambio de permisos
-w /bin/chmod -p x -k permission_changes
-w /usr/bin/chmod -p x -k permission_changes
-w /bin/chown -p x -k permission_changes
-w /usr/bin/chown -p x -k permission_changes

# === AUDITORÍA DE LLAMADAS AL SISTEMA ===
# Cambios de fecha/hora del sistema
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time_change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time_change
-a always,exit -F arch=b64 -S clock_settime -k time_change
-a always,exit -F arch=b32 -S clock_settime -k time_change
-w /etc/localtime -p wa -k time_change

# Modificaciones de archivos
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k file_permissions
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k file_permissions
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k file_ownership
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k file_ownership

# Acceso a archivos sensibles
-a always,exit -F arch=b64 -S open -S truncate -S ftruncate -S openat -S open_by_handle_at -F dir=/etc -F success=0 -k config_access
-a always,exit -F arch=b32 -S open -S truncate -S ftruncate -S openat -S open_by_handle_at -F dir=/etc -F success=0 -k config_access

# Montaje de sistemas de archivos
-a always,exit -F arch=b64 -S mount -k filesystem_mount
-a always,exit -F arch=b32 -S mount -k filesystem_mount

# === AUDITORÍA ESPECÍFICA DE SERVIDORES DE ARCHIVOS ===
# Monitorización de accesos a archivos compartidos
-a always,exit -F arch=b64 -S openat -F dir=/srv -F success=1 -k file_server_access
-a always,exit -F arch=b32 -S openat -F dir=/srv -F success=1 -k file_server_access
-a always,exit -F arch=b64 -S openat -F dir=/var/ftp -F success=1 -k ftp_access
-a always,exit -F arch=b32 -S openat -F dir=/var/ftp -F success=1 -k ftp_access

# Configuraciones de Samba
-w /etc/samba/ -p wa -k samba_config
-w /var/lib/samba/ -p wa -k samba_database

# Configuraciones de NFS
-w /etc/exports -p wa -k nfs_exports
-w /etc/fstab -p wa -k filesystem_config

# Configuraciones de FTP
-w /etc/vsftpd/ -p wa -k ftp_config
-w /etc/proftpd/ -p wa -k ftp_config

# === FINALIZAR CONFIGURACIÓN ===
# Hacer inmutables las reglas de auditoría
-e 2
EOF

    echo "✅ Reglas de auditoría configuradas en $AUDIT_RULES_FILE"
    
    # Reiniciar auditd para aplicar las reglas
    if systemctl is-active --quiet auditd; then
        echo "🔄 Reiniciando auditd para aplicar nuevas reglas..."
        service auditd restart 2>/dev/null || systemctl restart auditd
    fi
}

# Función para detectar y configurar servicios específicos
detect_and_configure_services() {
    echo "🔍 Detectando servicios instalados para configurar auditoría específica..."
    
    DETECTED_SERVICES=()
    
    # Detectar Apache
    if systemctl list-units --full -all | grep -q "apache2\|httpd"; then
        DETECTED_SERVICES+=("apache")
        echo "  ✓ Apache detectado"
    fi
    
    # Detectar Nginx
    if systemctl list-units --full -all | grep -q "nginx"; then
        DETECTED_SERVICES+=("nginx")
        echo "  ✓ Nginx detectado"
    fi
    
    # Detectar MySQL/MariaDB
    if systemctl list-units --full -all | grep -q "mysql\|mariadb"; then
        DETECTED_SERVICES+=("mysql")
        echo "  ✓ MySQL/MariaDB detectado"
    fi
    
    # Detectar PostgreSQL
    if systemctl list-units --full -all | grep -q "postgresql"; then
        DETECTED_SERVICES+=("postgresql")
        echo "  ✓ PostgreSQL detectado"
    fi
    
    # Detectar Samba (Servidor de archivos Windows)
    if systemctl list-units --full -all | grep -q "smbd\|nmbd\|samba"; then
        DETECTED_SERVICES+=("samba")
        echo "  ✓ Samba (Servidor de archivos Windows) detectado"
    fi
    
    # Detectar NFS (Servidor de archivos Unix/Linux)
    if systemctl list-units --full -all | grep -q "nfs-server\|nfsd"; then
        DETECTED_SERVICES+=("nfs")
        echo "  ✓ NFS (Servidor de archivos Unix/Linux) detectado"
    fi
    
    # Detectar FTP servers
    if systemctl list-units --full -all | grep -q "vsftpd\|proftpd\|pure-ftpd"; then
        DETECTED_SERVICES+=("ftp")
        echo "  ✓ Servidor FTP detectado"
    fi
    
    # Detectar Docker
    if systemctl list-units --full -all | grep -q "docker"; then
        DETECTED_SERVICES+=("docker")
        echo "  ✓ Docker detectado"
    fi
    
    if [[ ${#DETECTED_SERVICES[@]} -eq 0 ]]; then
        echo "  → No se detectaron servicios adicionales"
    fi
    
    echo "${DETECTED_SERVICES[@]}"
}

# Función para detectar directorios compartidos y de archivos críticos
detect_file_server_directories() {
    echo "🔍 Detectando directorios de servidor de archivos..."
    
    SHARED_DIRECTORIES=()
    
    # Detectar compartidos de Samba
    if command -v smbstatus &>/dev/null; then
        echo "  🔍 Analizando compartidos de Samba..."
        # Obtener compartidos de smb.conf
        if [[ -f /etc/samba/smb.conf ]]; then
            SAMBA_SHARES=$(grep -E '^\[.*\]' /etc/samba/smb.conf | grep -v '\[global\]' | tr -d '[]')
            for share in $SAMBA_SHARES; do
                SHARE_PATH=$(grep -A 10 "^\[$share\]" /etc/samba/smb.conf | grep "path" | head -1 | sed 's/.*path.*=\s*//' | tr -d ' ')
                if [[ -d "$SHARE_PATH" ]]; then
                    SHARED_DIRECTORIES+=("$SHARE_PATH")
                    echo "    ✓ Compartido Samba: $share -> $SHARE_PATH"
                fi
            done
        fi
    fi
    
    # Detectar exports de NFS
    if [[ -f /etc/exports ]]; then
        echo "  🔍 Analizando exports de NFS..."
        while IFS= read -r line; do
            if [[ ! "$line" =~ ^# ]] && [[ -n "$line" ]]; then
                NFS_PATH=$(echo "$line" | awk '{print $1}')
                if [[ -d "$NFS_PATH" ]]; then
                    SHARED_DIRECTORIES+=("$NFS_PATH")
                    echo "    ✓ Export NFS: $NFS_PATH"
                fi
            fi
        done < /etc/exports
    fi
    
    # Detectar directorios FTP comunes
    for ftp_dir in "/var/ftp" "/srv/ftp" "/home/ftp" "/ftp"; do
        if [[ -d "$ftp_dir" ]]; then
            SHARED_DIRECTORIES+=("$ftp_dir")
            echo "    ✓ Directorio FTP: $ftp_dir"
        fi
    done
    
    # Detectar otros directorios comunes de servidor de archivos
    for common_dir in "/srv" "/var/www/html" "/var/lib/tftpboot" "/export" "/shared"; do
        if [[ -d "$common_dir" ]] && [[ $(find "$common_dir" -type f 2>/dev/null | wc -l) -gt 0 ]]; then
            SHARED_DIRECTORIES+=("$common_dir")
            echo "    ✓ Directorio de servidor: $common_dir"
        fi
    done
    
    # Eliminar duplicados
    if [[ ${#SHARED_DIRECTORIES[@]} -gt 0 ]]; then
        SHARED_DIRECTORIES=($(printf "%s\n" "${SHARED_DIRECTORIES[@]}" | sort -u))
        echo "  📂 Total de directorios detectados: ${#SHARED_DIRECTORIES[@]}"
    else
        echo "  → No se detectaron directorios de servidor de archivos específicos"
    fi
    
    echo "${SHARED_DIRECTORIES[@]}"
}

# Función para configurar logs específicos según servicios detectados
configure_service_specific_logs() {
    local services=("$@")
    local distro=$(detect_linux_distro)
    
    echo "🔧 Configurando logs específicos para servicios detectados..."
    
    # Crear configuración de logs personalizada
    SERVICE_LOGS_CONFIG=""
    
    # Logs básicos del sistema (siempre incluidos)
    SERVICE_LOGS_CONFIG+='
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/secure</location>
  </localfile>
  
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/messages</location>
  </localfile>
  
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
  
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>'
    
    # Configurar logs específicos por servicio
    for service in "${services[@]}"; do
        case "$service" in
            "apache")
                SERVICE_LOGS_CONFIG+='
  
  <!-- Apache Logs -->
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
  </localfile>
  
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/error.log</location>
  </localfile>
  
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/httpd/access_log</location>
  </localfile>
  
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/httpd/error_log</location>
  </localfile>'
                ;;
                
            "nginx")
                SERVICE_LOGS_CONFIG+='
  
  <!-- Nginx Logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>
  
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nginx/error.log</location>
  </localfile>'
                ;;
                
            "mysql")
                SERVICE_LOGS_CONFIG+='
  
  <!-- MySQL/MariaDB Logs -->
  <localfile>
    <log_format>mysql_log</log_format>
    <location>/var/log/mysql/error.log</location>
  </localfile>
  
  <localfile>
    <log_format>mysql_log</log_format>
    <location>/var/log/mysql/mysql.log</location>
  </localfile>
  
  <localfile>
    <log_format>mysql_log</log_format>
    <location>/var/log/mariadb/mariadb.log</location>
  </localfile>'
                ;;
                
            "postgresql")
                SERVICE_LOGS_CONFIG+='
  
  <!-- PostgreSQL Logs -->
  <localfile>
    <log_format>postgresql_log</log_format>
    <location>/var/log/postgresql/postgresql-*.log</location>
  </localfile>'
                ;;
                
            "samba")
                SERVICE_LOGS_CONFIG+='
  
  <!-- Samba Logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/samba/log.smbd</location>
  </localfile>
  
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/samba/log.nmbd</location>
  </localfile>
  
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/samba/log.winbindd</location>
  </localfile>'
                ;;
                
            "nfs")
                SERVICE_LOGS_CONFIG+='
  
  <!-- NFS Server Logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nfsd.log</location>
  </localfile>
  
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/rpc.mountd.log</location>
  </localfile>'
                ;;
                
            "ftp")
                SERVICE_LOGS_CONFIG+='
  
  <!-- FTP Server Logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/vsftpd.log</location>
  </localfile>
  
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/proftpd/proftpd.log</location>
  </localfile>
  
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/pure-ftpd/pure-ftpd.log</location>
  </localfile>'
                ;;
                
            "docker")
                SERVICE_LOGS_CONFIG+='
  
  <!-- Docker Logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/docker.log</location>
  </localfile>'
                ;;
        esac
    done
    
    echo "$SERVICE_LOGS_CONFIG"
}

# Función para configurar monitorización de integridad
configure_syscheck_directories() {
    local shared_dirs=("$@")
    
    echo "🔧 Configurando monitorización de integridad de archivos..."
    
    SYSCHECK_CONFIG='
  <!-- Monitorización de integridad de archivos críticos del sistema -->
  <directories realtime="no" check_all="yes" report_changes="yes">/usr/bin</directories>
  <directories realtime="no" check_all="yes" report_changes="yes">/usr/sbin</directories>
  <directories realtime="no" check_all="yes" report_changes="yes">/bin</directories>
  <directories realtime="no" check_all="yes" report_changes="yes">/sbin</directories>
  <directories realtime="no" check_all="yes" report_changes="yes">/boot</directories>
  
  <!-- Directorios de configuración específicos -->
  <directories realtime="yes" check_all="yes" report_changes="yes">/etc/ssh</directories>
  <directories realtime="yes" check_all="yes" report_changes="yes">/etc/pam.d</directories>
  <directories realtime="yes" check_all="yes" report_changes="yes">/etc/security</directories>
  <directories realtime="yes" check_all="yes" report_changes="yes">/etc/sudoers.d</directories>
  
  <!-- Configuraciones de servidores de archivos -->
  <directories realtime="yes" check_all="yes" report_changes="yes">/etc/samba</directories>
  <directories realtime="yes" check_all="yes" report_changes="yes">/etc/exports</directories>
  <directories realtime="yes" check_all="yes" report_changes="yes">/etc/vsftpd</directories>'
  
  #<!-- Logs críticos -->
  #<directories realtime="yes" check_all="yes" report_changes="yes">/var/log</directories>'
  
    # Añadir directorios compartidos detectados
    if [[ ${#shared_dirs[@]} -gt 0 ]]; then
        SYSCHECK_CONFIG+='
  
  <!-- Directorios de servidor de archivos detectados -->'
        for dir in "${shared_dirs[@]}"; do
            # Solo monitorizar si el directorio existe y es accesible
            if [[ -d "$dir" && -r "$dir" ]]; then
                SYSCHECK_CONFIG+="
  <directories realtime=\"yes\" check_all=\"yes\" report_changes=\"yes\">$dir</directories>"
            fi
        done
    fi
    
    SYSCHECK_CONFIG+='
  
  <!-- Excluir archivos temporales y frecuentemente modificados -->
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/hosts.deny</ignore>
  <ignore>/etc/mail/statistics</ignore>
  <ignore>/etc/random-seed</ignore>
  <ignore>/etc/random.seed</ignore>
  <ignore>/etc/adjtime</ignore>
  <ignore>/etc/httpd/logs</ignore>
  <ignore>/etc/utmpx</ignore>
  <ignore>/etc/wtmpx</ignore>
  <ignore>/etc/cups/certs</ignore>
  <ignore>/etc/dumpdates</ignore>
  <ignore>/etc/svc/volatile</ignore>
  
  <!-- Excluir archivos temporales de servidor de archivos -->
  <ignore type="sregex">\.tmp$</ignore>
  <ignore type="sregex">\.temp$</ignore>
  <ignore type="sregex">\.lock$</ignore>
  <ignore type="sregex">\.swp$</ignore>
  <ignore type="sregex">\.~lock</ignore>
  <ignore type="sregex">#.*#$</ignore>'
    
    echo "$SYSCHECK_CONFIG"
}

# Función para configurar wodles de monitorización
configure_monitoring_wodles() {
    local distro=$(detect_linux_distro)
    
    echo "🔧 Configurando wodles de monitorización del sistema..."
    
    WODLES_CONFIG='
  <!-- Monitorización de servicios críticos del sistema -->
  <wodle name="command">
    <disabled>no</disabled>
    <tag>linux-services-monitor</tag>
    <command>systemctl list-units --failed --no-legend | head -10</command>
    <interval>300</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>30</timeout>
  </wodle>
  
  <!-- Monitorización de procesos sospechosos -->
  <wodle name="command">
    <disabled>no</disabled>
    <tag>suspicious-processes</tag>
    <command>ps aux --sort=-%cpu | head -10</command>
    <interval>600</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>30</timeout>
  </wodle>
  
  <!-- Monitorización de conexiones de red -->
  <wodle name="command">
    <disabled>no</disabled>
    <tag>network-connections</tag>
    <command>netstat -tuln | grep LISTEN</command>
    <interval>600</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>30</timeout>
  </wodle>
  
  <!-- Monitorización de espacio en disco -->
  <wodle name="command">
    <disabled>no</disabled>
    <tag>disk-usage</tag>
    <command>df -h | awk '"'"'$5 > 80 {print $0}'"'"'</command>
    <interval>1800</interval>
    <ignore_output>no</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>30</timeout>
  </wodle>'
    
    echo "$WODLES_CONFIG"
}

# Variables por defecto
MANAGER_ADDRESS="localhost"
MANAGER_PORT="1514"
ENROLLMENT_PORT="1515"
CONFIG_PROFILE="ubuntu, ubuntu22, ubuntu22.04"

# Comprobar si el agente de Wazuh ya está instalado
if systemctl list-units --full -all | grep -q "wazuh-agent.service"; then
    read -p "⚠️ Wazuh Agent ya está instalado. ¿Quieres desinstalarlo? (s/n): " response
    if [[ "$response" =~ ^[Ss]$ ]]; then
        echo "🔄 Desinstalando Wazuh Agent..."
        systemctl stop wazuh-agent 2>/dev/null || echo "⚠️ No se pudo detener el servicio, puede que no esté instalado."
        if command -v rpm &>/dev/null; then
            rpm -e wazuh-agent || echo "⚠️ wazuh-agent no estaba instalado con RPM."
        elif command -v dpkg &>/dev/null; then
            dpkg --purge wazuh-agent || echo "⚠️ wazuh-agent no estaba instalado con dpkg."
        fi
        echo "✅ Agente desinstalado."
    else
        echo "✅ No se desinstalará Wazuh Agent."
        exit 0
    fi
    
fi

# Descargar e instalar el agente de Wazuh
echo "⬇️ Descargando e instalando Wazuh Agent..."
if [[ "$PKG_MANAGER" == "yum" ]]; then
    wget -qO wazuh-agent.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.12.0-1.x86_64.rpm
    yum install -y wazuh-agent.rpm
elif [[ "$PKG_MANAGER" == "apt" ]]; then
    wget -qO wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.12.0-1_amd64.deb
    dpkg -i wazuh-agent.deb || (echo "🔄 Error en la instalación, intentando de nuevo..." && rm -f wazuh-agent.deb && wget -qO wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.12.0-1_amd64.deb && dpkg -i wazuh-agent.deb)
fi

# Comprobar si la instalación se realizó correctamente
if [[ ! -d /var/ossec ]]; then
    echo "❌ Error: La instalación de Wazuh Agent falló. Revisa los logs."
    exit 1
fi

echo "🔧 Iniciando configuración completa de auditoría del sistema..."

# Configurar reglas completas de auditoría
configure_audit_rules

# Detectar servicios instalados
echo "🔍 Detectando servicios para configuración específica..."
DETECTED_SERVICES=($(detect_and_configure_services))

# Detectar directorios de servidor de archivos
FILE_SERVER_DIRECTORIES=($(detect_file_server_directories))

# Informar servicios detectados
if [[ ${#DETECTED_SERVICES[@]} -gt 0 ]]; then
    echo "📋 Servicios detectados: ${DETECTED_SERVICES[*]}"
else
    echo "📋 Solo se configurará auditoría básica del sistema"
fi

# Informar directorios de servidor de archivos detectados
if [[ ${#FILE_SERVER_DIRECTORIES[@]} -gt 0 ]]; then
    echo "📂 Directorios de servidor de archivos detectados:"
    for dir in "${FILE_SERVER_DIRECTORIES[@]}"; do
        echo "   → $dir"
    done
    echo "🔍 Estos directorios serán monitorizados en tiempo real para cambios"
else
    echo "📂 No se detectaron directorios específicos de servidor de archivos"
fi

# Usar el prefijo predefinido y convertir a mayúsculas
wazuhPrefix=$(echo "$COMPANY_PREFIX" | tr '[:lower:]' '[:upper:]')
echo "🏢 Prefijo de la compañía configurado: $wazuhPrefix"

hostname=$(hostname)
#Pedir nombre para el activo monitorizado. Si no se introduce nada, se usará el hostname
read -p "✏️ Introduce el nombre del activo monitorizado (Ej: servidor, pc, etc.). Si no introduces nada, se usará el hostname ($hostname): " assetName
# Comprobar si el nombre es válido (solo letras y números, si está vacío se usará el hostname)
if [[ ! "$assetName" =~ ^[a-zA-Z0-9]+$ && -n "$assetName" ]]; then
    echo "❌ Error: Nombre no válido. Debe contener solo letras y números o estar vacío."
    exit 1
fi
# Si el nombre está vacío, usar el hostname
if [[ -z "$assetName" ]]; then
    assetName="$hostname"
fi

#Pedir genero del activo monitorizado mediante 3 opciones: M, F o N
read -p "✏️ Introduce el género del activo monitorizado (masculino (M), femenino (F), neutro (N, válido también para servidores)): " assetGender
# Comprobar si género es válido
if [[ ! "$assetGender" =~ ^[MmFfNn]$ ]]; then
    echo "❌ Error: Género no válido. Debe ser M, F o N."
    exit 1
fi
# Convertir a mayúsculas
assetGender=$(echo "$assetGender" | tr '[:lower:]' '[:upper:]')

agent_name="${wazuhPrefix}-${assetGender}-${assetName}"
echo "🔗 El agente se registrará como: $agent_name"

# Definir el archivo de configuración
CONFIG_FILE="/var/ossec/etc/ossec.conf"

# Función para insertar la sección de enrollment
insert_enrollment_section() {
    # Crear un archivo temporal
    cp "$CONFIG_FILE" "${CONFIG_FILE}.tmp"
    
    # Insertar la sección de enrollment justo antes del cierre de </client>
    sed -i '/<\/client>/i\    <enrollment>\n      <enabled>yes</enabled>\n      <manager_address>'"$MANAGER_ADDRESS"'</manager_address>\n      <port>'"$ENROLLMENT_PORT"'</port>\n      <agent_name>'"$agent_name"'</agent_name>\n      <groups>linux</groups>\n    </enrollment>' "${CONFIG_FILE}.tmp"
    
    # Reemplazar el archivo original
    mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
}

# Reemplazar la dirección IP del manager en <client>
echo "🔄 Actualizando dirección IP del Manager en ossec.conf..."
sed -i "s|<address>MANAGER_IP</address>|<address>$MANAGER_ADDRESS</address>|" "$CONFIG_FILE"

# Reemplazar el puerto del manager en <client>
echo "🔄 Actualizando el puerto del Manager en ossec.conf..."
sed -i "s|\(<port>\)[^<]*\(</port>\)|\1$MANAGER_PORT\2|" "$CONFIG_FILE"

echo "✅ Dirección IP y puerto del Manager actualizados en ossec.conf."

# Verificar si la sección de enrollment existe
if ! grep -q "<enrollment>" "$CONFIG_FILE"; then
    echo "🔧 Insertando sección de enrollment..."
    insert_enrollment_section
else
    echo "🔄 Actualizando sección de enrollment existente..."
    # Si existe, reemplazar su contenido
    perl -0777 -i -pe "s|<enrollment>.*?</enrollment>|<enrollment>\n      <enabled>yes</enabled>\n      <manager_address>$MANAGER_ADDRESS</manager_address>\n      <port>$ENROLLMENT_PORT</port>\n      <agent_name>$agent_name</agent_name>\n      <groups>linux</groups>\n    </enrollment>|s" "$CONFIG_FILE"
fi

# ======================================================================
# CONFIGURACIÓN PERSONALIZADA DE OSSEC.CONF
# ======================================================================

echo "🔧 Aplicando configuración personalizada de ossec.conf..."

# Crear backup del archivo original
cp "$CONFIG_FILE" "${CONFIG_FILE}.backup.$(date +%Y%m%d-%H%M%S)"
echo "✅ Backup creado: ${CONFIG_FILE}.backup.$(date +%Y%m%d-%H%M%S)"

# Obtener configuraciones personalizadas
SERVICE_LOGS=$(configure_service_specific_logs "${DETECTED_SERVICES[@]}")
SYSCHECK_DIRS=$(configure_syscheck_directories "${FILE_SERVER_DIRECTORIES[@]}")
MONITORING_WODLES=$(configure_monitoring_wodles)

# Función para aplicar configuración completa
apply_complete_ossec_config() {
    # Crear archivo temporal con la configuración completa
    cat > "${CONFIG_FILE}.new" << EOF
<ossec_config>
  <client>
    <server>
      <address>$MANAGER_ADDRESS</address>
      <port>$MANAGER_PORT</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>linux</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
    <enrollment>
      <enabled>yes</enabled>
      <manager_address>$MANAGER_ADDRESS</manager_address>
      <port>$ENROLLMENT_PORT</port>
      <agent_name>$agent_name</agent_name>
      <groups>linux</groups>
    </enrollment>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <!-- ======================== -->
  <!-- LOGS ESPECÍFICOS DEL SISTEMA -->
  <!-- ======================== -->
  $SERVICE_LOGS

  <!-- ======================== -->
  <!-- MONITORIZACIÓN DE INTEGRIDAD -->
  <!-- ======================== -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>
    <alert_new_files>yes</alert_new_files>
    <remove_old_diff>yes</remove_old_diff>
    <restart_audit>yes</restart_audit>
    
    $SYSCHECK_DIRS
  </syscheck>

  <!-- ======================== -->
  <!-- DETECCIÓN DE ROOTKITS -->
  <!-- ======================== -->
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>36000</frequency>
    <rootkit_files>/var/ossec/etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>
    <skip_nfs>yes</skip_nfs>
  </rootcheck>

  <!-- ======================== -->
  <!-- WODLES DE MONITORIZACIÓN -->
  <!-- ======================== -->
  $MONITORING_WODLES

  <!-- ======================== -->
  <!-- DETECCIÓN DE VULNERABILIDADES -->
  <!-- ======================== -->
  <wodle name="vulnerability-detector">
    <disabled>no</disabled>
    <interval>5m</interval>
    <ignore_time>6h</ignore_time>
    <run_on_start>yes</run_on_start>
    <provider name="canonical">
      <enabled>yes</enabled>
      <os>trusty</os>
      <os>xenial</os>
      <os>bionic</os>
      <os>focal</os>
      <os>jammy</os>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="debian">
      <enabled>yes</enabled>
      <os_version>9</os_version>
      <os_version>10</os_version>
      <os_version>11</os_version>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="redhat">
      <enabled>yes</enabled>
      <os_version>6</os_version>
      <os_version>7</os_version>
      <os_version>8</os_version>
      <os_version>9</os_version>
      <update_interval>1h</update_interval>
    </provider>
  </wodle>

  <!-- ======================== -->
  <!-- CONFIGURACIÓN DE LOGS -->
  <!-- ======================== -->
  <logging>
    <log_format>plain</log_format>
  </logging>

</ossec_config>
EOF

    # Reemplazar el archivo original
    mv "${CONFIG_FILE}.new" "$CONFIG_FILE"
    echo "✅ Configuración personalizada aplicada a ossec.conf"
}

# Aplicar la configuración completa
apply_complete_ossec_config

# ======================================================================
# CONFIGURACIONES ADICIONALES DE SEGURIDAD
# ======================================================================

echo "🔒 Aplicando configuraciones adicionales de seguridad..."

# Configurar logrotate para audit logs si no existe
if [[ ! -f /etc/logrotate.d/audit ]]; then
    cat > /etc/logrotate.d/audit << 'EOF'
/var/log/audit/audit.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    create 0640 root root
    postrotate
        /sbin/service auditd restart 2>/dev/null || /bin/systemctl restart auditd 2>/dev/null || true
    endscript
}
EOF
    echo "✅ Configuración de logrotate para audit aplicada"
fi

# Configurar límites de archivos de log si es necesario
if [[ -f /etc/audit/auditd.conf ]]; then
    # Configurar tamaño máximo de log y número de archivos
    sed -i 's/^max_log_file = .*/max_log_file = 100/' /etc/audit/auditd.conf
    sed -i 's/^num_logs = .*/num_logs = 10/' /etc/audit/auditd.conf
    sed -i 's/^max_log_file_action = .*/max_log_file_action = rotate/' /etc/audit/auditd.conf
    echo "✅ Configuración de límites de audit aplicada"
fi

# Configurar rsyslog para mejor manejo de logs si existe
if systemctl is-active --quiet rsyslog; then
    if [[ ! -f /etc/rsyslog.d/50-soc-t.conf ]]; then
        echo "🔧 Configurando rsyslog para SOC-T..."
        
        # Verificar si ya existe una regla para auth,authpriv en algún archivo de configuración
        AUTH_RULE_EXISTS=false
        if grep -r "^auth,authpriv\.\*.*\/var\/log\/auth\.log" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | grep -q "auth.log"; then
            AUTH_RULE_EXISTS=true
            echo "  ℹ️  Ya existe una regla para auth,authpriv en la configuración de rsyslog"
        fi
        
        # Crear el archivo de configuración
        cat > /etc/rsyslog.d/50-soc-t.conf << EOF
# SOC-T - Configuración adicional de logging
EOF
        
        # Añadir regla de auth solo si no existe previamente
        if [[ "$AUTH_RULE_EXISTS" == false ]]; then
            cat >> /etc/rsyslog.d/50-soc-t.conf << 'EOF'
# Separar logs de autenticación
auth,authpriv.*                 /var/log/auth.log
EOF
            echo "  ✅ Regla de autenticación añadida a 50-soc-t.conf"
        else
            cat >> /etc/rsyslog.d/50-soc-t.conf << 'EOF'
# Nota: Regla de auth,authpriv ya existe en otra configuración, omitida para evitar duplicados
EOF
            echo "  ⚠️  Regla de autenticación omitida para evitar duplicación"
        fi
        
        # Añadir el resto de configuraciones
        cat >> /etc/rsyslog.d/50-soc-t.conf << 'EOF'

# Logs de sudo en archivo separado
local0.*                        /var/log/sudo.log

# Configurar formato de timestamp más detallado
$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
EOF
        
        systemctl restart rsyslog
        echo "✅ Configuración de rsyslog aplicada"
    else
        echo "✅ Configuración de rsyslog ya existe en 50-soc-t.conf"
    fi
fi

# Verificar estado de servicios críticos
echo "🔍 Verificando estado de servicios críticos..."
for service in auditd rsyslog systemd-journald; do
    if systemctl is-active --quiet "$service"; then
        echo "  ✅ $service está activo"
    else
        echo "  ⚠️  $service no está activo"
    fi
done

# Mostrar resumen de configuración
echo ""
echo "📊 RESUMEN DE CONFIGURACIÓN APLICADA:"
echo "====================================="
echo "🔧 Reglas de auditoría: $(wc -l < /etc/audit/rules.d/soc-t-audit.rules) reglas configuradas"
echo "📂 Servicios detectados: ${#DETECTED_SERVICES[@]} servicios"
echo "📁 Directorios de servidor de archivos: ${#FILE_SERVER_DIRECTORIES[@]} directorios"
echo "🔍 Monitorización de integridad: Directorios críticos + servidores de archivos"
echo "�️  Wodles de monitorización: Servicios, procesos, red y disco"
echo "🛡️  Detección de vulnerabilidades: Habilitada"
echo "📋 Detección de rootkits: Habilitada"
if [[ ${#FILE_SERVER_DIRECTORIES[@]} -gt 0 ]]; then
    echo "📂 Directorios monitorizados en tiempo real:"
    for dir in "${FILE_SERVER_DIRECTORIES[@]}"; do
        echo "   ✓ $dir"
    done
fi
echo ""

# Eliminar bloques duplicados del archivo de configuración (conservar del script original)
if grep -qPz "(?s)<logging>.*<\/logging>.*<ossec_config>.*<\/ossec_config>" "$CONFIG_FILE"; then
    echo "⚠️ Duplicado encontrado, procediendo a limpiar..."
    awk '
    BEGIN { inside_ossec_config=0; }
    /<ossec_config>/ { if (!inside_ossec_config) { print; inside_ossec_config=1; next; } }
    /<ossec_config>/ { if (inside_ossec_config) next; }
    { print; }
    /<\/ossec_config>/ { if (inside_ossec_config) { inside_ossec_config=0; } }
    ' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
    echo "✅ Archivo de configuración limpiado"
fi

# Reiniciar servicios para aplicar cambios
echo "🔄 Reiniciando servicios para aplicar configuración..."
systemctl daemon-reload

# Reiniciar auditd de forma segura
if systemctl is-active --quiet auditd; then
    service auditd restart 2>/dev/null || echo "⚠️ auditd requiere reinicio manual"
fi

# Reiniciar wazuh-agent
systemctl restart wazuh-agent

# Verificar estado final
sleep 3
if systemctl is-active --quiet wazuh-agent; then
    echo "✅ Wazuh Agent está funcionando correctamente"
else
    echo "⚠️ Wazuh Agent no se inició correctamente, verificar logs"
fi

echo ""
echo "🎉 ¡CONFIGURACIÓN COMPLETA DE AUDITORÍA FINALIZADA!"
echo "=================================================="
echo "✅ Auditoría completa del sistema configurada"
echo "✅ Agente Wazuh: $agent_name"
echo "✅ Manager: $MANAGER_ADDRESS:$MANAGER_PORT"
echo "✅ Servicios detectados y configurados: ${DETECTED_SERVICES[*]:-"Solo básicos"}"
echo ""
echo "📋 Archivos de configuración importantes:"
echo "   - Reglas de auditoría: /etc/audit/rules.d/soc-t-audit.rules"
echo "   - Configuración Wazuh: $CONFIG_FILE"
echo "   - Backup original: ${CONFIG_FILE}.backup.*"
echo ""
echo "🔍 Para verificar el estado:"
echo "   - Estado de auditoría: auditctl -s"
echo "   - Estado de Wazuh: systemctl status wazuh-agent"
echo "   - Logs de Wazuh: tail -f /var/ossec/logs/ossec.log"