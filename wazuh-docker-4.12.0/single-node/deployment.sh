#!/bin/bash
# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuración de API Keys
# Leer API key desde archivo .env (recomendado)
if [ -f ".env" ]; then
    source .env
    echo -e "${GREEN} Archivo .env cargado${NC}"
else
    echo -e "${YELLOW} Archivo .env no encontrado. Creando uno de ejemplo...${NC}"
    echo -e "${RED} Por favor, edita el archivo .env y coloca tu API key real de Shuffle${NC}"
    echo -e "${YELLOW}Luego vuelve a ejecutar el script${NC}"
    exit 1
fi

export SHUFFLE_API_KEY
#Obtener la direccion IP de la maquina host
HOST_IP=$(hostname -I | awk '{print $1}')
#Cargar imagenes de la carpeta docker_images
cd docker_images
#Bucle para cargar cada .tar
for img in *.tar; do
    image_name=$(basename "$img" .tar)   # quita la extensión
    if ! docker images --format "{{.Repository}}:{{.Tag}}" | grep -q "^${image_name}:latest$"; then
        echo -e "${BLUE} Cargando imagen $img...${NC}"
        docker load -i "$img"
    else
        echo -e "${YELLOW} Imagen $image_name ya está cargada${NC}"
    fi
done

cd ..
echo -e "${BLUE} Iniciando despliegue del stack...${NC}"
# Verificar directorios
directories=("wazuh-docker-4.12.0" "misp-docker" "cortex" "iris-web" "shuffle")
for dir in "${directories[@]}"; do
    if [ ! -d "$dir" ]; then
        echo -e "${RED} Directorio $dir no encontrado${NC}"
        exit 1
    fi
done

update_cortex_misp_analyzer() {
    # --- CONFIGURACIÓN ---
    local cortex_url="http://localhost:9001"
    local analyzer_name="MISP_2_1"

    # --- VALIDACIÓN DE VARIABLES ---
    if [[ -z "$CORTEX_API_KEY" || -z "$MISP_IP" ]]; then
        echo "Error: Las variables CORTEX_API_KEY y MISP_IP deben estar definidas."
        return 1
    fi

    local new_url="https://""${MISP_IP}"":4433"

    echo "  Iniciando la actualización para el analizador '${analyzer_name}'..."
    echo "    Nueva URL a configurar: ${new_url}"

    local analyzer_id="59bdc5839e13e9856602fdad86098dec"

    # --- PASO 3: OBTENER Y MODIFICAR CONFIGURACIÓN ---
    echo -n "    3. Obteniendo y modificando la configuración actual... "
    local current_config
    current_config=$(curl -s -k -H "Authorization: Bearer ${CORTEX_API_KEY}" "${cortex_url}/api/analyzer/${analyzer_id}")
    
    local final_payload
    # --- LÍNEA CORREGIDA ---
    # Se añade `[$new_url]` para crear un array con la URL como único elemento.
    final_payload=$(echo "${current_config}" | jq --arg new_url "${new_url}" '(.configuration.url = [$new_url]) | {configuration: .configuration}')
    
    if [[ -z "$final_payload" ]]; then
        echo " Error al modificar la configuración."
        return 1
    fi
    echo " Hecho."

    # --- PASO 4: ENVIAR ACTUALIZACIÓN ---
    echo "    4. Enviando la nueva configuración a Cortex..."
    local response
    response=$(curl -s -k -w "\n%{http_code}" -X PATCH \
      -H "Authorization: Bearer ${CORTEX_API_KEY}" \
      -H "Content-Type: application/json" \
      "${cortex_url}/api/analyzer/${analyzer_id}" \
      -d "${final_payload}")
    
    local http_code
    http_code=$(tail -n1 <<< "$response")
    local body
    body=$(sed '$ d' <<< "$response")

    if [[ "$http_code" -eq 200 ]]; then
        echo " ¡Éxito! La configuración del analizador ha sido actualizada."
    else
        echo " Error: La API devolvió el código de estado ${http_code}."
        echo "Respuesta:"
        echo "$body" | jq .
        return 1
    fi
}

# Función para verificar el estado de los contenedores
check_containers() {
    echo -e "${YELLOW}Verificando contenedores en $1...${NC}"
    docker-compose ps
    
    # Verificar que los contenedores estén healthy o running
    local failed_containers=$(docker-compose ps --filter "health=unhealthy" -q)
    if [ ! -z "$failed_containers" ]; then
        echo -e "${RED} Contenedores con problemas de salud detectados${NC}"
        docker-compose ps --filter "health=unhealthy"
    fi

    echo -e "${BLUE}Esperando 8 segundos para estabilización...${NC}"
    sleep 8
}


# Función para verificar puertos
check_ports() {
    local ports=("443" "8081" "4433" "9001" "8443" "3001" "5001")
    echo -e "${YELLOW}Verificando disponibilidad de puertos...${NC}"
    
    for port in "${ports[@]}"; do
        if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null ; then
            echo -e "${RED}Puerto $port ya está en uso${NC}"
        else
            echo -e "${GREEN} Puerto $port disponible${NC}"
        fi
    done
}

# Verificar recursos del sistema
check_resources() {
    echo -e "${YELLOW}Verificando recursos del sistema...${NC}"
    
    # Verificar RAM disponible (mínimo 8GB recomendado)
    total_ram=$(free -g | awk 'NR==2{printf "%d", $2}')
    if [ $total_ram -lt 8 ]; then
        echo -e "${RED} RAM insuficiente: ${total_ram}GB (mínimo 8GB recomendado)${NC}"
    else
        echo -e "${GREEN} RAM suficiente: ${total_ram}GB${NC}"
    fi
    
    # Verificar espacio en disco (mínimo 20GB)
    available_space=$(df -BG . | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ $available_space -lt 20 ]; then
        echo -e "${RED} Espacio insuficiente: ${available_space}GB (mínimo 20GB recomendado)${NC}"
    else
        echo -e "${GREEN} Espacio suficiente: ${available_space}GB${NC}"
    fi
}

# Verificaciones iniciales
check_resources
check_ports
#Crear red de Docker para los contenedores con la direccion 172.18.0.0/16
docker network create --subnet=172.18.0.0/16 valorh2_network
echo ""

# 1. Shuffle
echo -e "${BLUE} Desplegando Shuffle...${NC}"
cd shuffle
# Crear directorios necesarios
mkdir -p ./shuffle-apps ./shuffle-files ./shuffle-database
docker-compose up -d
check_containers "Shuffle"
cd ..

# 2. Wazuh
echo -e "${BLUE} Desplegando Wazuh...${NC}"
cd wazuh-docker-4.12.0/single-node
echo -e "${YELLOW}Generando certificados SSL...${NC}"
docker-compose -f generate-indexer-certs.yml run --rm generator
if [ $? -eq 0 ]; then
    echo -e "${GREEN} Certificados generados correctamente${NC}"
else
    echo -e "${RED} Error generando certificados${NC}"
    exit 1
fi

echo -e "${YELLOW}Desplegando Wazuh stack...${NC}"
docker-compose up -d
check_containers "Wazuh"

#Verificar que existe un ossec.conf en la carpeta
if [ ! -f ossec.conf ]; then
    echo -e "${RED} ossec.conf no encontrado en el directorio actual${NC}"
else
    echo -e "${GREEN} ossec.conf encontrado${NC}"
    #Copiar ossec.conf al contenedor del wazuh manager, si existe el contenedor
    if [ $(docker ps -q -f name=wazuh.manager | wc -l) -gt 0 ]; then
        
        echo -e "${YELLOW}Configurando ossec.conf con la IP del host: ${HOST_IP}${NC}"

        #Función para obtener el webhook de un workflow de Shuffle
        workflow_name="test valorh2"
        echo -e "${YELLOW}Intentando obtener el webhook del workflow '${workflow_name}' de Shuffle...${NC}"

        # Verificar si jq está instalado
        if ! command -v jq &> /dev/null; then
            echo -e "${RED} El comando 'jq' no está instalado. Por favor, instálalo para continuar.${NC}"
        else
            # Verificar si la API key está configurada
            if [ -z "$SHUFFLE_API_KEY" ]; then
                echo -e "${RED} La variable de entorno SHUFFLE_API_KEY no está configurada.${NC}"
                echo -e "${YELLOW}Por favor, configúrala con tu API key de Shuffle y vuelve a ejecutar el script.${NC}"
            else
                # Esperar a que la API de Shuffle esté disponible
                echo -e "${BLUE}Esperando a que la API de Shuffle esté disponible...${NC}"
                while ! curl -s -o /dev/null "http://localhost:3001/api/v1/status"; do
                    echo -n "."
                    sleep 5
                done
                
                echo -e "\n${GREEN} API de Shuffle está activa.${NC}"
                # Obtener los workflows y filtrar para encontrar el webhook ID
                webhook_id=$(curl -s -H "Authorization: Bearer ${SHUFFLE_API_KEY}" "http://localhost:3001/api/v1/workflows" | \
                    jq -r --arg WORKFLOW_NAME "test valorh2" '.[] | select(.name == $WORKFLOW_NAME) | .triggers[] | select(.trigger_type == "WEBHOOK") | .parameters[] | select(.name == "url") | .value | split("/") | last')

                if [ -z "$webhook_id" ]; then
                    echo -e "${RED} No se pudo encontrar el webhook para el workflow '${workflow_name}'.${NC}"
                    echo -e "${YELLOW}Verifica que el workflow existe y tiene un trigger de tipo webhook.${NC}"
                else
                    #Reemplazar el webhook de Shuffle en ossec.conf
                    echo -e "${YELLOW}Configurando webhook de Shuffle: ${webhook_id}${NC}"
                    #Buscar en ossec.conf la linea que contiene webhook_id y reemplazarla
                    sed -i "s/webhook_id/${webhook_id}/g" ossec.conf
                fi
            fi
        fi

        #Reemplazar localhost por la IP en el webhook de shuffle en ossec.conf
        sed -i "s/localhost:/$HOST_IP:/g" ossec.conf
        
        #Copiar el archivo al contenedor
        echo -e "${YELLOW}Copiando ossec.conf al contenedor wazuh-manager...${NC}"
        docker cp ossec.conf single-node-wazuh.manager-1:/var/ossec/etc/ossec.conf
        #Copiar también el internal_options.conf
        docker cp internal_options.conf single-node-wazuh.manager-1:/var/ossec/etc/internal_options.conf
        if [ $? -eq 0 ]; then
            echo -e "${GREEN} ossec.conf copiado correctamente al contenedor wazuh-manager${NC}"
            #Poner de propietario a root:wazuh
            docker exec single-node-wazuh.manager-1 chown root:wazuh /var/ossec/etc/ossec.conf
            if [ $? -eq 0 ]; then
                echo -e "${GREEN} Propietario de ossec.conf cambiado a root:wazuh${NC}"
            else
                echo -e "${RED} Error al cambiar el propietario de ossec.conf${NC}"
            fi
            #Recargar la configuración del Wazuh Manager
            docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
            if [ $? -eq 0 ]; then
                echo -e "${GREEN} Configuración del Wazuh Manager recargada correctamente${NC}"
            else
                echo -e "${RED} Error al recargar la configuración del Wazuh Manager${NC}"
            fi
        else
            echo -e "${RED} Error al copiar ossec.conf al contenedor wazuh-manager${NC}"
        fi
    fi
fi
cd ..
cd ..

# 3. MISP
echo -e "${BLUE}🔍 Desplegando MISP...${NC}"
cd misp-docker
#Si no hay un .env, renombrar model.env a .env
if [ ! -f .env ]; then
    mv model.env .env
fi
#Poner IP de la maquina en el .env dentro de BASE_URL
sed -i "s|BASE_URL=.*|BASE_URL=https://$HOST_IP:4433|g" .env
docker-compose up -d
check_containers "MISP"
# Verificar que el contenedor de misp-modules esté corriendo
if [ $(docker ps -q -f name=misp-modules | wc -l) -eq 0 ]; then
    echo -e "${RED}El contenedor misp-modules no está corriendo${NC}"
    #Volver a intentar el despliegue en bucle
    while [ $(docker ps -q -f name=misp-modules | wc -l) -eq 0 ]; do
        echo -e "${YELLOW}Reintentando despliegue de MISP...${NC}"
        docker-compose up -d misp-modules
        if [ $? -eq 0 ]; then
            echo -e "${GREEN} MISP Modules desplegado correctamente${NC}"
            break
        fi
    done
    echo -e "${RED} Error al desplegar MISP Modules${NC}"
fi
cd ..

# 4. Cortex
echo -e "${BLUE} Desplegando Cortex...${NC}"
cd cortex
# Crear directorio de trabajos si no existe
sudo mkdir -p cortex-jobs
#Ajustar propietario al usuario cortex
sudo chown cortex:cortex cortex-jobs
docker-compose up -d
check_containers "Cortex"
cd ..

echo "--------------------------------------------------------"
echo "Iniciando configuración de analizadores de Cortex..."
echo "--------------------------------------------------------"

# DEFINE LAS VARIABLES REQUERIDAS ANTES DE LLAMAR A LA FUNCIÓN
export CORTEX_API_KEY="prZY/OChDUr54hvOMjVW80bXcYE8/+Fc"
echo $HOST_IP
export MISP_IP=$HOST_IP 
# LLAMA A LA FUNCIÓN Y VERIFICA SU CÓDIGO DE SALIDA
if update_cortex_misp_analyzer; then
    echo "Configuración del analizador MISP finalizada con éxito."
else
    echo "Falló la configuración del analizador MISP. Revisar los logs."
    # Opcional: puedes decidir terminar el script principal si esto falla
    # exit 1 
fi

echo "--------------------------------------------------------"

# 5. DFIR-IRIS
echo -e "${BLUE}🔬 Desplegando DFIR-IRIS...${NC}"
cd iris-web
docker-compose up -d
check_containers "IRIS"
cd ..

echo -e "${GREEN} Despliegue completado!${NC}"
echo ""
echo -e "${BLUE}📋 URLs de acceso:${NC}"
echo -e "${GREEN}- Wazuh Dashboard: https://localhost:443${NC}"
echo -e "${GREEN}- MISP: http://localhost:8081 | https://localhost:4433${NC}"
echo -e "${GREEN}- Cortex: http://localhost:9001${NC}"
echo -e "${GREEN}- DFIR-IRIS: https://localhost:8443${NC}"
echo -e "${GREEN}- Shuffle: http://localhost:3001${NC}"
echo ""
echo -e "${YELLOW} Para verificar el estado completo:${NC}"
echo "docker ps -a | grep -E 'wazuh|misp|cortex|iris|shuffle'"
echo ""
echo -e "${YELLOW} Para ver logs de un servicio específico:${NC}"
echo "cd [directorio] && docker-compose logs -f [servicio]"
echo ""
echo -e "${RED} IMPORTANTE: Cambiar todas las credenciales por defecto antes de usar en producción${NC}"