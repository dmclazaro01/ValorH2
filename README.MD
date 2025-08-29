-El zip del drive que se adjunta tiene un backup de la database de MISP. En caso de querer usarlos es necesario descargar el zip y colocarlo en esta misma carpeta.
-Para lanzar el proyecto es necesario lanzar como sudo el 'deployment.sh'. 
-En ninguno de los casos vendrá preconfigurado Wazuh ya que la versión dockerizada no permite exportar la base de datos, por lo que será necesario
realizar configuraciones manuales siguiendo la guía oficial: https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html. Para incluir la integración de Shuffle, el bloque que se debe introducir en el ossec.conf es el siguiente:
  <integration>
    <name>shuffle</name>
    <hook_url>https://shuffle-frontend/api/v1/hooks/webhook_id</hook_url>
    <level>10</level>
    <alert_format>json</alert_format>
  </integration>
Donde webhook_id será el identificador del hook que aparecerá al importar el flujo de trabajo dentro de Shuffle. Tras ello, guardar el ossec.conf y reiniciar el cluster.
-En caso de error en el despliegue de MISP, repetir el docker compose up -d. En ocasiones los contenedores misp-core/misp-modules dan errores al ser el primer despliegue.
-El test_valorh2-json es el flujo de trabajo de Shuffle. Viene preconfigurado con API Keys usadas en el despliegue de prueba. En caso de que se hayan usado los backup a priori no deberían cambiar, en caso contrario deberán ajustarse con las nuevas API Keys de MISP, IRIS, etc. Importar este flujo en caso de que no se hayan usado los backups, en caso contrario debería aparecer ya.

**CREDENCIALES**
-MISP
    Usuario:admin@admin.test
    Contraseña:admin
-IRIS
    Usuario:administrator
    Contraseña:chv7uev3ahg@rjf@ZND
