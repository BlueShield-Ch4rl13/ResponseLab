# Conectar los SIEM

Cada SIEM envía sus alertas al motor tal como las produce, a
`POST https://<motor>:8443/v1/<cliente>/alertas/<siem>`. El motor las normaliza a un
mismo esquema y no hace falta transformarlas antes. Todo lo que hay en
`siem/` se genera desde el catálogo o está escrito a mano, y lo dice en su cabecera.

| SIEM | `<siem>` | Autenticación |
|---|---|---|
| Wazuh | `wazuh` | `Authorization: Bearer <token de ingesta>` |
| Splunk | `splunk` | `?token=<token de ingesta>` (el webhook de Splunk no admite cabeceras) |
| Elastic Security | `elastic` | Básica, con el token de ingesta como contraseña (Kibana la guarda cifrada) |
| Microsoft Sentinel | `sentinel` | `Authorization: Bearer`, desde la Logic App *RL-Reenviar-al-motor* |
| Cualquier otro | `generico` | La alerta ya en el esquema de ResponseLab |

El token de ingesta solo sirve para enviar alertas de su cliente. El de la URL de
Splunk termina en el registro de cualquier proxy; por eso no abre nada más.

---

## Wazuh

Es el SIEM del laboratorio (Infra-SocAnalyst) y, además, el brazo ejecutor en los
equipos: el motor ordena acciones a los agentes por la API de Wazuh, y los agentes
confirman lo que hicieron por el propio Wazuh.

```
alerta ─► integratord ─► custom-responselab ─► motor
motor ─► API de Wazuh (PUT /active-response) ─► agente ─► responselab-<accion>
agente ─► active-responses.log ─► manager (reglas 109900-109903) ─► custom-responselab ─► /acuses
```

### En el manager

```bash
sudo sh siem/wazuh/instalar-manager.sh --prueba   # dice qué haría
sudo sh siem/wazuh/instalar-manager.sh
sudo vi /var/ossec/etc/responselab.json            # URL del motor, cliente y tokens
```

El instalador hace cinco cosas:
1. Copia la integración a `integrations/`.
2. Instala las reglas de acuse.
3. Crea `responselab.json` desde el ejemplo si no existe.
4. Mete en `ossec.conf` el bloque generado entre marcas.
5. Valida con `wazuh-analysisd -t` y reinicia. Si algo falla, restaura `ossec.conf`.

Se puede repetir tras cada sincronización: solo sustituye su propio bloque.

El bloque de `ossec.conf` envía al motor tres cosas:
- las reglas que el catálogo conoce, por id exacto;
- cualquier alerta de nivel 12 o más, a la que el motor aplica el playbook genérico;
- los acuses de los agentes.

`responselab.json` (root:wazuh, 640):

| Clave | Qué es |
|---|---|
| `motor` | URL del motor (`https://10.0.30.20:8443`) |
| `cliente` | Cliente por defecto |
| `clientes.<id>.token_ingesta` / `token_agentes` | Tokens de cada cliente que pasa por este manager |
| `clientes_por_agente` | `[{patron, cliente}]` para un manager compartido (MSSP): el nombre del agente decide el cliente |
| `ca` / `verificar_tls` | CA del proxy del motor. `verificar_tls: false` solo en laboratorio |
| `timeout`, `reintentos` | Si el motor no contesta, la alerta va a `var/responselab/pendientes` y se reenvía con la siguiente |

### En los agentes

Linux (como root):

```bash
sudo sh siem/wazuh/instalar-agente-linux.sh
```

Windows (PowerShell como administrador, o desde una GPO o Intune):

```powershell
powershell -ExecutionPolicy Bypass -File siem\wazuh\instalar-agente-windows.ps1
```

Los instaladores hacen tres cosas:
- Copian `responselab_ar` y los 14 lanzadores `responselab-<accion>`.
- Dejan esos ficheros y la carpeta de custodia solo para root/SYSTEM y
  administradores. Los scripts se ejecutan como SYSTEM: un usuario que pudiera
  editarlos tendría una escalada de privilegios servida.
- Comprueban que el agente envía `active-responses.log` al manager, que es por donde
  vuelven los acuses.

Las acciones que entienden los scripts:

| Acción | Linux | Windows |
|---|---|---|
| `aislar` / `liberar` | nftables (o iptables) con política drop, salvo manager, motor y `permitidos` | Reglas de bloqueo del Firewall de Windows con todo el rango salvo lo permitido |
| `matar` | Comprueba PID, hora de arranque e imagen antes de matar | Igual, y nunca un proceso crítico del sistema |
| `cuarentena` / `restaurar` | A custodia con permisos 000, sin tocar rutas del sistema | A custodia con ACL solo para SYSTEM y administradores |
| `conservar` | Copia a custodia con su hash (nunca un almacén de credenciales) | Igual |
| `persistencia` / `persistencia-restaurar` | Unidades systemd, líneas de crontab, ld.so.preload. Nunca ficheros de paquetes ni ficheros de cron enteros | Tarea programada, clave Run, servicio o fichero |
| `bloquear-destino` / `desbloquear-destino` | Solo IP públicas | Solo IP públicas |
| `ssh-clave` / `ssh-clave-restaurar` | Retira una clave concreta de authorized_keys | Igual (OpenSSH de Windows) |
| `triage` | Lanza FtriageDFIR en segundo plano y devuelve el informe | Igual |
| `instantanea-ad` | — | Exporta un objeto del directorio antes de tocarlo (en un DC) |

**Aislamiento y DNS.** Un equipo aislado no resuelve nombres. Lo más seguro es
tener el manager por IP en el `ossec.conf` del agente. Si está por nombre, los
scripts lo resuelven justo antes de cerrar y dejan pasar esas IP, y el instalador
de Windows lo advierte. Si la IP del manager cambia con el equipo aislado, se
pierde el contacto. Añade a `permitidos` (en el perfil del cliente,
`conectores.wazuh`) el motor y lo que el equipo aislado tenga que seguir viendo.

**Triage.** Con `responselab.conf` repartido por la configuración centralizada
(`/var/ossec/etc/shared/<grupo>/responselab.conf`), el agente sabe dónde está
FtriageDFIR y puede subir el informe completo al motor con el token de agentes. Sin
él, el resumen vuelve en el acuse.

---

## Splunk

Las búsquedas de DetectionLab (`TA-detection-lab`) y de SplunkLab (`mi_indice`)
ya existen. ResponseLab solo les añade la acción webhook:

1. Copia `siem/splunk/savedsearches-detectionlab.conf` a
   `$SPLUNK_HOME/etc/apps/TA-detection-lab/local/savedsearches.conf`. Haz lo mismo
   con `savedsearches-splunklab.conf` en `apps/mi_indice/local/`. Splunk combina
   `local/` con `default/` clave a clave: el resto de cada búsqueda no cambia.
2. Sustituye `MOTOR`, `CLIENTE` y `TOKEN_DE_INGESTA`.
3. Splunk 9 descarta en silencio un webhook a una URL que no esté permitida. Copia
   `siem/splunk/alert_actions.conf` a `etc/system/local/` (o a la app) con el nombre
   del motor.
4. Reinicia Splunk o recarga la configuración.

El motor reconoce cada búsqueda por su nombre (`DL - ...`, `DET-...`), con o sin los
prefijos y sufijos que añade Splunk ES. También acepta notables planos de ES tal
como los reenvía un SOAR.

---

## Elastic

```powershell
$token = Read-Host -AsSecureString 'Token de ingesta'
./siem/elastic/configurar.ps1 -Kibana https://kibana:5601 -Usuario elastic `
    -Motor https://motor:8443 -Cliente lab -TokenIngesta $token
```

El script hace dos cosas:
- Crea o actualiza en Kibana el conector webhook «ResponseLab», con autenticación
  básica: Kibana la guarda cifrada, mientras que una cabecera escrita a mano quedaría
  en claro.
- Añade la acción a todas las reglas de detección cuyo nombre está en
  `siem/elastic/reglas-responselab.json`, en bloque.

Con `-SoloConector` crea el conector y no toca las reglas. Requiere Kibana 8.8 o
posterior.

---

## Microsoft Sentinel

En Sentinel, la entrada y la respuesta van juntas: una regla de automatización
ejecuta una Logic App cuando se crea un incidente. Hay dos modos:
- **nativo**: las Logic Apps aíslan con Defender y revocan sesiones con Entra ID
  ellas mismas;
- **motor**: reenvían el incidente al motor.

Todo está en [`SOAR.md`](SOAR.md#microsoft-sentinel).

---

## Cualquier otro SIEM

Envía a `/v1/<cliente>/alertas/generico` un JSON con el esquema de ResponseLab. El
esquema está documentado en el comentario de `nucleo.py`, sección «Normalización».
Como mínimo lleva `titulo`, y lo ideal es incluir `regla_id` o `regla_nombre`,
`equipo.nombre`, `usuario.nombre` y lo que traiga la alerta (proceso, fichero, red,
correo).
