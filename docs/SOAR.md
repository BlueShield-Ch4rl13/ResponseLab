# Importar en cada SOAR

Todo lo que hay en `soar/` se genera desde el catálogo con `python tools/compilar.py`
y se regenera en cada sincronización con el ecosistema. Las acciones cambian de
nombre en cada SOAR; la decisión, no.

| SOAR | Quién decide | Qué se importa |
|---|---|---|
| Shuffle + TheHive | El motor (`/decidir`) | Workflow y plantillas de caso |
| n8n | El motor (`/decidir`) | Workflow |
| Splunk SOAR | El núcleo, incrustado en el playbook enrutador | Un playbook enrutador y uno por familia |
| Cortex XSOAR | El núcleo, incrustado en el script `ResponseLabDecidir` | Script, enrutador, un playbook por familia y una lista con el perfil del cliente |
| Microsoft Sentinel | Las Logic Apps (traducción estática, con comprobaciones en ejecución) o el motor | Plantillas ARM, regla de automatización y permisos |

Cuando el SOAR ejecuta él mismo, cada acción que no tiene traducción a ese SOAR se
convierte en tarea manual. Nunca se omite en silencio.

---

## Shuffle y TheHive

Es la combinación del laboratorio (Infra-SocAnalyst).

1. **Plantillas de caso en TheHive 5**, una por familia, con el playbook entero como
   tareas:

   ```powershell
   $env:THEHIVE_API_KEY = "<clave de API de TheHive>"
   python tools/importar_thehive.py --url http://thehive:9000 --organizacion SOC --comprobar
   python tools/importar_thehive.py --url http://thehive:9000 --organizacion SOC
   ```

   Las que ya existen se actualizan y conservan los campos personalizados que les
   hayas añadido. En un MSSP con una organización por cliente, se ejecuta una vez
   por organización. Si tu versión de TheHive no acepta cambiar tareas con PATCH,
   usa `--reemplazar`.

2. **Workflow de Shuffle**: *Workflows → Import* con
   `soar/shuffle/workflow-responselab.json`. Después, rellena sus variables
   (`motor_url`, `cliente`, `token_motor` y `ollama_url`) y la autenticación de
   las apps de TheHive y Discord.

3. Apunta la integración de Wazuh al webhook del trigger `SIEM` del workflow.

En este modo, Shuffle abre los casos y avisa, y el motor decide y ejecuta. Para que
nada salga dos veces, el perfil del cliente en el motor no declara la capacidad
`casos` ni canales de aviso.

## n8n

1. *Workflows → Import from file* con `soar/n8n/responselab.json`.
2. Edita el nodo *Configuracion* (URL del motor y cliente).
3. Crea dos credenciales de tipo *Header Auth*:
   - **ResponseLab motor**: `Authorization: Bearer <token de ingesta>`;
   - **TheHive**: `Authorization: Bearer <clave de API>`.
4. Apunta el SIEM al webhook del workflow.

## Splunk SOAR

Para cada fichero de `soar/splunk-soar/`:

1. Ve a *Playbooks → + Playbook → Automation* y cambia a edición de código completo.
2. Pega el fichero y guarda el playbook con el mismo nombre que el fichero, sin
   extensión (`responselab_enrutador`, `responselab_endpoint`...).
3. Activa `responselab_enrutador` para la etiqueta de los contenedores que llegan
   del SIEM.

Arriba de cada playbook hay dos bloques editables:

- `APROBACION`: quién aprueba (usuario o rol) y cuánto espera.
- `ASSETS`: qué asset usa cada acción si hay varias apps que la soportan.

El enrutador lleva incrustado el núcleo de decisión. Guarda el plan como artefacto
del contenedor y llama al playbook de la familia, que ejecuta con las acciones
genéricas de SOAR: `quarantine device`, `block hash`, `disable user`…

## Cortex XSOAR

1. **Script.** *Settings → Advanced → Automation → Import*, con
   `soar/xsoar/script-ResponseLabDecidir.yml`.
2. **Playbooks.** *Playbooks → Import*: primero los de familia y después
   `playbook-ResponseLab_-_Enrutador.yml`.
3. **Perfil del cliente.** Ve a *Settings → Advanced → Lists*, crea
   `ResponseLab_Cliente` y pega el contenido de `lista-ResponseLab_Cliente.json`.
   Ajusta la política, el inventario y las listas. Sin esa lista se aplica el perfil
   prudente: toda excepción sin datos pide aprobación.
4. **Asignación.** Pon *ResponseLab - Enrutador* como playbook por defecto de los
   tipos de incidente que llegan del SIEM.

Los playbooks de familia usan playbooks genéricos del pack *Common Playbooks*:

- Isolate Endpoint - Generic V2
- Block Indicators - Generic v3
- Block Account - Generic v2
- Block File - Generic v2
- Block IP - Generic v3
- Block URL - Generic v2
- Block Email - Generic v2

También usan comandos de integración de Microsoft Defender for Endpoint y Microsoft
Graph User, si están configuradas.

Cada paso del plan llega como `ResponseLab.Plan.modos.<id>` (automática, aprobación o
manual), con sus entradas ya resueltas en `ResponseLab.Plan.entradas.<id>`. Lo
automático se ejecuta sin preguntar. Lo de aprobación es una tarea condicional
manual con *Sí* o *No*. Lo manual es una tarea con el motivo.

## Microsoft Sentinel

Hay dos modos, y se elige en la regla de automatización:

- **nativo**: la Logic App *RL-Respuesta* decide en Azure con las reglas del catálogo
  y actúa sobre Defender for Endpoint y Entra ID. Comprueba en ejecución tres cosas:
  - que el equipo exista en Defender y sea uno solo;
  - los activos y cuentas protegidos;
  - los hashes de negocio.
- **motor**: *RL-Reenviar-al-motor* envía el incidente al motor de ResponseLab, que
  decide y ejecuta con todos sus conectores.

### 1. Desplegar los playbooks

```powershell
New-AzResourceGroupDeployment -ResourceGroupName rg-soar `
    -TemplateFile soar/sentinel/playbooks.json `
    -ContencionAutomatica $false `
    -ActivosProtegidos @('dc01', 'dc02') -CuentasProtegidas @('breakglass01@acme.test')
```

| Parámetro | Por defecto | Qué es |
|---|---|---|
| `ContencionAutomatica` | `false` | Con `false`, *RL-Respuesta* comenta en el incidente lo que haría, sin hacerlo. Ponlo a `true` después de revisar esos comentarios |
| `ActivosProtegidos` | `[]` | Nombres cortos de equipo, en minúsculas, que nunca se contienen solos |
| `CuentasProtegidas` | `[]` | Cuentas que nunca se tocan solas: emergencia, servicio crítico |
| `HashesDeNegocio` | `[]` | SHA-1 o SHA-256 que nunca se ponen en cuarentena solos |
| `ApiDefender` | `https://api.security.microsoft.com` | Endpoint regional de Defender si hace falta (UE: `https://eu.api.security.microsoft.com`) |
| `DesplegarReenvio`, `MotorUrl`, `Cliente`, `TokenMotor` | — | Solo para el modo motor. El token, mejor como referencia a Key Vault |

### 2. Conceder permisos

```powershell
./soar/sentinel/conceder-permisos.ps1 -GrupoPlaybooks rg-soar -GrupoWorkspace rg-sentinel
```

El script hace tres cosas, y puede ejecutarse varias veces:
- Da a la identidad de cada playbook el rol *Microsoft Sentinel Responder*.
- Concede solo los permisos de aplicación de Defender y Graph que ese playbook usa.
- Permite a *Azure Security Insights* ejecutar los playbooks.

### 3. Regla de automatización

```powershell
New-AzResourceGroupDeployment -ResourceGroupName rg-sentinel `
    -TemplateFile soar/sentinel/automatizacion.json `
    -Workspace mi-workspace -Modo nativo -GrupoPlaybooks rg-soar
```

*RL-Respuesta* reconoce la regla de analítica de cada alerta por su nombre, con o sin
el prefijo `DL - `. Las reglas que no están en el catálogo terminan sin hacer nada.

Además de los playbooks de respuesta, hay playbooks de acción para usar a mano
desde el incidente: *RL-Aislar-equipo*, *RL-Liberar-equipo*,
*RL-Cuarentena-fichero*, *RL-Paquete-investigacion*, *RL-Revocar-sesiones*,
*RL-Confirmar-compromiso* y *RL-Descartar-riesgo*.

---

## Mantener al día lo importado

Cuando el workflow de sincronización publica un catálogo nuevo:

- el **motor** lo recoge solo;
- en **Splunk SOAR** y **XSOAR** hay que volver a importar el enrutador o el script,
  porque el núcleo va incrustado y la decisión cambia con el catálogo; los playbooks
  de familia solo cambian si cambia la contención de esa familia;
- en **Sentinel** hay que volver a desplegar `playbooks.json`; el despliegue es
  idempotente;
- en **TheHive** se repite `tools/importar_thehive.py`.

Para saber qué cambió, mira el diff del commit de sincronización en `soar/`.
