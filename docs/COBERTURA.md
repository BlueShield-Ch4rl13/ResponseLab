# Cobertura de respuesta

<!-- Generado por tools/compilar.py desde catalogo/catalogo.json - no editar a mano -->

Catálogo `01bbe55923a1` · **235 reglas** · **16 familias** · **54 acciones ejecutables** · **7 secuencias de ataque**

| Origen | Reglas |
|---|---:|
| detectionlab | 207 |
| infra-socanalyst | 7 |
| splunklab | 21 |

## Qué sabe contestar la máquina

Las preguntas de triaje y las condiciones de cierre vienen de los playbooks de
DetectionLab. Las que tienen evaluador las contesta el motor con datos de la
alerta, del perfil del cliente, de la inteligencia o del histórico; el resto
quedan como tarea del analista. Ninguna se contesta por defecto.

| Familia | Reglas | Triaje automático | Cierre automático | Contención mapeada |
|---|---:|---:|---:|---:|
| `_generico` | 1 | 0/0 | 0/0 | 0/0 |
| `ad` | 20 | 2/5 | 0/0 | 4/4 |
| `cloud` | 11 | 3/6 | 0/2 | 4/4 |
| `contenedores` | 10 | 3/6 | 0/1 | 4/4 |
| `correo` | 8 | 3/6 | 1/2 | 4/4 |
| `credenciales` | 7 | 3/4 | 0/0 | 2/2 |
| `cumplimiento` | 14 | 3/3 | 0/2 | 2/2 |
| `endpoint` | 18 | 5/6 | 1/2 | 5/5 |
| `exfiltracion` | 8 | 3/6 | 0/0 | 4/4 |
| `inteligencia` | 7 | 4/4 | 2/2 | 4/4 |
| `linux` | 19 | 5/6 | 1/1 | 4/4 |
| `macos` | 8 | 4/5 | 1/1 | 4/4 |
| `red` | 6 | 4/5 | 1/2 | 4/4 |
| `web` | 20 | 6/6 | 0/2 | 4/4 |
| `xdr` | 10 | 3/6 | 0/0 | 4/4 |
| `zta` | 68 | 4/5 | 3/3 | 2/2 |
| **Total** | **235** | **55/79** | **10/20** | **55/55** |

## Qué se ejecuta sin persona en una alerta crítica

Simulación de una alerta `critical` de cada regla, con todos los campos presentes
y un cliente que no restringe nada. Es el techo: en producción, el perfil del
cliente, el inventario y los datos que traiga la alerta solo pueden bajar estas
cifras, nunca subirlas.

| Familia | Automática | Con aprobación | Manual | No aplica |
|---|---:|---:|---:|---:|
| `ad` | 80 | 20 | 0 | 0 |
| `cloud` | 33 | 11 | 0 | 0 |
| `contenedores` | 30 | 10 | 0 | 0 |
| `correo` | 16 | 16 | 0 | 0 |
| `credenciales` | 21 | 0 | 0 | 0 |
| `cumplimiento` | 28 | 0 | 0 | 0 |
| `endpoint` | 90 | 18 | 0 | 0 |
| `exfiltracion` | 32 | 8 | 0 | 0 |
| `inteligencia` | 21 | 7 | 0 | 0 |
| `linux` | 76 | 19 | 0 | 0 |
| `macos` | 32 | 8 | 0 | 0 |
| `red` | 24 | 6 | 0 | 0 |
| `web` | 80 | 20 | 0 | 0 |
| `xdr` | 40 | 10 | 0 | 0 |
| `zta` | 69 | 0 | 0 | 67 |

## Acciones por radio

| Acción | Radio | Reversible | Capacidad | Conectores |
|---|---|:---:|---|---|
| `aplicacion.invalidar_sesion` | objeto | si | aplicacion | declarativo |
| `caso.nota` | objeto | si | casos | interno, thehive |
| `caso.tarea_desviacion` | objeto | si | itsm | interno, declarativo |
| `caso.tarea_obligacion` | objeto | si | interno | interno |
| `correo.bloquear_remitente` | organizacion | si | pasarela_correo | declarativo |
| `correo.bloquear_url` | organizacion | si | perimetro | defender, edl, declarativo |
| `correo.deshabilitar_regla` | objeto | si | correo | exchange |
| `correo.retirar_mensaje` | objeto | si | correo | exchange |
| `credenciales.marcar_rotacion` | objeto | si | interno | interno, declarativo |
| `cuenta.deshabilitar` | cuenta | si | identidad | entra, declarativo |
| `cuenta.retirar_clave_ssh` | cuenta | si | agente | wazuh |
| `endpoint.aislar` | equipo | si | edr | wazuh, defender, crowdstrike, sentinelone |
| `evidencia.conservar_fichero` | objeto | si | agente | wazuh |
| `evidencia.instantanea_ad` | objeto | si | agente | wazuh |
| `evidencia.paquete_investigacion` | objeto | si | edr | defender |
| `evidencia.retener` | objeto | si | siem | splunk, interno |
| `evidencia.triage_forense` | objeto | si | agente | wazuh |
| `fichero.cuarentena` | objeto | si | edr | wazuh, defender |
| `flota.bloquear_hash` | organizacion | si | edr | defender, crowdstrike, sentinelone |
| `identidad.marcar_riesgo` | sesion | si | identidad | entra |
| `identidad.retirar_consentimiento` | cuenta | si | identidad | entra |
| `identidad.revocar_sesiones` | sesion | si | identidad | entra |
| `inventario.marcar_no_fiable` | equipo | si | interno | interno |
| `itsm.ticket` | objeto | si | itsm | declarativo, interno |
| `k8s.acordonar_nodo` | equipo | si | kubernetes | kubernetes |
| `k8s.aislar_pod` | objeto | si | kubernetes | kubernetes |
| `k8s.escalar_cero` | equipo | si | kubernetes | kubernetes |
| `k8s.retirar_rolebinding` | objeto | si | kubernetes | kubernetes |
| `perimetro.bloquear_destino` | organizacion | si | perimetro | paloalto, fortinet, defender, edl, declarativo |
| `persistencia.deshabilitar` | objeto | si | agente | wazuh |
| `proceso.matar` | proceso | no | edr | wazuh, crowdstrike |
| `red.aislar_equipo` | equipo | si | nac | paloalto, fortinet, declarativo |
| `red.bloquear_destino_equipo` | equipo | si | agente | wazuh, declarativo |
| `waf.bloquear_origen` | organizacion | si | waf | cloudflare, edl, declarativo |

## Traducción a cada SOAR

El motor ejecuta todas las acciones con sus conectores; Shuffle y n8n le
delegan la ejecución. Cuando el SOAR actúa por su cuenta, esto es lo que
tiene traducción nativa; lo demás se exporta como tarea manual.

| Acción | Cortex XSOAR | Splunk SOAR | Sentinel (Logic Apps) |
|---|---|---|---|
| `correo.bloquear_remitente` | `Block Email - Generic v2` | tarea | tarea |
| `correo.bloquear_url` | `Block URL - Generic v2` | `block url` | tarea |
| `correo.retirar_mensaje` | tarea | `delete email` | tarea |
| `cuenta.deshabilitar` | `Block Account - Generic v2` | `disable user` | tarea |
| `endpoint.aislar` | `Isolate Endpoint - Generic V2` | `quarantine device` | `mde_aislar` |
| `endpoint.liberar` | `Unisolate Endpoint - Generic` | `unquarantine device` | tarea |
| `evidencia.paquete_investigacion` | `!microsoft-atp-collect-investigation-package` | `collect investigation package` | `mde_paquete` |
| `fichero.cuarentena` | `!microsoft-atp-stop-and-quarantine-file` | `quarantine file` | `mde_cuarentena` |
| `flota.bloquear_hash` | `Block File - Generic v2` | `block hash` | tarea |
| `identidad.marcar_riesgo` | tarea | tarea | `graph_riesgo` |
| `identidad.revocar_sesiones` | `!msgraph-user-session-revoke` | `revoke session` | `graph_revocar` |
| `perimetro.bloquear_destino` | `Block Indicators - Generic v3` | `block ip` | tarea |
| `proceso.matar` | tarea | `terminate process` | tarea |
| `red.aislar_equipo` | `Isolate Endpoint - Generic V2` | tarea | tarea |
| `waf.bloquear_origen` | `Block IP - Generic v3` | `block ip` | tarea |

