# Arquitectura

ResponseLab tiene dos mitades que no se mezclan:

- **Decidir.** [`responselab/nucleo.py`](../responselab/nucleo.py) recibe una alerta
  ya normalizada, el catálogo y el perfil del cliente, y devuelve un plan. No hace
  red, no escribe en disco y no lee el reloj si no se le da la hora. Por eso el mismo
  fichero puede ir dentro de un nodo de Shuffle, de un playbook de Splunk SOAR o del
  script de Cortex XSOAR.
- **Ejecutar.** El motor (`ejecutor.py`, `api.py`, `conectores/`) recibe alertas,
  guarda el estado, correlaciona incidentes, ejecuta lo que el plan permite, pide
  aprobación para lo demás y avisa.

## Recorrido de una alerta

```
SIEM ──► POST /v1/<cliente>/alertas/<siem>          (token de ingesta del cliente)
         │  normalizar: el formato de cada SIEM a un esquema comun
         │  duplicada? limitada? -> se responde 202 en milisegundos
         ▼
       cola persistente (SQLite)  ── sobrevive a un reinicio
         ▼
       contexto: CTI de News CTI, DNS inverso, alertas recientes (7 dias)
         ▼
       nucleo.decidir ──► plan
         │  regla y familia (Wazuh id, nombre de busqueda de Splunk, titulo)
         │  triaje: cada pregunta contesta si / no / no se
         │  secuencias: varias alertas del mismo equipo o persona
         │  cierre automatico (solo con todas las condiciones comprobadas)
         │  cada accion: automatica / aprobacion / manual / no_aplicable / prohibida
         │  escalado: L2, L3 o guardia, y a quien mas avisar
         ▼
       verificar_invariantes (defensa en profundidad)
         ▼
       incidente: el abierto de ese equipo o persona, o uno nuevo
       plazos legales: RGPD, NIS2, DORA, segun el cliente y el activo
         ▼
       automatica ──► conector ──► acuse (los agentes confirman por Wazuh)
       aprobacion ──► panel / API ──► aprobar ──► conector
       manual     ──► tarea en el incidente
         ▼
       caso en TheHive con la plantilla de la familia, aviso por el canal del cliente
       auditoria encadenada de todo lo anterior
```

## Piezas

| Pieza | Fichero | Qué hace |
|---|---|---|
| Núcleo | `responselab/nucleo.py` | Normalización (Wazuh, Splunk, Sentinel, Elastic, genérico), evaluadores, secuencias, política, plan |
| Motor | `responselab/ejecutor.py` | Cola, trabajadores, correlación, ejecución, aprobaciones, deshacer, acuses, ingesta de FtriageDFIR y Malpipe, vigilancia periódica |
| Almacén | `responselab/almacen.py` | SQLite en WAL: alertas, incidentes, ejecuciones, aprobaciones, tareas, EDL, auditoría encadenada |
| API | `responselab/api.py` | HTTP, autenticación por función y cliente, panel |
| Clientes | `responselab/clientes.py` | Perfiles YAML con recarga en caliente; un perfil inválido no sustituye al bueno |
| Catálogo | `responselab/gestor_catalogo.py` | Carga, valida y actualiza el catálogo desde el repositorio |
| Inteligencia | `responselab/cti.py` | Feed de News CTI: IOCs con nivel, edad y fuentes; CVE del catálogo KEV |
| Plazos legales | `responselab/regulatorio.py` | Relojes de RGPD, NIS2 y DORA |
| Avisos | `responselab/avisos.py` | Teams, Slack, Discord, webhook y correo |
| Conectores | `responselab/conectores/` | Una clase por herramienta y el conector declarativo para el resto |
| Exportadores | `responselab/exportadores/` | Lo que se importa en cada SOAR y SIEM |

## El catálogo

`tools/compilar.py` junta tres fuentes en `catalogo/catalogo.json`:

1. **`ecosistema/`**: lo que se sincroniza de los otros repositorios. Son los
   playbooks de respuesta de DetectionLab (las preguntas de triaje, las condiciones
   de cierre y la contención con su radio, su reversibilidad y su justificación) y
   las reglas de DetectionLab, Infra-SocAnalyst y SplunkLab.
2. **`playbooks/`**: la capa ejecutable. Traduce cada pregunta y cada excepción
   escritas en prosa a un evaluador que la máquina puede contestar, y define las
   secuencias de ataque. Ver [`playbooks/LEEME.md`](../playbooks/LEEME.md).
3. **`acciones/catalogo.yml`**: las acciones ejecutables y cómo se llaman en cada
   SOAR.

El compilador es determinista: sin marcas de tiempo y con identificadores
derivados del contenido. El CI regenera todo y falla si el resultado no coincide
con lo que hay en el repositorio. Lo mismo vale para los 65 ficheros de `soar/`,
`siem/` y `docs/COBERTURA.md`.

## Actualización automática

```
DetectionLab ─┐
Infra-Soc ────┼─► sincronizar.yml (diario o repository_dispatch)
SplunkLab ────┤     sincronizar ─► compilar ─► validar ─► pytest ─► escenarios
News CTI ─────┘           │ solo si todo pasa
                          ▼
                 commit en main (catalogo/, soar/, siem/, ecosistema/)
                          ▼
     motores: RL_ACTUALIZACION_URL cada 30 min ─► validar otra vez ─► usar
```

Hay dos validaciones, y es a propósito. La del CI impide publicar un catálogo roto.
La del motor impide usar uno que haya llegado mal (por ejemplo, un catálogo hecho
para una versión más nueva del núcleo, con evaluadores que esta no conoce). Si la
segunda falla, el motor sigue con el catálogo anterior y lo dice en `/salud`.

Los artefactos de cada SOAR también se regeneran en cada sincronización. Volver a
importarlos es la parte que no se puede automatizar desde aquí, porque cada SOAR
tiene su propio mecanismo. [`SOAR.md`](SOAR.md) explica cómo hacerlo en cada uno.

## Estado y concurrencia

- **Un único proceso por motor.** SQLite en modo WAL, con un cerrojo para las
  escrituras. La decisión, la correlación y el guardado de una alerta van en serie:
  dos alertas del mismo ataque procesadas a la vez tienen que verse la una a la otra,
  o la secuencia no se detecta nunca.
- **Cola persistente.** Un trabajo interrumpido por un reinicio vuelve a la cola al
  arrancar.
- **Idempotencia.** Una alerta repetida (los SIEM reintentan) se descarta por su id
  y cliente. La misma acción sobre el mismo objetivo en el mismo incidente no se
  ejecuta dos veces mientras no se deshaga.

## Seguridad del propio motor

| Riesgo | Medida |
|---|---|
| Token de ingesta filtrado (viaja en la URL del webhook de Splunk) | Solo sirve para ingerir alertas de su cliente: ni acuses, ni aprobaciones, ni administración |
| Un cliente actúa sobre otro | Cada ruta lleva el cliente y cada token es de uno. Los incidentes, ejecuciones y aprobaciones se comprueban contra el cliente de la petición |
| Catálogo manipulado o mal escrito | Las invariantes están en el código, no en el catálogo. La validación simula una alerta crítica de cada regla y rechaza cualquier acción automática de radio amplio |
| Alertas en bucle | Limitador por regla y equipo; cuerpo máximo de 1 MiB (configurable), contado aunque no venga `Content-Length` |
| Secretos en los perfiles | Prohibidos por validación: solo nombres de variables de entorno y huellas SHA-256 |
| Alteración del historial | Auditoría encadenada por hash: `GET /v1/admin/auditoria/verificar` |
| Plantillas de conectores declarativos | Sin expresiones: solo rutas de datos y cuatro filtros fijos |
| Contenedor | Usuario sin privilegios, sistema de ficheros en solo lectura, sin capacidades, `no-new-privileges` |
