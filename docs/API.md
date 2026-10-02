# API del motor

Todo va bajo `https://<motor>:8443`. Las respuestas son JSON salvo `/metricas`, las
listas EDL y el panel. Los errores tienen la forma `{"error": "motivo"}`.

## Autenticación

Cada token sirve para una función y un cliente:

| Función | Token | Cómo se envía | Rutas |
|---|---|---|---|
| Ingesta | `autenticacion.token_sha256` del cliente | `Authorization: Bearer`, básica (token como contraseña) o `?token=` | `alertas`, `decidir` |
| Agentes | `autenticacion.agentes` | `Authorization: Bearer` | `acuses`, `evidencias/*` |
| Listas EDL | `autenticacion.edl` | `Authorization`, básica o `?token=` | `edl/*` |
| Aprobador | `aprobadores[].token_sha256` | `Authorization: Bearer` | Incidentes, aprobaciones, ejecuciones, acciones, auditoría |
| Administración | `RL_ADMIN_TOKEN` | `Authorization: Bearer` | `/metricas`, `/v1/admin/*`; también vale como aprobador de cualquier cliente |

`?token=` solo se acepta donde la herramienta no sabe enviar cabeceras: el webhook
de Splunk y algunos cortafuegos que leen listas EDL. Un token en la URL acaba en los
registros de los proxies, así que nunca abre nada más.

## Entrada

| Método y ruta | Qué hace |
|---|---|
| `POST /v1/{cliente}/alertas/{siem}` | Encola una alerta, o una lista, en el formato nativo de `wazuh`, `splunk`, `sentinel`, `elastic` o `generico`. Responde `202` con `{alerta_id, estado}`, donde `estado` es `encolada`, `duplicada`, `limitada` o `rechazada` |
| `POST /v1/{cliente}/decidir/{siem}` | Devuelve el plan de una alerta sin guardar ni ejecutar nada. Es lo que usan Shuffle y n8n |

Una carga de Elastic con varias alertas se separa en una por alerta. El cuerpo
máximo es `RL_TAMANO_MAXIMO` (1 MiB): por encima, `413`.

```powershell
$cab = @{ Authorization = "Bearer $env:RL_LAB_TOKEN" }
Invoke-RestMethod -Method Post -Uri https://motor:8443/v1/lab/decidir/wazuh -Headers $cab `
    -ContentType application/json -InFile alerta.json
```

## Incidentes y aprobaciones (token de aprobador)

| Método y ruta | Qué hace |
|---|---|
| `GET /v1/{cliente}/incidentes?estado=abierto&limite=100` | Lista de incidentes |
| `GET /v1/{cliente}/incidentes/{id}` | Incidente con sus alertas, ejecuciones, aprobaciones y tareas |
| `POST /v1/{cliente}/incidentes/{id}/asumir` | Lo asume quien llama (para el plazo de escalado) |
| `POST /v1/{cliente}/incidentes/{id}/cerrar` | Lo cierra |
| `GET /v1/{cliente}/aprobaciones?estado=pendiente` | Lo que espera a una persona |
| `POST /v1/{cliente}/aprobaciones/{id}/aprobar` | Ejecuta la acción. Cuerpo opcional: `{"comentario": "..."}` |
| `POST /v1/{cliente}/aprobaciones/{id}/rechazar` | La descarta |
| `GET /v1/{cliente}/ejecuciones?incidente={id}` | Lo ejecutado o simulado, con el detalle de cada petición |
| `POST /v1/{cliente}/ejecuciones/{id}/deshacer` | Ejecuta la acción inversa con el mismo conector |
| `POST /v1/{cliente}/acciones/{accion}` | Ejecuta una acción del catálogo a demanda. Cuerpo: `{"objetivo": {"equipo.nombre": "PC-01"}, "incidente": "inc-...", "comentario": "..."}` |
| `GET /v1/{cliente}/auditoria?limite=200` | Registros de auditoría del cliente |
| `GET /v1/{cliente}/conectores` | Estado de cada conector del cliente: configurado o qué le falta |

Aprobar una aprobación caducada, deshacer dos veces o referirse a un incidente de
otro cliente devuelve un error y no ejecuta nada.

## Agentes (token de agentes)

| Método y ruta | Qué hace |
|---|---|
| `POST /v1/{cliente}/acuses` | Lo que pasó de verdad en el equipo: `{"ejecucion_id", "estado": "aplicada" o "fallida", "detalle": {...}}`. Lo envía la integración de Wazuh |
| `POST /v1/{cliente}/evidencias/ftriage` | Informe de FtriageDFIR: sus IOCs y técnicas van al incidente del equipo, y un veredicto crítico sube la severidad |
| `POST /v1/{cliente}/evidencias/malpipe?incidente={id}` | Veredicto de Malpipe: si es malicioso, propone bloquear el hash en la flota (con aprobación) |

## Listas EDL (token de EDL)

`GET /v1/{cliente}/edl/{ip|dominio|url}` devuelve una entrada por línea. Es el
formato que leen las *External Dynamic Lists* de Palo Alto, los *Threat Feeds* de
FortiGate, los alias *URL Table* de pfSense u OPNsense y, en general, cualquier
cortafuegos. Las entradas caducan solas según `politica.bloqueo_perimetro_horas`.

## Administración (token de administración)

| Método y ruta | Qué hace |
|---|---|
| `GET /salud` | Sin token. Estado, versión, catálogo en uso, CTI, clientes, perfiles con error y cola |
| `GET /metricas` | Métricas para Prometheus |
| `GET /v1/admin/catalogo` | Versión, origen y último error del catálogo |
| `POST /v1/admin/catalogo/actualizar` | Fuerza la descarga y validación del catálogo |
| `POST /v1/admin/cti/actualizar` | Fuerza el refresco de News CTI |
| `GET /v1/admin/auditoria/verificar` | Recorre la cadena de auditoría entera y dice si está íntegra |

## Panel

`GET /panel` es una página sin dependencias externas. Con el cliente y un token de
aprobador muestra:
- los incidentes y sus alertas;
- lo que se ejecutó o se habría ejecutado;
- las aprobaciones pendientes, con botones para aprobar, rechazar y deshacer.
