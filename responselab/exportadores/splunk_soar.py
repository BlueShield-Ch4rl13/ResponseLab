"""
Splunk SOAR: un playbook enrutador que decide y un playbook por familia que ejecuta.

    responselab_enrutador     on_start: contenedor -> alerta -> nucleo.decidir
                              guarda el plan como artefacto y llama al de su familia
    responselab_<familia>     un bloque por accion del playbook, legible y editable:
                              automatica -> phantom.act; aprobacion -> prompt2 y,
                              si se aprueba, phantom.act; manual -> nota en el caso

El nucleo de decision va incrustado una sola vez (en el enrutador) y es el
mismo fichero que usa el motor. Las acciones de SOAR son genericas ("quarantine
device", "block hash"...): SOAR las ejecuta con la app instalada que las
soporte. Si el cliente tiene varias, ASSETS fija cual.

Importar: SOAR > Playbooks > + Playbook > Automation, cambiar a edicion de
codigo completo (Full code) y pegar cada fichero, con el mismo nombre que el
fichero sin extension. Detalle en docs/SOAR.md.
"""
from __future__ import annotations

import json
import pprint

from .comun import CLIENTE_POR_DEFECTO, codigo_nucleo, compacto, familias, titulo_familia

CABECERA = '''"""
{titulo}

Generado por ResponseLab (tools/compilar.py) desde el catalogo {version}.
{descripcion}
"""
import json
{tipos}
import phantom.rules as phantom
'''

ENRUTADOR = CABECERA + '''
# ═══ Configuracion de este SOAR (editar) ═══════════════════════════════════
CLIENTE = {cliente}

# ═══ Generado por ResponseLab: no editar ════════════════════════════════════
CATALOGO = {catalogo}
NUCLEO_SRC = {nucleo}

_nucleo = types.ModuleType("responselab_nucleo")
exec(compile(NUCLEO_SRC, "responselab_nucleo", "exec"), _nucleo.__dict__)
_CATALOGO = _nucleo.Catalogo(CATALOGO)
SEVERIDAD = {{1: "low", 2: "medium", 3: "high", 4: "high"}}

# Campos CEF (y de notables de Splunk ES) -> esquema normalizado de ResponseLab
CEF = {{
    "equipo.nombre": ["deviceHostname", "destinationHostName", "sourceHostName", "dest", "host", "dvc"],
    "equipo.ip": ["deviceAddress", "dest_ip"],
    "equipo.id_edr": ["deviceExternalId", "machineId", "device_id"],
    "usuario.nombre": ["destinationUserName", "sourceUserName", "suser", "duser", "user"],
    "usuario.upn": ["userPrincipalName", "upn"],
    "proceso.pid": ["sourceProcessId", "processId", "pid"],
    "proceso.imagen": ["sourceProcessName", "processName", "process_path", "Image"],
    "proceso.linea": ["deviceCustomString1", "cmdline", "CommandLine"],
    "fichero.ruta": ["filePath", "file_path"],
    "fichero.sha256": ["fileHashSha256", "sha256"],
    "fichero.sha1": ["fileHashSha1", "sha1"],
    "fichero.md5": ["fileHashMd5", "md5", "fileHash"],
    "red.ip_origen": ["sourceAddress", "src", "src_ip"],
    "red.ip_destino": ["destinationAddress", "dest_ip"],
    "red.dominio": ["destinationDnsDomain", "domain", "query"],
    "red.url": ["requestURL", "url"],
    "correo.message_id": ["internetMessageId", "emailHeaders.Message-ID"],
    "correo.remitente": ["fromEmail", "emailFrom"],
    "correo.buzon": ["toEmail", "emailTo"],
}}


def _alerta(container):
    filas = phantom.collect2(container=container, datapath=["artifact:*.cef", "artifact:*.name"])
    carga = {{"id": str(container.get("id")), "titulo": container.get("name", ""),
             "regla_nombre": container.get("name", ""), "momento": container.get("start_time") or container.get("create_time")}}
    busqueda = None
    for cef, _nombre in filas:
        if not isinstance(cef, dict):
            continue
        # El nombre de la busqueda de Splunk ES identifica la regla mejor que el
        # nombre del contenedor, que el conector de ingesta puede reescribir.
        busqueda = busqueda or cef.get("search_name") or cef.get("rule_name")
        for ruta, claves in CEF.items():
            if _nucleo.leer(carga, ruta) is not None:
                continue
            for c in claves:
                if cef.get(c) not in (None, ""):
                    _nucleo.poner(carga, ruta, cef[c])
                    break
    if busqueda:
        carga["regla_nombre"] = busqueda
    return _nucleo.normalizar("generico", carga, CLIENTE.get("id", "soar"))


@phantom.playbook_block()
def on_start(container):
    alerta = _alerta(container)
    plan = _nucleo.decidir(alerta, _CATALOGO, CLIENTE, {{}})
    phantom.debug("ResponseLab: " + plan["resumen"])
    phantom.set_severity(container=container, severity=SEVERIDAD.get(plan["severidad"], "medium"))
    phantom.add_note(container=container, note_type="general", title="ResponseLab - " + plan["playbook"],
                     content=_nota(plan), note_format="markdown")
    if plan["estado"] in ("descartada", "cerrada_auto"):
        phantom.set_status(container=container, status="closed")
        return
    phantom.add_artifact(container=container, raw_data={{}}, label="responselab", name="ResponseLab plan",
                         severity=SEVERIDAD.get(plan["severidad"], "medium"), artifact_type="responselab",
                         cef_data={{"responselab_plan": json.dumps(plan), "responselab_alerta": json.dumps(alerta)}},
                         run_automation=False)
    phantom.playbook(playbook="local/responselab_" + plan["familia"].lstrip("_"), container=container,
                     name="responselab_" + plan["familia"].lstrip("_"))
    return


def _nota(plan):
    l = ["**%s** | clase `%s` | severidad %s" % (plan["playbook"], plan["clase"], plan["severidad"]), ""]
    for p in plan["acciones"]:
        l.append("- `%s` %s: %s" % (p["modo"], p["nombre"], p["motivo"]))
    l.append("")
    for t in plan["triaje"]:
        l.append("- [%s] %s" % (t["resultado"], t["pregunta"]))
    l.append("")
    l.append("Escalar a **%s** en %s min" % (plan["escalado"].get("a"), plan["escalado"].get("plazo_min")))
    return "\\n".join(l)


def on_finish(container, summary):
    return
'''

FAMILIA = CABECERA + '''
# ═══ Configuracion de este SOAR (editar) ═══════════════════════════════════
# Quien aprueba lo que no se ejecuta solo (usuario o rol de SOAR)
APROBACION = {{"user": None, "role": "Administrator", "minutos": 120}}
# Asset de SOAR para cada accion de ResponseLab; vacio = cualquiera que la soporte
ASSETS = {{}}

# ═══ Generado por ResponseLab: no editar ════════════════════════════════════
FAMILIA = {familia!r}
ACCIONES = {acciones}


def _plan(container):
    filas = phantom.collect2(container=container, datapath=["artifact:*.cef.responselab_plan",
                                                            "artifact:*.cef.responselab_alerta"])
    for plan, alerta in reversed(filas):
        if plan:
            return json.loads(plan), json.loads(alerta or "{{}}")
    return None, None


def _leer(datos, ruta):
    actual = datos
    for parte in ruta.split("."):
        if not isinstance(actual, dict):
            return None
        actual = actual.get(parte)
    return actual


def _valor(alerta, origen):
    # "a.b|c.d": el primer campo que traiga la alerta; sin punto es una constante
    if not (isinstance(origen, str) and "." in origen and " " not in origen):
        return origen
    for alternativa in origen.split("|"):
        valor = _leer(alerta, alternativa.strip())
        if valor not in (None, ""):
            return valor
    return None


def _parametros(paso, alerta):
    spec = ACCIONES.get(paso["id"], {{}})
    salida = {{}}
    for nombre, origen in (spec.get("parametros") or {{}}).items():
        valor = _valor(alerta, origen)
        if valor in (None, ""):
            return None
        salida[nombre] = valor
    return salida


def _ejecutar(container, paso, alerta):
    spec = ACCIONES.get(paso["id"], {{}})
    if not spec.get("accion_soar"):
        phantom.comment(container=container, comment="ResponseLab: %s no tiene accion de SOAR; tarea manual." % paso["nombre"])
        return
    params = _parametros(paso, alerta)
    if params is None:
        phantom.comment(container=container, comment="ResponseLab: faltan datos para %s; no se ejecuta." % paso["nombre"])
        return
    activo = ASSETS.get(paso["accion"])
    phantom.act(action=spec["accion_soar"], parameters=[params], assets=[activo] if activo else None,
                name="rl_" + paso["id"], callback=resultado_cb)


def _pedir(container, paso):
    mensaje = ("ResponseLab pide aprobacion para: %s\\nMotivo: %s\\nObjetivo: %s\\n%s"
               % (paso["nombre"], paso["motivo"], json.dumps(paso.get("objetivo")), paso.get("justificacion", "")))
    phantom.prompt2(container=container, user=APROBACION["user"], role=APROBACION["role"], message=mensaje,
                    respond_in_mins=APROBACION["minutos"], name="rl_aprobar_" + paso["id"],
                    response_types=[{{"prompt": "Aprobar la accion?", "options": {{"type": "list", "choices": ["Si", "No"]}}}}],
                    callback=aprobacion_cb)


@phantom.playbook_block()
def on_start(container):
    plan, alerta = _plan(container)
    if not plan:
        phantom.comment(container=container, comment="ResponseLab: no hay plan; ejecuta antes responselab_enrutador.")
        return
    for paso in plan["acciones"]:
        if paso["modo"] == "automatica":
            _ejecutar(container, paso, alerta)
        elif paso["modo"] == "aprobacion":
            _pedir(container, paso)
        else:
            phantom.comment(container=container, comment="ResponseLab [%s] %s: %s" % (paso["modo"], paso["nombre"], paso["motivo"]))
    pendientes = [t["pregunta"] for t in plan["triaje"] if t["resultado"] == "pendiente"]
    if pendientes:
        phantom.add_note(container=container, note_type="general", title="ResponseLab - triaje pendiente",
                         content="\\n".join("- " + p for p in pendientes), note_format="markdown")
    return


def aprobacion_cb(action=None, success=None, container=None, results=None, handle=None, **kwargs):
    nombre = (action or {{}}).get("name", "")
    paso_id = nombre.replace("rl_aprobar_", "", 1)
    respuestas = phantom.collect2(container=container, datapath=[nombre + ":action_result.summary.responses.0"],
                                  action_results=results)
    respuesta = respuestas[0][0] if respuestas and respuestas[0] else None
    plan, alerta = _plan(container)
    paso = next((p for p in (plan or {{}}).get("acciones", []) if p["id"] == paso_id), None)
    if paso is None:
        return
    if respuesta == "Si":
        phantom.comment(container=container, comment="ResponseLab: aprobado %s" % paso["nombre"])
        _ejecutar(container, paso, alerta)
    else:
        phantom.comment(container=container, comment="ResponseLab: rechazado o sin respuesta: %s" % paso["nombre"])
    return


def resultado_cb(action=None, success=None, container=None, results=None, handle=None, **kwargs):
    phantom.debug("ResponseLab %s: %s" % ((action or {{}}).get("name"), "correcto" if success else "fallido"))
    return


def on_finish(container, summary):
    return
'''


def _literal(datos) -> str:
    return pprint.pformat(datos, width=110, sort_dicts=True)


def exportar(catalogo: dict) -> dict[str, str]:
    salidas = {}
    comp = compacto(catalogo, texto=False)
    salidas["soar/splunk-soar/responselab_enrutador.py"] = ENRUTADOR.format(
        titulo="ResponseLab - enrutador", version=catalogo["version"], tipos="import types\n",
        descripcion="Decide con el nucleo de ResponseLab y llama al playbook de la familia.",
        cliente=_literal(dict(CLIENTE_POR_DEFECTO, id="soar")),
        catalogo=_literal(comp), nucleo=json.dumps(codigo_nucleo()))
    for nombre in familias(catalogo):
        f = catalogo["familias"][nombre]
        acciones = {}
        pasos = [(f"c{i}", c["accion"]) for i, c in enumerate(f.get("contencion") or [], 1)]
        pasos += [(f"e{j}", e["accion"]) for j, e in enumerate(f.get("evidencia_automatica") or [], 1)]
        for pid, accion in pasos:
            meta = (catalogo["acciones"].get(accion or "") or {})
            soar = (meta.get("soar") or {}).get("splunk_soar") or {}
            acciones[pid] = {"accion": accion, "nombre": meta.get("nombre", ""),
                             "accion_soar": soar.get("accion", ""), "parametros": soar.get("parametros", {})}
        salidas[f"soar/splunk-soar/responselab_{nombre.lstrip('_')}.py"] = FAMILIA.format(
            titulo=f"ResponseLab - {titulo_familia(nombre)}: {f['nombre']}", version=catalogo["version"], tipos="",
            descripcion="Ejecuta el plan que deja responselab_enrutador para esta familia.",
            familia=nombre, acciones=_literal(acciones))
    return salidas
