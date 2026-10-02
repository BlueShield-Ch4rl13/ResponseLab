"""
ResponseLab - Cloud: Identidad y plano de control en la nube

Generado por ResponseLab (tools/compilar.py) desde el catalogo 01bbe55923a1.
Ejecuta el plan que deja responselab_enrutador para esta familia.
"""
import json

import phantom.rules as phantom

# ═══ Configuracion de este SOAR (editar) ═══════════════════════════════════
# Quien aprueba lo que no se ejecuta solo (usuario o rol de SOAR)
APROBACION = {"user": None, "role": "Administrator", "minutos": 120}
# Asset de SOAR para cada accion de ResponseLab; vacio = cualquiera que la soporte
ASSETS = {}

# ═══ Generado por ResponseLab: no editar ════════════════════════════════════
FAMILIA = 'cloud'
ACCIONES = {'c1': {'accion': 'identidad.revocar_sesiones',
        'accion_soar': 'revoke session',
        'nombre': 'Revocar las sesiones y los tokens de refresco de una identidad',
        'parametros': {'user_id': 'usuario.upn'}},
 'c2': {'accion': 'identidad.marcar_riesgo',
        'accion_soar': '',
        'nombre': 'Marcar la identidad como comprometida en la proteccion de identidad',
        'parametros': {}},
 'c3': {'accion': 'caso.nota', 'accion_soar': '', 'nombre': 'Anotar en el caso', 'parametros': {}},
 'c4': {'accion': 'identidad.retirar_consentimiento',
        'accion_soar': '',
        'nombre': 'Retirar el consentimiento concedido a una aplicacion',
        'parametros': {}}}


def _plan(container):
    filas = phantom.collect2(container=container, datapath=["artifact:*.cef.responselab_plan",
                                                            "artifact:*.cef.responselab_alerta"])
    for plan, alerta in reversed(filas):
        if plan:
            return json.loads(plan), json.loads(alerta or "{}")
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
    spec = ACCIONES.get(paso["id"], {})
    salida = {}
    for nombre, origen in (spec.get("parametros") or {}).items():
        valor = _valor(alerta, origen)
        if valor in (None, ""):
            return None
        salida[nombre] = valor
    return salida


def _ejecutar(container, paso, alerta):
    spec = ACCIONES.get(paso["id"], {})
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
    mensaje = ("ResponseLab pide aprobacion para: %s\nMotivo: %s\nObjetivo: %s\n%s"
               % (paso["nombre"], paso["motivo"], json.dumps(paso.get("objetivo")), paso.get("justificacion", "")))
    phantom.prompt2(container=container, user=APROBACION["user"], role=APROBACION["role"], message=mensaje,
                    respond_in_mins=APROBACION["minutos"], name="rl_aprobar_" + paso["id"],
                    response_types=[{"prompt": "Aprobar la accion?", "options": {"type": "list", "choices": ["Si", "No"]}}],
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
                         content="\n".join("- " + p for p in pendientes), note_format="markdown")
    return


def aprobacion_cb(action=None, success=None, container=None, results=None, handle=None, **kwargs):
    nombre = (action or {}).get("name", "")
    paso_id = nombre.replace("rl_aprobar_", "", 1)
    respuestas = phantom.collect2(container=container, datapath=[nombre + ":action_result.summary.responses.0"],
                                  action_results=results)
    respuesta = respuestas[0][0] if respuestas and respuestas[0] else None
    plan, alerta = _plan(container)
    paso = next((p for p in (plan or {}).get("acciones", []) if p["id"] == paso_id), None)
    if paso is None:
        return
    if respuesta == "Si":
        phantom.comment(container=container, comment="ResponseLab: aprobado %s" % paso["nombre"])
        _ejecutar(container, paso, alerta)
    else:
        phantom.comment(container=container, comment="ResponseLab: rechazado o sin respuesta: %s" % paso["nombre"])
    return


def resultado_cb(action=None, success=None, container=None, results=None, handle=None, **kwargs):
    phantom.debug("ResponseLab %s: %s" % ((action or {}).get("name"), "correcto" if success else "fallido"))
    return


def on_finish(container, summary):
    return
