"""
Shuffle: workflow importable para la plataforma de Infra-SocAnalyst.

    Webhook (Wazuh) ─► DECIDIR (POST al motor /decidir) ─► RESPONSELAB (Python)
          │                                                   │
          │        ┌──────────────────────┬──────────────────┼─────────────────────┐
          │   crear_caso?            hay_contencion?     usar_llm?                 │
          │        ▼                      ▼                  ▼                      │
          │   ALERTA (TheHive) ─► CASO   MOTOR (ejecuta    OLLAMA ─► LIMPIAR ─► DISCORD (notificar?)
          │   con la plantilla de        y pide
          │   la familia                 aprobaciones)

Mismas apps y versiones que el workflow exportado de Infra-SocAnalyst
(Shuffle Tools 1.2.0, http 1.4.0, TheHive 1.1.0, Discord 1.1.0), con las
lecciones de su README aplicadas: los nodos Python terminan en
print(json.dumps(...)), se leen las variables entre triples comillas y al LLM
solo le llegan textos ya escapados, nunca objetos JSON.

La decision la toma el motor (/decidir): Shuffle no lleva una copia de la
politica que pueda quedarse desfasada. Para que no haya casos ni avisos
duplicados, el perfil del cliente en el motor no declara capacidad `casos` ni
canales de aviso: de eso se encarga este workflow.
"""
from __future__ import annotations

import json

from .comun import uid

APPS = {
    "python": {"app_name": "Shuffle Tools", "app_version": "1.2.0", "app_id": "037959ba-1ff3-4df7-bf8b-5924e481cf85",
               "name": "execute_python", "category": "Other",
               "description": "Runs python with the data input. Any prints will be returned."},
    "http": {"app_name": "http", "app_version": "1.4.0", "app_id": "df38e95a-d41a-4b46-bbd8-abf6d91c37d9",
             "name": "POST", "category": "Other", "description": "Runs a POST request towards the specified endpoint"},
    "alerta": {"app_name": "TheHive", "app_version": "1.1.0", "app_id": "e0aa86a03c8e8abf8a684ac6549dad5d",
               "name": "post_create_alert", "category": "Cases", "description": "http://your-instance/api/v1/alert"},
    "caso": {"app_name": "TheHive", "app_version": "1.1.0", "app_id": "e0aa86a03c8e8abf8a684ac6549dad5d",
             "name": "post_create_case_from_alert", "category": "Cases",
             "description": "http://your-instance/api/v1/alert/{alertId}/case"},
    "discord": {"app_name": "Discord", "app_version": "1.1.0", "app_id": "368274c62b28039f34b775bc7f5a5da9",
                "name": "post_send_json_data_as_webhook", "category": "Communication",
                "description": "Send a message to Discord server"},
}


def _param(nombre: str, valor: str, *, configuracion: bool = False, multilinea: bool = False,
           requerido: bool = False, variante: str = "STATIC_VALUE", opciones=None) -> dict:
    return {"description": "", "id": "", "name": nombre, "example": "", "value": valor, "multiline": multilinea,
            "multiselect": False, "options": opciones, "action_field": "", "variant": variante,
            "required": requerido, "configuration": configuracion, "tags": None, "schema": {"type": "string"},
            "skip_multicheck": False, "custom_value": False, "value_replace": None, "unique_toggled": False,
            "error": "", "hidden": False}


def _accion(clave: str, etiqueta: str, parametros: list, x: int, y: int, inicio: bool = False) -> dict:
    app = APPS[clave]
    return {
        "app_name": app["app_name"], "app_version": app["app_version"], "description": app["description"],
        "app_id": app["app_id"], "errors": [], "id": uid("shuffle", etiqueta), "is_valid": True,
        "isStartNode": inicio, "sharing": True, "label": etiqueta, "public": True, "generated": False,
        "environment": "Shuffle", "name": app["name"], "parameters": parametros,
        "execution_variable": {"description": "", "id": "", "name": "", "value": ""},
        "position": {"x": x, "y": y}, "authentication_id": "", "category": app["category"], "reference_url": "",
        "sub_action": False, "run_magic_output": False, "run_magic_input": False, "execution_delay": 0,
        "category_label": None, "suggestion": False, "parent_controlled": False, "source_workflow": "",
        "source_execution": "",
    }


def _rama(origen: str, destino: str, condicion: tuple | None = None) -> dict:
    condiciones = []
    if condicion:
        fuente, op, valor = condicion
        condiciones.append({
            "condition": dict(_param("condition", op), id=uid("cond", origen, destino, "c")),
            "source": dict(_param("source", fuente), id=uid("cond", origen, destino, "s")),
            "destination": dict(_param("destination", valor), id=uid("cond", origen, destino, "d")),
        })
    return {"destination_id": uid("shuffle", destino), "id": uid("rama", origen, destino),
            "source_id": uid("shuffle", origen) if origen != "SIEM" else uid("shuffle-trigger", "SIEM"),
            "label": "", "has_errors": False, "conditions": condiciones, "decorator": False,
            "parent_controlled": False, "source_parent": ""}


CODIGO_RESPONSELAB = r'''# ============================================================
#  Nodo "RESPONSELAB" - Shuffle (Shuffle Tools / execute_python)
#  Generado por ResponseLab (tools/compilar.py). No editar a mano.
#
#  Lee la decision del motor (nodo DECIDIR) y la deja en campos
#  simples para las condiciones y los nodos de aguas abajo:
#    $responselab.crear_caso  $responselab.hay_contencion
#    $responselab.usar_llm    $responselab.notificar
#  Los campos *_json ya van escapados para meterlos dentro de un
#  cuerpo JSON (TheHive, Discord, Ollama) sin romperlo.
#
#  Reglas de Shuffle (las de Infra-SocAnalyst): leer entre triples
#  comillas, terminar con print(json.dumps(...)), sin return.
# ============================================================
import json

raw = r"""$decidir"""
try:
    r = json.loads(raw)
except Exception:
    r = {}
plan = r.get("body") if isinstance(r.get("body"), dict) else r
if not isinstance(plan, dict):
    plan = {}

acciones = plan.get("acciones") or []
auto = [a for a in acciones if a.get("modo") == "automatica"]
espera = [a for a in acciones if a.get("modo") == "aprobacion"]
manual = [a for a in acciones if a.get("modo") == "manual"]
escalado = plan.get("escalado") or {}
regla = plan.get("regla") or {}


def esc(texto, limite=1500):
    return json.dumps(str(texto or "")[:limite], ensure_ascii=False)[1:-1]


lineas = ["Playbook: %s | clase %s | severidad %s" % (plan.get("playbook", "?"), plan.get("clase", "?"), plan.get("severidad", "?"))]
lineas += ["[%s] %s - %s" % (a.get("modo"), a.get("nombre"), a.get("motivo")) for a in acciones]
lineas += ["Triaje [%s] %s" % (t.get("resultado"), t.get("pregunta")) for t in plan.get("triaje") or []]
lineas.append("Escalar a %s en %s min" % (escalado.get("a", "L2"), escalado.get("plazo_min", 30)))

salida = {
    "familia": plan.get("familia", "_generico"),
    "clase": plan.get("clase", "auto_analisis"),
    "severidad": int(plan.get("severidad", 2) or 2),
    "estado": plan.get("estado", ""),
    "crear_caso": bool(plan.get("crear_caso")),
    "notificar": bool(plan.get("notificar")),
    "usar_llm": bool(plan.get("usar_llm")),
    "hay_contencion": bool(auto or espera),
    "plantilla_caso": plan.get("plantilla_caso", "ResponseLab - _generico"),
    "escalar_a": escalado.get("a", "L2"),
    "plazo_min": escalado.get("plazo_min", 30),
    "titulo_json": esc(regla.get("titulo") or plan.get("titulo"), 300),
    "resumen_json": esc(plan.get("resumen"), 600),
    "descripcion_json": esc("\n".join(lineas), 8000),
    "automaticas_json": esc("; ".join(a.get("nombre", "") for a in auto) or "ninguna", 900),
    "en_espera_json": esc("; ".join(a.get("nombre", "") for a in espera) or "ninguna", 900),
    "manuales_json": esc("; ".join(a.get("nombre", "") for a in manual) or "ninguna", 900),
    "color": {4: 15158332, 3: 15105570, 2: 3447003}.get(int(plan.get("severidad", 2) or 2), 9807270),
}
print(json.dumps(salida))
'''

CODIGO_LIMPIAR = r'''# Nodo "LIMPIAR": deja el analisis del LLM en una linea segura para Discord.
import json

texto = """$ollama.body.response"""
texto = texto.replace("**", "").replace("*", "").replace("`", "")
texto = " ".join(texto.split())
if not texto or texto.startswith("$ollama"):
    texto = "Sin analisis del LLM."
print(json.dumps({"mensaje_json": json.dumps(texto[:900], ensure_ascii=False)[1:-1]}))
'''


def workflow() -> dict:
    cab_motor = "Content-Type: application/json\nAuthorization: Bearer $token_motor"
    acciones = [
        _accion("http", "DECIDIR", [
            _param("url", "$motor_url/v1/$cliente/decidir/wazuh", requerido=True, variante=""),
            _param("body", "$exec", multilinea=True, variante=""),
            _param("headers", cab_motor, multilinea=True, variante=""),
            _param("username", "", variante=""), _param("password", "", variante=""),
            _param("verify", "true", variante="", opciones=["false", "true"]),
            _param("http_proxy", "", variante=""), _param("https_proxy", "", variante=""),
            _param("timeout", "30", variante=""),
        ], 0, 300, inicio=True),
        _accion("python", "RESPONSELAB", [_param("code", CODIGO_RESPONSELAB, multilinea=True, requerido=True, variante="")],
                300, 300),
        _accion("alerta", "ALERTA", [
            _param("apikey", "", configuracion=True, requerido=True),
            _param("url", "", configuracion=True, requerido=True),
            _param("body", json.dumps({
                "type": "responselab", "source": "ResponseLab-Wazuh", "sourceRef": "rl-$exec.id",
                "title": "[$responselab.familia] $responselab.titulo_json",
                "description": "$responselab.descripcion_json",
                "severity": "__SEV__", "tlp": 2, "pap": 2,
                "tags": ["responselab", "rl:familia=$responselab.familia", "rl:clase=$responselab.clase"],
                "caseTemplate": "$responselab.plantilla_caso"}, ensure_ascii=False, indent=2).replace(
                '"__SEV__"', "$responselab.severidad"), multilinea=True, requerido=True),
            _param("headers", "Content-Type=application/json\nAccept=application/json\n", multilinea=True),
            _param("queries", ""), _param("ssl_verify", "False"), _param("to_file", "False"),
        ], 600, 120),
        _accion("caso", "CASO", [
            _param("apikey", "", configuracion=True, requerido=True),
            _param("url", "", configuracion=True, requerido=True),
            _param("body", "{}", multilinea=True, requerido=True),
            _param("alertId", "$alerta.body._id", requerido=True),
            _param("headers", "Content-Type=application/json\nAccept=application/json\n", multilinea=True),
            _param("queries", ""), _param("ssl_verify", "False"), _param("to_file", "False"),
        ], 900, 120),
        _accion("http", "MOTOR", [
            _param("url", "$motor_url/v1/$cliente/alertas/wazuh", requerido=True, variante=""),
            _param("body", "$exec", multilinea=True, variante=""),
            _param("headers", cab_motor, multilinea=True, variante=""),
            _param("username", "", variante=""), _param("password", "", variante=""),
            _param("verify", "true", variante="", opciones=["false", "true"]),
            _param("http_proxy", "", variante=""), _param("https_proxy", "", variante=""),
            _param("timeout", "30", variante=""),
        ], 600, 300),
        _accion("http", "OLLAMA", [
            _param("url", "$ollama_url/api/generate", requerido=True, variante=""),
            _param("body", '{"model":"llama3.2:3b","prompt":"Eres un analista SOC. En espanol, maximo 4 frases, '
                           'sin markdown: valora esta alerta y que harias primero. $responselab.resumen_json",'
                           '"stream":false,"options":{"num_predict":60}}', multilinea=True, variante=""),
            _param("headers", "Content-Type: application/json", multilinea=True, variante=""),
            _param("username", "", variante=""), _param("password", "", variante=""),
            _param("verify", "false", variante="", opciones=["false", "true"]),
            _param("http_proxy", "", variante=""), _param("https_proxy", "", variante=""),
            _param("timeout", "120", variante=""),
        ], 600, 480),
        _accion("python", "LIMPIAR", [_param("code", CODIGO_LIMPIAR, multilinea=True, requerido=True, variante="")],
                900, 480),
        _accion("discord", "DISCORD", [
            _param("url", "", configuracion=True, requerido=True),
            _param("body", json.dumps({
                "username": "ResponseLab",
                "embeds": [{"title": "$responselab.titulo_json", "color": "__COLOR__",
                            "description": "$responselab.resumen_json",
                            "fields": [
                                {"name": "Familia / clase", "value": "$responselab.familia / $responselab.clase", "inline": True},
                                {"name": "Escalar a", "value": "$responselab.escalar_a en $responselab.plazo_min min", "inline": True},
                                {"name": "Automatico", "value": "$responselab.automaticas_json"},
                                {"name": "Espera aprobacion", "value": "$responselab.en_espera_json"},
                                {"name": "Analisis IA", "value": "$limpiar.mensaje_json"}]}]},
                ensure_ascii=False, indent=2).replace('"__COLOR__"', "$responselab.color"), multilinea=True, requerido=True),
            _param("headers", "Content-Type=application/json", multilinea=True),
            _param("queries", ""), _param("ssl_verify", "False"), _param("to_file", "False"),
        ], 1200, 480),
    ]
    disparador = {
        "app_name": "Webhook", "description": "", "long_description": "", "status": "stopped", "app_version": "1.0.0",
        "errors": [], "id": uid("shuffle-trigger", "SIEM"), "is_valid": True, "isStartNode": False, "label": "SIEM",
        "small_image": "", "environment": "Shuffle", "trigger_type": "WEBHOOK", "name": "Webhook", "tags": None,
        "parameters": [_param("url", "", variante=""), _param("tmp", "", variante=""),
                       _param("auth_headers", "", variante=""), _param("custom_response_body", "", variante=""),
                       _param("await_response", "v1", variante="")],
        "position": {"x": -300, "y": 300}, "priority": 0, "source_workflow": "", "execution_delay": 0,
        "app_association": {}, "parent_controlled": False, "replacement_for_trigger": "",
    }
    verdadero = lambda campo: (f"$responselab.{campo}", "equals", "true")  # noqa: E731
    ramas = [
        _rama("SIEM", "DECIDIR"),
        _rama("DECIDIR", "RESPONSELAB"),
        _rama("RESPONSELAB", "ALERTA", verdadero("crear_caso")),
        _rama("ALERTA", "CASO"),
        _rama("RESPONSELAB", "MOTOR", verdadero("hay_contencion")),
        _rama("RESPONSELAB", "OLLAMA", verdadero("usar_llm")),
        _rama("OLLAMA", "LIMPIAR"),
        _rama("LIMPIAR", "DISCORD", verdadero("notificar")),
    ]
    variables = [{"description": d, "id": uid("var", n), "name": n, "value": v} for n, v, d in (
        ("motor_url", "https://HOST_SOC:8443", "URL del motor de ResponseLab, sin barra final"),
        ("cliente", "lab", "Identificador del cliente en el motor"),
        ("token_motor", "CAMBIAME", "Token de ingesta del cliente en el motor"),
        ("ollama_url", "http://HOST_SOC:11434", "URL de Ollama"),
    )]
    return {
        "workflow_as_code": False, "actions": acciones, "branches": ramas, "visual_branches": [],
        "triggers": [disparador], "comments": [],
        "configuration": {"exit_on_error": False, "start_from_top": False, "skip_notifications": False},
        "created": 0, "edited": 0, "last_runtime": 0, "due_date": 0, "id": uid("shuffle", "workflow"),
        "is_valid": True, "name": "ResponseLab - respuesta a incidentes",
        "description": "Recibe alertas de Wazuh, pide la decision al motor de ResponseLab, abre el caso en TheHive con "
                       "la plantilla de su familia, manda la contencion al motor (que ejecuta lo automatico y pide "
                       "aprobacion para lo demas), analiza con Ollama y avisa por Discord. Configura las variables "
                       "del workflow y la autenticacion de TheHive y Discord antes de activarlo.",
        "start": uid("shuffle", "DECIDIR"), "owner": "", "sharing": "private", "image": "", "execution_org": {},
        "org_id": "", "workflow_variables": variables, "execution_environment": "", "previously_saved": False,
        "categories": {}, "example_argument": "", "public": False, "default_return_value": "", "contact_info": {},
        "published_id": "", "revision_id": "", "usecase_ids": [], "input_questions": [], "form_control": {},
        "blogpost": "", "video": "", "status": "", "workflow_type": "", "generated": False, "hidden": False,
        "background_processing": False, "updated_by": "", "validated": False, "validation": {},
        "parentorg_workflow": "", "childorg_workflow_ids": [], "suborg_distribution": [], "backup_config": {},
        "auth_groups": [], "org": [], "first_save": False,
    }


def exportar(catalogo: dict) -> dict[str, str]:
    return {
        "soar/shuffle/workflow-responselab.json": json.dumps(workflow(), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        "soar/shuffle/nodos/responselab.py": CODIGO_RESPONSELAB,
        "soar/shuffle/nodos/limpiar.py": CODIGO_LIMPIAR,
    }
