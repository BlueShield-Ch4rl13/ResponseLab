# ============================================================
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
