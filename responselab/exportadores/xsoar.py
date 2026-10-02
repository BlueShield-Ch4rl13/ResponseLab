"""
Cortex XSOAR: un script que decide y playbooks que ejecutan.

    ResponseLabDecidir             script: incidente -> nucleo.decidir -> ResponseLab.Plan
    ResponseLab - Enrutador        decide, cierra lo que el nucleo cierra y llama
                                   al playbook de la familia
    ResponseLab - <Familia>        1. contencion automatica (no espera a nadie)
                                   2. aprobaciones y tareas a mano
                                   3. checklist: escalado, evidencia, triaje, cierre

El nucleo va incrustado en el script: es el mismo fichero que usa el motor.
Cada paso del plan tiene su modo en ResponseLab.Plan.modos.<id> y sus entradas
ya resueltas en ResponseLab.Plan.entradas.<id>: el playbook solo pregunta el
modo y pasa las entradas. Las acciones se ejecutan con playbooks genericos del
marketplace de XSOAR (Isolate Endpoint - Generic V2, Block Indicators - Generic
v3...) o con comandos de integracion (Defender, Graph); lo que no tiene
traduccion se convierte en tarea manual, nunca se omite.

El perfil del cliente (politica, inventario, listas) se lee de una lista de
XSOAR en JSON (por defecto "ResponseLab_Cliente"); sin lista, el perfil
prudente: toda excepcion sin datos pide aprobacion.

Importar: docs/SOAR.md. Script en Automation > Import; playbooks en
Playbooks > Import, primero los de familia y despues el enrutador.
"""
from __future__ import annotations

import json

import yaml

from .comun import CLIENTE_POR_DEFECTO, codigo_nucleo, compacto, familias, titulo_familia, uid

VERSION_MINIMA = "6.10.0"
X0, DX, DY = 450, 420, 190
ESTADOS_CIERRE = ("descartada", "cerrada_auto")

SCRIPT = '''"""ResponseLabDecidir: decide la respuesta al incidente con el nucleo de ResponseLab.

Generado por ResponseLab (tools/compilar.py) desde el catalogo {version}. No editar:
se regenera con cada actualizacion del ecosistema.
"""
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403

import json
import types

CATALOGO = json.loads({catalogo})
MAPEO = json.loads({mapeo})
CLIENTE_POR_DEFECTO = json.loads({cliente})
NUCLEO_SRC = {nucleo}

_nucleo = types.ModuleType("responselab_nucleo")
exec(compile(NUCLEO_SRC, "responselab_nucleo", "exec"), _nucleo.__dict__)
_CATALOGO = _nucleo.Catalogo(CATALOGO)
SEVERIDAD_XSOAR = {{1: 1, 2: 2, 3: 3, 4: 4}}


def detectar_siem(carga):
    """El formato del rawJSON dice de que SIEM viene el incidente."""
    if not isinstance(carga, dict):
        return "generico"
    if isinstance(carga.get("rule"), dict) and ("agent" in carga or "manager" in carga or "decoder" in carga):
        return "wazuh"
    obj = carga.get("object") if isinstance(carga.get("object"), dict) else carga
    props = obj.get("properties") if isinstance(obj.get("properties"), dict) else {{}}
    if "relatedEntities" in props or "incidentNumber" in props:
        return "sentinel"
    if "search_name" in carga or "rule_name" in carga or ("result" in carga and "sid" in carga):
        return "splunk"
    if "kibana.alert.rule.name" in carga or isinstance(carga.get("kibana"), dict) or "signal" in carga \\
            or isinstance(carga.get("alerts"), list):
        return "elastic"
    return "generico"


def carga_del_incidente(incidente):
    crudo = incidente.get("rawJSON") or incidente.get("rawJson") or ""
    if crudo:
        try:
            datos = json.loads(crudo) if isinstance(crudo, str) else crudo
            if isinstance(datos, dict):
                return datos
        except ValueError:
            pass
    # Sin rawJSON (incidente creado a mano o por otra via): lo que hay en el incidente
    etiquetas = {{e.get("type"): e.get("value") for e in incidente.get("labels") or [] if isinstance(e, dict)}}
    campos = incidente.get("CustomFields") or {{}}
    return {{"id": str(incidente.get("id") or ""), "titulo": incidente.get("name") or "",
            "regla_nombre": etiquetas.get("rule_name") or campos.get("rulename") or incidente.get("name") or "",
            "momento": incidente.get("occurred") or "",
            "equipo": {{"nombre": campos.get("hostname") or etiquetas.get("hostname")}},
            "usuario": {{"nombre": campos.get("username") or etiquetas.get("username")}},
            "red": {{"ip_origen": campos.get("sourceip"), "ip_destino": campos.get("destinationip")}}}}


def perfil_del_cliente(nombre):
    if not nombre:
        return dict(CLIENTE_POR_DEFECTO)
    try:
        res = demisto.executeCommand("getList", {{"listName": nombre}})
        if is_error(res):
            return dict(CLIENTE_POR_DEFECTO)
        texto = res[0].get("Contents") or ""
        if not texto or "Item not found" in str(texto):
            return dict(CLIENTE_POR_DEFECTO)
        perfil = json.loads(texto)
        return perfil if isinstance(perfil, dict) else dict(CLIENTE_POR_DEFECTO)
    except Exception as e:  # una lista mal escrita no debe dejar el incidente sin plan
        demisto.debug("ResponseLab: perfil {{}} ilegible: {{}}".format(nombre, e))
        return dict(CLIENTE_POR_DEFECTO)


def resolver(alerta, origen):
    """"a.b|c.d" -> primer campo presente; sin punto, constante."""
    if not (isinstance(origen, str) and "." in origen and " " not in origen):
        return origen
    for alternativa in origen.split("|"):
        valor = _nucleo.leer(alerta, alternativa.strip())
        if valor not in (None, ""):
            return valor if not isinstance(valor, (dict, list)) else json.dumps(valor)
    return ""


def tabla(filas, cabeceras):
    lineas = ["| " + " | ".join(cabeceras) + " |", "|" + "---|" * len(cabeceras)]
    for f in filas:
        lineas.append("| " + " | ".join(str(x).replace("|", "/").replace("\\n", " ") for x in f) + " |")
    return "\\n".join(lineas)


def main():
    try:
        args = demisto.args()
        incidente = demisto.incident() or {{}}
        carga = carga_del_incidente(incidente)
        siem = (args.get("siem") or "auto").lower()
        if siem == "auto":
            siem = detectar_siem(carga)
        cliente = perfil_del_cliente(args.get("perfil"))
        alerta = _nucleo.normalizar(siem, carga, cliente.get("id", "xsoar"))
        if not alerta.get("id"):
            alerta["id"] = str(incidente.get("id") or "")
        plan = _nucleo.decidir(alerta, _CATALOGO, cliente, {{}})
        # Defensa en profundidad: lo que rompa una invariante no se ejecuta solo
        for fallo in _nucleo.verificar_invariantes(plan, alerta):
            for p in plan["acciones"]:
                if p["modo"] == "automatica" and fallo.startswith(p["accion"]):
                    p["modo"], p["motivo"] = "aprobacion", "invariante: " + fallo
        entradas = {{}}
        for p in plan["acciones"]:
            m = MAPEO.get(p["accion"])
            if m:
                entradas[p["id"]] = {{k: resolver(alerta, v) for k, v in m["entradas"].items()}}
        salida = {{
            "alerta_id": plan["alerta_id"], "siem": siem, "familia": plan["familia"], "playbook": plan["playbook"],
            "regla": plan["regla"]["titulo"], "regla_conocida": plan["regla"]["conocida"], "clase": plan["clase"],
            "severidad": plan["severidad"], "estado": plan["estado"], "resumen": plan["resumen"],
            "modos": {{p["id"]: p["modo"] for p in plan["acciones"]}},
            "acciones": [{{k: p.get(k) for k in ("id", "accion", "nombre", "modo", "motivo", "radio", "reversible", "deshacer")}}
                         for p in plan["acciones"]],
            "entradas": entradas,
            "triaje_pendiente": [t["pregunta"] for t in plan["triaje"] if t["resultado"] == "pendiente"],
            "escalado": plan["escalado"], "cierre": plan.get("cierre"),
            "crear_caso": plan["crear_caso"], "notificar": plan["notificar"],
            "secuencias": [s.get("nombre") for s in plan.get("secuencias") or []],
            "alerta": {{k: alerta.get(k) for k in ("equipo", "usuario", "proceso", "fichero", "red", "correo", "nube", "k8s")}},
        }}
        if args.get("ajustar_severidad", "true").lower() == "true" and plan["estado"] == "en_curso":
            try:
                demisto.executeCommand("setIncident", {{"severity": SEVERIDAD_XSOAR.get(plan["severidad"], 2)}})
            except Exception as e:
                demisto.debug("ResponseLab: no se pudo ajustar la severidad: {{}}".format(e))
        md = "### ResponseLab: {{}}\\n**{{}}** | clase `{{}}` | severidad {{}} | {{}}\\n\\n".format(
            plan["playbook"], plan["regla"]["titulo"], plan["clase"], plan["severidad"], plan["estado"])
        if plan["acciones"]:
            md += tabla([(p["id"], p["nombre"], p["modo"], p["motivo"]) for p in plan["acciones"]],
                        ["Paso", "Accion", "Modo", "Motivo"]) + "\\n\\n"
        if salida["triaje_pendiente"]:
            md += "**Triaje pendiente**\\n" + "\\n".join("- " + x for x in salida["triaje_pendiente"]) + "\\n\\n"
        md += "Escalar a **{{}}** en {{}} min.".format(plan["escalado"].get("a"), plan["escalado"].get("plazo_min"))
        if plan["avisos"]:
            md += "\\n\\n_Avisos: {{}}_".format("; ".join(plan["avisos"]))
        return_results(CommandResults(outputs_prefix="ResponseLab.Plan", outputs_key_field="alerta_id",
                                      outputs=salida, readable_output=md, raw_response=plan))
    except Exception as e:
        return_error("ResponseLabDecidir: {{}}".format(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
'''

SALIDAS = [
    ("familia", "Familia del playbook (endpoint, correo, cloud...)", "String"),
    ("playbook", "Nombre del playbook de DetectionLab", "String"),
    ("regla", "Regla reconocida", "String"),
    ("regla_conocida", "Si la regla esta en el catalogo", "Boolean"),
    ("clase", "Clase de automatizacion (auto_cierre, auto_enriq, auto_analisis, auto_contener)", "String"),
    ("severidad", "Severidad tras el triaje (1-4)", "Number"),
    ("estado", "en_curso, descartada o cerrada_auto", "String"),
    ("resumen", "Resumen del plan", "String"),
    ("modos", "Modo de cada paso: automatica, aprobacion, manual, no_aplicable, prohibida", "Unknown"),
    ("acciones", "Pasos del plan con su modo y motivo", "Unknown"),
    ("entradas", "Entradas ya resueltas para el playbook o comando de cada paso", "Unknown"),
    ("triaje_pendiente", "Preguntas de triaje que la maquina no pudo contestar", "Unknown"),
    ("escalado", "A quien escalar y en cuantos minutos", "Unknown"),
    ("alerta", "Alerta normalizada (equipo, usuario, fichero, red...)", "Unknown"),
]


# ═══ Piezas de playbook ══════════════════════════════════════════════════════

class Playbook:
    def __init__(self, nombre: str, descripcion: str):
        self.nombre = nombre
        self.descripcion = descripcion
        self.tareas: dict[str, dict] = {}
        self.n = 0

    def tarea(self, tipo: str, nombre: str, x: int, y: int, descripcion: str = "", **extra) -> str:
        tid = str(self.n)
        self.n += 1
        ident = uid("xsoar", self.nombre, tid)
        tarea = {"id": tid, "version": -1, "name": nombre[:250], "description": descripcion[:4000],
                 "type": tipo, "iscommand": False, "brand": ""}
        tarea.update(extra.pop("task", {}))
        t = {"id": tid, "taskid": ident, "type": tipo, "task": dict(tarea, id=ident), "separatecontext": False,
             "continueonerrortype": "", "view": json.dumps({"position": {"x": x, "y": y}}, indent=2),
             "note": False, "timertriggers": [], "ignoreworker": False, "skipunavailable": False,
             "quietmode": 0, "isoversize": False, "isautoswitchedtoquietmode": False}
        t["task"]["id"] = ident
        t.update(extra)
        self.tareas[tid] = t
        return tid

    def enlazar(self, desde: str, hacia: str, etiqueta: str = "#none#"):
        siguientes = self.tareas[desde].setdefault("nexttasks", {})
        lista = siguientes.setdefault(etiqueta, [])
        if hacia not in lista:
            lista.append(hacia)

    def a_yaml(self, entradas=None) -> str:
        ys = [int(json.loads(t["view"])["position"]["y"]) for t in self.tareas.values()]
        xs = [int(json.loads(t["view"])["position"]["x"]) for t in self.tareas.values()]
        d = {"id": self.nombre, "version": -1, "name": self.nombre, "description": self.descripcion,
             "starttaskid": "0", "tasks": self.tareas,
             "view": json.dumps({"linkLabelsPosition": {}, "paper": {"dimensions": {
                 "height": max(ys) - min(ys) + 200, "width": max(xs) - min(xs) + 400,
                 "x": min(xs) - 50, "y": min(ys) - 50}}}, indent=2),
             "inputs": entradas or [], "outputs": [], "tests": ["No tests"], "fromversion": VERSION_MINIMA}
        return yaml.safe_dump(d, sort_keys=False, allow_unicode=True, width=1000)


def _modo_es(paso: str, modo: str) -> list:
    return [[{"operator": "isEqualString",
              "left": {"value": {"simple": f"ResponseLab.Plan.modos.{paso}"}, "iscontext": True},
              "right": {"value": {"simple": modo}}}]]


def _argumentos(paso: str, entradas: dict) -> dict:
    """Cada entrada sale de ResponseLab.Plan.entradas.<paso>.<nombre>, ya resuelta por el script."""
    return {k: {"complex": {"root": f"ResponseLab.Plan.entradas.{paso}", "accessor": k}} for k in entradas}


def _ejecutar(pb: Playbook, paso: str, mapeo: dict, nombre: str, x: int, y: int) -> str:
    if mapeo["tipo"] == "playbook":
        return pb.tarea("playbook", mapeo["nombre"], x, y, f"ResponseLab {paso}: {nombre}",
                        task={"playbookName": mapeo["nombre"]},
                        scriptarguments=_argumentos(paso, mapeo["entradas"]), separatecontext=True,
                        loop={"iscommand": False, "exitCondition": "", "wait": 1, "max": 0},
                        skipunavailable=True, continueonerror=True)
    return pb.tarea("regular", mapeo["nombre"], x, y, f"ResponseLab {paso}: {nombre}",
                    task={"script": "|||" + mapeo["nombre"], "iscommand": True},
                    scriptarguments=_argumentos(paso, mapeo["entradas"]),
                    skipunavailable=True, continueonerror=True)


def _mapeo(catalogo: dict) -> dict:
    salida = {}
    for accion, meta in catalogo["acciones"].items():
        x = (meta.get("soar") or {}).get("xsoar")
        if not x:
            continue
        if x.get("playbook"):
            salida[accion] = {"tipo": "playbook", "nombre": x["playbook"], "entradas": dict(x.get("entradas") or {})}
        elif x.get("comando"):
            salida[accion] = {"tipo": "comando", "nombre": x["comando"], "entradas": dict(x.get("argumentos") or {})}
    return salida


def _lista(titulo: str, elementos: list) -> str:
    return titulo + "\n" + "\n".join("- " + " ".join(str(e).split()) for e in elementos)


def playbook_familia(nombre: str, f: dict, catalogo: dict, mapeo: dict) -> Playbook:
    pb = Playbook(f"ResponseLab - {titulo_familia(nombre)}",
                  f"{f['nombre']}. Generado por ResponseLab desde el playbook de "
                  f"{'DetectionLab' if f.get('origen') == 'detectionlab' else 'ResponseLab'} ({nombre}). "
                  "Necesita que ResponseLabDecidir haya dejado el plan en ResponseLab.Plan.")
    acciones = catalogo["acciones"]
    pasos = [(f"c{i}", c.get("accion"), c.get("texto", "")) for i, c in enumerate(f.get("contencion") or [], 1)]
    pasos += [(f"e{j}", e["accion"], acciones.get(e["accion"], {}).get("nombre", e["accion"]))
              for j, e in enumerate(f.get("evidencia_automatica") or [], 1)]
    y = 50
    actual = pb.tarea("start", "", X0, y)

    def seguir(tid):
        nonlocal actual
        pb.enlazar(actual, tid)
        actual = tid

    # ── 1. Contencion automatica: lo que la politica permite, sin esperar a nadie ──
    y += DY
    seguir(pb.tarea("title", "Contencion automatica", X0, y,
                    "Pasos que ResponseLab marco como automaticos. No hay tareas manuales en esta fase."))
    nativos = [(p, a, t) for p, a, t in pasos if a in mapeo]
    for paso, accion, texto in nativos:
        nombre_accion = acciones[accion].get("nombre", accion)
        y += DY
        cond = pb.tarea("condition", f"{paso}: {nombre_accion[:120]} - automatica?", X0, y,
                        f"Origen: {' '.join(texto.split())[:500]}",
                        conditions=[{"label": "yes", "condition": _modo_es(paso, "automatica")}])
        pb.enlazar(actual, cond)
        accion_t = _ejecutar(pb, paso, mapeo[accion], nombre_accion, X0 + DX, y + DY)
        pb.enlazar(cond, accion_t, "yes")
        y += 2 * DY
        # las dos ramas se juntan: si no era automatica, la accion queda saltada
        hecho = pb.tarea("title", f"{paso} hecho", X0, y, "")
        pb.enlazar(cond, hecho, "#default#")
        pb.enlazar(accion_t, hecho)
        actual = hecho

    # ── 2. Aprobaciones y acciones a mano ──
    y += DY
    seguir(pb.tarea("title", "Aprobaciones y acciones a mano", X0, y,
                    "Lo que pide aprobacion se aprueba aqui; lo que no tiene traduccion en XSOAR es una tarea."))
    for paso, accion, texto in pasos:
        meta = acciones.get(accion or "") or {}
        nombre_accion = meta.get("nombre") or " ".join(texto.split())[:200]
        origen = " ".join(texto.split())
        just = ""
        for c in f.get("contencion") or []:
            if " ".join(str(c.get("texto", "")).split()) == origen and c.get("justificacion"):
                just = " ".join(str(c["justificacion"]).split())
        y += DY
        ramas = [{"label": "aprobacion", "condition": _modo_es(paso, "aprobacion")},
                 {"label": "manual", "condition": _modo_es(paso, "manual")}]
        if accion not in mapeo:
            ramas.append({"label": "automatica", "condition": _modo_es(paso, "automatica")})
        cond = pb.tarea("condition", f"{paso}: {nombre_accion[:150]} - que modo?", X0, y,
                        f"Motivo del modo en la War Room (salida de ResponseLabDecidir). Origen: {origen[:400]}",
                        conditions=ramas)
        pb.enlazar(actual, cond)
        fin = pb.tarea("title", f"{paso} resuelto", X0, y + 3 * DY, "")
        pb.enlazar(cond, fin, "#default#")
        # aprobacion
        aprobar = pb.tarea("condition", f"Aprobar: {nombre_accion[:200]}", X0 - DX, y + DY,
                           f"Radio {meta.get('radio', '?')}, reversible {meta.get('reversible', '?')}"
                           + (f", se deshace con {meta['deshacer']}" if meta.get("deshacer") else "")
                           + f". Origen: {origen[:300]}" + (f" Por que: {just[:600]}" if just else ""))
        pb.enlazar(cond, aprobar, "aprobacion")
        if accion in mapeo:
            ejec = _ejecutar(pb, paso, mapeo[accion], nombre_accion, X0 - DX, y + 2 * DY)
        else:
            ejec = pb.tarea("regular", f"Ejecutar a mano: {nombre_accion[:200]}", X0 - DX, y + 2 * DY,
                            f"Aprobada. XSOAR no tiene traduccion nativa de {accion or 'esta accion'}: hazla con la "
                            f"herramienta del cliente o con el motor de ResponseLab. Origen: {origen[:400]}")
        pb.enlazar(aprobar, ejec, "Si")
        pb.enlazar(aprobar, fin, "No")
        pb.enlazar(ejec, fin)
        # manual (o automatica sin traduccion)
        a_mano = pb.tarea("regular", f"A mano: {nombre_accion[:200]}", X0 + DX, y + DY,
                          f"ResponseLab la deja al analista (motivo en la War Room). Origen: {origen[:400]}"
                          + (f" Por que: {just[:600]}" if just else ""))
        pb.enlazar(cond, a_mano, "manual")
        if accion not in mapeo:
            pb.enlazar(cond, a_mano, "automatica")
        pb.enlazar(a_mano, fin)
        actual = fin
        y += 3 * DY

    # ── 3. Checklist ──
    y += DY
    seguir(pb.tarea("title", "Checklist del playbook", X0, y, ""))
    esc = f.get("escalado") or {}
    desc = f"Plazo del playbook: {esc.get('a', 'L2')} en {esc.get('plazo_min', 30)} min. El plan de este incidente: " \
           "${ResponseLab.Plan.escalado.a} en ${ResponseLab.Plan.escalado.plazo_min} min."
    for clave, nivel in (("a_L3_si", "L3"), ("a_guardia_si", "guardia")):
        if esc.get(clave):
            desc += f"\nA {nivel} si: {' '.join(str(esc[clave]).split())}"
    if esc.get("ademas_avisar_a"):
        desc += f"\nAvisar ademas a: {', '.join(esc['ademas_avisar_a'])}"
    y += DY
    seguir(pb.tarea("regular", "Escalar segun el plan", X0, y, desc))
    for e in f.get("evidencia") or []:
        y += DY
        seguir(pb.tarea("regular", "Evidencia: " + " ".join(e["descripcion"].split())[:200], X0, y,
                        f"Como: {e.get('comando', '')}\nDonde: {e.get('donde', '')}"))
    if f.get("triaje"):
        y += DY
        seguir(pb.tarea("regular", "Contestar el triaje pendiente", X0, y,
                        "Pendientes en este incidente: ${ResponseLab.Plan.triaje_pendiente}\n\n"
                        + _lista("Preguntas del playbook:", [t["pregunta"] for t in f["triaje"]])))
    if f.get("cierre"):
        y += DY
        seguir(pb.tarea("regular", "Comprobar las condiciones de cierre", X0, y,
                        _lista("Se puede cerrar como benigno si:", [c["condicion"] for c in f["cierre"]])))
    if f.get("requiere_persona"):
        y += DY
        seguir(pb.tarea("regular", "Situaciones que requieren a una persona", X0, y,
                        _lista("Nunca automatico:", [r["situacion"] for r in f["requiere_persona"]])))
    y += DY
    seguir(pb.tarea("title", "Hecho", X0, y, ""))
    return pb


def playbook_enrutador(nombres: list) -> Playbook:
    pb = Playbook("ResponseLab - Enrutador",
                  "Decide con el nucleo de ResponseLab (script ResponseLabDecidir), cierra lo que el nucleo cierra "
                  "y llama al playbook de la familia. Ponlo como playbook por defecto del tipo de incidente.")
    y = 50
    inicio = pb.tarea("start", "", X0, y)
    y += DY
    decidir = pb.tarea("regular", "ResponseLabDecidir", X0, y, "Normaliza la alerta, decide y deja el plan en ResponseLab.Plan.",
                       task={"scriptName": "ResponseLabDecidir"},
                       scriptarguments={"siem": {"simple": "${inputs.siem}"}, "perfil": {"simple": "${inputs.perfil}"}})
    pb.enlazar(inicio, decidir)
    y += DY
    cerrada = pb.tarea("condition", "Descartada o cerrada por el playbook?", X0, y,
                       "Reglas base de correlacion (auto_cierre) y condiciones de cierre que el nucleo pudo comprobar con datos.",
                       conditions=[{"label": "yes", "condition": [[{
                           "operator": "isEqualString",
                           "left": {"value": {"simple": "ResponseLab.Plan.estado"}, "iscontext": True},
                           "right": {"value": {"simple": e}}} for e in ESTADOS_CIERRE]]}])
    pb.enlazar(decidir, cerrada)
    cerrar = pb.tarea("regular", "Cerrar el incidente", X0 + DX, y + DY, "Cierre con la justificacion del playbook.",
                      task={"script": "Builtin|||closeInvestigation", "iscommand": True},
                      scriptarguments={"closeReason": {"simple": "Resolved"},
                                       "closeNotes": {"simple": "ResponseLab: ${ResponseLab.Plan.resumen}"}})
    pb.enlazar(cerrada, cerrar, "yes")
    y += DY
    familia = pb.tarea("condition", "Que playbook?", X0, y, "Segun ResponseLab.Plan.familia.",
                       conditions=[{"label": n, "condition": [[{
                           "operator": "isEqualString",
                           "left": {"value": {"simple": "ResponseLab.Plan.familia"}, "iscontext": True},
                           "right": {"value": {"simple": n}}}]]} for n in nombres if n != "_generico"])
    pb.enlazar(cerrada, familia, "#default#")
    fin = pb.tarea("title", "Hecho", X0, y + 3 * DY, "")
    pb.enlazar(cerrar, fin)
    for i, n in enumerate(nombres):
        x = X0 + (i - len(nombres) // 2) * 260
        sub = pb.tarea("playbook", f"ResponseLab - {titulo_familia(n)}", x, y + DY + DY // 2, "",
                       task={"playbookName": f"ResponseLab - {titulo_familia(n)}"},
                       separatecontext=False, loop={"iscommand": False, "exitCondition": "", "wait": 1, "max": 0})
        pb.enlazar(familia, sub, "#default#" if n == "_generico" else n)
        pb.enlazar(sub, fin)
    return pb


def script_yaml(catalogo: dict, mapeo: dict) -> str:
    codigo = SCRIPT.format(version=catalogo["version"],
                           catalogo=json.dumps(json.dumps(compacto(catalogo, texto=False), ensure_ascii=True,
                                                          separators=(",", ":"), sort_keys=True)),
                           mapeo=json.dumps(json.dumps(mapeo, ensure_ascii=True, sort_keys=True)),
                           cliente=json.dumps(json.dumps(dict(CLIENTE_POR_DEFECTO, id="xsoar"), sort_keys=True)),
                           nucleo=json.dumps(codigo_nucleo(), ensure_ascii=True))
    d = {
        "commonfields": {"id": "ResponseLabDecidir", "version": -1},
        "name": "ResponseLabDecidir",
        "script": codigo,
        "type": "python",
        "subtype": "python3",
        "tags": ["ResponseLab"],
        "comment": "Decide la respuesta al incidente con el nucleo de ResponseLab: familia, clase, modo de cada "
                   "accion (automatica, aprobacion, manual) y entradas resueltas. Generado; no editar.",
        "enabled": True,
        "args": [
            {"name": "siem", "auto": "PREDEFINED", "predefined": ["auto", "wazuh", "splunk", "sentinel", "elastic", "generico"],
             "defaultValue": "auto", "description": "Formato del rawJSON del incidente; auto lo detecta."},
            {"name": "perfil", "defaultValue": "ResponseLab_Cliente",
             "description": "Lista de XSOAR con el perfil del cliente en JSON (politica, inventario, listas)."},
            {"name": "ajustar_severidad", "auto": "PREDEFINED", "predefined": ["true", "false"], "defaultValue": "true",
             "description": "Ajustar la severidad del incidente a la del plan."},
        ],
        "outputs": [{"contextPath": f"ResponseLab.Plan.{k}", "description": d_, "type": t} for k, d_, t in SALIDAS],
        "scripttarget": 0,
        "runas": "DBotWeakRole",
        "fromversion": VERSION_MINIMA,
        "tests": ["No tests"],
    }

    class Literal(str):
        pass

    def literal(dumper, data):
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")

    yaml.SafeDumper.add_representer(Literal, literal)
    d["script"] = Literal(codigo)
    return yaml.safe_dump(d, sort_keys=False, allow_unicode=False, width=1000)


def exportar(catalogo: dict) -> dict[str, str]:
    mapeo = _mapeo(catalogo)
    salidas = {"soar/xsoar/script-ResponseLabDecidir.yml": script_yaml(catalogo, mapeo)}
    nombres = familias(catalogo)
    for n in nombres:
        pb = playbook_familia(n, catalogo["familias"][n], catalogo, mapeo)
        salidas[f"soar/xsoar/playbook-ResponseLab_-_{titulo_familia(n)}.yml"] = pb.a_yaml()
    entradas = [
        {"key": "siem", "value": {"simple": "auto"}, "required": False,
         "description": "Formato del incidente: auto, wazuh, splunk, sentinel, elastic o generico.", "playbookInputQuery": None},
        {"key": "perfil", "value": {"simple": "ResponseLab_Cliente"}, "required": False,
         "description": "Lista de XSOAR con el perfil del cliente en JSON.", "playbookInputQuery": None},
    ]
    salidas["soar/xsoar/playbook-ResponseLab_-_Enrutador.yml"] = playbook_enrutador(nombres).a_yaml(entradas)
    salidas["soar/xsoar/lista-ResponseLab_Cliente.json"] = json.dumps(
        dict(CLIENTE_POR_DEFECTO, id="nombre-del-cliente", zona_horaria="Europe/Madrid",
             inventario={"completo": False, "activos": [{"nombre": "DC01", "etiquetas": ["servidor_produccion"]}],
                         "protegidos": ["^DC\\d+$"]},
             listas={"aplicaciones_negocio": []}),
        ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    return salidas
