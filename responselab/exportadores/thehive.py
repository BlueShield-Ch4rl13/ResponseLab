"""
TheHive 5: una plantilla de caso por familia.

La plantilla lleva el playbook entero como lista de tareas: evidencia, triaje,
contencion, condiciones de cierre, lo que requiere persona y el escalado. El
motor abre los casos con ella (caseTemplate) y anade encima lo que solo se sabe
en tiempo real. Si un cliente usa TheHive sin el motor, la plantilla sigue
siendo el playbook, ejecutado a mano con su checklist.

Importar: tools/importar_thehive.py, o en TheHive Organisation > Templates >
Import con cada fichero de soar/thehive/plantillas/.
"""
from __future__ import annotations

from ..util import json_estable
from .comun import familias, titulo_familia

EFECTO = {"subir_severidad": "sube la severidad", "bajar_severidad": "baja la severidad (un escalon como mucho)"}


def _tarea(grupo: str, titulo: str, descripcion: str, orden: int) -> dict:
    return {"title": titulo[:250], "group": grupo, "description": descripcion[:4000], "order": orden,
            "mandatory": False, "flag": False}


def plantilla(nombre: str, f: dict, acciones: dict) -> dict:
    tareas, orden = [], 0

    def add(grupo, titulo, desc):
        nonlocal orden
        tareas.append(_tarea(grupo, titulo, desc, orden))
        orden += 1

    for e in f.get("evidencia") or []:
        add("1. Evidencia", e["descripcion"], f"Como: {e.get('comando', '')}\nDonde: {e.get('donde', '')}")
    for t in f.get("triaje") or []:
        auto = ("ResponseLab la contesta sola si hay datos; si queda pendiente, contestarla aqui."
                if t.get("evaluador") else "Pregunta para el analista: la maquina no tiene datos para contestarla.")
        add("2. Triaje", t["pregunta"], f"Fuente: {t.get('fuente', '')}. Si es afirmativa, {EFECTO.get(t.get('efecto'), t.get('efecto'))}.\n"
                                       f"{auto}\n{t.get('nota', '')}".strip())
    for c in f.get("contencion") or []:
        meta = acciones.get(c.get("accion") or "", {})
        modo = ("Requiere aprobacion." if c.get("requiere_aprobacion") == "si" or c.get("radio") in ("cuenta", "organizacion")
                else "Automatica en clase auto_contener si la politica del cliente lo permite.")
        add("3. Contencion", c["texto"],
            f"Alcance: {c.get('alcance', '')}\nRadio: {c.get('radio')} · Reversible: {c.get('reversible')}\n{modo}\n"
            f"Accion de ResponseLab: {c.get('accion') or 'sin mapear (manual)'}"
            + (f" · se deshace con {meta['deshacer']}" if meta.get("deshacer") else "")
            + (f"\nExcepcion: {c['excepcion']}" if c.get("excepcion") else "")
            + (f"\nPor que: {c['justificacion']}" if c.get("justificacion") else ""))
    for c in f.get("cierre") or []:
        add("4. Cierre", "Comprobar si se puede cerrar: " + c["condicion"][:200],
            f"{c['condicion']}\n\nPor que es seguro: {c.get('justificacion', '')}")
    for r in f.get("requiere_persona") or []:
        add("5. Requiere persona", r["situacion"], r.get("motivo", ""))
    esc = f.get("escalado") or {}
    desc = f"Escalar a {esc.get('a', 'L2')} en {esc.get('plazo_min', 30)} minutos."
    if esc.get("a_L3_si"):
        desc += f"\nA L3 si: {esc['a_L3_si']}"
    if esc.get("a_guardia_si"):
        desc += f"\nA guardia si: {esc['a_guardia_si']}"
    if esc.get("ademas_avisar_a"):
        desc += f"\nAvisar ademas a: {', '.join(esc['ademas_avisar_a'])}"
    if esc.get("nota_plazo"):
        desc += f"\n{' '.join(str(esc['nota_plazo']).split())}"
    add("6. Escalado", f"Escalado: {esc.get('a', 'L2')} en {esc.get('plazo_min', 30)} min", desc)

    return {
        "name": f.get("plantilla_caso") or f"ResponseLab - {nombre}",
        "displayName": f"ResponseLab · {f['nombre']}"[:200],
        "titlePrefix": f"[RL {titulo_familia(nombre)}]",
        "description": (f.get("descripcion") or "") + "\n\nGenerada por ResponseLab desde el playbook de "
                       f"{'DetectionLab' if f.get('origen') == 'detectionlab' else 'ResponseLab'} ({nombre}).",
        "severity": 2, "tlp": 2, "pap": 2, "flag": False,
        "tags": ["responselab", f"rl:familia={nombre}"],
        "tasks": tareas,
        "customFields": [],
    }


def exportar(catalogo: dict) -> dict[str, str]:
    salidas = {}
    for nombre in familias(catalogo):
        p = plantilla(nombre, catalogo["familias"][nombre], catalogo["acciones"])
        salidas[f"soar/thehive/plantillas/{nombre}.json"] = json_estable(p)
    return salidas
