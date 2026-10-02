"""Utilidades de los exportadores: catalogo compacto, codigo del nucleo, ids deterministas."""
from __future__ import annotations

import copy
import json
import re
import uuid
from pathlib import Path

from .. import nucleo

NAMESPACE = uuid.UUID("6f7c1d2e-3b4a-5c6d-8e9f-0a1b2c3d4e5f")
FAMILIAS_ORDEN = ["ad", "cloud", "contenedores", "correo", "credenciales", "cumplimiento", "endpoint",
                  "exfiltracion", "inteligencia", "linux", "macos", "red", "web", "xdr", "zta", "_generico"]


def uid(*partes) -> str:
    """UUID determinista: mismo origen, mismo id. Sin esto cada compilacion
    cambiaria todos los ids y el CI veria cambios donde no los hay."""
    return str(uuid.uuid5(NAMESPACE, "/".join(str(p) for p in partes)))


def slug(texto: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", nucleo.norm(texto)).strip("_")


def titulo_familia(nombre: str) -> str:
    return {"ad": "AD", "_generico": "Generico", "xdr": "XDR", "zta": "ZTA"}.get(nombre, nombre.capitalize())


def familias(catalogo: dict) -> list[str]:
    return [f for f in FAMILIAS_ORDEN if f in catalogo["familias"]] + \
           sorted(f for f in catalogo["familias"] if f not in FAMILIAS_ORDEN)


def compacto(catalogo: dict, solo: list[str] | None = None, texto: bool = True) -> dict:
    """Lo minimo que necesita nucleo.decidir. Para incrustar en un SOAR.

    texto=False quita la prosa (justificaciones, descripciones): la decision no
    la usa y el artefacto pesa la mitad.
    """
    fams = {}
    for nombre, f in catalogo["familias"].items():
        if solo and nombre not in solo and nombre != "_generico":
            continue
        fams[nombre] = {
            "nombre": f["nombre"], "plantilla_caso": f.get("plantilla_caso"),
            "enriquecimiento": [{"fuente": e.get("fuente")} for e in f.get("enriquecimiento") or []],
            "triaje": [{k: t[k] for k in ("pregunta", "fuente", "efecto", "evaluador", "nota") if k in t and (texto or k != "nota")}
                       for t in f.get("triaje") or []],
            "cierre": [{"condicion": c["condicion"], "evaluador": c.get("evaluador")} for c in f.get("cierre") or []],
            "contencion": [{k: c.get(k) for k in ("texto", "accion", "radio", "reversible", "requiere_aprobacion",
                                                  "solo_reglas", "excepciones", "parametros")}
                           | ({"justificacion": c.get("justificacion", "")} if texto else {})
                           for c in f.get("contencion") or []],
            "evidencia_automatica": f.get("evidencia_automatica") or [],
            "evidencia": [{"descripcion": e["descripcion"], "donde": e.get("donde", "")} for e in f.get("evidencia") or []],
            "requiere_persona": [{"situacion": r["situacion"]} for r in f.get("requiere_persona") or []],
            "escalado": {k: v for k, v in (f.get("escalado") or {}).items()
                         if k in ("a", "plazo_min", "a_L3_si", "a_guardia_si", "ademas_avisar_a")},
            "escalado_evaluadores": f.get("escalado_evaluadores") or {},
        }
    acciones_usadas = {c["accion"] for f in fams.values() for c in f["contencion"] if c.get("accion")}
    acciones_usadas |= {e["accion"] for f in fams.values() for e in f["evidencia_automatica"]}
    acciones = {k: {kk: v[kk] for kk in ("nombre", "radio", "reversible", "requiere", "capacidad", "deshacer", "registro")
                    if kk in v}
                for k, v in catalogo["acciones"].items() if k in acciones_usadas}
    reglas = [{k: r[k] for k in ("clave", "titulo", "titulos", "nivel", "clase", "familia", "tecnicas", "wazuh_ids",
                                 "splunk", "sigma_id", "fichero") if r.get(k)}
              for r in catalogo["reglas"] if not solo or r["familia"] in solo]
    return {"version": catalogo["version"], "familias": fams, "acciones": acciones, "reglas": reglas,
            "secuencias": catalogo.get("secuencias") or []}


def codigo_nucleo() -> str:
    """El fichero nucleo.py tal cual, para incrustarlo en un SOAR."""
    return Path(nucleo.__file__).read_text(encoding="utf-8")


def json_compacto(datos) -> str:
    return json.dumps(datos, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


CLIENTE_POR_DEFECTO = {
    # Lo que asume un SOAR que no tiene perfil de cliente: lo mas prudente.
    # Sin inventario, toda excepcion que no se pueda descartar pide aprobacion.
    "politica": {"contencion_automatica": True, "excepcion_sin_datos": "aprobacion", "escalado_por_correlacion": True},
    "inventario": {"completo": False, "activos": [], "protegidos": []},
    "listas": {},
}


def catalogo_para_soar(catalogo: dict, comprobada=None) -> "nucleo.Catalogo":
    """Catalogo para decidir de antemano en un SOAR sin motor.

    comprobada(accion, excepcion) -> True si el SOAR comprueba esa excepcion en
    tiempo real (por ejemplo, "servidor de produccion" contra su propia lista
    de activos protegidos). Esas se quitan del catalogo para la decision
    estatica; las demas se quedan y, sin datos, mandan la accion a aprobacion.
    """
    if comprobada is None:
        return nucleo.Catalogo(catalogo)
    datos = copy.deepcopy(catalogo)
    for f in datos["familias"].values():
        for c in f.get("contencion") or []:
            if c.get("excepciones"):
                c["excepciones"] = [e for e in c["excepciones"] if not comprobada(c.get("accion"), e)]
    return nucleo.Catalogo(datos)


def modos_estaticos(cat: "nucleo.Catalogo", regla: dict, disponibles: set) -> dict:
    """Modo de cada accion de una regla decidido de antemano, sin contexto.

    Para los SOAR que no pueden llamar al motor: se ejecuta el nucleo con una
    alerta que trae todos los campos y el cliente prudente. Lo que sale
    "automatica" aqui es lo que la politica permite con la peor informacion
    posible (sin inventario: toda excepcion que el SOAR no compruebe por su
    cuenta pide aprobacion); el SOAR solo tiene que comprobar en tiempo real
    que el objetivo existe, no es ambiguo y no esta protegido.
    Devuelve {accion: modo}; si una accion sale en varios pasos, gana el modo
    mas restrictivo, salvo que alguno sea automatico por su regla concreta.
    """
    from ..validacion import alerta_completa
    alerta = alerta_completa(regla)
    plan = nucleo.decidir(alerta, cat, CLIENTE_POR_DEFECTO, {}, acciones_disponibles=disponibles)
    fallos = nucleo.verificar_invariantes(plan, alerta)
    if fallos:
        raise ValueError("invariante rota al exportar %s: %s" % (regla["clave"], "; ".join(fallos)))
    modos = {}
    for p in plan["acciones"]:
        if not p.get("accion"):
            continue
        previo = modos.get(p["accion"])
        if previo == "automatica" or p["modo"] == "automatica":
            modos[p["accion"]] = "automatica"
        elif previo is None or p["modo"] == "aprobacion":
            modos[p["accion"]] = p["modo"]
    return {"clase": plan["clase"], "familia": plan["familia"], "modos": modos}
