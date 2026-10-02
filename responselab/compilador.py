"""
Compila el catalogo que carga el motor: ecosistema + capa ejecutable + acciones.

    ecosistema/detectionlab/playbooks/*.yml   la razon de cada decision (prosa)
    ecosistema/*/reglas.json                  que regla es de que familia
    playbooks/*.yml                           que sabe contestar la maquina
    acciones/catalogo.yml                     que se puede ejecutar y con que radio
                       │
                       ▼
             catalogo/catalogo.json            lo unico que lee el motor

Por que un fichero compilado y no leer los YAML en el motor
-----------------------------------------------------------
Porque el motor en produccion se actualiza solo (descarga el catalogo del
repositorio). Un unico JSON con version por hash se valida entero antes de
cambiarlo, se cambia de golpe y se puede volver al anterior. Varios YAML
sueltos se actualizarian a medias.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from . import nucleo
from .util import RAIZ, json_estable, normalizar_texto, sha256_texto

ECOSISTEMA = RAIZ / "ecosistema"
PLAYBOOKS = RAIZ / "playbooks"
ACCIONES = RAIZ / "acciones" / "catalogo.yml"
SALIDA = RAIZ / "catalogo" / "catalogo.json"

FUENTES_REGLAS = [
    ECOSISTEMA / "detectionlab" / "reglas.json",
    ECOSISTEMA / "infra-socanalyst" / "reglas.json",
    ECOSISTEMA / "splunklab" / "reglas.json",
]


def _yaml(ruta: Path):
    return yaml.safe_load(ruta.read_text(encoding="utf-8")) or {}


def cargar_reglas() -> list[dict]:
    reglas = []
    for f in FUENTES_REGLAS:
        if f.exists():
            reglas += json.loads(f.read_text(encoding="utf-8")).get("reglas", [])
    for r in reglas:
        r.setdefault("clase", nucleo.CLASE_POR_NIVEL.get(r.get("nivel", "medium"), "auto_analisis"))
    return sorted(reglas, key=lambda r: r["clave"])


def cargar_acciones() -> dict:
    return _yaml(ACCIONES).get("acciones", {})


def _mapa_contencion(comun: dict, capa: dict) -> dict:
    mapa = {}
    for entrada in (comun.get("contencion") or []) + (capa.get("contencion") or []):
        mapa[normalizar_texto(entrada["texto"])] = entrada
    return mapa


def compilar_familia(nombre: str, dl: dict, capa: dict, comun: dict, avisos: list) -> dict:
    """Une el playbook de DetectionLab con su capa ejecutable."""
    mapa = _mapa_contencion(comun, capa)
    exc_comunes = comun.get("excepciones_por_accion") or {}
    exc_familia = capa.get("excepciones") or {}

    contencion = []
    for c in dl.get("contencion") or []:
        clave = normalizar_texto(c.get("accion", ""))
        m = mapa.get(clave)
        if m is None:
            avisos.append(f"{nombre}: accion de DetectionLab sin mapear -> tarea manual: '{c.get('accion')}'")
        accion = m["accion"] if m else None
        contencion.append({
            "texto": c.get("accion", ""),
            "accion": accion,
            "alcance": " ".join(str(c.get("alcance", "")).split()),
            "radio": c.get("radio"),
            "reversible": str(c.get("reversible")),
            "requiere_aprobacion": str(c.get("requiere_aprobacion")),
            "justificacion": c.get("justificacion", ""),
            "excepcion": c.get("excepcion", ""),
            "solo_reglas": (m or {}).get("solo_reglas") or [],
            "parametros": (m or {}).get("parametros") or {},
            "excepciones": list(exc_comunes.get(accion, [])) + list(exc_familia.get(accion, [])) if accion else [],
        })

    triaje_rl = {normalizar_texto(t["pregunta"]): t for t in capa.get("triaje") or []}
    usados = set()
    triaje = []
    for t in dl.get("triaje") or []:
        k = normalizar_texto(t["pregunta"])
        rl = triaje_rl.get(k)
        if rl:
            usados.add(k)
        notas = [x for x in (t.get("nota"), (rl or {}).get("nota")) if x]
        triaje.append({
            "pregunta": t["pregunta"],
            "fuente": t.get("fuente", ""),
            "efecto": t.get("si_afirmativo", ""),
            "evaluador": (rl or {}).get("evaluador"),
            "nota": " ".join(" ".join(notas).split()),
        })
    for k, t in triaje_rl.items():
        if k not in usados:
            avisos.append(f"{nombre}: evaluador de triaje huerfano (la pregunta ya no esta en DetectionLab): '{t['pregunta']}'")

    cierres_rl = capa.get("cierre") or []
    cierre = []
    usados_c = set()
    for c in dl.get("cierre_automatico") or []:
        texto = " ".join(str(c.get("condicion", "")).split())
        ev = None
        for i, rl in enumerate(cierres_rl):
            if normalizar_texto(texto).startswith(normalizar_texto(rl["empieza"])):
                ev = rl.get("evaluador")
                usados_c.add(i)
                break
        cierre.append({"condicion": texto, "justificacion": " ".join(str(c.get("justificacion", "")).split()),
                       "evaluador": ev})
    for i, rl in enumerate(cierres_rl):
        if i not in usados_c:
            avisos.append(f"{nombre}: evaluador de cierre huerfano: '{rl['empieza']}'")

    escalado = dict(dl.get("escalado") or {})
    return {
        "nombre": dl.get("nombre", nombre),
        "descripcion": " ".join(str(dl.get("descripcion", "")).split()),
        "origen": "detectionlab",
        "plantilla_caso": capa.get("plantilla_caso") or f"ResponseLab - {nombre}",
        "enriquecimiento": dl.get("enriquecimiento") or [],
        "evidencia": [{"descripcion": e.get("descripcion", ""), "comando": e.get("comando", ""),
                       "donde": e.get("donde", "")} for e in dl.get("evidencia") or []],
        "triaje": triaje,
        "cierre": cierre,
        "contencion": contencion,
        "evidencia_automatica": (comun.get("evidencia_automatica") or {}).get(nombre, []),
        "requiere_persona": [{"situacion": r.get("situacion", ""), "motivo": " ".join(str(r.get("motivo", "")).split())}
                             for r in dl.get("requiere_persona") or []],
        "escalado": escalado,
        "escalado_evaluadores": capa.get("escalado") or {},
    }


def compilar() -> tuple[dict, list[str]]:
    avisos: list[str] = []
    comun = _yaml(PLAYBOOKS / "comun.yml")
    acciones = cargar_acciones()
    reglas = cargar_reglas()

    familias = {}
    dl_dir = ECOSISTEMA / "detectionlab" / "playbooks"
    for f in sorted(dl_dir.glob("*.yml")):
        dl = _yaml(f)
        nombre = dl.get("familia", f.stem)
        capa_ruta = PLAYBOOKS / f"{nombre}.yml"
        capa = _yaml(capa_ruta) if capa_ruta.exists() else {}
        if not capa_ruta.exists():
            avisos.append(f"{nombre}: familia nueva en DetectionLab sin capa ejecutable: todo su triaje queda para el analista")
        familias[nombre] = compilar_familia(nombre, dl, capa, comun, avisos)

    gen = _yaml(PLAYBOOKS / "_generico.yml")
    familias["_generico"] = {
        "nombre": gen.get("nombre", "Generico"),
        "descripcion": " ".join(str(gen.get("descripcion", "")).split()),
        "origen": "responselab",
        "plantilla_caso": "ResponseLab - _generico",
        "enriquecimiento": gen.get("enriquecimiento") or [],
        "evidencia": gen.get("evidencia") or [],
        "triaje": [], "cierre": [], "contencion": [], "evidencia_automatica": [],
        "requiere_persona": gen.get("requiere_persona") or [],
        "escalado": gen.get("escalado") or {"a": "L2", "plazo_min": 30},
        "escalado_evaluadores": {},
    }

    for r in reglas:
        if r["familia"] not in familias:
            avisos.append(f"regla {r['clave']}: familia '{r['familia']}' sin playbook -> generico")

    secuencias = _yaml(PLAYBOOKS / "secuencias.yml").get("secuencias") or []
    estado = json.loads((ECOSISTEMA / "ESTADO.json").read_text(encoding="utf-8")) if (ECOSISTEMA / "ESTADO.json").exists() else {}

    catalogo = {
        "formato": 1,
        "fuentes": {k: {"commit": v.get("commit", ""), "contenido_sha256": v.get("contenido_sha256", "")}
                    for k, v in sorted(estado.items())},
        "familias": familias,
        "acciones": acciones,
        "reglas": reglas,
        "secuencias": secuencias,
    }
    catalogo["version"] = sha256_texto(json_estable(catalogo))[:12]
    return catalogo, sorted(set(avisos))


def escribir(catalogo: dict, ruta: Path = SALIDA) -> bool:
    from .util import escribir_si_cambia
    return escribir_si_cambia(ruta, json_estable(catalogo))
