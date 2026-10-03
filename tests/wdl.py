"""
Comprobaciones estructurales de workflows de Logic Apps (WDL).

No sustituye a desplegar en Azure, pero caza lo que rompe un despliegue o una
ejecucion y no se ve leyendo el JSON: runAfter a acciones que no existen,
ciclos, items() fuera de su bucle, variables sin inicializar, parametros sin
declarar, anidamiento o expresiones por encima de los limites del servicio.
Limites: https://learn.microsoft.com/azure/logic-apps/logic-apps-limits-and-config
"""
from __future__ import annotations

import re

LIMITE_ACCIONES = 500
LIMITE_ANIDAMIENTO = 8
LIMITE_EXPRESION = 8192
LIMITE_NOMBRE = 80
TIPOS_CON_HIJOS = {"If", "Foreach", "Scope", "Until", "Switch"}
TIPOS_CONOCIDOS = TIPOS_CON_HIJOS | {"Http", "Compose", "Query", "Select", "InitializeVariable", "SetVariable",
                                     "AppendToArrayVariable", "AppendToStringVariable", "IncrementVariable",
                                     "Terminate", "ApiConnection", "ParseJson", "Response", "Wait", "Table", "Join"}
RE_REF = re.compile(r"\b(body|outputs|actions|result)\('([^']+)'\)")
RE_ITEMS = re.compile(r"\bitems\('([^']+)'\)")
RE_VAR = re.compile(r"\bvariables\('([^']+)'\)")
RE_PARAM = re.compile(r"\bparameters\('([^']+)'\)")
ESTADOS = {"Succeeded", "Failed", "Skipped", "TimedOut"}


def _cadenas(valor):
    if isinstance(valor, str):
        yield valor
    elif isinstance(valor, dict):
        for k, v in valor.items():
            yield from _cadenas(k)
            yield from _cadenas(v)
    elif isinstance(valor, list):
        for v in valor:
            yield from _cadenas(v)


def _hijos(accion: dict) -> list[dict]:
    salida = []
    if "actions" in accion:
        salida.append(accion["actions"])
    if isinstance(accion.get("else"), dict) and "actions" in accion["else"]:
        salida.append(accion["else"]["actions"])
    for caso in (accion.get("cases") or {}).values():
        salida.append(caso.get("actions") or {})
    if isinstance(accion.get("default"), dict):
        salida.append(accion["default"].get("actions") or {})
    return salida


def _propias(accion: dict) -> dict:
    """La accion sin sus hijas: para buscar referencias solo en lo suyo."""
    return {k: v for k, v in accion.items() if k not in ("actions", "else", "cases", "default")}


def revisar(definicion: dict, nombre: str = "workflow") -> list[str]:
    errores: list[str] = []
    todas: dict[str, str] = {}   # nombre de accion -> tipo
    total = 0
    parametros = set((definicion.get("parameters") or {}).keys())
    variables_top = set()

    for accion in (definicion.get("actions") or {}).values():
        if accion.get("type") == "InitializeVariable":
            for v in accion["inputs"]["variables"]:
                variables_top.add(v["name"])

    def recorrer(ambito: dict, profundidad: int, bucles: list[str], ruta: str):
        nonlocal total
        if profundidad > LIMITE_ANIDAMIENTO:
            errores.append(f"{nombre}: anidamiento {profundidad} > {LIMITE_ANIDAMIENTO} en {ruta}")
        if not ambito:
            return
        sin_previas = [n for n, a in ambito.items() if not a.get("runAfter")]
        if not sin_previas:
            errores.append(f"{nombre}: ninguna accion arranca el ambito {ruta} (todas tienen runAfter)")
        for n, a in ambito.items():
            total += 1
            if n in todas:
                errores.append(f"{nombre}: accion duplicada {n}")
            todas[n] = a.get("type", "")
            if len(n) > LIMITE_NOMBRE:
                errores.append(f"{nombre}: nombre de accion de {len(n)} caracteres: {n[:40]}...")
            if a.get("type") not in TIPOS_CONOCIDOS:
                errores.append(f"{nombre}: tipo de accion desconocido {a.get('type')} en {n}")
            for previa, estados in (a.get("runAfter") or {}).items():
                if previa not in ambito:
                    errores.append(f"{nombre}: {n} corre despues de {previa}, que no esta en su ambito ({ruta})")
                if not set(estados) <= ESTADOS or not estados:
                    errores.append(f"{nombre}: estados de runAfter invalidos en {n}: {estados}")
            if a.get("type") == "Terminate" and bucles:
                errores.append(f"{nombre}: Terminate dentro de un bucle ({n})")
            if a.get("type") == "InitializeVariable" and ruta != "raiz":
                errores.append(f"{nombre}: InitializeVariable fuera del nivel superior ({n})")
            if a.get("type") == "If" and "expression" not in a:
                errores.append(f"{nombre}: If sin expression ({n})")
            if a.get("type") == "Foreach" and not str(a.get("foreach", "")).startswith("@"):
                errores.append(f"{nombre}: Foreach sin expresion ({n})")
            for texto in _cadenas(_propias(a)):
                if len(texto) > LIMITE_EXPRESION and texto.startswith("@"):
                    errores.append(f"{nombre}: expresion de {len(texto)} caracteres en {n}")
                for b in RE_ITEMS.findall(texto):
                    if b not in bucles and b != n:
                        errores.append(f"{nombre}: items('{b}') fuera de su bucle en {n}")
            for hijo in _hijos(a):
                recorrer(hijo, profundidad + 1, bucles + ([n] if a.get("type") == "Foreach" else []), n)
        # ciclos en runAfter
        visitando, hechos = set(), set()

        def dfs(x):
            if x in hechos:
                return
            if x in visitando:
                errores.append(f"{nombre}: ciclo en runAfter que pasa por {x}")
                return
            visitando.add(x)
            for previa in (ambito.get(x, {}).get("runAfter") or {}):
                if previa in ambito:
                    dfs(previa)
            visitando.discard(x)
            hechos.add(x)

        for x in ambito:
            dfs(x)

    recorrer(definicion.get("actions") or {}, 1, [], "raiz")
    if total > LIMITE_ACCIONES:
        errores.append(f"{nombre}: {total} acciones > {LIMITE_ACCIONES}")

    disparadores = set((definicion.get("triggers") or {}).keys())
    for texto in _cadenas(definicion.get("actions") or {}):
        for _, ref in RE_REF.findall(texto):
            if ref not in todas and ref not in disparadores:
                errores.append(f"{nombre}: referencia a una accion que no existe: {ref}")
        for v in RE_VAR.findall(texto):
            if v not in variables_top:
                errores.append(f"{nombre}: variable sin inicializar: {v}")
        for p in RE_PARAM.findall(texto):
            if p not in parametros:
                errores.append(f"{nombre}: parametro no declarado: {p}")
    for nombre_accion, accion in _todas_las_acciones(definicion.get("actions") or {}):
        if accion.get("type") in ("AppendToArrayVariable", "SetVariable", "IncrementVariable", "AppendToStringVariable"):
            if accion["inputs"]["name"] not in variables_top:
                errores.append(f"{nombre}: {nombre_accion} usa la variable {accion['inputs']['name']} sin inicializar")
    return sorted(set(errores))


def _todas_las_acciones(ambito: dict):
    for n, a in ambito.items():
        yield n, a
        for hijo in _hijos(a):
            yield from _todas_las_acciones(hijo)


def revisar_plantilla_arm(plantilla: dict) -> list[str]:
    """Plantilla ARM con workflows: estructura ARM y cada definicion."""
    errores = []
    for clave in ("$schema", "contentVersion", "resources"):
        if clave not in plantilla:
            errores.append(f"plantilla ARM sin {clave}")
    parametros = set((plantilla.get("parameters") or {}).keys())
    variables = set((plantilla.get("variables") or {}).keys())
    for texto in _cadenas({k: v for k, v in plantilla.items() if k != "resources"} | {
            "resources": [{k: v for k, v in r.items() if k != "properties"} | {
                "properties": {k: v for k, v in (r.get("properties") or {}).items() if k != "definition"}}
                for r in plantilla.get("resources") or []]}):
        if texto.startswith("[") and texto.endswith("]") and not texto.startswith("[["):
            for p in re.findall(r"parameters\('([^']+)'\)", texto):
                if p not in parametros:
                    errores.append(f"parametro ARM no declarado: {p}")
            for v in re.findall(r"variables\('([^']+)'\)", texto):
                if v not in variables:
                    errores.append(f"variable ARM no declarada: {v}")
    for r in plantilla.get("resources") or []:
        if r.get("type") != "Microsoft.Logic/workflows":
            continue
        definicion = r["properties"]["definition"]
        for texto in _cadenas(definicion):
            # ARM evalua "[...]" (empieza por '[' y acaba en ']'); "[[" es el escape
            if texto.startswith("[") and texto.endswith("]") and not texto.startswith("[["):
                errores.append(f"{r['name']}: cadena que ARM evaluaria como expresion: {texto[:60]}")
            if texto.startswith("[[") and not texto.endswith("]"):
                errores.append(f"{r['name']}: '[[' sin ']' final: ARM no lo desescapa: {texto[:60]}")
        errores += revisar(definicion, r["name"])
        declarados = set((definicion.get("parameters") or {}).keys())
        for p in (r["properties"].get("parameters") or {}):
            if p not in declarados:
                errores.append(f"{r['name']}: se pasa el parametro {p}, que la definicion no declara")
    return errores
