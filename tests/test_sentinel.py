"""
Microsoft Sentinel: plantillas ARM con los playbooks (Logic Apps), la regla
de automatizacion y el script de permisos.

Las definiciones se pasan por tests/wdl.py (estructura de WDL y de ARM) y
ademas se comprueba lo que hace cada playbook: que RL-Respuesta no contiene
nada si ContencionAutomatica no es true, que no hay secretos con valor por
defecto y que ninguna cadena de los workflows se evalua como expresion ARM.
"""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest
import wdl

from responselab.exportadores import sentinel

RAIZ = Path(__file__).resolve().parent.parent
SENTINEL = RAIZ / "soar" / "sentinel"
PLANTILLA = json.loads((SENTINEL / "playbooks.json").read_text(encoding="utf-8"))
AUTOMATIZACION = json.loads((SENTINEL / "automatizacion.json").read_text(encoding="utf-8"))
FLUJOS = {r["name"]: r for r in PLANTILLA["resources"] if r["type"] == "Microsoft.Logic/workflows"}
CONTENCION = {"mde_aislar", "mde_cuarentena", "graph_revocar", "graph_riesgo"}
CONDICION_ACTIVO = {"and": [{"equals": ["@parameters('ContencionAutomatica')", True]}]}
PWSH = Path("/opt/pwsh/pwsh") if Path("/opt/pwsh/pwsh").exists() else (Path(shutil.which("pwsh")) if shutil.which("pwsh") else None)


def cadenas(valor):
    """Todas las cadenas de un JSON, claves incluidas."""
    if isinstance(valor, str):
        yield valor
    elif isinstance(valor, dict):
        for k, v in valor.items():
            yield k
            yield from cadenas(v)
    elif isinstance(valor, list):
        for v in valor:
            yield from cadenas(v)


def acciones_con_ancestros(ambito: dict, ancestros=()):
    """(nombre, accion, [(nombre_padre, accion_padre, rama)]) de todo el arbol de acciones."""
    for nombre, accion in ambito.items():
        yield nombre, accion, list(ancestros)
        for rama, hijo in (("actions", accion.get("actions")), ("else", (accion.get("else") or {}).get("actions"))):
            if isinstance(hijo, dict):
                yield from acciones_con_ancestros(hijo, ancestros + ((nombre, accion, rama),))


def definicion(nombre: str) -> dict:
    return FLUJOS[nombre]["properties"]["definition"]


# === Lint de WDL y ARM =======================================================

def test_plantilla_de_playbooks_sin_errores():
    assert wdl.revisar_plantilla_arm(PLANTILLA) == []


def test_plantilla_de_automatizacion_sin_errores():
    assert wdl.revisar_plantilla_arm(AUTOMATIZACION) == []


@pytest.mark.parametrize("nombre", sorted(FLUJOS))
def test_cada_logic_app_pasa_el_lint(nombre):
    assert wdl.revisar(definicion(nombre), nombre) == []
    d = definicion(nombre)
    assert d["$schema"].endswith("/workflowdefinition.json#")
    assert list(d["triggers"]) == ["Microsoft_Sentinel_incident"]
    assert d["triggers"]["Microsoft_Sentinel_incident"]["inputs"]["path"] == "/incident-creation"


def test_el_lint_detecta_lo_que_romperia_un_despliegue():
    """Control del propio lint: una definicion rota no puede pasar."""
    roto = copy.deepcopy(definicion("RL-Aislar-equipo"))
    roto["actions"]["Comentar"]["runAfter"] = {"No_existe": ["Succeeded"]}
    roto["actions"]["Sin_declarar"] = {"type": "Compose", "inputs": "@parameters('NoDeclarado')",
                                       "runAfter": {"Comentar": ["Succeeded"]}}
    errores = wdl.revisar(roto, "roto")
    assert any("No_existe" in e for e in errores) and any("NoDeclarado" in e for e in errores)


def test_todos_los_playbooks_tienen_identidad_y_salida():
    assert set(FLUJOS) == set(sentinel.PERMISOS)
    for nombre, r in FLUJOS.items():
        assert r["identity"] == {"type": "SystemAssigned"}
        assert r["properties"]["state"] == "Enabled"
        conexion = r["properties"]["parameters"]["$connections"]["value"]["azuresentinel"]
        assert conexion["connectionProperties"]["authentication"]["type"] == "ManagedServiceIdentity"
        salida = PLANTILLA["outputs"][nombre.replace("-", "_")]
        assert f"'{nombre}'" in salida["value"] and salida["value"].endswith(".identity.principalId]")
        assert salida["condition"] == r.get("condition", True)
    assert FLUJOS["RL-Reenviar-al-motor"]["condition"] == "[parameters('DesplegarReenvio')]"


def test_cada_llamada_http_usa_la_identidad_con_su_audiencia():
    audiencias = {"parameters('ApiDefender')": sentinel.AUD_MDE, "graph.microsoft.com": sentinel.AUD_GRAPH,
                  "management.azure.com": sentinel.AUD_ARM}
    for nombre in FLUJOS:
        for accion_nombre, accion, _ in acciones_con_ancestros(definicion(nombre)["actions"]):
            if accion["type"] != "Http":
                continue
            entradas = accion["inputs"]
            if nombre == "RL-Reenviar-al-motor" and accion_nombre == "Enviar_al_motor":
                assert "authentication" not in entradas
                continue
            [audiencia] = [a for clave, a in audiencias.items() if clave in entradas["uri"]]
            assert entradas["authentication"] == {"type": "ManagedServiceIdentity", "audience": audiencia}, accion_nombre


# === RL-Respuesta: modo observacion por defecto ==============================

def test_contencion_automatica_es_false_por_defecto():
    d = definicion("RL-Respuesta")
    assert d["parameters"]["ContencionAutomatica"] == {"type": "Bool", "defaultValue": False}
    assert PLANTILLA["parameters"]["ContencionAutomatica"]["type"] == "bool"
    assert PLANTILLA["parameters"]["ContencionAutomatica"]["defaultValue"] is False
    assert FLUJOS["RL-Respuesta"]["properties"]["parameters"]["ContencionAutomatica"] == {
        "value": "[parameters('ContencionAutomatica')]"}


def test_ninguna_accion_de_contencion_se_ejecuta_sin_contencion_automatica():
    """Cada POST a Defender o a Graph cuelga de la rama 'true' de un If sobre ContencionAutomatica."""
    llamadas = 0
    for nombre, accion, ancestros in acciones_con_ancestros(definicion("RL-Respuesta")["actions"]):
        if accion["type"] != "Http" or accion["inputs"]["method"] != "POST":
            continue
        llamadas += 1
        guardas = [(n, rama) for n, a, rama in ancestros if a["type"] == "If" and a["expression"] == CONDICION_ACTIVO]
        assert guardas and all(rama == "actions" for _, rama in guardas), f"{nombre} se ejecuta sin ContencionAutomatica"
    assert llamadas == 5, "aislar, cuarentena, paquete, revocar y riesgo"


def test_en_modo_observacion_solo_se_anota():
    for nombre, accion, _ in acciones_con_ancestros(definicion("RL-Respuesta")["actions"]):
        if accion["type"] == "If" and accion["expression"] == CONDICION_ACTIVO:
            otra = (accion.get("else") or {}).get("actions") or {}
            assert otra, f"{nombre}: sin rama de observacion"
            assert {a["type"] for a in otra.values()} == {"AppendToArrayVariable"}
            assert all("Observacion" in a["inputs"]["value"] for a in otra.values())


def test_los_playbooks_de_aprobacion_no_dependen_de_contencion_automatica():
    """Los ejecuta una persona desde el incidente: esa ejecucion es la aprobacion."""
    for nombre in set(FLUJOS) - {"RL-Respuesta", "RL-Reenviar-al-motor"}:
        assert "ContencionAutomatica" not in json.dumps(definicion(nombre)), nombre


def test_tabla_de_reglas_de_rl_respuesta(catalogo_datos):
    d = definicion("RL-Respuesta")
    reglas = d["parameters"]["Reglas"]["defaultValue"]
    familias = d["parameters"]["Familias"]["defaultValue"]
    tipos = d["parameters"]["Tipos"]["defaultValue"]
    sigma = {r["titulo"].strip().lower() for r in catalogo_datos["reglas"] if str(r.get("tipo", "")).startswith("sigma")}
    assert set(reglas) == sigma, "en Sentinel estan exactamente las reglas Sigma"
    assert PLANTILLA["metadata"]["reglas_reconocidas"] == len(reglas)
    assert set(tipos) == set(sentinel.TIPOS)
    for clave, r in reglas.items():
        assert r["f"] in familias, clave
        assert r["w"] == sentinel.PESO_CLASE[r["c"]], clave
        assert r["a"] == sorted(r["a"]) and r["p"] == sorted(r["p"])
        assert set(r["a"]) <= set(sentinel.TIPOS) and set(r["p"]) <= set(sentinel.TIPOS)
        assert not set(r["a"]) & set(r["p"]), clave
        if r["c"] != "auto_contener":
            assert not set(r["a"]) & CONTENCION, f"{clave}: contencion automatica en clase {r['c']}"
    for nombre, f in familias.items():
        assert f["e"] in ("L1", "L2", "L3", "guardia") and isinstance(f["m"], int)
        assert 1 <= len(f["t"]) <= sentinel.MAX_TAREAS, nombre
        assert f["t"][0]["t"].startswith("Escalado:")
    # Lo mismo que sale de calcularlo ahora: la tabla no esta desfasada respecto del catalogo
    assert sentinel._datos(catalogo_datos) == (reglas, familias)


def test_cada_tipo_lleva_a_un_playbook_desplegado():
    for tipo, texto in definicion("RL-Respuesta")["parameters"]["Tipos"]["defaultValue"].items():
        assert texto.endswith(sentinel.TIPOS[tipo]["playbook"])
        assert sentinel.TIPOS[tipo]["playbook"] in FLUJOS


def test_la_regla_se_reconoce_por_el_nombre_de_las_alertas():
    pasos = definicion("RL-Respuesta")["actions"]
    assert "alertDisplayName" in pasos["Nombres_de_alertas"]["inputs"]["select"]
    assert "'dl - '" in pasos["Nombres_sin_prefijo"]["inputs"]["select"]
    assert pasos["Si_no_es_de_ResponseLab"]["actions"]["Terminar"]["inputs"] == {"runStatus": "Succeeded"}


# === Secretos ================================================================

def test_sin_secretos_con_valor_por_defecto():
    """Los parametros seguros no traen valor (vacio como mucho) y nada que parezca un secreto es texto plano."""
    for nombre, p in PLANTILLA["parameters"].items():
        if p["type"].lower() in ("securestring", "secureobject"):
            assert p.get("defaultValue") in (None, "", {}), nombre
        elif any(x in nombre.lower() for x in ("token", "secret", "password", "clave", "key")):
            pytest.fail(f"{nombre} parece un secreto y no es securestring")
    for flujo in FLUJOS:
        for nombre, p in (definicion(flujo).get("parameters") or {}).items():
            if p["type"].lower() in ("securestring", "secureobject"):
                assert p.get("defaultValue") in (None, "", {}), f"{flujo}.{nombre}"


def test_token_del_motor_es_seguro_y_no_queda_en_el_historial():
    assert PLANTILLA["parameters"]["TokenMotor"]["type"] == "securestring"
    d = definicion("RL-Reenviar-al-motor")
    assert d["parameters"]["TokenMotor"]["type"] == "SecureString"
    enviar = d["actions"]["Enviar_al_motor"]
    assert enviar["inputs"]["headers"]["Authorization"] == "Bearer @{parameters('TokenMotor')}"
    assert enviar["inputs"]["uri"] == "@{parameters('MotorUrl')}/v1/@{parameters('Cliente')}/alertas/sentinel"
    assert "inputs" in enviar["runtimeConfiguration"]["secureData"]["properties"]
    usos = [t for t in cadenas(d["actions"]) if "TokenMotor" in t]
    assert usos == ["Bearer @{parameters('TokenMotor')}"]
    assert "TokenMotor" not in json.dumps(PLANTILLA["outputs"])


# === Escape de corchetes =====================================================

@pytest.mark.parametrize("nombre", sorted(FLUJOS))
def test_ninguna_cadena_del_workflow_es_una_expresion_arm(nombre):
    for texto in cadenas(definicion(nombre)):
        if texto.startswith("[") and texto.endswith("]"):
            assert texto.startswith("[["), f"ARM evaluaria {texto[:60]!r}"
        if texto.startswith("[["):
            assert texto.endswith("]"), f"ARM no desescapa {texto[:60]!r}"


def test_escapar_arm():
    assert sentinel._escapar_arm("[Prueba]") == "[[Prueba]"
    assert sentinel._escapar_arm("[sin cierre") == "[sin cierre"
    assert sentinel._escapar_arm("sin apertura]") == "sin apertura]"
    assert sentinel._escapar_arm({"a": ["[x]", {"b": "[y]"}], "n": 3, "v": True}) == {"a": ["[[x]", {"b": "[[y]"}], "n": 3,
                                                                                       "v": True}
    assert sentinel._escapar_arm("@{x}") == "@{x}"


def test_titulo_de_regla_que_arm_tomaria_por_expresion(catalogo_datos):
    datos = copy.deepcopy(catalogo_datos)
    regla = next(r for r in datos["reglas"] if r.get("tipo") == "sigma")
    regla["titulo"] = "[Prueba]"
    with pytest.raises(ValueError, match="ARM tomaria por expresion"):
        sentinel.plantilla_playbooks(datos)


def test_tipo_de_sentinel_desconocido(catalogo_datos):
    datos = copy.deepcopy(catalogo_datos)
    datos["acciones"]["endpoint.aislar"]["soar"]["sentinel"]["tipo"] = "mde_formatear"
    with pytest.raises(ValueError, match="tipo de Sentinel desconocido"):
        sentinel.plantilla_playbooks(datos)


# === Regla de automatizacion =================================================

def test_regla_de_automatizacion():
    p = AUTOMATIZACION["parameters"]
    assert p["Modo"]["allowedValues"] == ["nativo", "motor"] and p["Modo"]["defaultValue"] == "nativo"
    assert "defaultValue" not in p["Workspace"], "el workspace no se adivina"
    eleccion = AUTOMATIZACION["variables"]["playbook"]
    assert "'RL-Reenviar-al-motor'" in eleccion and "'RL-Respuesta'" in eleccion
    assert {"RL-Reenviar-al-motor", "RL-Respuesta"} <= set(FLUJOS)
    [regla] = AUTOMATIZACION["resources"]
    assert regla["type"] == "Microsoft.SecurityInsights/automationRules"
    uuid.UUID(regla["name"])
    logica = regla["properties"]["triggeringLogic"]
    assert (logica["isEnabled"], logica["triggersOn"], logica["triggersWhen"]) == (True, "Incidents", "Created")
    [accion] = regla["properties"]["actions"]
    assert accion["actionType"] == "RunPlaybook"
    assert "variables('playbook')" in accion["actionConfiguration"]["logicAppResourceId"]


def test_plantillas_deterministas(catalogo_datos):
    assert sentinel.plantilla_playbooks(catalogo_datos) == PLANTILLA
    assert sentinel.plantilla_automatizacion() == AUTOMATIZACION


# === conceder-permisos.ps1 ===================================================

PS1 = SENTINEL / "conceder-permisos.ps1"


def test_permisos_ps1_crlf_y_ascii():
    datos = PS1.read_bytes()
    assert datos.isascii()
    assert b"\r\n" in datos and b"\n" not in datos.replace(b"\r\n", b"")


def test_permisos_ps1_cubre_cada_playbook():
    texto = PS1.read_bytes().decode("ascii")      # sin traducir CRLF
    for nombre, permisos in sentinel.PERMISOS.items():
        mde = ", ".join(f"'{x}'" for x in permisos.get("mde", []))
        graph = ", ".join(f"'{x}'" for x in permisos.get("graph", []))
        assert f"    '{nombre}' = @{{ mde = @({mde}); graph = @({graph}) }}\r\n" in texto
    # Cada playbook solo con lo que llama: el que no toca Defender no tiene permisos de Defender
    for nombre in FLUJOS:
        uris = " ".join(a["inputs"]["uri"] for _, a, _ in acciones_con_ancestros(definicion(nombre)["actions"])
                        if a["type"] == "Http")
        assert bool(sentinel.PERMISOS[nombre].get("mde")) == ("ApiDefender" in uris), nombre
        assert bool(sentinel.PERMISOS[nombre].get("graph")) == ("graph.microsoft.com" in uris), nombre


def test_permisos_ps1_se_analiza_sin_errores():
    if PWSH is None:
        pytest.skip("PowerShell (pwsh) no esta instalado")
    orden = ("$t = $null; $e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile("
             f"'{PS1}', [ref]$t, [ref]$e); $e | ForEach-Object {{ $_.ToString() }}; exit $e.Count")
    p = subprocess.run([str(PWSH), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", orden],
                       capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stdout + p.stderr
