"""
Cortex XSOAR: playbooks generados (grafo de tareas) y el script
ResponseLabDecidir ejecutado de verdad.

El script se ejecuta en este proceso con demistomock y CommonServerPython
falsos en sys.modules, alimentado con las alertas de escenarios/*.yml tal como
llegarian en el rawJSON del incidente. Su plan tiene que ser el mismo que da
nucleo.decidir con el catalogo completo: el catalogo compacto que lleva
incrustado no puede cambiar ninguna decision.
"""
from __future__ import annotations

import functools
import json
import sys
import types
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from responselab import nucleo, simulador
from responselab.exportadores import comun, xsoar

RAIZ = Path(__file__).resolve().parent.parent
XSOAR = RAIZ / "soar" / "xsoar"
FICHEROS_PLAYBOOK = sorted(XSOAR.glob("playbook-*.yml"))
TIPOS_TAREA = {"start", "regular", "condition", "playbook", "title"}
CLIENTE_XSOAR = dict(comun.CLIENTE_POR_DEFECTO, id="xsoar")
MOMENTO = datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)


@functools.lru_cache(maxsize=None)
def cargar_yaml(ruta: Path) -> dict:
    """Los playbooks son grandes: se leen una vez (las pruebas no los modifican)."""
    cargador = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    return yaml.load(ruta.read_text(encoding="utf-8"), Loader=cargador)


@pytest.fixture(scope="module")
def playbooks() -> dict[str, dict]:
    return {d["name"]: d for d in (cargar_yaml(f) for f in FICHEROS_PLAYBOOK)}


@pytest.fixture(scope="module")
def script() -> dict:
    return cargar_yaml(XSOAR / "script-ResponseLabDecidir.yml")


# === Grafo de los playbooks ==================================================

def test_un_playbook_por_familia_y_el_enrutador(catalogo_datos, playbooks):
    esperados = {f"ResponseLab - {comun.titulo_familia(f)}" for f in comun.familias(catalogo_datos)}
    assert set(playbooks) == esperados | {"ResponseLab - Enrutador"}
    for f in FICHEROS_PLAYBOOK:
        d = cargar_yaml(f)
        assert f.name == "playbook-" + d["name"].replace(" ", "_") + ".yml"
        assert d["id"] == d["name"] and d["version"] == -1 and d["fromversion"] == xsoar.VERSION_MINIMA


def _alcanzables(d: dict) -> set:
    vistos, pila = set(), [d["starttaskid"]]
    while pila:
        t = pila.pop()
        if t in vistos:
            continue
        vistos.add(t)
        for destinos in (d["tasks"][t].get("nexttasks") or {}).values():
            pila.extend(destinos)
    return vistos


@pytest.mark.parametrize("fichero", FICHEROS_PLAYBOOK, ids=[f.stem for f in FICHEROS_PLAYBOOK])
def test_grafo_del_playbook(fichero):
    d = cargar_yaml(fichero)
    tareas = d["tasks"]
    assert d["starttaskid"] in tareas and tareas[d["starttaskid"]]["type"] == "start"
    assert [t for t in tareas.values() if t["type"] == "start"] == [tareas[d["starttaskid"]]]
    ids = [t["taskid"] for t in tareas.values()]
    assert len(set(ids)) == len(ids), "taskid repetido"
    for clave, t in tareas.items():
        assert clave == t["id"], f"la tarea {clave} se llama {t['id']}"
        assert t["type"] in TIPOS_TAREA and t["task"]["type"] == t["type"]
        assert t["task"]["id"] == t["taskid"]
        posicion = json.loads(t["view"])["position"]
        assert isinstance(posicion["x"], int) and isinstance(posicion["y"], int)
        for etiqueta, destinos in (t.get("nexttasks") or {}).items():
            assert destinos, f"{clave}: rama {etiqueta} vacia"
            for x in destinos:
                assert x in tareas, f"{clave} -> {x}: la tarea no existe"
                assert x != clave, f"{clave} se llama a si misma"
    assert _alcanzables(d) == set(tareas), f"tareas inalcanzables: {sorted(set(tareas) - _alcanzables(d))}"
    finales = [k for k, t in tareas.items() if not t.get("nexttasks")]
    assert len(finales) == 1 and tareas[finales[0]]["type"] == "title", "un unico final ('Hecho')"


@pytest.mark.parametrize("fichero", FICHEROS_PLAYBOOK, ids=[f.stem for f in FICHEROS_PLAYBOOK])
def test_condiciones_con_sus_ramas(fichero):
    for clave, t in cargar_yaml(fichero)["tasks"].items():
        if t["type"] != "condition":
            assert "conditions" not in t, clave
            continue
        ramas = set(t.get("nexttasks") or {})
        etiquetas = [c["label"] for c in t.get("conditions") or []]
        if etiquetas:
            # condicion automatica: cada etiqueta tiene rama y hay rama por defecto
            assert len(set(etiquetas)) == len(etiquetas), clave
            assert set(etiquetas) <= ramas, f"{clave}: etiquetas sin rama {set(etiquetas) - ramas}"
            assert "#default#" in ramas, f"{clave}: condicion sin rama por defecto"
            assert ramas <= set(etiquetas) | {"#default#"}, f"{clave}: ramas sin condicion {ramas - set(etiquetas)}"
            for c in t["conditions"]:
                for grupo in c["condition"]:
                    for regla in grupo:
                        assert regla["operator"] == "isEqualString"
                        assert regla["left"]["iscontext"] is True
                        assert regla["left"]["value"]["simple"].startswith("ResponseLab.Plan.")
        else:
            # condicion manual (la decide el analista): Si / No
            assert ramas == {"Si", "No"}, f"{clave}: {ramas}"


@pytest.mark.parametrize("fichero", FICHEROS_PLAYBOOK, ids=[f.stem for f in FICHEROS_PLAYBOOK])
def test_tareas_de_comando_y_de_playbook(fichero):
    for clave, t in cargar_yaml(fichero)["tasks"].items():
        tarea = t["task"]
        if tarea.get("iscommand"):
            assert tarea["script"].startswith("|||") or tarea["script"] == "Builtin|||closeInvestigation", tarea["script"]
            assert len(tarea["script"]) > 3
        else:
            assert "script" not in tarea, f"{clave}: script sin iscommand"
        if t["type"] == "playbook":
            assert tarea["playbookName"] and tarea["name"] == tarea["playbookName"]
        for nombre, arg in (t.get("scriptarguments") or {}).items():
            assert set(arg) <= {"simple", "complex"}, (clave, nombre)
            if "complex" in arg:
                assert arg["complex"]["root"].startswith("ResponseLab.Plan.entradas.")


def test_el_enrutador_llama_a_playbooks_que_existen(playbooks, catalogo_datos):
    enrutador = playbooks["ResponseLab - Enrutador"]
    llamados = {t["task"]["playbookName"] for t in enrutador["tasks"].values() if t["type"] == "playbook"}
    assert llamados == set(playbooks) - {"ResponseLab - Enrutador"}
    # La condicion "Que playbook?" envia cada familia a su playbook y lo demas al generico
    [que] = [t for t in enrutador["tasks"].values() if t["task"]["name"] == "Que playbook?"]
    for etiqueta, [destino] in que["nexttasks"].items():
        nombre = enrutador["tasks"][destino]["task"]["playbookName"]
        familia = "_generico" if etiqueta == "#default#" else etiqueta
        assert familia in catalogo_datos["familias"]
        assert nombre == f"ResponseLab - {comun.titulo_familia(familia)}"
    [decidir] = [t for t in enrutador["tasks"].values() if t["task"]["name"] == "ResponseLabDecidir"]
    assert decidir["task"]["scriptName"] == "ResponseLabDecidir"
    assert {e["key"] for e in enrutador["inputs"]} == set(decidir["scriptarguments"]) == {"siem", "perfil"}


def test_el_enrutador_cierra_lo_descartado_y_lo_cerrado(playbooks):
    tareas = playbooks["ResponseLab - Enrutador"]["tasks"]
    [cond] = [t for t in tareas.values() if t["task"]["name"].startswith("Descartada o cerrada")]
    [[a, b]] = cond["conditions"][0]["condition"]   # un unico grupo O: descartada o cerrada_auto
    assert {a["right"]["value"]["simple"], b["right"]["value"]["simple"]} == set(xsoar.ESTADOS_CIERRE)
    [cerrar] = cond["nexttasks"]["yes"]
    assert tareas[cerrar]["task"]["script"] == "Builtin|||closeInvestigation"


def test_las_acciones_traducidas_se_ejecutan_solo_en_modo_automatico(catalogo_datos, playbooks):
    """En la fase 1 cada accion con traduccion nativa esta detras de su condicion 'automatica?'."""
    mapeo = xsoar._mapeo(catalogo_datos)
    for familia in comun.familias(catalogo_datos):
        tareas = playbooks[f"ResponseLab - {comun.titulo_familia(familia)}"]["tasks"]
        f = catalogo_datos["familias"][familia]
        pasos = [(f"c{i}", c.get("accion")) for i, c in enumerate(f.get("contencion") or [], 1)]
        pasos += [(f"e{j}", e["accion"]) for j, e in enumerate(f.get("evidencia_automatica") or [], 1)]
        nativos = [p for p, a in pasos if a in mapeo]
        condiciones = [t for t in tareas.values() if t["type"] == "condition" and t["task"]["name"].endswith("- automatica?")]
        assert sorted(t["task"]["name"].split(":")[0] for t in condiciones) == sorted(nativos), familia
        for t in condiciones:
            paso = t["task"]["name"].split(":")[0]
            [[regla]] = t["conditions"][0]["condition"]
            assert regla["left"]["value"]["simple"] == f"ResponseLab.Plan.modos.{paso}"
            assert regla["right"]["value"]["simple"] == "automatica"
            [ejecutar] = t["nexttasks"]["yes"]
            assert tareas[ejecutar]["type"] in ("playbook", "regular")
            assert tareas[ejecutar].get("continueonerror") is True


def test_lista_de_cliente_de_ejemplo():
    lista = json.loads((XSOAR / "lista-ResponseLab_Cliente.json").read_text(encoding="utf-8"))
    assert set(lista["politica"]) == set(comun.CLIENTE_POR_DEFECTO["politica"])
    assert lista["inventario"]["completo"] is False
    assert lista["listas"] == {"aplicaciones_negocio": []}


# === Script ResponseLabDecidir ===============================================

def test_metadatos_del_script(script):
    assert script["commonfields"] == {"id": "ResponseLabDecidir", "version": -1}
    assert script["name"] == "ResponseLabDecidir"
    assert (script["type"], script["subtype"]) == ("python", "python3")
    assert {a["name"] for a in script["args"]} == {"siem", "perfil", "ajustar_severidad"}
    assert {o["contextPath"] for o in script["outputs"]} == {f"ResponseLab.Plan.{k}" for k, _, _ in xsoar.SALIDAS}
    compile(script["script"], "ResponseLabDecidir.py", "exec")


def test_el_script_lleva_el_nucleo_y_el_catalogo_actuales(script, catalogo_datos):
    assert f"desde el catalogo {catalogo_datos['version']}" in script["script"]
    assert json.dumps(comun.codigo_nucleo(), ensure_ascii=True) in script["script"]


class Demisto(types.ModuleType):
    """demistomock: el incidente, los argumentos y executeCommand con listas."""

    def __init__(self, incidente: dict, argumentos: dict, listas: dict):
        super().__init__("demistomock")
        self._incidente, self._argumentos, self._listas = incidente, argumentos, listas
        self.comandos: list[tuple] = []
        self.depuracion: list[str] = []

    def incident(self):
        return self._incidente

    def args(self):
        return dict(self._argumentos)

    def executeCommand(self, comando, argumentos):  # noqa: N802 (API de XSOAR)
        self.comandos.append((comando, argumentos))
        if comando == "getList":
            valor = self._listas.get(argumentos["listName"])
            if isinstance(valor, Exception):
                raise valor
            if valor is None:
                return [{"Type": 4, "Contents": "Item not found (8)"}]
            return [{"Type": 1, "Contents": valor}]
        return [{"Type": 1, "Contents": "done"}]

    def debug(self, mensaje):
        self.depuracion.append(mensaje)


class Salida:
    def __init__(self):
        self.resultados, self.errores = [], []


def common_server_python(salida: Salida) -> types.ModuleType:
    m = types.ModuleType("CommonServerPython")

    class CommandResults:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    def is_error(respuesta):
        return isinstance(respuesta, list) and any(isinstance(e, dict) and e.get("Type") == 4 for e in respuesta)

    m.CommandResults = CommandResults
    m.is_error = is_error
    m.return_results = salida.resultados.append
    m.return_error = salida.errores.append
    m.__all__ = ["CommandResults", "is_error", "return_results", "return_error"]
    return m


def ejecutar_script(monkeypatch, codigo: str, incidente: dict, argumentos=None, listas=None):
    demisto = Demisto(incidente, {"siem": "auto", "perfil": "ResponseLab_Cliente", "ajustar_severidad": "true",
                                  **(argumentos or {})}, listas or {})
    salida = Salida()
    monkeypatch.setitem(sys.modules, "demistomock", demisto)
    monkeypatch.setitem(sys.modules, "CommonServerPython", common_server_python(salida))
    exec(compile(codigo, "ResponseLabDecidir.py", "exec"), {"__name__": "__main__"})
    assert salida.errores == [], salida.errores
    [resultado] = salida.resultados
    return demisto, resultado


def alertas_de_escenarios() -> list:
    casos = []
    for esc in simulador.cargar():
        for n, a in enumerate(esc["alertas"], 1):
            carga = simulador.preparar(a["siem"], a["carga"], MOMENTO, f"{esc['id']}-{n}")
            casos.append(pytest.param(a["siem"], carga, id=f"{esc['id']}-{n}-{a['siem']}"))
    return casos


def plan_esperado(siem: str, carga: dict, catalogo, cliente: dict) -> dict:
    return nucleo.decidir(nucleo.normalizar(siem, carga, cliente.get("id", "xsoar")), catalogo, cliente, {})


@pytest.mark.parametrize("siem,carga", alertas_de_escenarios())
def test_script_decide_lo_mismo_que_el_nucleo(monkeypatch, script, catalogo, siem, carga):
    incidente = {"id": "4242", "name": "incidente de prueba", "rawJSON": json.dumps(carga)}
    demisto, r = ejecutar_script(monkeypatch, script["script"], incidente)
    plan = plan_esperado(siem, carga, catalogo, CLIENTE_XSOAR)
    salida = r.outputs
    assert r.outputs_prefix == "ResponseLab.Plan" and r.outputs_key_field == "alerta_id"
    assert salida["siem"] == siem, "el rawJSON no se reconoce como alerta de su SIEM"
    for clave in ("alerta_id", "familia", "clase", "estado", "severidad", "playbook", "crear_caso", "notificar"):
        assert salida[clave] == plan[clave], clave
    assert salida["regla"] == plan["regla"]["titulo"]
    assert salida["regla_conocida"] == plan["regla"]["conocida"]
    assert salida["modos"] == {p["id"]: p["modo"] for p in plan["acciones"]}
    # nota_plazo es prosa que el catalogo compacto no lleva; el resto del escalado es decision
    sin_nota = {k: v for k, v in plan["escalado"].items() if k != "nota_plazo"}
    assert {k: v for k, v in salida["escalado"].items() if k != "nota_plazo"} == sin_nota
    assert [a["id"] for a in salida["acciones"]] == [p["id"] for p in plan["acciones"]]
    assert set(salida["entradas"]) <= set(salida["modos"])
    assert "### ResponseLab" in r.readable_output and "Escalar a" in r.readable_output
    # sin lista de cliente: el perfil prudente, y la severidad del incidente solo se toca si sigue en curso
    assert demisto.comandos[0] == ("getList", {"listName": "ResponseLab_Cliente"})
    ajustes = [a for c, a in demisto.comandos if c == "setIncident"]
    assert ajustes == ([{"severity": plan["severidad"]}] if plan["estado"] == "en_curso" else [])


def _carga_ransomware(n: int = 2) -> tuple[str, dict]:
    [esc] = simulador.cargar(nombres=["ransomware-puesto"])
    a = esc["alertas"][n - 1]
    return a["siem"], simulador.preparar(a["siem"], a["carga"], MOMENTO, f"rw-{n}")


def test_script_usa_el_perfil_de_la_lista(monkeypatch, script, catalogo, perfil_lab):
    siem, carga = _carga_ransomware(2)
    perfil = dict(perfil_lab, politica=dict(perfil_lab.get("politica") or {}, contencion_automatica=False))
    demisto, r = ejecutar_script(monkeypatch, script["script"], {"id": "1", "rawJSON": json.dumps(carga)},
                                 argumentos={"perfil": "Perfil_Lab"}, listas={"Perfil_Lab": json.dumps(perfil)})
    plan = plan_esperado(siem, carga, catalogo, perfil)
    assert r.outputs["modos"] == {p["id"]: p["modo"] for p in plan["acciones"]}
    contencion = [a for a in r.outputs["acciones"] if a["accion"] and not a["accion"].startswith(("evidencia.", "caso."))]
    assert contencion and all(a["modo"] != "automatica" for a in contencion), "el cliente no admite contencion automatica"


@pytest.mark.parametrize("listas", [{}, {"ResponseLab_Cliente": "{no es json"}, {"ResponseLab_Cliente": "[1, 2]"},
                                    {"ResponseLab_Cliente": ""}, {"ResponseLab_Cliente": RuntimeError("sin permisos")}],
                         ids=["sin-lista", "json-roto", "no-es-objeto", "vacia", "excepcion"])
def test_script_sin_perfil_valido_usa_el_prudente(monkeypatch, script, catalogo, listas):
    siem, carga = _carga_ransomware(2)
    _, r = ejecutar_script(monkeypatch, script["script"], {"id": "1", "rawJSON": json.dumps(carga)}, listas=listas)
    plan = plan_esperado(siem, carga, catalogo, CLIENTE_XSOAR)
    assert r.outputs["modos"] == {p["id"]: p["modo"] for p in plan["acciones"]}


def test_script_resuelve_las_entradas_de_cada_paso(monkeypatch, script, catalogo_datos):
    siem, carga = _carga_ransomware(2)
    _, r = ejecutar_script(monkeypatch, script["script"], {"id": "1", "rawJSON": json.dumps(carga)})
    mapeo = xsoar._mapeo(catalogo_datos)
    alerta = r.outputs["alerta"]
    for a in r.outputs["acciones"]:
        if a["accion"] not in mapeo:
            assert a["id"] not in r.outputs["entradas"]
            continue
        entradas = r.outputs["entradas"][a["id"]]
        assert set(entradas) == set(mapeo[a["accion"]]["entradas"])
        for nombre, origen in mapeo[a["accion"]]["entradas"].items():
            if "." in origen and " " not in origen:
                valores = [nucleo.leer(alerta, x.strip()) for x in origen.split("|")]
                esperado = next((v for v in valores if v not in (None, "")), "")
                assert entradas[nombre] == (json.dumps(esperado) if isinstance(esperado, (dict, list)) else esperado)
            else:
                assert entradas[nombre] == origen, "sin punto es una constante"


def test_script_sin_ajustar_la_severidad(monkeypatch, script):
    _, carga = _carga_ransomware(2)
    demisto, _ = ejecutar_script(monkeypatch, script["script"], {"id": "1", "rawJSON": json.dumps(carga)},
                                 argumentos={"ajustar_severidad": "false"})
    assert [c for c, _ in demisto.comandos] == ["getList"]


def test_script_con_el_siem_forzado(monkeypatch, script, catalogo):
    _, carga = _carga_ransomware(2)
    _, r = ejecutar_script(monkeypatch, script["script"], {"id": "1", "rawJSON": json.dumps(carga)},
                           argumentos={"siem": "generico"})
    assert r.outputs["siem"] == "generico"
    assert r.outputs["regla_conocida"] is False and r.outputs["familia"] == "_generico"


def test_script_sin_rawjson_usa_los_campos_del_incidente(monkeypatch, script, catalogo):
    regla = next(r for r in catalogo.reglas if r.get("splunk") and r["familia"] == "ad")
    incidente = {"id": "77", "name": regla["splunk"], "occurred": "2026-10-01T10:00:00Z",
                 "labels": [{"type": "hostname", "value": "DC01"}, {"type": "rule_name", "value": regla["splunk"]}],
                 "CustomFields": {"username": "LAB\\mruiz", "sourceip": "10.0.20.7"}}
    _, r = ejecutar_script(monkeypatch, script["script"], incidente)
    assert r.outputs["siem"] == "generico"
    assert r.outputs["alerta_id"] == "77"
    assert r.outputs["regla_conocida"] is True and r.outputs["familia"] == "ad"
    assert r.outputs["alerta"]["equipo"]["nombre"] == "DC01"
    assert r.outputs["alerta"]["usuario"]["nombre"] == "mruiz"


def test_script_regla_de_correlacion_se_descarta_sin_tocar_la_severidad(monkeypatch, script, catalogo):
    regla = next(r for r in catalogo.reglas if r["clase"] == "auto_cierre" and r.get("wazuh_ids"))
    carga = {"id": "1.2", "timestamp": "2026-10-01T10:00:00.000+0000", "agent": {"id": "1", "name": "PC-1"},
             "rule": {"id": str(regla["wazuh_ids"][0]), "level": 3, "description": regla["titulo"], "groups": []}}
    demisto, r = ejecutar_script(monkeypatch, script["script"], {"id": "1", "rawJSON": json.dumps(carga)})
    assert r.outputs["estado"] == "descartada" and r.outputs["clase"] == "auto_cierre"
    assert "setIncident" not in [c for c, _ in demisto.comandos]


def test_script_informa_del_error_en_vez_de_romper(monkeypatch, script):
    demisto = Demisto({"id": "1", "rawJSON": "{}"}, {"siem": "qradar"}, {})
    salida = Salida()
    monkeypatch.setitem(sys.modules, "demistomock", demisto)
    monkeypatch.setitem(sys.modules, "CommonServerPython", common_server_python(salida))
    exec(compile(script["script"], "ResponseLabDecidir.py", "exec"), {"__name__": "__main__"})
    assert salida.resultados == []
    assert len(salida.errores) == 1 and "SIEM no soportado" in salida.errores[0]


@pytest.mark.parametrize("carga,siem", [
    ({"rule": {"id": "1"}, "agent": {"name": "x"}}, "wazuh"),
    ({"object": {"properties": {"incidentNumber": 3}}}, "sentinel"),
    ({"properties": {"relatedEntities": []}}, "sentinel"),
    ({"search_name": "x", "result": {}}, "splunk"),
    ({"result": {}, "sid": "1"}, "splunk"),
    ({"kibana.alert.rule.name": "x"}, "elastic"),
    ({"alerts": [{}], "rule": {}}, "elastic"),
    ({"titulo": "x"}, "generico"),
    ("no es un objeto", "generico"),
])
def test_deteccion_del_siem(monkeypatch, script, carga, siem):
    monkeypatch.setitem(sys.modules, "demistomock", Demisto({}, {}, {}))
    monkeypatch.setitem(sys.modules, "CommonServerPython", common_server_python(Salida()))
    ns = {"__name__": "ResponseLabDecidir"}
    exec(compile(script["script"], "ResponseLabDecidir.py", "exec"), ns)
    assert ns["detectar_siem"](carga) == siem
