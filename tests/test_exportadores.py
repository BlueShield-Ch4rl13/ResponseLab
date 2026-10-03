"""
Exportadores: lo que genera tools/compilar.py para cada SOAR y SIEM.

Se genera todo una vez por sesion (generar_todo tarda unos segundos) y se
comprueba que es determinista, que coincide con lo commiteado y que cada
artefacto es valido en su plataforma: JSON y YAML que cargan, Python que
compila y se ejecuta con modulos falsos (phantom en Splunk SOAR), XML que
Wazuh puede leer y configuracion de Splunk con su lista de webhooks.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import re
import shutil
import subprocess
import sys
import types
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from responselab import nucleo, simulador
from responselab.exportadores import EXPORTADORES, comun, exportar_todo, shuffle, siem

RAIZ = Path(__file__).resolve().parent.parent
MAX_ETIQUETA_WAZUH = 20480
CLIENTE_SOAR = dict(comun.CLIENTE_POR_DEFECTO, id="soar")
MOMENTO = datetime(2026, 10, 1, 10, 0, tzinfo=timezone.utc)


def cargar_herramienta(nombre: str):
    spec = importlib.util.spec_from_file_location(f"rl_herramienta_{nombre}_{uuid.uuid4().hex}", RAIZ / "tools" / f"{nombre}.py")
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


@pytest.fixture(scope="session")
def generacion():
    salidas, avisos = cargar_herramienta("compilar").generar_todo()
    return salidas, avisos


@pytest.fixture(scope="session")
def generado(generacion) -> dict[str, str]:
    return generacion[0]


def esperados(catalogo: dict) -> set[str]:
    fams = comun.familias(catalogo)
    rutas = {"catalogo/catalogo.json", "docs/COBERTURA.md", "soar/n8n/responselab.json",
             "soar/shuffle/workflow-responselab.json", "soar/shuffle/nodos/responselab.py", "soar/shuffle/nodos/limpiar.py",
             "soar/sentinel/playbooks.json", "soar/sentinel/automatizacion.json", "soar/sentinel/conceder-permisos.ps1",
             "soar/splunk-soar/responselab_enrutador.py", "soar/xsoar/script-ResponseLabDecidir.yml",
             "soar/xsoar/playbook-ResponseLab_-_Enrutador.yml", "soar/xsoar/lista-ResponseLab_Cliente.json",
             "siem/wazuh/ossec-responselab.conf", "siem/elastic/reglas-responselab.json",
             "siem/splunk/savedsearches-detectionlab.conf", "siem/splunk/savedsearches-splunklab.conf"}
    for f in fams:
        rutas.add(f"soar/thehive/plantillas/{f}.json")
        rutas.add(f"soar/splunk-soar/responselab_{f.lstrip('_')}.py")
        rutas.add(f"soar/xsoar/playbook-ResponseLab_-_{comun.titulo_familia(f)}.yml")
    return rutas


# === Generacion ==============================================================

def test_genera_los_65_ficheros_esperados(generado, catalogo_datos):
    assert len(generado) == 65
    assert set(generado) == esperados(catalogo_datos)
    assert all(isinstance(v, str) and v for v in generado.values())


def test_avisos_de_compilacion(generacion):
    _, avisos = generacion
    assert isinstance(avisos, list) and all(isinstance(a, str) for a in avisos)


def test_generacion_determinista(generado):
    otra, _ = cargar_herramienta("compilar").generar_todo()
    assert otra.keys() == generado.keys()
    distintos = [k for k in generado if otra[k] != generado[k]]
    assert distintos == []


def test_lo_generado_coincide_con_lo_commiteado(generado):
    distintos = []
    for rel, contenido in generado.items():
        with open(RAIZ / rel, encoding="utf-8", newline="") as f:     # sin traducir CRLF
            if f.read() != contenido:
                distintos.append(rel)
    assert distintos == [], "ejecuta python tools/compilar.py"


def test_compilar_comprobar_sale_con_0():
    p = subprocess.run([sys.executable, str(RAIZ / "tools" / "compilar.py"), "--comprobar"], capture_output=True,
                       text=True, timeout=120, cwd=str(RAIZ))
    assert p.returncode == 0, p.stdout + p.stderr
    assert "Todo lo generado esta al dia (65 ficheros)" in p.stdout


def test_cada_exportador_escribe_sus_propios_ficheros(catalogo_datos, generado):
    vistos: dict[str, str] = {}
    for nombre in EXPORTADORES:
        modulo = importlib.import_module(f"responselab.exportadores.{nombre}")
        for rel in modulo.exportar(catalogo_datos):
            assert rel not in vistos, f"{rel} lo generan {vistos[rel]} y {nombre}"
            vistos[rel] = nombre
    assert vistos.keys() == exportar_todo(catalogo_datos).keys()
    assert set(vistos) | {"catalogo/catalogo.json", "docs/COBERTURA.md"} == set(generado)


def test_finales_de_linea(generado):
    for rel, contenido in generado.items():
        if rel.endswith(".ps1"):
            assert "\r\n" in contenido and "\n" not in contenido.replace("\r\n", ""), rel
        else:
            assert "\r" not in contenido, rel
            assert contenido.endswith("\n"), rel


@pytest.mark.parametrize("extension", [".json", ".yml", ".py"])
def test_cada_fichero_carga_en_su_formato(generado, extension):
    ficheros = {k: v for k, v in generado.items() if k.endswith(extension)}
    assert ficheros
    for rel, contenido in ficheros.items():
        if extension == ".json":
            json.loads(contenido)
        elif extension == ".yml":
            yaml.load(contenido, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))
        else:
            compile(contenido, rel, "exec")


def test_lo_generado_en_siem_lleva_la_marca(generado):
    """compilar.py solo borra de siem/ lo que lleva la marca en los primeros 400 caracteres."""
    for rel, contenido in generado.items():
        if rel.startswith("siem/"):
            assert "Generado por ResponseLab (tools/compilar.py)" in contenido[:400], rel


def test_catalogo_generado(generado, catalogo_datos):
    assert json.loads(generado["catalogo/catalogo.json"]) == catalogo_datos


# === Utilidades comunes ======================================================

def test_uid_determinista():
    assert comun.uid("xsoar", "pb", 1) == comun.uid("xsoar", "pb", "1")
    assert comun.uid("a") != comun.uid("b")
    assert uuid.UUID(comun.uid("a")).version == 5


def test_familias_en_orden_y_titulos(catalogo_datos):
    fams = comun.familias(catalogo_datos)
    assert sorted(fams) == sorted(catalogo_datos["familias"])
    assert fams[-1] == "_generico"
    assert [comun.titulo_familia(f) for f in ("ad", "_generico", "xdr", "zta", "red")] == ["AD", "Generico", "XDR", "ZTA", "Red"]
    assert comun.slug("Exfiltraci\u00f3n de datos!") == "exfiltracion_de_datos"


def test_compacto_quita_la_prosa_y_conserva_la_decision(catalogo_datos):
    c = comun.compacto(catalogo_datos, texto=False)
    for f in c["familias"].values():
        assert all("nota" not in t for t in f["triaje"])
        assert all("justificacion" not in x for x in f["contencion"])
    usadas = {x["accion"] for f in c["familias"].values() for x in f["contencion"] if x.get("accion")}
    assert usadas <= set(c["acciones"])
    con_texto = comun.compacto(catalogo_datos)
    assert all("justificacion" in x for f in con_texto["familias"].values() for x in f["contencion"])
    solo = comun.compacto(catalogo_datos, solo=["endpoint"])
    assert set(solo["familias"]) == {"endpoint", "_generico"}
    assert {r["familia"] for r in solo["reglas"]} == {"endpoint"}


# === TheHive =================================================================

GRUPOS = ["1. Evidencia", "2. Triaje", "3. Contencion", "4. Cierre", "5. Requiere persona", "6. Escalado"]


def test_plantillas_de_thehive(generado, catalogo_datos):
    for familia, f in catalogo_datos["familias"].items():
        p = json.loads(generado[f"soar/thehive/plantillas/{familia}.json"])
        assert p["name"] == f["plantilla_caso"]
        assert p["titlePrefix"] == f"[RL {comun.titulo_familia(familia)}]"
        assert f"rl:familia={familia}" in p["tags"] and "responselab" in p["tags"]
        assert p["customFields"] == [], "los campos que el SOC anada en TheHive no se pisan"
        tareas = p["tasks"]
        assert [t["order"] for t in tareas] == list(range(len(tareas)))
        grupos = [t["group"] for t in tareas]
        assert grupos == sorted(grupos, key=GRUPOS.index), "las fases van en orden"
        assert grupos.count("6. Escalado") == 1 and grupos[-1] == "6. Escalado"
        assert grupos.count("3. Contencion") == len(f.get("contencion") or [])
        assert grupos.count("2. Triaje") == len(f.get("triaje") or [])
        for t in tareas:
            assert 0 < len(t["title"]) <= 250 and len(t["description"]) <= 4000
            assert t["mandatory"] is False and t["flag"] is False


# === Shuffle =================================================================

def ejecutar_nodo(codigo: str) -> dict:
    salida = io.StringIO()
    with contextlib.redirect_stdout(salida):
        exec(compile(codigo, "nodo-shuffle", "exec"), {"__name__": "__main__"})
    return json.loads(salida.getvalue())


def sustituir(texto: str, variables: dict) -> str:
    """Lo que hace Shuffle con $nodo.campo: sustitucion de texto."""
    return re.sub(r"\$([a-z_]+(?:\.[A-Za-z_]+)*)", lambda m: str(variables.get(m.group(1), m.group(0))), texto)


def plan_ransomware() -> tuple[dict, dict]:
    [esc] = simulador.cargar(nombres=["ransomware-puesto"])
    a = esc["alertas"][1]
    carga = simulador.preparar(a["siem"], a["carga"], MOMENTO, "rw-2")
    alerta = nucleo.normalizar(a["siem"], carga, "lab")
    return alerta, nucleo.decidir(alerta, nucleo.Catalogo(json.loads((RAIZ / "catalogo" / "catalogo.json").read_text(
        encoding="utf-8"))), comun.CLIENTE_POR_DEFECTO, {})


def test_workflow_de_shuffle(generado):
    wf = json.loads(generado["soar/shuffle/workflow-responselab.json"])
    acciones = {a["id"]: a for a in wf["actions"]}
    etiquetas = {a["label"]: a["id"] for a in wf["actions"]}
    assert len(acciones) == len(wf["actions"])
    [disparador] = wf["triggers"]
    assert disparador["trigger_type"] == "WEBHOOK"
    assert wf["start"] == etiquetas["DECIDIR"] and acciones[wf["start"]]["isStartNode"] is True
    for rama in wf["branches"]:
        assert rama["source_id"] in acciones or rama["source_id"] == disparador["id"]
        assert rama["destination_id"] in acciones
    # cada nodo es alcanzable desde el webhook
    vistos, pila = set(), [disparador["id"]]
    while pila:
        x = pila.pop()
        if x not in vistos:
            vistos.add(x)
            pila += [r["destination_id"] for r in wf["branches"] if r["source_id"] == x]
    assert set(acciones) <= vistos
    # las condiciones preguntan por campos que el nodo RESPONSELAB produce
    _, plan = plan_ransomware()
    campos = set(ejecutar_nodo(shuffle.CODIGO_RESPONSELAB.replace("$decidir", "{}")))
    for rama in wf["branches"]:
        for c in rama["conditions"]:
            fuente = c["source"]["value"]
            assert fuente.startswith("$responselab.") and fuente.split(".", 1)[1] in campos
    variables = {v["name"] for v in wf["workflow_variables"]}
    usadas = set(re.findall(r"\$(motor_url|cliente|token_motor|ollama_url)\b", json.dumps(wf)))
    assert usadas <= variables


def test_nodos_de_shuffle_publicados_aparte(generado):
    assert generado["soar/shuffle/nodos/responselab.py"] == shuffle.CODIGO_RESPONSELAB
    assert generado["soar/shuffle/nodos/limpiar.py"] == shuffle.CODIGO_LIMPIAR
    wf = json.loads(generado["soar/shuffle/workflow-responselab.json"])
    codigos = {a["label"]: p["value"] for a in wf["actions"] for p in a["parameters"] if p["name"] == "code"}
    assert codigos == {"RESPONSELAB": shuffle.CODIGO_RESPONSELAB, "LIMPIAR": shuffle.CODIGO_LIMPIAR}


def test_nodo_responselab_sin_decision_usa_valores_prudentes():
    s = ejecutar_nodo(shuffle.CODIGO_RESPONSELAB)          # $decidir sin sustituir
    assert s["familia"] == "_generico" and s["crear_caso"] is False and s["hay_contencion"] is False
    assert s["notificar"] is False and s["usar_llm"] is False


def test_nodo_responselab_y_cuerpos_json_de_thehive_y_discord(generado):
    """Lo que sale del nodo cabe en los cuerpos JSON de aguas abajo aunque lleve comillas y saltos de linea."""
    plan = {"familia": "correo", "clase": "auto_contener", "severidad": 4, "estado": "en_curso", "crear_caso": True,
            "notificar": True, "usar_llm": True, "plantilla_caso": "ResponseLab - correo",
            "regla": {"titulo": 'Regla con "comillas" y\nsalto'}, "resumen": 'resumen "citado"',
            "acciones": [{"modo": "automatica", "nombre": "Retirar el mensaje", "motivo": "radio objeto"},
                         {"modo": "aprobacion", "nombre": "Bloquear remitente", "motivo": "radio organizacion"}],
            "triaje": [{"resultado": "pendiente", "pregunta": "Otros buzones?"}],
            "escalado": {"a": "L3", "plazo_min": 15}}
    # Shuffle sustituye $decidir por el JSON tal cual: el nodo lo lee en una cadena r"""..."""
    texto = json.dumps({"status": 200, "body": plan})
    s = ejecutar_nodo(shuffle.CODIGO_RESPONSELAB.replace("$decidir", texto))
    assert (s["familia"], s["clase"], s["severidad"]) == ("correo", "auto_contener", 4)
    assert s["crear_caso"] and s["notificar"] and s["usar_llm"] and s["hay_contencion"]
    assert s["automaticas_json"] == "Retirar el mensaje" and s["en_espera_json"] == "Bloquear remitente"
    assert (s["escalar_a"], s["plazo_min"], s["color"]) == ("L3", 15, 15158332)
    limpio = ejecutar_nodo(shuffle.CODIGO_LIMPIAR.replace("$ollama.body.response", "**Aislar** el `equipo`\n\nya"))
    variables = {f"responselab.{k}": v for k, v in s.items()} | {"exec.id": "a1", "limpiar.mensaje_json": limpio["mensaje_json"]}
    wf = json.loads(generado["soar/shuffle/workflow-responselab.json"])
    cuerpos = {a["label"]: p["value"] for a in wf["actions"] for p in a["parameters"] if p["name"] == "body"}
    alerta_th = json.loads(sustituir(cuerpos["ALERTA"], variables))
    assert alerta_th["title"] == '[correo] Regla con "comillas" y\nsalto'
    assert alerta_th["severity"] == 4 and alerta_th["caseTemplate"] == "ResponseLab - correo"
    discord = json.loads(sustituir(cuerpos["DISCORD"], variables))
    assert discord["embeds"][0]["color"] == 15158332
    assert discord["embeds"][0]["fields"][-1]["value"] == "Aislar el equipo ya"


@pytest.mark.parametrize("caso", ["ruta_de_windows", "comillas"])
def test_nodo_responselab_con_escapes_json(caso):
    alerta, plan = plan_ransomware()
    if caso == "comillas":
        plan = json.loads(json.dumps(plan).replace("\\\\", "/"))
        plan["regla"]["titulo"] = 'Ejecucion de "vssadmin" con\nborrado de copias'
    texto = json.dumps({"status": 200, "body": plan})
    assert "\\" in texto, "el JSON del plan lleva escapes"
    s = ejecutar_nodo(shuffle.CODIGO_RESPONSELAB.replace("$decidir", texto))
    assert s["familia"] == plan["familia"] == "endpoint"
    assert s["crear_caso"] is True and s["hay_contencion"] is True


# === n8n =====================================================================

def test_workflow_de_n8n(generado):
    wf = json.loads(generado["soar/n8n/responselab.json"])
    nodos = {n["name"]: n for n in wf["nodes"]}
    assert len(nodos) == len(wf["nodes"]) and len({n["id"] for n in wf["nodes"]}) == len(nodos)
    for origen, salidas in wf["connections"].items():
        assert origen in nodos
        for grupo in salidas["main"]:
            for destino in grupo:
                assert destino["node"] in nodos and destino["type"] == "main"
    destinos = {d["node"] for s in wf["connections"].values() for g in s["main"] for d in g}
    assert destinos | {"Webhook"} == set(nodos), "nodos sueltos"
    referencias = set(re.findall(r"\$\('([^']+)'\)", json.dumps(wf)))
    assert referencias <= set(nodos)
    for n in wf["nodes"]:
        if n["type"] == "n8n-nodes-base.httpRequest" and "credentials" in n:
            assert n["credentials"]["httpHeaderAuth"]["name"] in ("ResponseLab motor", "TheHive")
            assert n["credentials"]["httpHeaderAuth"]["id"] == "", "sin ids de credenciales de otra instancia"
    assert wf["active"] is False
    assert "/v1/{{ $json.cliente }}/decidir/{{ $json.siem }}" in nodos["Decidir"]["parameters"]["url"]


def test_codigo_javascript_de_n8n_es_valido(generado, tmp_path):
    node = shutil.which("node") or ("/opt/node22/bin/node" if Path("/opt/node22/bin/node").exists() else None)
    if node is None:
        pytest.skip("Node.js no esta instalado: no se puede comprobar la sintaxis de los nodos Code")
    wf = json.loads(generado["soar/n8n/responselab.json"])
    for n in wf["nodes"]:
        if n["type"] != "n8n-nodes-base.code":
            continue
        fichero = tmp_path / f"{n['name']}.js"
        # n8n ejecuta el codigo como cuerpo de una funcion asincrona
        fichero.write_text("async function nodo($input, $) {\n" + n["parameters"]["jsCode"] + "\n}\n", encoding="utf-8")
        p = subprocess.run([node, "--check", str(fichero)], capture_output=True, text=True, timeout=60)
        assert p.returncode == 0, f"{n['name']}: {p.stderr}"


# === Splunk SOAR =============================================================

class Phantom(types.ModuleType):
    """phantom.rules: apunta cada llamada; collect2 devuelve las filas que se le den."""

    def __init__(self, artefactos=None, respuestas=None):
        super().__init__("phantom.rules")
        self.llamadas: list[tuple[str, dict]] = []
        self.artefactos = artefactos or []
        self.respuestas = respuestas or []

    def playbook_block(self):
        return lambda funcion: funcion

    def collect2(self, container=None, datapath=None, action_results=None):
        self.llamadas.append(("collect2", {"datapath": datapath}))
        return self.artefactos if datapath[0].startswith("artifact:") else self.respuestas

    def _apuntar(nombre):
        def metodo(self, *args, **kw):
            self.llamadas.append((nombre, dict(kw, args=args) if args else kw))
        return metodo

    debug = _apuntar("debug")
    set_severity = _apuntar("set_severity")
    add_note = _apuntar("add_note")
    set_status = _apuntar("set_status")
    add_artifact = _apuntar("add_artifact")
    playbook = _apuntar("playbook")
    act = _apuntar("act")
    prompt2 = _apuntar("prompt2")
    comment = _apuntar("comment")

    def de(self, nombre: str) -> list[dict]:
        return [kw for n, kw in self.llamadas if n == nombre]


def cargar_playbook_soar(monkeypatch, codigo: str, phantom: Phantom) -> dict:
    paquete = types.ModuleType("phantom")
    paquete.__path__ = []
    paquete.rules = phantom
    monkeypatch.setitem(sys.modules, "phantom", paquete)
    monkeypatch.setitem(sys.modules, "phantom.rules", phantom)
    ns = {"__name__": "playbook_soar"}
    exec(compile(codigo, "playbook_soar.py", "exec"), ns)
    return ns


def enrutar(monkeypatch, generado, contenedor: dict, cef: dict | None) -> tuple[Phantom, dict]:
    phantom = Phantom(artefactos=[[cef, "artefacto"]] if cef is not None else [])
    ns = cargar_playbook_soar(monkeypatch, generado["soar/splunk-soar/responselab_enrutador.py"], phantom)
    ns["on_start"](contenedor)
    return phantom, ns


def test_enrutador_de_splunk_soar_decide_como_el_nucleo(monkeypatch, generado, catalogo):
    regla = next(r for r in catalogo.reglas if r.get("splunk") and r["familia"] == "ad" and r["clase"] == "auto_contener")
    cef = {"search_name": regla["splunk"], "dest": "PC-0042", "user": "LAB\\mruiz", "src_ip": "10.0.20.7",
           "fileHashSha256": "a" * 64}
    phantom, _ = enrutar(monkeypatch, generado, {"id": 99, "name": "Notable renombrado por la ingesta",
                                                 "start_time": "2026-10-01T10:00:00Z"}, cef)
    [artefacto] = phantom.de("add_artifact")
    plan = json.loads(artefacto["cef_data"]["responselab_plan"])
    alerta = json.loads(artefacto["cef_data"]["responselab_alerta"])
    assert alerta["regla_nombre"] == regla["splunk"], "manda el nombre de la busqueda, no el del contenedor"
    assert alerta["equipo"]["nombre"] == "PC-0042" and alerta["usuario"]["nombre"] == "mruiz"
    assert alerta["red"]["ip_origen"] == "10.0.20.7" and alerta["fichero"]["sha256"] == "a" * 64
    esperado = nucleo.decidir(alerta, catalogo, CLIENTE_SOAR, {})
    for clave in ("familia", "clase", "estado", "severidad", "modos"):
        assert plan[clave] == esperado[clave], clave
    assert plan["familia"] == "ad" and plan["regla"]["conocida"] is True
    assert phantom.de("set_severity") == [{"container": {"id": 99, "name": "Notable renombrado por la ingesta",
                                                         "start_time": "2026-10-01T10:00:00Z"}, "severity": "high"}]
    [nota] = phantom.de("add_note")
    assert nota["title"] == "ResponseLab - " + plan["playbook"] and "Escalar a" in nota["content"]
    [llamada] = phantom.de("playbook")
    assert llamada["playbook"] == "local/responselab_ad"
    assert "soar/splunk-soar/responselab_ad.py" in generado
    assert phantom.de("set_status") == []


def test_enrutador_de_splunk_soar_cierra_lo_que_descarta(monkeypatch, generado, catalogo):
    regla = next(r for r in catalogo.reglas if r["clase"] == "auto_cierre")
    phantom, _ = enrutar(monkeypatch, generado, {"id": 5, "name": regla["titulo"]}, None)
    assert phantom.de("set_status")[0]["status"] == "closed"
    assert phantom.de("add_artifact") == [] and phantom.de("playbook") == []


def test_enrutador_de_splunk_soar_sin_regla_va_al_generico(monkeypatch, generado):
    phantom, _ = enrutar(monkeypatch, generado, {"id": 6, "name": "Regla local sin playbook"}, {"dvc": "srv-9"})
    [llamada] = phantom.de("playbook")
    assert llamada["playbook"] == "local/responselab_generico"
    assert "soar/splunk-soar/responselab_generico.py" in generado
    plan = json.loads(phantom.de("add_artifact")[0]["cef_data"]["responselab_plan"])
    assert plan["familia"] == "_generico" and plan["clase"] != "auto_contener"


def plan_de_endpoint(acciones: dict) -> tuple[str, str]:
    aislar = next(p for p, s in acciones.items() if s["accion"] == "endpoint.aislar")
    cuarentena = next(p for p, s in acciones.items() if s["accion"] == "fichero.cuarentena")
    return aislar, cuarentena


def test_playbook_de_familia_de_splunk_soar(monkeypatch, generado):
    codigo = generado["soar/splunk-soar/responselab_endpoint.py"]
    ns = cargar_playbook_soar(monkeypatch, codigo, Phantom())
    aislar, cuarentena = plan_de_endpoint(ns["ACCIONES"])
    plan = {"acciones": [
        {"id": aislar, "accion": "endpoint.aislar", "nombre": "Aislar el equipo", "modo": "automatica", "motivo": "radio equipo"},
        {"id": cuarentena, "accion": "fichero.cuarentena", "nombre": "Cuarentena", "modo": "aprobacion",
         "motivo": "clase auto_analisis", "objetivo": {"fichero.sha1": "b" * 40}, "justificacion": "por que"},
        {"id": "c99", "accion": "", "nombre": "Avisar al usuario", "modo": "manual", "motivo": "sin mapear"}],
        "triaje": [{"pregunta": "Hay mas equipos?", "resultado": "pendiente"}, {"pregunta": "Es un admin?", "resultado": "no"}]}
    alerta = {"equipo": {"id_edr": "mde-123"}, "fichero": {"sha1": "b" * 40}}
    phantom = Phantom(artefactos=[[json.dumps(plan), json.dumps(alerta)]], respuestas=[["Si"]])
    ns = cargar_playbook_soar(monkeypatch, codigo, phantom)
    ns["on_start"]({"id": 1})
    [act] = phantom.de("act")
    assert act["action"] == "quarantine device" and act["name"] == f"rl_{aislar}"
    assert act["parameters"] == [{"comment": "ResponseLab", "device_id": "mde-123", "type": "Full"}]
    assert act["assets"] is None and act["callback"] is ns["resultado_cb"]
    [pregunta] = phantom.de("prompt2")
    assert pregunta["name"] == f"rl_aprobar_{cuarentena}" and pregunta["role"] == "Administrator"
    assert "Cuarentena" in pregunta["message"] and "por que" in pregunta["message"]
    assert any("[manual] Avisar al usuario" in c["comment"] for c in phantom.de("comment"))
    [nota] = phantom.de("add_note")
    assert nota["content"] == "- Hay mas equipos?"

    # El analista aprueba: se ejecuta la cuarentena con el hash de la alerta
    ns["aprobacion_cb"](action={"name": f"rl_aprobar_{cuarentena}"}, container={"id": 1}, results=[])
    act = phantom.de("act")[-1]
    assert act["action"] == "quarantine file"
    assert act["parameters"] == [{"comment": "ResponseLab", "device_id": "mde-123", "file_hash": "b" * 40}]


def test_playbook_de_familia_sin_datos_o_rechazado(monkeypatch, generado):
    codigo = generado["soar/splunk-soar/responselab_endpoint.py"]
    aislar, cuarentena = plan_de_endpoint(cargar_playbook_soar(monkeypatch, codigo, Phantom())["ACCIONES"])
    plan = {"acciones": [{"id": aislar, "accion": "endpoint.aislar", "nombre": "Aislar", "modo": "automatica", "motivo": "m"},
                         {"id": cuarentena, "accion": "fichero.cuarentena", "nombre": "Cuarentena", "modo": "aprobacion",
                          "motivo": "m"}], "triaje": []}
    phantom = Phantom(artefactos=[[json.dumps(plan), json.dumps({"equipo": {"nombre": "PC-1"}})]], respuestas=[["No"]])
    ns = cargar_playbook_soar(monkeypatch, codigo, phantom)
    ns["on_start"]({"id": 1})
    assert phantom.de("act") == [], "sin id del EDR no hay objetivo: no se ejecuta"
    assert any("faltan datos para Aislar" in c["comment"] for c in phantom.de("comment"))
    ns["aprobacion_cb"](action={"name": f"rl_aprobar_{cuarentena}"}, container={"id": 1}, results=[])
    assert phantom.de("act") == []
    assert any("rechazado o sin respuesta: Cuarentena" in c["comment"] for c in phantom.de("comment"))


def test_playbook_de_familia_sin_plan(monkeypatch, generado):
    phantom = Phantom()
    ns = cargar_playbook_soar(monkeypatch, generado["soar/splunk-soar/responselab_red.py"], phantom)
    ns["on_start"]({"id": 1})
    assert phantom.de("act") == [] and "no hay plan" in phantom.de("comment")[0]["comment"]


def test_cada_paso_de_splunk_soar_tiene_su_accion(monkeypatch, generado, catalogo_datos):
    for familia in comun.familias(catalogo_datos):
        ns = cargar_playbook_soar(monkeypatch, generado[f"soar/splunk-soar/responselab_{familia.lstrip('_')}.py"], Phantom())
        f = catalogo_datos["familias"][familia]
        assert ns["FAMILIA"] == familia
        assert len(ns["ACCIONES"]) == len(f.get("contencion") or []) + len(f.get("evidencia_automatica") or [])
        for spec in ns["ACCIONES"].values():
            soar = ((catalogo_datos["acciones"].get(spec["accion"] or "") or {}).get("soar") or {}).get("splunk_soar") or {}
            assert spec["accion_soar"] == soar.get("accion", "")


# === Wazuh ===================================================================

def test_configuracion_de_la_integracion_de_wazuh(generado, catalogo_datos):
    texto = generado["siem/wazuh/ossec-responselab.conf"]
    raiz = ET.fromstring(f"<ossec_config>{texto}</ossec_config>")
    bloques = raiz.findall("integration")
    assert all(b.findtext("name") == "custom-responselab" and b.findtext("alert_format") == "json" for b in bloques)
    ids_catalogo = {str(w) for r in catalogo_datos["reglas"] for w in r.get("wazuh_ids") or []}
    vistos = []
    for etiqueta in re.findall(r"<rule_id>(.*?)</rule_id>", texto):
        assert len(etiqueta.encode("utf-8")) <= MAX_ETIQUETA_WAZUH
        vistos += etiqueta.split(",")
    assert all(re.fullmatch(r"\d+", x) for x in vistos)
    assert len(vistos) == len(set(vistos)), "un id en dos bloques llegaria dos veces"
    assert set(vistos) == ids_catalogo
    assert [b.findtext("level") for b in bloques if b.find("level") is not None] == [str(siem.NIVEL_SIN_PLAYBOOK)]
    assert [b.findtext("group") for b in bloques if b.find("group") is not None] == ["responselab_acuse"]
    assert f"Las {len(ids_catalogo)} reglas de Wazuh" in texto


def test_lotes_de_reglas_de_wazuh_por_debajo_del_limite():
    catalogo = {"version": "x", "reglas": [{"wazuh_ids": [str(100000 + i) for i in range(5000)]}]}
    texto = siem._wazuh(catalogo)
    etiquetas = re.findall(r"<rule_id>(.*?)</rule_id>", texto)
    assert len(etiquetas) == 25
    assert max(len(e.encode()) for e in etiquetas) <= MAX_ETIQUETA_WAZUH


def test_reglas_de_acuse_de_wazuh(raiz):
    arbol = ET.parse(raiz / "siem" / "wazuh" / "reglas" / "responselab_rules.xml")
    grupo = arbol.getroot()
    assert grupo.tag == "group" and "responselab" in grupo.get("name")
    reglas = {r.get("id"): r for r in grupo.findall("rule")}
    assert sorted(reglas) == ["109900", "109901", "109902", "109903"]
    for ident, r in reglas.items():
        assert "responselab_acuse" in r.findtext("group")
        assert r.findtext("description").startswith("ResponseLab")
        if ident != "109900":
            assert r.findtext("if_sid") == "109900"
    base = reglas["109900"]
    assert base.findtext("decoded_as") == "json"
    assert base.find("field").get("name") == "responselab_ar.accion"
    campos = {(f.get("name"), f.text) for f in reglas["109902"].findall("field")}
    assert campos == {("responselab_ar.accion", "^aislar$"), ("responselab_ar.estado", "^aplicada$")}


# === Splunk y Elastic ========================================================

def leer_conf_splunk(texto: str) -> dict[str, dict[str, str]]:
    stanzas: dict[str, dict[str, str]] = {}
    actual = None
    for linea in texto.splitlines():
        linea = linea.strip()
        if not linea or linea.startswith("#"):
            continue
        if linea.startswith("[") and linea.endswith("]"):
            actual = linea[1:-1]
            assert actual not in stanzas, f"stanza repetida: {actual}"
            stanzas[actual] = {}
            continue
        clave, _, valor = linea.partition("=")
        assert actual is not None and _ == "=", linea
        stanzas[actual][clave.strip()] = valor.strip()
    return stanzas


def lista_de_webhooks(raiz: Path) -> re.Pattern:
    conf = leer_conf_splunk((raiz / "siem" / "splunk" / "alert_actions.conf").read_text(encoding="utf-8"))
    assert conf["webhook"]["enable_allowlist"] == "true"
    return re.compile(conf["webhook"]["allowlist.responselab"])


@pytest.mark.parametrize("origen", sorted(siem.APPS_SPLUNK))
def test_busquedas_de_splunk_con_webhook_permitido(generado, catalogo_datos, raiz, origen):
    ruta, _ = siem.APPS_SPLUNK[origen]
    stanzas = leer_conf_splunk(generado[ruta])
    esperadas = {r["splunk"] for r in catalogo_datos["reglas"] if r.get("splunk") and r.get("origen") == origen}
    assert set(stanzas) == esperadas and stanzas
    permitida = lista_de_webhooks(raiz)
    clientes = sorted(p.stem for p in (raiz / "clientes").glob("*.yml") if not p.name.startswith("_"))
    for nombre, claves in stanzas.items():
        assert set(claves) == {"action.webhook", "action.webhook.param.url"}, nombre
        assert claves["action.webhook"] == "1"
        url = claves["action.webhook.param.url"]
        assert "/alertas/splunk?token=TOKEN_DE_INGESTA" in url
        # Al sustituir CLIENTE por el id de un cliente real, Splunk 9 la deja salir
        for cliente in clientes:
            assert permitida.match(url.replace("CLIENTE", cliente)), (nombre, cliente)
    assert f"a las {len(stanzas)} busquedas guardadas de {origen}" in generado[ruta]


def test_la_lista_de_webhooks_no_deja_salir_a_otro_sitio(raiz):
    permitida = lista_de_webhooks(raiz)
    for url in ("https://atacante.example/v1/lab/alertas/splunk", "http://MOTOR:8443/v1/lab/alertas/splunk",
                "https://MOTOR.atacante.example/v1/lab/alertas/splunk", "https://MOTOR:8443/v1/lab/acuses"):
        assert not permitida.match(url), url


def test_reglas_de_elastic(generado, catalogo_datos):
    datos = json.loads(generado["siem/elastic/reglas-responselab.json"])
    sigma = sorted({r["titulo"] for r in catalogo_datos["reglas"] if str(r.get("tipo", "")).startswith("sigma")})
    assert datos["titulos"] == sigma and sigma
    assert datos["version_catalogo"] == catalogo_datos["version"]


# === Cobertura ===============================================================

def test_cobertura(generado, catalogo_datos):
    texto = generado["docs/COBERTURA.md"]
    assert texto.startswith("# Cobertura de respuesta\n")
    assert f"Cat\u00e1logo `{catalogo_datos['version']}`" in texto
    assert f"**{len(catalogo_datos['reglas'])} reglas**" in texto
    for familia in catalogo_datos["familias"]:
        if familia != "_generico":
            assert f"| `{familia}` |" in texto, familia
    for accion, a in catalogo_datos["acciones"].items():
        if not a.get("inversa"):
            assert f"| `{accion}` | {a['radio']} |" in texto, accion
