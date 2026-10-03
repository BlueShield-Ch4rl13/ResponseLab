"""
Integracion Wazuh -> motor (siem/wazuh/integracion/custom-responselab.py).

Se ejecuta como la ejecuta wazuh-integratord: un proceso por alerta, con el
fichero de la alerta y el resto de argumentos posicionales. El motor es un
servidor HTTP falso en 127.0.0.1 con puerto efimero, en un hilo; la
instalacion de Wazuh es una carpeta de tmp_path (RL_WAZUH_DIR).
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
INTEGRACION = RAIZ / "siem" / "wazuh" / "integracion"
SCRIPT = INTEGRACION / "custom-responselab.py"
TOKENS = {
    "lab": {"token_ingesta": "ingesta-lab", "token_agentes": "agentes-lab"},
    "acme": {"token_ingesta": "ingesta-acme", "token_agentes": "agentes-acme"},
}


# === Motor falso =============================================================

class MotorFalso:
    """Servidor HTTP que apunta cada peticion y contesta con el codigo que toque."""

    def __init__(self, puerto: int = 0, codigo: int = 202):
        self.peticiones: list[dict] = []
        self.codigo = codigo
        motor = self

        class Manejador(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 (nombre impuesto por http.server)
                largo = int(self.headers.get("Content-Length") or 0)
                crudo = self.rfile.read(largo)
                motor.peticiones.append({"metodo": "POST", "ruta": self.path, "cabeceras": dict(self.headers),
                                         "cuerpo": json.loads(crudo) if crudo else None})
                cuerpo = json.dumps({"estado": "recibida"}).encode()
                self.send_response(motor.codigo)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(cuerpo)))
                self.end_headers()
                self.wfile.write(cuerpo)

            def log_message(self, *args):
                pass

        self.servidor = ThreadingHTTPServer(("127.0.0.1", puerto), Manejador)
        self.puerto = self.servidor.server_address[1]
        self.hilo = threading.Thread(target=self.servidor.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.puerto}"

    def __enter__(self):
        self.hilo.start()
        return self

    def __exit__(self, *exc):
        self.servidor.shutdown()
        self.servidor.server_close()
        self.hilo.join(timeout=5)


def puerto_cerrado() -> int:
    """Un puerto en el que no escucha nadie (el motor caido)."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# === Wazuh falso =============================================================

@pytest.fixture
def wazuh(tmp_path) -> Path:
    base = tmp_path / "ossec"
    (base / "integrations").mkdir(parents=True)
    (base / "etc").mkdir()
    (base / "logs").mkdir()
    for f in ("custom-responselab", "custom-responselab.py"):
        shutil.copy2(INTEGRACION / f, base / "integrations" / f)
        os.chmod(base / "integrations" / f, 0o750)   # lo que hace instalar-manager.sh
    return base


def configurar(wazuh: Path, motor: str, **extra) -> dict:
    conf = {"motor": motor, "cliente": "lab", "clientes": json.loads(json.dumps(TOKENS)), "verificar_tls": True,
            "timeout": 5, "reintentos": 0, "clientes_por_agente": [{"patron": "^ACME-", "cliente": "acme"}]}
    conf.update(extra)
    (wazuh / "etc" / "responselab.json").write_text(json.dumps(conf), encoding="utf-8")
    return conf


def alerta(agente: str = "PC-0042", regla: str = "101216", **extra) -> dict:
    a = {"id": f"1727776800.{uuid.uuid4().int % 10**6}", "timestamp": "2026-10-01T10:00:00.000+0000",
         "rule": {"id": regla, "level": 12, "description": "Defensas de seguridad deshabilitadas",
                  "groups": ["detection_lab", "soc_endpoint"]},
         "agent": {"id": "042", "name": agente, "ip": "10.0.20.42"},
         "manager": {"name": "wazuh-manager"}, "decoder": {"name": "windows_eventchannel"},
         "data": {"win": {"system": {"eventID": "1"}, "eventdata": {"image": "C:\\Users\\x\\upd.exe"}}}}
    a.update(extra)
    return a


def acuse(estado: str = "aplicada", datos: str | None = None) -> dict:
    d = {"v": "1", "accion": "aislar", "estado": estado, "ejecucion_id": "ej-77",
         "detalle": "equipo aislado con nftables", "equipo": "pc-0042"}
    if datos is not None:
        d["datos"] = datos
    return {"id": "1727776900.555", "timestamp": "2026-10-01T10:01:40.000+0000",
            "rule": {"id": "109902", "level": 10, "description": "ResponseLab: equipo aislado",
                     "groups": ["responselab", "active_response", "responselab_acuse"]},
            "agent": {"id": "042", "name": "PC-0042"}, "decoder": {"name": "json"},
            "data": {"responselab_ar": d}}


def integrar(wazuh: Path, carga: dict, *, api_key: str = "", hook: str = "", debug: str = "", opciones: str = "",
             con_lanzador: bool = False, por_entorno: bool = True) -> subprocess.CompletedProcess:
    """Una ejecucion de integratord: argumentos 1-7 como en Wazuh 4.x."""
    fichero = wazuh / "integrations" / f"alerta-{uuid.uuid4().hex}.alert"
    fichero.write_text(json.dumps(carga), encoding="utf-8")
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("RL_") and k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
    env["NO_PROXY"] = env["no_proxy"] = "*"
    if por_entorno:
        env["RL_WAZUH_DIR"] = str(wazuh)
    if con_lanzador:
        cmd = [str(wazuh / "integrations" / "custom-responselab")]
    else:
        cmd = [sys.executable, str(wazuh / "integrations" / "custom-responselab.py")]
    cmd += [str(fichero), api_key, hook, debug, opciones, "10", "3"]
    return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=60)


def pendientes(wazuh: Path) -> list[dict]:
    carpeta = wazuh / "var" / "responselab" / "pendientes"
    if not carpeta.is_dir():
        return []
    return [json.loads(f.read_text(encoding="utf-8")) for f in sorted(carpeta.iterdir())]


def registro(wazuh: Path) -> str:
    f = wazuh / "logs" / "integrations.log"
    return f.read_text(encoding="utf-8") if f.exists() else ""


def cargar_modulo():
    spec = importlib.util.spec_from_file_location(f"custom_responselab_{uuid.uuid4().hex}", SCRIPT)
    modulo = importlib.util.module_from_spec(spec)
    flag = sys.dont_write_bytecode
    sys.dont_write_bytecode = True        # nada de __pycache__ junto al script
    try:
        spec.loader.exec_module(modulo)
    finally:
        sys.dont_write_bytecode = flag
    return modulo


# === Envio de alertas ========================================================

def test_alerta_al_motor_con_el_token_de_ingesta(wazuh):
    with MotorFalso() as motor:
        configurar(wazuh, motor.url)
        a = alerta()
        p = integrar(wazuh, a, debug="debug")
        assert p.returncode == 0, registro(wazuh)
    [pet] = motor.peticiones
    assert pet["metodo"] == "POST" and pet["ruta"] == "/v1/lab/alertas/wazuh"
    assert pet["cabeceras"]["Authorization"] == "Bearer ingesta-lab"
    assert pet["cabeceras"]["Content-Type"] == "application/json"
    assert pet["cabeceras"]["User-Agent"].startswith("wazuh-custom-responselab/")
    assert pet["cuerpo"] == a, "la alerta llega entera: el motor normaliza"
    assert "enviada /v1/lab/alertas/wazuh (202)" in registro(wazuh)
    assert pendientes(wazuh) == []


def test_cliente_por_nombre_de_agente(wazuh):
    with MotorFalso() as motor:
        configurar(wazuh, motor.url)
        assert integrar(wazuh, alerta(agente="ACME-PC01")).returncode == 0
        assert integrar(wazuh, alerta(agente="PC-ACME-01")).returncode == 0
    rutas = [(p["ruta"], p["cabeceras"]["Authorization"]) for p in motor.peticiones]
    assert rutas == [("/v1/acme/alertas/wazuh", "Bearer ingesta-acme"), ("/v1/lab/alertas/wazuh", "Bearer ingesta-lab")]


def test_patron_de_agente_mal_escrito_no_rompe_nada(wazuh):
    with MotorFalso() as motor:
        configurar(wazuh, motor.url, clientes_por_agente=[{"patron": "([", "cliente": "acme"}, {"cliente": "acme"}])
        assert integrar(wazuh, alerta(agente="ACME-PC01")).returncode == 0
    assert motor.peticiones[0]["ruta"] == "/v1/lab/alertas/wazuh"


def test_acuse_de_active_response_va_a_acuses_con_el_token_de_agentes(wazuh):
    datos = json.dumps({"metodo": "nftables", "permitidos": ["10.0.30.2"]})
    with MotorFalso() as motor:
        configurar(wazuh, motor.url)
        assert integrar(wazuh, acuse(datos=datos)).returncode == 0
    [pet] = motor.peticiones
    assert pet["ruta"] == "/v1/lab/acuses"
    assert pet["cabeceras"]["Authorization"] == "Bearer agentes-lab"
    assert pet["cuerpo"] == {
        "ejecucion_id": "ej-77", "estado": "aplicada",
        "detalle": {"detalle": "equipo aislado con nftables", "accion": "aislar", "equipo": "pc-0042",
                    "agente": "PC-0042", "alerta_wazuh": "1727776900.555",
                    "metodo": "nftables", "permitidos": ["10.0.30.2"]}}


def test_acuse_con_datos_que_no_son_json(wazuh):
    with MotorFalso() as motor:
        configurar(wazuh, motor.url)
        assert integrar(wazuh, acuse(estado="fallida", datos="{roto")).returncode == 0
    cuerpo = motor.peticiones[0]["cuerpo"]
    assert cuerpo["estado"] == "fallida"
    assert cuerpo["detalle"]["texto"] == "{roto"


def test_acuse_de_un_agente_de_otro_cliente(wazuh):
    a = acuse()
    a["agent"]["name"] = "ACME-SRV02"
    with MotorFalso() as motor:
        configurar(wazuh, motor.url)
        assert integrar(wazuh, a).returncode == 0
    assert motor.peticiones[0]["ruta"] == "/v1/acme/acuses"
    assert motor.peticiones[0]["cabeceras"]["Authorization"] == "Bearer agentes-acme"


def test_grupo_de_acuse_sin_datos_de_responselab_es_una_alerta(wazuh):
    a = acuse()
    a["data"] = {"otra_cosa": {"x": 1}}
    with MotorFalso() as motor:
        configurar(wazuh, motor.url)
        assert integrar(wazuh, a).returncode == 0
    assert motor.peticiones[0]["ruta"] == "/v1/lab/alertas/wazuh"


def test_lanzador_y_carpeta_de_wazuh_por_defecto(wazuh):
    """Sin RL_WAZUH_DIR: la instalacion es la carpeta padre de integrations/ (como en el manager)."""
    with MotorFalso() as motor:
        configurar(wazuh, motor.url)
        p = integrar(wazuh, alerta(), con_lanzador=True, por_entorno=False, debug="debug")
        assert p.returncode == 0, p.stderr + registro(wazuh)
    assert [x["ruta"] for x in motor.peticiones] == ["/v1/lab/alertas/wazuh"]
    assert "enviada" in registro(wazuh)


def test_hook_url_y_api_key_de_ossec_conf(wazuh):
    """Sin motor ni token en responselab.json valen el hook_url y el api_key de <integration>."""
    with MotorFalso() as motor:
        (wazuh / "etc" / "responselab.json").write_text(json.dumps({"cliente": "lab", "reintentos": 0}), encoding="utf-8")
        p = integrar(wazuh, alerta(), api_key="clave-de-ossec", hook=motor.url)
        assert p.returncode == 0, registro(wazuh)
    assert motor.peticiones[0]["ruta"] == "/v1/lab/alertas/wazuh"
    assert motor.peticiones[0]["cabeceras"]["Authorization"] == "Bearer clave-de-ossec"


def test_fichero_de_opciones_completa_la_configuracion(wazuh, tmp_path):
    with MotorFalso() as motor:
        configurar(wazuh, "http://127.0.0.1:9", cliente="lab")
        opciones = tmp_path / "custom-responselab-1.options"
        opciones.write_text(json.dumps({"motor": motor.url}), encoding="utf-8")
        assert integrar(wazuh, alerta(), opciones=str(opciones)).returncode == 0, registro(wazuh)
    assert len(motor.peticiones) == 1


# === Errores sin reintento ===================================================

def test_sin_configuracion_ni_hook(wazuh):
    p = integrar(wazuh, alerta())
    assert p.returncode == 1
    assert "sin " in registro(wazuh) and "responselab.json" in registro(wazuh)


def test_configuracion_sin_cliente(wazuh):
    (wazuh / "etc" / "responselab.json").write_text(json.dumps({"motor": "http://127.0.0.1:9"}), encoding="utf-8")
    assert integrar(wazuh, alerta()).returncode == 1
    assert "necesita 'motor' y 'cliente'" in registro(wazuh)


def test_alerta_ilegible(wazuh):
    fichero = wazuh / "integrations" / "rota.alert"
    fichero.write_text("{no es json", encoding="utf-8")
    p = subprocess.run([sys.executable, str(SCRIPT), str(fichero), "", "", "", "", "10", "3"],
                       capture_output=True, text=True, env=dict(os.environ, RL_WAZUH_DIR=str(wazuh)), timeout=60)
    assert p.returncode == 1
    assert "alerta ilegible" in registro(wazuh)


def test_sin_token_para_el_cliente_no_se_envia_ni_se_encola(wazuh):
    with MotorFalso() as motor:
        configurar(wazuh, motor.url, clientes={"lab": {"token_agentes": "solo-agentes"}})
        assert integrar(wazuh, alerta()).returncode == 1
    assert motor.peticiones == []
    assert pendientes(wazuh) == []
    assert "no hay token" in registro(wazuh)


def test_rechazo_4xx_no_se_encola(wazuh):
    with MotorFalso(codigo=401) as motor:
        configurar(wazuh, motor.url)
        assert integrar(wazuh, alerta()).returncode == 1
    assert len(motor.peticiones) == 1, "un 4xx no mejora reintentando"
    assert pendientes(wazuh) == []
    assert "rechazo /v1/lab/alertas/wazuh con 401" in registro(wazuh)


# === Cola de pendientes ======================================================

def test_motor_caido_encola_y_la_siguiente_ejecucion_vacia_la_cola(wazuh):
    puerto = puerto_cerrado()
    configurar(wazuh, f"http://127.0.0.1:{puerto}")
    primera = alerta()
    assert integrar(wazuh, primera).returncode == 1
    [pendiente] = pendientes(wazuh)
    assert pendiente == {"ruta": "/v1/lab/alertas/wazuh", "cuerpo": primera, "token_de": "token_ingesta"}
    contenido = "".join(f.read_text(encoding="utf-8") for f in (wazuh / "var" / "responselab" / "pendientes").iterdir())
    assert "ingesta-lab" not in contenido, "los tokens no se escriben en la cola"
    assert "queda en pendientes" in registro(wazuh)

    segunda = acuse()
    with MotorFalso(puerto=puerto) as motor:
        assert integrar(wazuh, segunda).returncode == 0, registro(wazuh)
    assert [p["ruta"] for p in motor.peticiones] == ["/v1/lab/alertas/wazuh", "/v1/lab/acuses"]
    assert motor.peticiones[0]["cuerpo"] == primera
    assert motor.peticiones[0]["cabeceras"]["Authorization"] == "Bearer ingesta-lab"
    assert motor.peticiones[1]["cabeceras"]["Authorization"] == "Bearer agentes-lab"
    assert pendientes(wazuh) == []


def test_errores_5xx_mantienen_la_cola_en_orden(wazuh):
    with MotorFalso(codigo=503) as motor:
        configurar(wazuh, motor.url)
        a1, a2 = alerta(), alerta(agente="ACME-PC01")
        assert integrar(wazuh, a1).returncode == 1
        assert integrar(wazuh, a2).returncode == 1
        assert [p["cuerpo"] for p in pendientes(wazuh)] == [a1, a2]
        motor.codigo = 202
        motor.peticiones.clear()
        a3 = alerta()
        assert integrar(wazuh, a3).returncode == 0
    assert [p["cuerpo"] for p in motor.peticiones] == [a1, a2, a3]
    assert [p["ruta"] for p in motor.peticiones] == ["/v1/lab/alertas/wazuh", "/v1/acme/alertas/wazuh",
                                                     "/v1/lab/alertas/wazuh"]
    assert pendientes(wazuh) == []


def test_pendiente_que_el_motor_rechaza_se_descarta(wazuh):
    puerto = puerto_cerrado()
    configurar(wazuh, f"http://127.0.0.1:{puerto}")
    assert integrar(wazuh, alerta()).returncode == 1
    with MotorFalso(puerto=puerto, codigo=400) as motor:
        assert integrar(wazuh, alerta()).returncode == 1
    assert len(motor.peticiones) == 2
    assert pendientes(wazuh) == []
    assert "rechazado por el motor (400)" in registro(wazuh)


def test_pendiente_corrupto_se_descarta(wazuh):
    carpeta = wazuh / "var" / "responselab" / "pendientes"
    carpeta.mkdir(parents=True)
    (carpeta / "0001-1.json").write_text("{roto", encoding="utf-8")
    (carpeta / "0002-1.json").write_text(json.dumps({"cuerpo": {}}), encoding="utf-8")
    with MotorFalso() as motor:
        configurar(wazuh, motor.url)
        assert integrar(wazuh, alerta()).returncode == 0
    assert len(motor.peticiones) == 1
    assert pendientes(wazuh) == []


def test_motor_caido_varias_veces_no_pierde_alertas(wazuh):
    puerto = puerto_cerrado()
    configurar(wazuh, f"http://127.0.0.1:{puerto}")
    a1, a2 = alerta(), alerta()
    assert integrar(wazuh, a1).returncode == 1
    assert integrar(wazuh, a2).returncode == 1
    assert [p["cuerpo"] for p in pendientes(wazuh)] == [a1, a2]


# === Argumentos de integratord ===============================================

def test_argumentos_en_sus_posiciones(tmp_path):
    m = cargar_modulo()
    opciones = tmp_path / "custom-responselab-1.options"
    opciones.write_text("{}", encoding="utf-8")
    a = m.argumentos(["custom-responselab.py", "/tmp/a.alert", "CLAVE", "https://motor:8443", "debug",
                      str(opciones), "10", "3"])
    assert a == {"alerta": "/tmp/a.alert", "hook": "https://motor:8443", "api_key": "CLAVE",
                 "opciones": str(opciones), "debug": True}
    a = m.argumentos(["custom-responselab.py", "/tmp/a.alert", "", "", "", "", "10", "3"])
    assert a == {"alerta": "/tmp/a.alert", "hook": "", "api_key": "", "opciones": "", "debug": False}


def test_argumentos_corridos_sin_api_key(tmp_path):
    """Sin api_key ni debug, el hook queda en la segunda posicion y se reconoce por su forma."""
    m = cargar_modulo()
    a = m.argumentos(["custom-responselab.py", "/tmp/a.alert", "https://motor:8443", "10", "3"])
    assert a["hook"] == "https://motor:8443" and a["api_key"] == ""


def test_argumentos_corridos_no_confunden_el_fichero_de_opciones_con_la_clave(tmp_path):
    m = cargar_modulo()
    opciones = tmp_path / "custom-responselab-1.options"
    opciones.write_text("{}", encoding="utf-8")
    a = m.argumentos(["custom-responselab.py", "/tmp/a.alert", str(opciones), "10", "3"])
    assert a["opciones"] == str(opciones)
    assert a["api_key"] == ""
