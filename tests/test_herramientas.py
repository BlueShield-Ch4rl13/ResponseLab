"""
Herramientas de tools/: importar_thehive.py contra un TheHive falso, validar.py
y simular.py como los ejecuta el CI.

Todo se ejecuta como proceso aparte, igual que desde la consola. El TheHive
falso escucha en 127.0.0.1 con puerto efimero; los proxies del entorno se
quitan para que nada salga del equipo.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

RAIZ = Path(__file__).resolve().parent.parent
PLANTILLAS = RAIZ / "soar" / "thehive" / "plantillas"
API_KEY = "clave-de-prueba-thehive"


def entorno(**extra) -> dict:
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("RL_", "THEHIVE_")) and k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
    env["NO_PROXY"] = env["no_proxy"] = "*"
    env["PYTHONIOENCODING"] = "utf-8"
    env.update(extra)
    return env


def herramienta(nombre: str, *args, env: dict | None = None, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(RAIZ / "tools" / nombre), *args], capture_output=True, text=True,
                          env=env or entorno(), timeout=timeout, cwd=str(RAIZ))


def plantillas() -> dict[str, dict]:
    return {f.stem: json.loads(f.read_text(encoding="utf-8")) for f in sorted(PLANTILLAS.glob("*.json"))}


# === TheHive falso ===========================================================

class TheHiveFalso:
    """API v1 de TheHive 5: lo justo para listar, crear, actualizar y borrar plantillas."""

    def __init__(self, existentes: dict[str, str] | None = None, fallar_en: str | None = None, fallar_listado=False):
        self.peticiones: list[dict] = []
        self.existentes = dict(existentes or {})       # nombre -> _id
        self.fallar_en = fallar_en                      # nombre de plantilla cuyo POST/PATCH devuelve 500
        self.fallar_listado = fallar_listado
        th = self

        class Manejador(BaseHTTPRequestHandler):
            def _atender(self, metodo):
                largo = int(self.headers.get("Content-Length") or 0)
                crudo = self.rfile.read(largo) if largo else b""
                partes = urlsplit(self.path)
                pet = {"metodo": metodo, "ruta": partes.path, "consulta": parse_qs(partes.query),
                       "cabeceras": dict(self.headers), "cuerpo": json.loads(crudo) if crudo else None}
                th.peticiones.append(pet)
                codigo, respuesta = th.responder(pet)
                datos = json.dumps(respuesta).encode()
                self.send_response(codigo)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(datos)))
                self.end_headers()
                self.wfile.write(datos)

            def do_POST(self):  # noqa: N802
                self._atender("POST")

            def do_PATCH(self):  # noqa: N802
                self._atender("PATCH")

            def do_DELETE(self):  # noqa: N802
                self._atender("DELETE")

            def log_message(self, *args):
                pass

        self.servidor = ThreadingHTTPServer(("127.0.0.1", 0), Manejador)
        self.hilo = threading.Thread(target=self.servidor.serve_forever, daemon=True)

    def responder(self, pet):
        if pet["ruta"] == "/api/v1/query":
            if self.fallar_listado:
                return 500, {"type": "InternalError"}
            return 200, [{"_id": i, "_type": "CaseTemplate", "name": n} for n, i in self.existentes.items()] + \
                [{"_id": "~sin-nombre", "_type": "CaseTemplate"}]
        nombre = (pet["cuerpo"] or {}).get("name")
        if self.fallar_en and nombre == self.fallar_en:
            return 500, {"type": "InternalError", "message": "fallo simulado"}
        if pet["metodo"] == "POST" and pet["ruta"] == "/api/v1/caseTemplate":
            return 201, {"_id": "~nueva", "name": nombre}
        if pet["metodo"] in ("PATCH", "DELETE") and pet["ruta"].startswith("/api/v1/caseTemplate/"):
            return 204, {}
        return 404, {"type": "NotFound"}

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.servidor.server_address[1]}"

    def __enter__(self):
        self.hilo.start()
        return self

    def __exit__(self, *exc):
        self.servidor.shutdown()
        self.servidor.server_close()
        self.hilo.join(timeout=5)

    def escrituras(self) -> list[dict]:
        return [p for p in self.peticiones if p["ruta"] != "/api/v1/query"]


# === importar_thehive.py =====================================================

def test_importar_crea_las_nuevas_y_actualiza_las_existentes():
    todas = plantillas()
    with TheHiveFalso(existentes={todas["endpoint"]["name"]: "~1001", "Plantilla del SOC": "~9"}) as th:
        p = herramienta("importar_thehive.py", "--url", th.url + "/", "--organizacion", "ACME",
                        env=entorno(THEHIVE_API_KEY=API_KEY))
        assert p.returncode == 0, p.stdout + p.stderr
    # Primero el listado de plantillas existentes
    listado = th.peticiones[0]
    assert listado["metodo"] == "POST" and listado["ruta"] == "/api/v1/query"
    assert listado["consulta"] == {"name": ["caseTemplate"]}
    assert listado["cuerpo"]["query"][0] == {"_name": "listCaseTemplate"}
    # Credenciales y organizacion en todas las peticiones
    for pet in th.peticiones:
        assert pet["cabeceras"]["Authorization"] == f"Bearer {API_KEY}"
        assert pet["cabeceras"]["X-Organisation"] == "ACME"
    escrituras = th.escrituras()
    assert len(escrituras) == len(todas)
    parches = [e for e in escrituras if e["metodo"] == "PATCH"]
    assert [e["ruta"] for e in parches] == ["/api/v1/caseTemplate/~1001"]
    assert parches[0]["cuerpo"]["name"] == todas["endpoint"]["name"]
    nuevas = [e for e in escrituras if e["metodo"] == "POST"]
    assert {e["ruta"] for e in nuevas} == {"/api/v1/caseTemplate"}
    assert sorted(e["cuerpo"]["name"] for e in nuevas) == sorted(t["name"] for k, t in todas.items() if k != "endpoint")
    # El cuerpo es la plantilla generada, sin customFields vacios (no pisa los del SOC)
    for e in escrituras:
        original = next(t for t in todas.values() if t["name"] == e["cuerpo"]["name"])
        esperado = {k: v for k, v in original.items() if not (k == "customFields" and not v)}
        assert e["cuerpo"] == esperado
        assert "customFields" not in e["cuerpo"]
    assert f"{len(todas)}/{len(todas)} plantillas importadas en la organizacion ACME." in p.stdout


def test_importar_solo_algunas_familias():
    with TheHiveFalso() as th:
        p = herramienta("importar_thehive.py", "--url", th.url, "endpoint", "_generico", env=entorno(THEHIVE_API_KEY=API_KEY))
        assert p.returncode == 0, p.stdout + p.stderr
    nombres = sorted(e["cuerpo"]["name"] for e in th.escrituras())
    assert nombres == sorted([plantillas()["endpoint"]["name"], plantillas()["_generico"]["name"]])
    assert all("X-Organisation" not in pet["cabeceras"] for pet in th.peticiones)


def test_comprobar_no_escribe_nada():
    todas = plantillas()
    with TheHiveFalso(existentes={todas["ad"]["name"]: "~7"}) as th:
        p = herramienta("importar_thehive.py", "--url", th.url, "--organizacion", "SOC", "--comprobar",
                        env=entorno(THEHIVE_API_KEY=API_KEY))
        assert p.returncode == 0, p.stdout + p.stderr
    assert [x["ruta"] for x in th.peticiones] == ["/api/v1/query"], "con --comprobar solo se lista"
    lineas = [x.split() for x in p.stdout.splitlines() if x.strip()]
    assert len(lineas) == len(todas)
    verbos = {" ".join(x[1:-2]): x[0] for x in lineas}
    assert verbos[todas["ad"]["name"]] == "actualizar"
    assert verbos[todas["cloud"]["name"]] == "crear"


def test_reemplazar_borra_y_crea():
    todas = plantillas()
    with TheHiveFalso(existentes={todas["red"]["name"]: "~55"}) as th:
        p = herramienta("importar_thehive.py", "--url", th.url, "--reemplazar", "red", env=entorno(THEHIVE_API_KEY=API_KEY))
        assert p.returncode == 0, p.stdout + p.stderr
    assert [(e["metodo"], e["ruta"]) for e in th.escrituras()] == [("DELETE", "/api/v1/caseTemplate/~55"),
                                                                    ("POST", "/api/v1/caseTemplate")]


def test_sin_api_key_sale_con_2_sin_peticiones():
    with TheHiveFalso() as th:
        p = herramienta("importar_thehive.py", "--url", th.url, env=entorno())
        assert p.returncode == 2
        assert "THEHIVE_API_KEY" in p.stderr
    assert th.peticiones == []


def test_un_fallo_en_una_plantilla_no_para_las_demas():
    todas = plantillas()
    with TheHiveFalso(fallar_en=todas["web"]["name"]) as th:
        p = herramienta("importar_thehive.py", "--url", th.url, env=entorno(THEHIVE_API_KEY=API_KEY))
    assert p.returncode == 1
    assert len(th.escrituras()) == len(todas)
    assert "MAL" in p.stdout and "HTTP 500" in p.stdout
    assert f"{len(todas) - 1}/{len(todas)} plantillas importadas" in p.stdout


def test_si_no_se_puede_listar_no_se_escribe():
    with TheHiveFalso(fallar_listado=True) as th:
        p = herramienta("importar_thehive.py", "--url", th.url, env=entorno(THEHIVE_API_KEY=API_KEY))
    assert p.returncode == 1
    assert "No se pudo listar" in p.stderr
    assert th.escrituras() == []


def test_familia_que_no_existe():
    p = herramienta("importar_thehive.py", "--url", "http://127.0.0.1:9", "no-existe", env=entorno(THEHIVE_API_KEY=API_KEY))
    assert p.returncode == 1
    assert "No hay plantillas" in p.stderr


# === validar.py ==============================================================

def test_validar_sale_con_0():
    p = herramienta("validar.py")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "0 error(es)" in p.stdout
    assert "Catalogo coherente" in p.stdout


def test_validar_json():
    p = herramienta("validar.py", "--json")
    assert p.returncode == 0, p.stderr
    datos = json.loads(p.stdout)
    assert datos["errores"] == []
    catalogo = json.loads((RAIZ / "catalogo" / "catalogo.json").read_text(encoding="utf-8"))
    assert datos["metricas"]["reglas"] == len(catalogo["reglas"])
    assert set(datos["metricas"]["familias"]) == set(catalogo["familias"])
    # El techo de automatizacion: nunca una accion automatica de radio amplio
    for fam, modos in datos["metricas"]["modos_critico"].items():
        assert set(modos) <= {"automatica", "aprobacion", "manual", "no_aplicable", "prohibida"}, fam


# === simular.py ==============================================================

def test_simular_un_escenario_desde_la_consola():
    p = herramienta("simular.py", "ransomware-puesto", "--detalle")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "OK  ransomware-puesto" in p.stdout
    assert "1/1 escenarios correctos" in p.stdout
    assert "MAL" not in p.stdout


def test_simular_json():
    p = herramienta("simular.py", "regla-desconocida", "--json")
    assert p.returncode == 0, p.stderr
    [r] = json.loads(p.stdout)
    assert r["id"] == "regla-desconocida" and r["ok"] is True and r["fallos"] == []


def test_simular_escenario_que_no_existe():
    p = herramienta("simular.py", "no-existe")
    assert p.returncode == 1
    assert "No hay escenarios" in p.stdout


@pytest.mark.parametrize("nombre", ["compilar.py", "importar_thehive.py", "simular.py", "validar.py", "sincronizar.py"])
def test_las_herramientas_tienen_ayuda(nombre):
    p = herramienta(nombre, "--help")
    assert p.returncode == 0, p.stderr
    assert "usage" in p.stdout.lower()
