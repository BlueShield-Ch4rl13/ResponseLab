"""
Pruebas del despliegue en servidor: preparar_servidor.py, las copias y
comprobar_despliegue.py contra un motor de verdad (un proceso uvicorn local).
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "tools"))

import comprobar_despliegue  # noqa: E402
import preparar_servidor  # noqa: E402
from responselab.almacen import Almacen  # noqa: E402
from responselab.copias import hacer_copia  # noqa: E402

POSIX = os.name == "posix"


def raiz_falsa(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    for rel in (".env.example", "clientes/lab.yml", "siem/wazuh/responselab.json.ejemplo",
                "siem/splunk/savedsearches-detectionlab.conf", "siem/splunk/savedsearches-splunklab.conf",
                "siem/splunk/alert_actions.conf"):
        (r / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(RAIZ / rel, r / rel)
    return r


def argumentos(*extra: str):
    import argparse
    ap = argparse.ArgumentParser()
    for opcion, defecto in (("--motor", None), ("--dominio", None), ("--tls", "internal"), ("--bind", None),
                            ("--wazuh", "10.0.30.10"), ("--soar", "10.0.30.11"), ("--cliente", "lab"),
                            ("--env", ".env"), ("--salida", "despliegue/generado")):
        ap.add_argument(opcion, default=defecto)
    return ap.parse_args(["--motor", "10.0.30.20", *extra])


def env_de(ruta: Path) -> dict:
    return comprobar_despliegue.leer_env(ruta)


# ───────────────────────────── preparar_servidor ─────────────────────────────
def test_preparar_genera_los_secretos_y_la_configuracion(tmp_path):
    r = raiz_falsa(tmp_path)
    res = preparar_servidor.preparar(argumentos(), r)
    env = env_de(r / ".env")
    secretos = ["RL_ADMIN_TOKEN", "RL_LAB_TOKEN", "RL_LAB_TOKEN_AGENTES", "RL_LAB_TOKEN_EDL",
                "RL_LAB_TOKEN_APROBADOR", "RL_CLAVE_AUDITORIA"]
    assert all(len(env[s]) >= 32 for s in secretos)
    assert len({env[s] for s in secretos}) == len(secretos), "cada funcion con su propio token"
    assert set(res["generados"]) == set(secretos)
    assert env["RL_URL_PUBLICA"] == "https://10.0.30.20:8443" and env["RL_BIND"] == "10.0.30.20"
    assert env["COMPOSE_FILE"] == "docker-compose.yml:docker-compose.servidor.yml"

    gen = r / "despliegue" / "generado"
    wazuh = json.loads((gen / "wazuh" / "responselab.json").read_text(encoding="utf-8"))
    assert wazuh["motor"] == "https://10.0.30.20:8443" and wazuh["ca"].endswith("responselab-ca.pem")
    assert wazuh["clientes"]["lab"] == {"token_ingesta": env["RL_LAB_TOKEN"],
                                        "token_agentes": env["RL_LAB_TOKEN_AGENTES"]}
    for f in (gen / "splunk").iterdir():
        texto = f.read_text(encoding="utf-8")
        for marcador in ("https://MOTOR", "/v1/CLIENTE/", "TOKEN_DE_INGESTA"):
            assert marcador not in texto, f"{f.name} sigue con {marcador}"
    assert f"token={env['RL_LAB_TOKEN']}" in (gen / "splunk" / "savedsearches-splunklab.conf").read_text()
    assert r"^https:\/\/10\.0\.30\.20(:\d+)?" in (gen / "splunk" / "alert_actions.conf").read_text()
    assert f"edl/ip?token={env['RL_LAB_TOKEN_EDL']}" in (gen / "pfsense" / "edl.txt").read_text()
    if POSIX:
        assert stat.S_IMODE((r / ".env").stat().st_mode) == 0o600
        assert stat.S_IMODE(gen.stat().st_mode) == 0o700
        assert stat.S_IMODE((gen / "wazuh" / "responselab.json").stat().st_mode) == 0o600


def test_preparar_otra_vez_no_cambia_los_tokens(tmp_path):
    r = raiz_falsa(tmp_path)
    preparar_servidor.preparar(argumentos(), r)
    antes = env_de(r / ".env")
    res = preparar_servidor.preparar(argumentos("--dominio", "motor.soc.lab"), r)
    despues = env_de(r / ".env")
    assert res["generados"] == []
    assert all(despues[k] == antes[k] for k in antes if k.endswith(("TOKEN", "_AGENTES", "_EDL", "_APROBADOR"))
               or k == "RL_CLAVE_AUDITORIA")
    assert despues["RL_URL_PUBLICA"] == "https://motor.soc.lab:8443"


def test_preparar_avisa_si_el_perfil_apunta_a_otras_ip(tmp_path):
    r = raiz_falsa(tmp_path)
    res = preparar_servidor.preparar(argumentos("--wazuh", "192.168.30.10"), r)
    assert any("managers" in a and "192.168.30.10" in a for a in res["avisos"])
    res = preparar_servidor.preparar(argumentos(), r)
    assert not any("managers" in a or "permitidos" in a for a in res["avisos"])


def test_preparar_con_cloudflare(tmp_path):
    r = raiz_falsa(tmp_path)
    with pytest.raises(SystemExit):
        preparar_servidor.main(["--motor", "10.0.30.20", "--tls", "cloudflare"])   # sin dominio
    res = preparar_servidor.preparar(argumentos("--dominio", "motor.lab.ejemplo.com", "--tls", "cloudflare"), r)
    env = env_de(r / ".env")
    assert env["COMPOSE_FILE"].endswith(":docker-compose.cloudflare.yml")
    assert any("CLOUDFLARE_API_TOKEN" in a for a in res["avisos"])
    wazuh = json.loads((r / "despliegue/generado/wazuh/responselab.json").read_text(encoding="utf-8"))
    assert wazuh["ca"] == "", "con un certificado publico vale la confianza del sistema"


# ─────────────────────────────────── copias ──────────────────────────────────
def base_con_auditoria(tmp_path: Path, n: int = 5) -> Path:
    ruta = tmp_path / "datos" / "responselab.db"
    alm = Almacen(ruta, b"clave-de-prueba")
    for i in range(n):
        alm.auditar("lab", "prueba", "evento", {"n": i})
    alm.cerrar()
    return ruta


def test_copia_verificada_con_rotacion(tmp_path, monkeypatch):
    monkeypatch.setenv("RL_CLAVE_AUDITORIA", "clave-de-prueba")
    base = base_con_auditoria(tmp_path)
    destino = tmp_path / "copias"
    t0 = datetime(2026, 10, 25, 6, 0, tzinfo=timezone.utc)
    for h in range(3):
        r = hacer_copia(base, destino, conservar=2, ahora=t0 + timedelta(hours=6 * h))
        assert r["valida"] and r["integridad"] and r["auditoria"] == {**r["auditoria"], "integra": True}
    copias = sorted(p.name for p in destino.iterdir())
    assert copias == ["responselab-20261025T120000Z.db", "responselab-20261025T180000Z.db"]
    con = sqlite3.connect(destino / copias[-1])
    assert con.execute("SELECT COUNT(*) FROM auditoria").fetchone()[0] == 5
    assert con.execute("PRAGMA journal_mode").fetchone()[0] == "delete", "la copia es un solo fichero"
    con.close()
    if POSIX:
        assert stat.S_IMODE((destino / copias[-1]).stat().st_mode) == 0o600
    assert r["avisos"] == []


def test_una_copia_con_la_auditoria_rota_no_sustituye_a_nada(tmp_path, monkeypatch):
    monkeypatch.setenv("RL_CLAVE_AUDITORIA", "clave-de-prueba")
    base = base_con_auditoria(tmp_path)
    destino = tmp_path / "copias"
    assert hacer_copia(base, destino)["valida"]
    con = sqlite3.connect(base)
    con.execute("UPDATE auditoria SET detalle = '{\"n\": 99}' WHERE n = 3")   # alguien reescribe la historia
    con.commit()
    con.close()
    r = hacer_copia(base, destino, ahora=datetime.now(timezone.utc) + timedelta(hours=1))
    assert not r["valida"] and r["auditoria"]["integra"] is False
    assert len(list(destino.glob("responselab-*.db"))) == 1, "la copia buena anterior sigue ahi"
    assert not list(destino.glob("*.parcial")), "no quedan restos"


def test_la_orden_copia(tmp_path, monkeypatch):
    monkeypatch.setenv("RL_CLAVE_AUDITORIA", "clave-de-prueba")
    base = base_con_auditoria(tmp_path)
    monkeypatch.setenv("RL_DATOS", str(base.parent))
    from responselab.__main__ import main
    assert main(["copia", "--destino", str(tmp_path / "copias"), "--conservar", "3"]) == 0
    assert len(list((tmp_path / "copias").glob("responselab-*.db"))) == 1


# ───────────────────────────── comprobar_despliegue ──────────────────────────
def puerto_libre() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture
def motor_real(tmp_path):
    """El motor de verdad (python -m responselab servir) con los tokens de un .env
    generado por preparar_servidor, en simulacion y sin red."""
    r = raiz_falsa(tmp_path)
    preparar_servidor.preparar(argumentos(), r)
    env = env_de(r / ".env")
    puerto = puerto_libre()
    entorno = {**os.environ, **{k: v for k, v in env.items() if k.startswith("RL_")},
               "RL_DATOS": str(tmp_path / "datos"), "RL_SIMULACION_GLOBAL": "true",
               "RL_ACTUALIZACION_URL": "", "RL_CTI_URL": "", "PYTHONPATH": str(RAIZ)}
    proc = subprocess.Popen([sys.executable, "-m", "responselab", "servir", "--host", "127.0.0.1",
                             "--puerto", str(puerto)], cwd=RAIZ, env=entorno,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{puerto}"
    try:
        for _ in range(100):
            try:
                if httpx.get(f"{url}/salud", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        else:
            pytest.fail("el motor no arranco")
        yield url, r / ".env"
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_comprobar_un_motor_sano(motor_real, capsys):
    url, env = motor_real
    codigo = comprobar_despliegue.main(["--url", url, "--env", str(env), "--escenarios"])
    salida = capsys.readouterr().out
    assert codigo == 0, salida
    assert "FALLO" not in salida
    assert "escenarios" in salida and "incidente(s) nuevo(s)" in salida
    assert "AVISO modo" in salida, "en simulacion lo dice"


def test_comprobar_falla_con_un_token_que_no_es(motor_real, tmp_path, capsys):
    url, env = motor_real
    malo = tmp_path / "otro.env"
    malo.write_text(env.read_text().replace("RL_ADMIN_TOKEN=", "RL_ADMIN_TOKEN=otro"), encoding="utf-8")
    assert comprobar_despliegue.main(["--url", url, "--env", str(malo)]) == 1
    assert "FALLO" in capsys.readouterr().out


def test_comprobar_sin_motor(tmp_path, capsys):
    assert comprobar_despliegue.main(["--url", f"http://127.0.0.1:{puerto_libre()}",
                                      "--env", str(tmp_path / "no.env")]) == 1
    assert "FALLO conexion" in capsys.readouterr().out
