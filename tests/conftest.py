"""
Utilidades comunes de las pruebas.

Nada de lo que hay aqui toca la red ni el disco fuera de tmp_path: el motor se
construye en simulacion, sin DNS, sin descarga de CTI ni de catalogo, y los
conectores que hablan HTTP reciben un httpx.MockTransport.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest
import yaml

RAIZ = Path(__file__).resolve().parent.parent
PRUEBAS = Path(__file__).resolve().parent
for ruta in (RAIZ, PRUEBAS):
    if str(ruta) not in sys.path:
        sys.path.insert(0, str(ruta))

from responselab import nucleo  # noqa: E402
from responselab.config import Config  # noqa: E402

# Tokens de prueba: los perfiles de clientes/ los leen de estas variables
TOKENS = {
    "RL_LAB_TOKEN": "token-ingesta-lab",
    "RL_LAB_TOKEN_AGENTES": "token-agentes-lab",
    "RL_LAB_TOKEN_EDL": "token-edl-lab",
    "RL_LAB_TOKEN_APROBADOR": "token-aprobador-lab",
}


@pytest.fixture(scope="session")
def raiz() -> Path:
    return RAIZ


@pytest.fixture(scope="session")
def catalogo_datos() -> dict:
    return json.loads((RAIZ / "catalogo" / "catalogo.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def catalogo(catalogo_datos) -> nucleo.Catalogo:
    return nucleo.Catalogo(catalogo_datos)


def cargar_perfil(nombre: str) -> dict:
    return yaml.safe_load((RAIZ / "clientes" / f"{nombre}.yml").read_text(encoding="utf-8"))


@pytest.fixture
def perfil_lab() -> dict:
    return cargar_perfil("lab")


@pytest.fixture
def perfil_acme() -> dict:
    return cargar_perfil("acme")


@pytest.fixture
def perfil_norte() -> dict:
    return cargar_perfil("norte")


@pytest.fixture
def entorno_tokens(monkeypatch):
    for k, v in TOKENS.items():
        monkeypatch.setenv(k, v)
    return dict(TOKENS)


@pytest.fixture
def carpeta_clientes(tmp_path) -> Path:
    """Copia de clientes/ que cada prueba puede modificar sin tocar el repositorio."""
    destino = tmp_path / "clientes"
    shutil.copytree(RAIZ / "clientes", destino)
    return destino


@pytest.fixture
def config(tmp_path, carpeta_clientes) -> Config:
    return Config(datos=tmp_path / "datos", clientes=carpeta_clientes, simulacion_global=True, dns_ptr=False,
                  trabajadores=1, vigilancia_seg=3600, cti_url="", actualizacion_url="", token_admin="token-admin")


@pytest.fixture
async def motor(config, entorno_tokens):
    """Motor en simulacion, arrancado sin vigilante; se para al acabar la prueba."""
    from responselab.ejecutor import Motor
    m = Motor(config)
    await m.arrancar(vigilante=False)
    try:
        yield m
    finally:
        await m.parar()
        m.almacen.cerrar()


def alerta_wazuh(regla: str, equipo: str = "PC-0042", nivel: int = 12, descripcion: str = "", **eventdata) -> dict:
    """Alerta minima de Wazuh con datos de Sysmon."""
    return {
        "id": f"t-{regla}-{equipo}-{abs(hash(json.dumps(eventdata, sort_keys=True))) % 10**8}",
        "timestamp": "2026-10-01T10:00:00.000Z",
        "rule": {"id": regla, "level": nivel, "description": descripcion or f"regla {regla}", "groups": ["detection_lab"]},
        "agent": {"id": "042", "name": equipo, "ip": "10.0.20.42"},
        "data": {"win": {"system": {"eventID": "1", "computer": f"{equipo}.lab.test"}, "eventdata": eventdata}},
    }


@pytest.fixture
def nueva_alerta_wazuh():
    return alerta_wazuh
