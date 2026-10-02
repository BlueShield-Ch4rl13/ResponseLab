"""Configuracion del motor. Todo sale del entorno; nada sensible va en ficheros."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .util import RAIZ


def _bool(valor: str | None, defecto: bool = False) -> bool:
    if valor is None:
        return defecto
    return valor.strip().lower() in ("1", "true", "si", "yes", "on")


@dataclass
class Config:
    datos: Path = field(default_factory=lambda: Path(os.environ.get("RL_DATOS", RAIZ / "datos")))
    catalogo: Path = field(default_factory=lambda: Path(os.environ.get("RL_CATALOGO", RAIZ / "catalogo" / "catalogo.json")))
    clientes: Path = field(default_factory=lambda: Path(os.environ.get("RL_CLIENTES", RAIZ / "clientes")))
    conectores: Path = field(default_factory=lambda: Path(os.environ.get("RL_CONECTORES", RAIZ / "conectores")))
    # Token de administracion (recargar catalogo, ver todo). Sin el, la API de
    # administracion no responde: no hay token por defecto.
    token_admin: str = field(default_factory=lambda: os.environ.get("RL_ADMIN_TOKEN", ""))
    url_publica: str = field(default_factory=lambda: os.environ.get("RL_URL_PUBLICA", "http://localhost:8080"))
    # Modo global. "simulacion" se impone a todos los clientes aunque su perfil
    # diga produccion: es el interruptor de emergencia.
    simulacion_global: bool = field(default_factory=lambda: _bool(os.environ.get("RL_SIMULACION_GLOBAL"), False))
    trabajadores: int = field(default_factory=lambda: int(os.environ.get("RL_TRABAJADORES", "4")))
    # Actualizacion en caliente del catalogo desde el repositorio
    actualizacion_url: str = field(default_factory=lambda: os.environ.get(
        "RL_ACTUALIZACION_URL", ""))
    actualizacion_min: int = field(default_factory=lambda: int(os.environ.get("RL_ACTUALIZACION_MIN", "30")))
    # Inteligencia de News CTI
    cti_url: str = field(default_factory=lambda: os.environ.get(
        "RL_CTI_URL", "https://raw.githubusercontent.com/BlueShield-Ch4rl13/ScriptNewsCTI/main/data/iocs_latest.json"))
    cti_min: int = field(default_factory=lambda: int(os.environ.get("RL_CTI_MIN", "60")))
    cti_nivel_minimo: str = field(default_factory=lambda: os.environ.get("RL_CTI_NIVEL_MINIMO", "media"))
    cti_max_dias: int = field(default_factory=lambda: int(os.environ.get("RL_CTI_MAX_DIAS", "30")))
    # Resolucion inversa para la pregunta "el destino es una CDN"
    dns_ptr: bool = field(default_factory=lambda: _bool(os.environ.get("RL_DNS_PTR"), True))
    # Tareas periodicas
    vigilancia_seg: int = field(default_factory=lambda: int(os.environ.get("RL_VIGILANCIA_SEG", "60")))
    # Limitador: misma regla y mismo equipo, como el de la integracion de
    # DetectionLab. Una deteccion en bucle no consume el turno entero.
    limite_ventana_seg: int = field(default_factory=lambda: int(os.environ.get("RL_LIMITE_VENTANA_SEG", "300")))
    limite_por_clave: int = field(default_factory=lambda: int(os.environ.get("RL_LIMITE_POR_CLAVE", "5")))
    tamano_maximo: int = field(default_factory=lambda: int(os.environ.get("RL_TAMANO_MAXIMO", str(1024 * 1024))))
    log_nivel: str = field(default_factory=lambda: os.environ.get("RL_LOG_NIVEL", "INFO"))

    @property
    def base_datos(self) -> Path:
        return self.datos / "responselab.db"
