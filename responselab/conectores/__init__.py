"""Registro de conectores: nombre -> clase, y como se construyen para un cliente."""
from __future__ import annotations

from pathlib import Path

from .base import Conector, ErrorConector, NoSoportada, Resultado
from .declarativo import Declarativo, Script, cargar_declarativos
from .edr import CrowdStrike, SentinelOne
from .interno import Edl, Interno
from .kubernetes import Kubernetes
from .microsoft import Defender, Entra, Exchange
from .red import Cloudflare, Fortinet, PaloAlto
from .splunk import Splunk
from .thehive import Misp, TheHive
from .wazuh import Wazuh

CLASES: dict[str, type[Conector]] = {
    c.nombre: c for c in (Interno, Edl, Wazuh, TheHive, Misp, Defender, Entra, Exchange, CrowdStrike,
                          SentinelOne, PaloAlto, Fortinet, Cloudflare, Kubernetes, Splunk)
}


def construir(nombre: str, cliente: dict, simulacion: bool, carpeta_declarativos: Path,
              transporte=None, motor=None) -> Conector | None:
    """Instancia el conector `nombre` con la configuracion del cliente.

    Busca primero los integrados y despues los declarativos de conectores/*.yml;
    `script` usa conectores/scripts/.
    """
    cfg = (cliente.get("conectores") or {}).get(nombre) or {}
    if nombre in CLASES:
        return CLASES[nombre](cliente, cfg, simulacion, transporte=transporte, motor=motor)
    if nombre == "script":
        return Script(cliente, cfg, simulacion, transporte=transporte, motor=motor,
                      carpeta=carpeta_declarativos / "scripts")
    definiciones = cargar_declarativos(carpeta_declarativos)
    if nombre in definiciones:
        return Declarativo(cliente, cfg, simulacion, transporte=transporte, motor=motor, definicion=definiciones[nombre])
    return None


__all__ = ["CLASES", "Conector", "ErrorConector", "NoSoportada", "Resultado", "construir"]
