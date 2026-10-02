"""
Exportadores: del catalogo compilado a los artefactos nativos de cada SOAR y SIEM.

Cada exportador recibe el catalogo y devuelve {ruta relativa: contenido}. Son
funciones puras y deterministas: el CI los ejecuta y compara con lo commiteado.
"""
from __future__ import annotations

import importlib

EXPORTADORES = ["thehive", "shuffle", "splunk_soar", "n8n", "sentinel", "xsoar", "siem"]


def exportar_todo(catalogo: dict) -> dict[str, str]:
    salidas: dict[str, str] = {}
    for nombre in EXPORTADORES:
        try:
            modulo = importlib.import_module(f"{__name__}.{nombre}")
        except ModuleNotFoundError as e:
            if e.name == f"{__name__}.{nombre}":
                continue
            raise
        salidas.update(modulo.exportar(catalogo))
    return salidas
