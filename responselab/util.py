"""Utilidades compartidas por las herramientas de construccion y el motor."""
from __future__ import annotations

import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any

RAIZ = Path(__file__).resolve().parent.parent


def consola_utf8() -> None:
    """En Windows la consola usa cp1252 y no imprime ni tildes ni simbolos.

    Sin esto, una herramienta hace su trabajo y revienta con UnicodeEncodeError
    al contarlo, que es la peor forma de fallar.
    """
    for flujo in (sys.stdout, sys.stderr):
        if hasattr(flujo, "reconfigure"):
            try:
                flujo.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def normalizar_texto(texto: str) -> str:
    """Minusculas, sin tildes ni puntuacion: la clave estable de un texto.

    Se usa para casar las acciones de DetectionLab, que son prosa, con las
    acciones ejecutables de ResponseLab. Si alguien cambia una coma aguas
    arriba la clave no cambia; si cambia el sentido, si, y el validador lo
    senala como accion nueva sin mapear en vez de ejecutar algo distinto.
    """
    texto = unicodedata.normalize("NFKD", str(texto)).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", " ", texto.lower()).strip()


def json_estable(datos: Any) -> str:
    """JSON determinista: mismo contenido, mismos bytes.

    El CI regenera todo y compara con lo commiteado. Con claves desordenadas o
    marcas de tiempo, esa comparacion fallaria en cada ejecucion por un motivo
    que no es un error, y acabaria desactivada.
    """
    return json.dumps(datos, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def sha256_texto(texto: str) -> str:
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


def leer_exacto(ruta: Path) -> str:
    """Lee sin traducir finales de linea: un .ps1 con CRLF se compara tal cual."""
    with open(ruta, encoding="utf-8", newline="") as f:
        return f.read()


def escribir_si_cambia(ruta: Path, contenido: str) -> bool:
    """Escribe solo si el contenido es distinto. Devuelve True si escribio."""
    ruta.parent.mkdir(parents=True, exist_ok=True)
    if ruta.exists() and leer_exacto(ruta) == contenido:
        return False
    ruta.write_text(contenido, encoding="utf-8", newline="\n")
    return True
