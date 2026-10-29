"""
Copias del estado del motor.

    python -m responselab copia --destino /copias [--conservar 14]

El estado entero del motor es una base SQLite (alertas, incidentes, aprobaciones,
ejecuciones y la auditoria encadenada). La copia se hace en caliente con la API
de copia de SQLite, que es coherente aunque el motor siga escribiendo, y antes de
darla por buena se comprueba:

* que SQLite la da por integra (PRAGMA integrity_check);
* que la cadena de auditoria de la copia verifica con la misma clave del motor.

Una copia que no pasa las dos cosas no sustituye a ninguna anterior: se borra y
la orden termina con error, para que el cron o el servicio de copias lo avise.
Las copias van con permisos 0600 y se conservan las N mas recientes.

La clave de la auditoria no se copia. Si vive en el fichero junto a la base
(RL_CLAVE_AUDITORIA vacia), se avisa: sin ella, una copia restaurada en otra
maquina no se puede verificar.
"""
from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

PREFIJO = "responselab-"


def _nombre(ahora: datetime) -> str:
    return f"{PREFIJO}{ahora.strftime('%Y%m%dT%H%M%SZ')}.db"


def hacer_copia(base: Path, destino: Path, conservar: int = 14, ahora: datetime | None = None) -> dict:
    from .almacen import Almacen, clave_auditoria

    if not base.exists():
        raise FileNotFoundError(f"no existe la base de datos {base}")
    if conservar < 1:
        raise ValueError("--conservar tiene que ser al menos 1")
    destino.mkdir(parents=True, exist_ok=True)
    ahora = ahora or datetime.now(timezone.utc)
    final = destino / _nombre(ahora)
    parcial = final.with_name(final.name + ".parcial")
    clave = clave_auditoria(base)

    origen = sqlite3.connect(str(base), timeout=30)
    copia = sqlite3.connect(str(parcial))
    try:
        origen.backup(copia)
    finally:
        copia.close()
        origen.close()
    os.chmod(parcial, 0o600)

    resultado = {"copia": str(final), "bytes": parcial.stat().st_size, "avisos": []}
    try:
        con = sqlite3.connect(str(parcial))
        resultado["integridad"] = con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        con.close()
        alm = Almacen(parcial, clave)
        resultado["auditoria"] = alm.verificar_auditoria()
        alm.cerrar()
        con = sqlite3.connect(str(parcial))
        con.execute("PRAGMA journal_mode=DELETE")       # la copia es un unico fichero
        con.close()
        for sobrante in (parcial.with_name(parcial.name + "-wal"), parcial.with_name(parcial.name + "-shm")):
            sobrante.unlink(missing_ok=True)
    except sqlite3.DatabaseError as e:
        resultado["integridad"], resultado["error"] = False, str(e)

    if not (resultado.get("integridad") and resultado.get("auditoria", {}).get("integra")):
        parcial.unlink(missing_ok=True)
        resultado["valida"] = False
        return resultado

    os.replace(parcial, final)
    resultado["valida"] = True
    copias = sorted(destino.glob(f"{PREFIJO}*.db"))
    resultado["borradas"] = [str(p) for p in copias[:-conservar]]
    for p in copias[:-conservar]:
        p.unlink()
    resultado["conservadas"] = min(len(copias), conservar)
    if not os.environ.get("RL_CLAVE_AUDITORIA"):
        resultado["avisos"].append(
            "la clave de la auditoria esta en un fichero junto a la base (RL_CLAVE_AUDITORIA vacia): "
            "guardala aparte o una copia restaurada en otra maquina no se podra verificar")
    return resultado
