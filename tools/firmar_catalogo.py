#!/usr/bin/env python3
"""
Firma catalogo/catalogo.json para los motores que tienen RL_CATALOGO_CLAVE.

Lo ejecuta una persona despues de revisar el PR de sincronizacion, nunca el
bot: asi un catalogo que nadie ha mirado no llega a produccion aunque este en
main.

    RL_CATALOGO_CLAVE=... python tools/firmar_catalogo.py
    git add catalogo/catalogo.json.firma && git commit -m "firma el catalogo <version>"
"""
from __future__ import annotations

import hashlib
import hmac
import os
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent


def firmar(catalogo: Path, clave: str) -> str:
    return hmac.new(clave.encode(), catalogo.read_bytes(), hashlib.sha256).hexdigest()


def main() -> int:
    clave = os.environ.get("RL_CATALOGO_CLAVE", "")
    if not clave:
        print("falta RL_CATALOGO_CLAVE", file=sys.stderr)
        return 2
    catalogo = Path(sys.argv[1]) if len(sys.argv) > 1 else RAIZ / "catalogo" / "catalogo.json"
    firma = firmar(catalogo, clave)
    catalogo.with_name(catalogo.name + ".firma").write_text(firma + "\n", encoding="utf-8")
    print(f"{catalogo.name}.firma = {firma}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
