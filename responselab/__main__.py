"""
Linea de ordenes del motor.

    python -m responselab servir [--puerto 8080]      arranca la API
    python -m responselab token                        genera un token y su huella para un perfil
    python -m responselab decidir --siem wazuh --cliente lab alerta.json
                                                       plan de una alerta sin ejecutar nada
    python -m responselab auditoria                    verifica la cadena de auditoria
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path

from .util import consola_utf8

consola_utf8()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="responselab", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="orden", required=True)
    s = sub.add_parser("servir")
    s.add_argument("--puerto", type=int, default=8080)
    s.add_argument("--host", default="0.0.0.0")
    sub.add_parser("token")
    d = sub.add_parser("decidir")
    d.add_argument("--siem", default="generico")
    d.add_argument("--cliente", default="lab")
    d.add_argument("fichero", type=Path)
    sub.add_parser("auditoria")
    args = ap.parse_args(argv)

    if args.orden == "servir":
        import uvicorn
        uvicorn.run("responselab.api:app_desde_entorno", factory=True, host=args.host, port=args.puerto,
                    proxy_headers=True, forwarded_allow_ips="*")
        return 0

    if args.orden == "token":
        from .clientes import huella
        t = secrets.token_urlsafe(32)
        print(f"token (entregalo una vez, no se guarda):  {t}")
        print(f"token_sha256 (va en el perfil del cliente): {huella(t)}")
        return 0

    from .config import Config
    if args.orden == "decidir":
        from . import nucleo
        from .clientes import Clientes
        cfg = Config()
        catalogo = nucleo.Catalogo(json.loads(cfg.catalogo.read_text(encoding="utf-8")))
        cliente = Clientes(cfg.clientes).get(args.cliente) or {}
        alerta = nucleo.normalizar(args.siem, json.loads(args.fichero.read_text(encoding="utf-8")), args.cliente)
        plan = nucleo.decidir(alerta, catalogo, cliente, {})
        print(json.dumps(plan, indent=2, ensure_ascii=False))
        return 0

    if args.orden == "auditoria":
        from .almacen import Almacen
        r = Almacen(Config().base_datos).verificar_auditoria()
        print(json.dumps(r, indent=2))
        return 0 if r["integra"] else 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
