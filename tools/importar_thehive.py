#!/usr/bin/env python3
"""
Importa en TheHive 5 las plantillas de caso de soar/thehive/plantillas/.

    python tools/importar_thehive.py --url https://thehive:9000 --organizacion SOC
    python tools/importar_thehive.py --url ... --organizacion ACME endpoint ad
    python tools/importar_thehive.py --url ... --comprobar      dice que haria, sin tocar nada
    python tools/importar_thehive.py --url ... --reemplazar     borra y crea en vez de actualizar

La clave de API se lee de la variable de entorno THEHIVE_API_KEY, nunca de un
argumento: quedaria en el historial de la consola. Con --organizacion se envia
la cabecera X-Organisation; en un MSSP con una organizacion por cliente, se
ejecuta una vez por organizacion.

Una plantilla con el mismo nombre se actualiza (PATCH) con la descripcion y las
tareas nuevas. Los campos personalizados que el SOC le haya anadido en TheHive
se conservan: la plantilla generada no los trae. Los casos ya abiertos no
cambian; TheHive copia las tareas al crear el caso.

Sale con 1 si alguna plantilla no se pudo importar.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))
from responselab.util import consola_utf8  # noqa: E402

PLANTILLAS = RAIZ / "soar" / "thehive" / "plantillas"
consola_utf8()


def cargar(nombres: list[str]) -> list[dict]:
    salida = []
    for f in sorted(PLANTILLAS.glob("*.json")):
        if nombres and f.stem.lstrip("_") not in {n.lstrip("_") for n in nombres}:
            continue
        salida.append(json.loads(f.read_text(encoding="utf-8")))
    return salida


def existentes(http, base: str) -> dict[str, str]:
    """Nombre -> id de las plantillas de la organizacion."""
    r = http.post(f"{base}/api/v1/query", params={"name": "caseTemplate"},
                  json={"query": [{"_name": "listCaseTemplate"}, {"_name": "page", "from": 0, "to": 1000}]})
    r.raise_for_status()
    return {p["name"]: p["_id"] for p in r.json() if p.get("name")}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("familias", nargs="*", help="solo estas familias (por defecto, todas)")
    ap.add_argument("--url", required=True, help="URL de TheHive, p.ej. https://thehive:9000")
    ap.add_argument("--organizacion", default="", help="organizacion de TheHive (cabecera X-Organisation)")
    ap.add_argument("--comprobar", action="store_true", help="no escribe: dice que crearia o actualizaria")
    ap.add_argument("--reemplazar", action="store_true", help="borra y crea las que existen en vez de actualizarlas")
    ap.add_argument("--ca", default="", help="certificado de la CA del servidor")
    ap.add_argument("--sin-verificar-tls", action="store_true")
    args = ap.parse_args()

    clave = os.environ.get("THEHIVE_API_KEY", "")
    if not clave:
        print("Falta la variable de entorno THEHIVE_API_KEY.", file=sys.stderr)
        return 2
    plantillas = cargar(args.familias)
    if not plantillas:
        print("No hay plantillas que importar. Ejecuta antes: python tools/compilar.py", file=sys.stderr)
        return 1

    import httpx
    cabeceras = {"Authorization": f"Bearer {clave}"}
    if args.organizacion:
        cabeceras["X-Organisation"] = args.organizacion
    verificar = False if args.sin_verificar_tls else (args.ca or True)
    base = args.url.rstrip("/")
    fallos = 0
    with httpx.Client(headers=cabeceras, verify=verificar, timeout=30) as http:
        try:
            hay = existentes(http, base)
        except httpx.HTTPError as e:
            print(f"No se pudo listar las plantillas de TheHive: {e}", file=sys.stderr)
            return 1
        for p in plantillas:
            nombre = p["name"]
            cuerpo = {k: v for k, v in p.items() if not (k == "customFields" and not v)}
            ident = hay.get(nombre)
            verbo = "crear" if not ident else ("reemplazar" if args.reemplazar else "actualizar")
            if args.comprobar:
                print(f"  {verbo:11} {nombre} ({len(p.get('tasks') or [])} tareas)")
                continue
            try:
                if ident and args.reemplazar:
                    http.delete(f"{base}/api/v1/caseTemplate/{ident}").raise_for_status()
                    ident = None
                if ident:
                    r = http.patch(f"{base}/api/v1/caseTemplate/{ident}", json=cuerpo)
                else:
                    r = http.post(f"{base}/api/v1/caseTemplate", json=cuerpo)
                r.raise_for_status()
                print(f"  ok  {verbo:11} {nombre} ({len(p.get('tasks') or [])} tareas)")
            except httpx.HTTPStatusError as e:
                fallos += 1
                print(f"  MAL {verbo:11} {nombre}: HTTP {e.response.status_code} {e.response.text[:300]}")
                if ident and e.response.status_code == 400:
                    print("      si tu version de TheHive no admite cambiar las tareas con PATCH, usa --reemplazar")
            except httpx.HTTPError as e:
                fallos += 1
                print(f"  MAL {verbo:11} {nombre}: {e}")
    if not args.comprobar:
        print(f"\n{len(plantillas) - fallos}/{len(plantillas)} plantillas importadas"
              + (f" en la organizacion {args.organizacion}" if args.organizacion else "") + ".")
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
