#!/usr/bin/env python3
"""
Valida el catalogo compilado, los contratos con el ecosistema y las invariantes.

    python tools/validar.py              errores -> salida 1; avisos solo se listan
    python tools/validar.py --estricto   los avisos tambien cuentan como error
    python tools/validar.py --json       metricas en JSON (para el CI y el README)

Que comprueba y por que, en detalle, en responselab/validacion.py. La version
corta: que todo lo que el motor va a ejecutar existe y esta bien formado, que
los proyectos vecinos siguen produciendo lo que el motor sabe leer, y que
ninguna regla del catalogo puede acabar en una accion automatica de radio
cuenta u organizacion.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from responselab import compilador, validacion  # noqa: E402
from responselab.util import consola_utf8  # noqa: E402

consola_utf8()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--estricto", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if not compilador.SALIDA.exists():
        print("No hay catalogo compilado. Ejecuta antes: python tools/compilar.py")
        return 1
    catalogo = json.loads(compilador.SALIDA.read_text(encoding="utf-8"))
    errores, avisos, metricas = validacion.validar(catalogo, validacion.cargar_contratos())

    if args.json:
        print(json.dumps({"errores": errores, "avisos": avisos, "metricas": metricas}, indent=2, ensure_ascii=False))
        return 1 if errores or (args.estricto and avisos) else 0

    m = metricas
    print(f"Catalogo {catalogo['version']}: {m['reglas']} reglas "
          f"({', '.join(f'{k} {v}' for k, v in sorted(m['reglas_por_origen'].items()))}), "
          f"{len(m['familias'])} familias, {m['acciones_catalogo']} acciones")
    tri = sum(f["triaje"] for f in m["familias"].values())
    tri_a = sum(f["triaje_auto"] for f in m["familias"].values())
    con = sum(f["contencion"] for f in m["familias"].values())
    con_m = sum(f["contencion_mapeada"] for f in m["familias"].values())
    print(f"Triaje: {tri_a}/{tri} preguntas con evaluador automatico · "
          f"Contencion: {con_m}/{con} acciones de DetectionLab mapeadas a algo ejecutable")
    print("\nAlerta critica de cada familia, con un cliente que lo permite todo:")
    for fam, modos in m["modos_critico"].items():
        print(f"  {fam:14} " + "  ".join(f"{k}={v}" for k, v in sorted(modos.items())))

    print(f"\n{len(errores)} error(es), {len(avisos)} aviso(s)")
    for e in errores:
        print(f"  x {e}")
    for a in avisos:
        print(f"  ! {a}")
    if not errores:
        print("\nCatalogo coherente: ninguna regla puede producir una accion automatica de radio amplio.")
    return 1 if errores or (args.estricto and avisos) else 0


if __name__ == "__main__":
    sys.exit(main())
