#!/usr/bin/env python3
"""
Compila el catalogo del motor y genera los artefactos de cada SOAR.

    catalogo/catalogo.json           lo que carga el motor
    soar/thehive/                    plantillas de caso
    soar/shuffle/                    workflow + nodo con el nucleo de decision
    soar/splunk-soar/                playbooks Python
    soar/n8n/                        workflow
    soar/sentinel/                   Logic Apps (ARM) + reglas de automatizacion
    soar/xsoar/                      playbooks YAML + script de decision
    docs/COBERTURA.md                que se automatiza, por familia

Todo lo generado es determinista (sin marcas de tiempo): el CI lo regenera y
falla si no coincide con lo commiteado.

Uso:
    python tools/compilar.py             compila y escribe
    python tools/compilar.py --comprobar no escribe; sale con 1 si algo esta desfasado
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from responselab import compilador, validacion  # noqa: E402
from responselab import util  # noqa: E402
from responselab.util import RAIZ, consola_utf8, json_estable  # noqa: E402

consola_utf8()


def generar_todo() -> tuple[dict[str, str], list[str]]:
    """Devuelve {ruta relativa: contenido} de todo lo generado."""
    catalogo, avisos = compilador.compilar()
    salidas = {"catalogo/catalogo.json": json_estable(catalogo)}
    try:
        from responselab import exportadores
    except ImportError:
        exportadores = None
    if exportadores is not None:
        salidas.update(exportadores.exportar_todo(catalogo))
    _, _, metricas = validacion.validar(catalogo, validacion.cargar_contratos())
    from responselab.exportadores import cobertura
    salidas["docs/COBERTURA.md"] = cobertura.generar(catalogo, metricas)
    return salidas, avisos


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--comprobar", action="store_true")
    args = ap.parse_args()

    salidas, avisos = generar_todo()
    desfasados, escritos = [], []
    for rel, contenido in sorted(salidas.items()):
        ruta = RAIZ / rel
        actual = util.leer_exacto(ruta) if ruta.exists() else None
        if actual == contenido:
            continue
        if args.comprobar:
            desfasados.append(rel)
        else:
            ruta.parent.mkdir(parents=True, exist_ok=True)
            ruta.write_text(contenido, encoding="utf-8", newline="\n")
            escritos.append(rel)

    # Lo que sobra en soar/ (un SOAR o una familia que ya no existen) se borra:
    # dejarlo seria ofrecer para importar un playbook que nadie mantiene.
    # En siem/ conviven ficheros escritos a mano y generados: solo se borran los
    # que llevan la marca de generado y ya no salen de la compilacion.
    generados = {rel for rel in salidas if rel.startswith(("soar/", "siem/"))}
    candidatos = sorted((RAIZ / "soar").rglob("*")) if (RAIZ / "soar").exists() else []
    for f in sorted((RAIZ / "siem").rglob("*")) if (RAIZ / "siem").exists() else []:
        if f.is_file() and f.suffix in (".conf", ".json", ".xml", ".md", ".yml") and \
                "Generado por ResponseLab (tools/compilar.py)" in f.read_text(encoding="utf-8", errors="ignore")[:400]:
            candidatos.append(f)
    for f in candidatos:
        rel = f.relative_to(RAIZ).as_posix()
        if f.is_file() and rel not in generados and not f.name.startswith(("LEEME", "README", ".")):
            if args.comprobar:
                desfasados.append(rel + " (sobra)")
            else:
                f.unlink()
                escritos.append(rel + " (borrado)")

    if args.comprobar:
        if desfasados:
            print("Lo generado no coincide con las fuentes. Ejecuta 'python tools/compilar.py' y haz commit:")
            for d in desfasados:
                print(f"  ~ {d}")
            return 1
        print(f"Todo lo generado esta al dia ({len(salidas)} ficheros).")
        return 0

    for e in escritos:
        print(f"  ~ {e}")
    print(f"{len(salidas)} ficheros generados, {len(escritos)} cambiados.")
    if avisos:
        print(f"\n{len(avisos)} aviso(s) de compilacion:")
        for a in avisos:
            print(f"  ! {a}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
