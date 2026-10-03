#!/usr/bin/env python3
"""
Reproduce los escenarios de ataque de escenarios/ contra el motor y comprueba
la respuesta.

    python tools/simular.py                      todos, en un motor local en simulacion
    python tools/simular.py ransomware-puesto    uno
    python tools/simular.py --detalle            el plan de cada alerta
    python tools/simular.py --enviar https://motor:8443 --cliente lab --token TOKEN [escenario]
                                                 envia las alertas a un motor de verdad
                                                 (purple team: ver la respuesta en el panel)

Sale con 1 si alguna comprobacion falla: el CI lo ejecuta en cada cambio.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from responselab import simulador  # noqa: E402
from responselab.util import consola_utf8  # noqa: E402

consola_utf8()


def enviar(escenarios, url: str, cliente: str, token: str, verificar: bool) -> int:
    import httpx
    fallos = 0
    with httpx.Client(timeout=30, verify=verificar) as http:
        for esc in escenarios:
            if esc.get("cliente", "lab") != cliente:
                # Las alertas de un escenario tienen sentido contra el perfil para el
                # que se escribieron (inventario, capacidades); el token es de uno.
                print(f"\n== {esc['id']}: omitido (es del cliente {esc.get('cliente', 'lab')}, no de {cliente})")
                continue
            print(f"\n== {esc['id']}: {esc.get('nombre', '')}")
            base = simulador.momento_inicial(esc)
            for n, a in enumerate(esc["alertas"], 1):
                carga = simulador.preparar(a["siem"], a["carga"], base + timedelta(minutes=a.get("minuto", 0)),
                                           f"{esc['id']}-{n}-{int(time.time())}")
                r = http.post(f"{url.rstrip('/')}/v1/{cliente}/alertas/{a['siem']}", json=carga,
                              headers={"Authorization": f"Bearer {token}"})
                print(f"  {n}. {a.get('descripcion', a['siem'])}: HTTP {r.status_code} {r.text[:120]}")
                fallos += r.status_code >= 300
    print("\nLa respuesta se ve en el panel del motor (/panel) y en la auditoria.")
    return 1 if fallos else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("escenarios", nargs="*")
    ap.add_argument("--detalle", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--enviar", metavar="URL")
    ap.add_argument("--cliente", default="lab")
    ap.add_argument("--token", default="")
    ap.add_argument("--sin-verificar-tls", action="store_true")
    args = ap.parse_args()

    escenarios = simulador.cargar(nombres=args.escenarios or None)
    if not escenarios:
        print("No hay escenarios con ese nombre.")
        return 1
    if args.enviar:
        return enviar(escenarios, args.enviar, args.cliente, args.token, not args.sin_verificar_tls)

    resultados = simulador.ejecutar(escenarios)
    if args.json:
        print(json.dumps(resultados, ensure_ascii=False, indent=1, default=str))
        return 0 if all(r["ok"] for r in resultados) else 1
    for r in resultados:
        print(f"\n{'OK ' if r['ok'] else 'MAL'} {r['id']}: {r['nombre']} ({r['comprobaciones']} comprobaciones)")
        for a in r["alertas"]:
            print(f"   {a['n']}. {a['descripcion'] or a['regla']}")
            print(f"      {a['familia']} | {a['clase']} | sev {a['severidad']} | {a['estado']} | escalar a {a['escalado']}"
                  + (f" | secuencias: {', '.join(a['secuencias'])}" if a['secuencias'] else ""))
            if args.detalle:
                for pid, accion, modo, motivo in a["acciones"]:
                    print(f"        {pid:4} {modo:12} {accion}  ({motivo})")
                for accion, conector, estado in a["ejecuciones"]:
                    print(f"        -> {accion} con {conector or '-'}: {estado}")
            for ok, texto in a["comprobaciones"]:
                if not ok or args.detalle:
                    print(f"      {'ok ' if ok else 'MAL'} {texto}")
        for ok, texto in r["final"]:
            if not ok or args.detalle:
                print(f"   {'ok ' if ok else 'MAL'} {texto}")
    total = len(resultados)
    bien = sum(r["ok"] for r in resultados)
    print(f"\n{bien}/{total} escenarios correctos, "
          f"{sum(r['comprobaciones'] for r in resultados) - sum(len(r['fallos']) for r in resultados)}"
          f"/{sum(r['comprobaciones'] for r in resultados)} comprobaciones.")
    return 0 if bien == total else 1


if __name__ == "__main__":
    sys.exit(main())
