"""
Comprueba un motor desplegado, desde fuera, como lo veran Wazuh, Splunk y el panel.

    python tools/comprobar_despliegue.py --url https://10.0.30.20:8443 --ca responselab-ca.pem
    python tools/comprobar_despliegue.py --url ... --ca ... --conectividad   # y llega a Wazuh y TheHive
    python tools/comprobar_despliegue.py --url ... --ca ... --escenarios     # y le lanza los ataques

Lee los tokens de .env (los que dejo tools/preparar_servidor.py) y no los
muestra. Cada comprobacion sale con OK, AVISO o FALLO; si hay algun FALLO, la
orden termina con error, para usarla tras cada actualizacion o en un cron.

Que comprueba:
  - TLS: el certificado es valido para la URL con la CA indicada (o la del sistema).
  - /salud sin token: vivo, y sin datos de clientes.
  - /salud con el token de administracion: catalogo cargado, perfiles sin errores,
    News CTI, cola y si esta en simulacion.
  - Autenticacion: sin token no se ve nada; con el del aprobador, si.
  - La cadena de auditoria verifica entera.
  - La lista EDL responde con su token (lo que leera pfSense).
  - --conectividad: el servidor abre conexion con la API de Wazuh y con TheHive.
  - --escenarios: los ataques de escenarios/ del cliente entran y abren incidentes.
"""
from __future__ import annotations

import argparse
import re
import socket
import sys
from pathlib import Path

import httpx

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ))

from responselab.util import consola_utf8  # noqa: E402

consola_utf8()


def leer_env(ruta: Path) -> dict[str, str]:
    salida = {}
    if ruta.exists():
        for linea in ruta.read_text(encoding="utf-8").splitlines():
            m = re.match(r"^([A-Z0-9_]+)=(.*)$", linea.strip())
            if m:
                salida[m.group(1)] = m.group(2).strip()
    return salida


class Informe:
    def __init__(self):
        self.filas: list[tuple[str, str, str]] = []

    def anotar(self, estado: str, que: str, detalle: str = "") -> None:
        self.filas.append((estado, que, detalle))
        print(f"  {estado:5} {que}" + (f": {detalle}" if detalle else ""))

    def ok(self, que, detalle=""):
        self.anotar("OK", que, detalle)

    def aviso(self, que, detalle=""):
        self.anotar("AVISO", que, detalle)

    def fallo(self, que, detalle=""):
        self.anotar("FALLO", que, detalle)

    @property
    def fallos(self) -> int:
        return sum(1 for e, _, _ in self.filas if e == "FALLO")


def comprobar(url: str, verificar, env: dict, cliente: str, informe: Informe,
              escenarios: bool = False, conectividad: bool = False) -> None:
    url = url.rstrip("/")
    admin = env.get("RL_ADMIN_TOKEN", "")
    pre = f"RL_{cliente.upper()}_"
    ingesta = env.get(f"{pre}TOKEN", "")
    aprobador = env.get(f"{pre}TOKEN_APROBADOR", "")
    edl = env.get(f"{pre}TOKEN_EDL", "")

    http = httpx.Client(timeout=15, verify=verificar)
    try:
        r = http.get(f"{url}/salud")
    except httpx.ConnectError as e:
        http.close()
        informe.fallo("conexion y TLS", str(e)[:200])
        return
    if url.startswith("http://"):
        informe.aviso("conexion y TLS", "sin TLS: los SIEM tienen que llegar por https al proxy")
    else:
        informe.ok("conexion y TLS", "certificado valido" if verificar else "sin verificar el certificado")

    try:
        basico = r.json() if r.status_code == 200 else {}
        if r.status_code == 200 and basico.get("estado") == "ok":
            informe.ok("/salud", f"version {basico.get('version')}, cola {basico.get('cola')}")
        else:
            informe.fallo("/salud", f"HTTP {r.status_code} {r.text[:120]}")
        if "clientes" in basico or "perfiles_con_error" in basico:
            informe.fallo("/salud sin token", "publica datos de los clientes")

        if not admin:
            informe.fallo("token de administracion", "RL_ADMIN_TOKEN vacio en .env")
        else:
            d = http.get(f"{url}/salud", headers={"Authorization": f"Bearer {admin}"}).json()
            cat = d.get("catalogo") or {}
            if cat.get("version") and not cat.get("error"):
                informe.ok("catalogo", f"{cat['version']} ({cat.get('origen')})")
            elif cat.get("version"):
                informe.aviso("catalogo", f"{cat['version']}, ultimo error al actualizar: {cat['error']}")
            else:
                informe.fallo("catalogo", "no hay catalogo cargado")
            if d.get("perfiles_con_error"):
                informe.fallo("perfiles de cliente", f"con errores: {', '.join(d['perfiles_con_error'])}")
            else:
                informe.ok("perfiles de cliente", f"{d.get('clientes')} cargado(s), sin errores")
            cti = d.get("cti") or {}
            if cti.get("disponible"):
                informe.ok("News CTI", f"indicadores de {cti.get('generado')}")
            else:
                informe.aviso("News CTI", "sin indicadores: el motor no llega a RL_CTI_URL o aun no ha descargado")
            if d.get("simulacion_global"):
                informe.aviso("modo", "RL_SIMULACION_GLOBAL=true: decide pero no ejecuta nada")
            else:
                informe.ok("modo", "ejecuta de verdad en los clientes en modo produccion")
            v = http.get(f"{url}/v1/admin/auditoria/verificar", headers={"Authorization": f"Bearer {admin}"})
            a = v.json() if v.status_code == 200 else {}
            if a.get("integra"):
                informe.ok("auditoria", f"{a.get('registros')} registros, cadena integra")
            else:
                informe.fallo("auditoria", f"HTTP {v.status_code} {a or v.text[:120]}")

        r = http.get(f"{url}/v1/{cliente}/incidentes")
        if r.status_code in (401, 403):
            informe.ok("sin token", f"HTTP {r.status_code}: no se ve nada")
        else:
            informe.fallo("sin token", f"HTTP {r.status_code}: los incidentes no deberian verse sin token")
        if aprobador:
            r = http.get(f"{url}/v1/{cliente}/incidentes", headers={"Authorization": f"Bearer {aprobador}"})
            (informe.ok if r.status_code == 200 else informe.fallo)("token del aprobador", f"HTTP {r.status_code}")
        if edl:
            r = http.get(f"{url}/v1/{cliente}/edl/ip", params={"token": edl})
            if r.status_code == 200:
                informe.ok("lista EDL de IP", f"{len([x for x in r.text.splitlines() if x.strip()])} entradas")
            else:
                informe.fallo("lista EDL de IP", f"HTTP {r.status_code}")

        if escenarios:
            if not (ingesta and aprobador):
                informe.fallo("escenarios", f"faltan {pre}TOKEN o {pre}TOKEN_APROBADOR en .env")
            else:
                lanzar_escenarios(http, url, cliente, ingesta, aprobador, informe)
    finally:
        http.close()

    if conectividad:
        for nombre, ip, puerto in (("API de Wazuh", env.get("RL_IP_WAZUH"), 55000),
                                   ("TheHive", env.get("RL_IP_SOAR"), 9000)):
            if not ip:
                informe.aviso(nombre, "sin IP en .env")
                continue
            try:
                socket.create_connection((ip, puerto), timeout=5).close()
                informe.ok(nombre, f"{ip}:{puerto} acepta conexiones")
            except OSError as e:
                informe.fallo(nombre, f"{ip}:{puerto}: {e}")


def lanzar_escenarios(http: httpx.Client, url: str, cliente: str, ingesta: str, aprobador: str,
                      informe: Informe) -> None:
    import time
    from datetime import timedelta

    from responselab import simulador

    cab = {"Authorization": f"Bearer {aprobador}"}
    antes = http.get(f"{url}/v1/{cliente}/incidentes", headers=cab).json()
    n_antes = len(antes) if isinstance(antes, list) else len(antes.get("incidentes", []))
    enviadas = rechazadas = 0
    for esc in simulador.cargar():
        if esc.get("cliente", "lab") != cliente:
            continue
        base = simulador.momento_inicial(esc)
        for n, a in enumerate(esc["alertas"], 1):
            carga = simulador.preparar(a["siem"], a["carga"], base + timedelta(minutes=a.get("minuto", 0)),
                                       f"comprobacion-{esc['id']}-{n}-{int(time.time())}")
            r = http.post(f"{url}/v1/{cliente}/alertas/{a['siem']}", json=carga,
                          headers={"Authorization": f"Bearer {ingesta}"})
            enviadas += 1
            rechazadas += r.status_code >= 300
    if not enviadas:
        informe.aviso("escenarios", f"no hay escenarios para el cliente {cliente}")
        return
    if rechazadas:
        informe.fallo("escenarios", f"{rechazadas} de {enviadas} alertas rechazadas")
        return
    n_despues = n_antes
    for _ in range(30):                     # la cola los procesa en segundo plano
        d = http.get(f"{url}/v1/{cliente}/incidentes", headers=cab).json()
        n_despues = len(d) if isinstance(d, list) else len(d.get("incidentes", []))
        if n_despues > n_antes:
            break
        time.sleep(1)
    if n_despues > n_antes:
        informe.ok("escenarios", f"{enviadas} alertas aceptadas, {n_despues - n_antes} incidente(s) nuevo(s)")
    else:
        informe.fallo("escenarios", f"{enviadas} alertas aceptadas y ningun incidente nuevo en 30 s")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True, help="URL del motor tal como la usan los SIEM")
    ap.add_argument("--ca", type=Path, help="CA del proxy (RL_TLS=internal); sin ella, la del sistema")
    ap.add_argument("--inseguro", action="store_true", help="no verificar el certificado (solo para depurar)")
    ap.add_argument("--env", type=Path, default=RAIZ / ".env")
    ap.add_argument("--cliente", default="lab")
    ap.add_argument("--escenarios", action="store_true")
    ap.add_argument("--conectividad", action="store_true")
    args = ap.parse_args(argv)

    verificar = False if args.inseguro else (str(args.ca) if args.ca else True)
    print(f"Comprobando {args.url} (cliente {args.cliente})")
    informe = Informe()
    comprobar(args.url, verificar, leer_env(args.env), args.cliente, informe,
              escenarios=args.escenarios, conectividad=args.conectividad)
    avisos = sum(1 for e, _, _ in informe.filas if e == "AVISO")
    print(f"\n{len(informe.filas)} comprobaciones: {informe.fallos} fallo(s), {avisos} aviso(s)")
    return 1 if informe.fallos else 0


if __name__ == "__main__":
    sys.exit(main())
