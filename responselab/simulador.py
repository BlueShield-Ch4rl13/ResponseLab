"""
Simulador de escenarios de ataque.

Un escenario (escenarios/*.yml) es una cadena de alertas reales, en el formato
nativo de cada SIEM, con lo que se espera que haga ResponseLab con cada una:
familia, clase, secuencias, escalado, el modo de cada accion y, sobre todo, lo
que NO debe pasar nunca (aislar un controlador de dominio, poner en cuarentena
un binario del sistema). El simulador las pasa por el motor de verdad, en modo
simulacion y con una base de datos temporal, y comprueba cada expectativa.

Es la prueba de extremo a extremo del proyecto y el CI la ejecuta en cada
sincronizacion: si un cambio en DetectionLab o en el catalogo hace que el motor
deje de contener un ransomware, o que empiece a aislar un servidor de
produccion, el CI se pone rojo antes de que llegue a produccion.

Formato: ver escenarios/LEEME.md.
"""
from __future__ import annotations

import asyncio
import copy
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from .config import Config
from .util import RAIZ

ESCENARIOS = RAIZ / "escenarios"
ORDEN_MODOS = ["automatica", "aprobacion", "manual", "no_aplicable", "prohibida"]


def cargar(carpeta: Path = ESCENARIOS, nombres: list[str] | None = None) -> list[dict]:
    salida = []
    for f in sorted(carpeta.glob("*.yml")):
        if f.name.startswith("_"):
            continue
        esc = yaml.safe_load(f.read_text(encoding="utf-8"))
        esc.setdefault("id", f.stem)
        esc["_fichero"] = f.name
        if not nombres or esc["id"] in nombres or f.stem in nombres:
            salida.append(esc)
    return salida


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def momento_inicial(esc: dict) -> datetime:
    """Hora de la primera alerta.

    Por defecto, "ahora" menos lo que dura el escenario: las alertas llegan como
    si acabaran de pasar. Con inicio: (ISO 8601) la hora es fija, para lo que
    depende del reloj del cliente (ventanas de escaneo o de mantenimiento).
    """
    if esc.get("inicio"):
        valor = esc["inicio"]
        dt = valor if isinstance(valor, datetime) else datetime.fromisoformat(str(valor).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    duracion = max([a.get("minuto", 0) for a in esc["alertas"]] + [0])
    return datetime.now(timezone.utc) - timedelta(minutes=duracion + 1)


def preparar(siem: str, carga: dict, momento: datetime, ident: str) -> dict:
    """Pone a la alerta un id unico y la hora del escenario en el campo de cada SIEM."""
    c = copy.deepcopy(carga)
    t = _iso(momento)
    if siem == "wazuh":
        c["id"], c["timestamp"] = ident, t
    elif siem == "splunk":
        c["sid"] = ident
        c.setdefault("result", {})["_time"] = t
    elif siem == "sentinel":
        obj = c.setdefault("object", {})
        obj["name"] = ident
        props = obj.setdefault("properties", {})
        props["firstActivityTimeUtc"] = props["createdTimeUtc"] = t
    elif siem == "elastic":
        if isinstance(c.get("alerts"), list):
            for i, a in enumerate(c["alerts"]):
                a["_id"], a["@timestamp"] = f"{ident}-{i}", t
        else:
            c["_id"], c["@timestamp"] = ident, t
    else:
        c["id"], c["momento"] = ident, t
    return c


def _modos_por_accion(plan: dict) -> dict[str, set]:
    modos: dict[str, set] = {}
    for p in plan.get("acciones") or []:
        if p.get("accion"):
            modos.setdefault(p["accion"], set()).add(p["modo"])
    return modos


def comprobar_alerta(esperado: dict, plan: dict, ejecuciones: list, aprobaciones: list) -> list[tuple[bool, str]]:
    r = []

    def ver(ok, texto):
        r.append((bool(ok), texto))

    for campo in ("familia", "clase", "estado"):
        if campo in esperado:
            ver(plan.get(campo) == esperado[campo], f"{campo} = {esperado[campo]} (es {plan.get(campo)})")
    if "regla_conocida" in esperado:
        ver(plan["regla"]["conocida"] == esperado["regla_conocida"],
            f"regla conocida = {esperado['regla_conocida']} (es {plan['regla']['conocida']}, via {plan['regla']['via'] or '-'})")
    if "severidad_minima" in esperado:
        ver(plan.get("severidad", 0) >= esperado["severidad_minima"],
            f"severidad >= {esperado['severidad_minima']} (es {plan.get('severidad')})")
    if "severidad_maxima" in esperado:
        ver(plan.get("severidad", 0) <= esperado["severidad_maxima"],
            f"severidad <= {esperado['severidad_maxima']} (es {plan.get('severidad')})")
    for texto, resultado in (esperado.get("triaje") or {}).items():
        preguntas = [t for t in plan.get("triaje") or [] if str(texto).lower() in t["pregunta"].lower()]
        ver(any(t["resultado"] == resultado for t in preguntas),
            f"triaje '{texto}': {resultado} (es {', '.join(t['resultado'] for t in preguntas) or 'pregunta no encontrada'})")
    for texto in esperado.get("cierre_propuesto") or []:
        ver(any(str(texto).lower() in c["condicion"].lower() for c in plan.get("cierres_propuestos") or []),
            f"cierre propuesto a una persona: '{texto}'")
    if "escalado" in esperado:
        ver(plan["escalado"].get("a") == esperado["escalado"], f"escalar a {esperado['escalado']} (es {plan['escalado'].get('a')})")
    for s in esperado.get("secuencias") or []:
        ids = [x["id"] for x in plan.get("secuencias") or []]
        ver(s in ids, f"secuencia {s} detectada (detectadas: {', '.join(ids) or 'ninguna'})")
    if esperado.get("sin_secuencias"):
        ver(not plan.get("secuencias"), f"sin secuencias (hay {[x['id'] for x in plan.get('secuencias') or []]})")
    modos = _modos_por_accion(plan)
    for accion, modo in (esperado.get("modos") or {}).items():
        reales = modos.get(accion, set())
        ver(modo in reales, f"{accion}: {modo} (es {', '.join(sorted(reales)) or 'no esta en el plan'})")
    if esperado.get("sin_contencion_automatica"):
        auto = [p["accion"] or p["origen"][:40] for p in plan.get("acciones") or []
                if p["modo"] == "automatica" and not p.get("registro") and not p.get("es_evidencia")]
        ver(not auto, f"ninguna contencion automatica (hay: {', '.join(auto) or 'ninguna'})")
    for accion in esperado.get("nunca_automatica") or []:
        ver("automatica" not in modos.get(accion, set()),
            f"{accion} nunca automatica (modos: {', '.join(sorted(modos.get(accion, set()))) or 'no esta en el plan'})")
    for accion, estado in (esperado.get("ejecuciones") or {}).items():
        de_accion = [e for e in ejecuciones if e["accion"] == accion]
        estados = sorted({e["estado"] for e in de_accion})
        ver(estado in estados, f"ejecucion de {accion}: {estado} (hay: {', '.join(estados) or 'ninguna'})")
    for accion, conector in (esperado.get("conectores") or {}).items():
        usados = sorted({e["conector"] for e in ejecuciones if e["accion"] == accion})
        ver(conector in usados, f"{accion} con el conector {conector} (usados: {', '.join(usados) or 'ninguno'})")
    for accion in esperado.get("sin_ejecucion") or []:
        # "simulada" cuenta: en simulacion es lo que habria hecho de verdad
        hechas = [e for e in ejecuciones if e["accion"] == accion
                  and e["estado"] in ("ok", "simulada", "en_curso", "confirmada")]
        ver(not hechas, f"{accion} no se ejecuta (se ejecuto {len(hechas)} vez/veces)")
    for accion in esperado.get("aprobaciones") or []:
        ver(any(a["paso"].get("accion") == accion for a in aprobaciones), f"aprobacion pedida para {accion}")
    for aviso in esperado.get("avisar_ademas") or []:
        ver(aviso in (plan["escalado"].get("avisar_ademas") or []), f"avisar ademas a {aviso}")
    if "notificar" in esperado:
        ver(plan.get("notificar") == esperado["notificar"], f"notificar = {esperado['notificar']}")
    return r


def comprobar_final(esperado: dict, motor, cliente: str) -> list[tuple[bool, str]]:
    r = []
    incidentes = motor.almacen.incidentes(cliente, limite=500)
    if "incidentes" in esperado:
        r.append((len(incidentes) == esperado["incidentes"], f"incidentes = {esperado['incidentes']} (hay {len(incidentes)})"))
    if "aprobaciones_pendientes" in esperado:
        n = len(motor.almacen.aprobaciones(cliente, "pendiente", 500))
        r.append((n == esperado["aprobaciones_pendientes"], f"aprobaciones pendientes = {esperado['aprobaciones_pendientes']} (hay {n})"))
    for marco in esperado.get("plazos") or []:
        hay = any(any(str(p.get("marco", "")).lower() == str(marco).lower() for p in (i.get("plazos_regulatorios") or []))
                  for i in incidentes)
        r.append((hay, f"plazos regulatorios de {marco} en el incidente"))
    if "ejecuciones_ok" in esperado:
        n = len([e for e in motor.almacen.ejecuciones(cliente, limite=1000) if e["estado"] == "ok"])
        r.append((n == esperado["ejecuciones_ok"], f"ejecuciones correctas = {esperado['ejecuciones_ok']} (hay {n})"))
    if esperado.get("auditoria_integra", True):
        v = motor.almacen.verificar_auditoria()
        r.append((v.get("integra", False), f"auditoria encadenada integra ({v.get('registros', 0)} registros)"))
    return r


async def ejecutar_escenario(esc: dict, carpeta_datos: Path | None = None) -> dict:
    """Un escenario en un motor nuevo, en simulacion y sin red."""
    from .ejecutor import Motor

    with tempfile.TemporaryDirectory(prefix="rl-escenario-") as tmp:
        config = Config(datos=carpeta_datos or Path(tmp), simulacion_global=True, dns_ptr=False, trabajadores=1,
                        vigilancia_seg=3600, cti_url="", actualizacion_url="")
        motor = Motor(config)
        if esc.get("cti"):
            motor.cti._procesar({"iocs": esc["cti"], "cisa_kev_recent": esc.get("kev") or [],
                                 "generated_utc": _iso(datetime.now(timezone.utc))}, registrar=True)
        cliente = esc.get("cliente", "lab")
        base = momento_inicial(esc)
        sufijo = uuid.uuid4().hex[:6]
        await motor.arrancar(vigilante=False)
        resultado = {"id": esc["id"], "nombre": esc.get("nombre", esc["id"]), "alertas": [], "final": []}
        try:
            for n, a in enumerate(esc["alertas"], 1):
                carga = preparar(a["siem"], a["carga"], base + timedelta(minutes=a.get("minuto", 0)),
                                 f"{esc['id']}-{n}-{sufijo}")
                recibida = motor.recibir(cliente, a["siem"], carga)
                await motor.drenar()
                fila = next((x for x in motor.almacen.alertas(cliente, limite=500) if x["id"] == recibida.get("alerta_id")), None)
                plan = (fila or {}).get("plan") or {}
                ejecuciones = [e for e in motor.almacen.ejecuciones(cliente, limite=1000) if e["alerta_id"] == recibida.get("alerta_id")]
                aprobaciones = [x for x in motor.almacen.aprobaciones(cliente, limite=1000) if x["alerta_id"] == recibida.get("alerta_id")]
                comprobaciones = comprobar_alerta(a.get("esperado") or {}, plan, ejecuciones, aprobaciones) if plan else \
                    [(False, f"la alerta no llego a decidirse ({recibida})")]
                resultado["alertas"].append({
                    "n": n, "descripcion": a.get("descripcion", ""), "regla": (plan.get("regla") or {}).get("titulo", ""),
                    "familia": plan.get("familia"), "clase": plan.get("clase"), "severidad": plan.get("severidad"),
                    "estado": plan.get("estado"), "secuencias": [s["id"] for s in plan.get("secuencias") or []],
                    "escalado": (plan.get("escalado") or {}).get("a"),
                    "acciones": [(p["id"], p["accion"] or p["origen"][:40], p["modo"], p["motivo"]) for p in plan.get("acciones") or []],
                    "ejecuciones": [(e["accion"], e["conector"], e["estado"]) for e in ejecuciones],
                    "comprobaciones": comprobaciones})
            resultado["final"] = comprobar_final(esc.get("final") or {}, motor, cliente)
        finally:
            await motor.parar()
            motor.almacen.cerrar()
    todas = [c for a in resultado["alertas"] for c in a["comprobaciones"]] + resultado["final"]
    resultado["ok"] = all(ok for ok, _ in todas)
    resultado["comprobaciones"] = len(todas)
    resultado["fallos"] = [t for ok, t in todas if not ok]
    return resultado


def ejecutar(escenarios: list[dict]) -> list[dict]:
    return [asyncio.run(ejecutar_escenario(e)) for e in escenarios]
