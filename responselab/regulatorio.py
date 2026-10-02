"""
Plazos regulatorios que empiezan a correr con un incidente.

Lo que el motor hace: calcular desde cuando corre cada reloj y avisar antes de
que venza. Lo que NO hace: decidir si el incidente es notificable ni notificar.
Eso lo firma una persona (lo dice el playbook de cumplimiento de DetectionLab y
lo repite este modulo): el motor solo evita que el plazo se descubra tarde.

Los plazos son los del texto europeo. La transposicion nacional y la guia de
cada autoridad pueden concretarlos; el perfil del cliente puede sustituirlos
con `plazos_propios`.

    NIS2 (Directiva 2022/2555, art. 23)
        alerta temprana       24 h desde que se conoce el incidente significativo
        notificacion          72 h
        informe final         1 mes desde la notificacion
    DORA (Reglamento 2022/2554 y RTS de notificacion)
        notificacion inicial  4 h desde que se clasifica como grave y como
                              maximo 24 h desde que se conoce
        informe intermedio    72 h desde la notificacion inicial
        informe final         1 mes desde el ultimo informe intermedio
    RGPD (art. 33)
        notificacion a la autoridad de control   72 h desde que se conoce la brecha
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

PLAZOS = {
    "nis2": [
        ("Alerta temprana a la autoridad competente o al CSIRT", 24,
         "Si se califica como significativo. NIS2 art. 23.4.a: sin dilacion indebida y en todo caso en 24 h desde que se conoce."),
        ("Notificacion del incidente", 72,
         "Si es significativo. NIS2 art. 23.4.b: en 72 h desde que se conoce, con la evaluacion inicial de gravedad e impacto."),
        ("Informe final", 24 * 30,
         "NIS2 art. 23.4.d: como maximo un mes despues de la notificacion del incidente."),
    ],
    "dora": [
        ("Notificacion inicial de incidente grave", 24,
         "Si se clasifica como grave. DORA: 4 h desde la clasificacion y nunca mas de 24 h desde que se conoce."),
        ("Informe intermedio", 24 + 72,
         "DORA: 72 h desde la notificacion inicial (se calcula sobre el maximo de 24 h)."),
        ("Informe final", 24 * 30,
         "DORA: un mes desde el ultimo informe intermedio (orientativo)."),
    ],
    "rgpd": [
        ("Notificacion de la brecha a la autoridad de control", 72,
         "Si hay datos personales afectados con riesgo. RGPD art. 33: sin dilacion indebida y, si es posible, en 72 h desde que se tiene constancia."),
    ],
}


def aplica(cliente: dict, plan: dict, etiquetas=None) -> list[str]:
    """Que marcos tienen el reloj en marcha para este plan.

    etiquetas: las del activo afectado en el inventario del cliente. Un
    incidente significativo en un equipo marcado "datos_personales" (un
    ransomware que cifra nominas) es una brecha de disponibilidad para el
    RGPD aunque no salga ni un byte.
    """
    marcos = {str(m).lower() for m in (cliente or {}).get("marcos") or []}
    if not marcos:
        return []
    familia = plan.get("familia")
    avisar = set((plan.get("escalado") or {}).get("avisar_ademas") or [])
    significativo = int(plan.get("severidad", 0)) >= 4 or bool(plan.get("secuencias")) or familia == "cumplimiento"
    datos_personales = familia == "exfiltracion" or "dpd" in avisar or \
        (significativo and "datos_personales" in {str(e) for e in etiquetas or []})
    salida = []
    if "rgpd" in marcos and datos_personales:
        salida.append("rgpd")
    if "nis2" in marcos and (significativo or datos_personales):
        salida.append("nis2")
    if "dora" in marcos and (significativo or datos_personales):
        salida.append("dora")
    return salida


def plazos_para(cliente: dict, plan: dict, conocido: datetime, ahora: datetime | None = None,
                etiquetas=None) -> list[dict]:
    ahora = ahora or datetime.now(timezone.utc)
    propios = (cliente or {}).get("plazos_propios") or {}
    salida = []
    for marco in aplica(cliente, plan, etiquetas):
        for hito, horas, descripcion in propios.get(marco) and [
                (p["hito"], p["horas"], p.get("descripcion", "")) for p in propios[marco]] or PLAZOS[marco]:
            vence = conocido + timedelta(hours=horas)
            salida.append({
                "marco": marco.upper(), "hito": hito, "descripcion": descripcion,
                "vence": vence.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "horas_restantes": round((vence - ahora).total_seconds() / 3600, 1),
            })
    return salida


def horas_restantes(plazos: list[dict], ahora: datetime | None = None) -> list[dict]:
    """Recalcula las horas restantes de plazos ya guardados en un incidente."""
    ahora = ahora or datetime.now(timezone.utc)
    salida = []
    for p in plazos or []:
        vence = datetime.fromisoformat(str(p["vence"]).replace("Z", "+00:00"))
        salida.append(dict(p, horas_restantes=round((vence - ahora).total_seconds() / 3600, 1)))
    return salida
