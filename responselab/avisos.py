"""
Avisos al turno: Discord, Slack, Microsoft Teams, correo y webhook generico.

Que se avisa
------------
Lo que DetectionLab dice que se avisa: la clase auto_contener, la severidad 3
o mas, y las secuencias. Ademas, las aprobaciones pendientes (con su enlace),
los incidentes que vencen sin que nadie los asuma y los fallos de ejecucion.
Una cola que avisa de todo deja de leerse; por eso aqui no se avisa de lo que
solo se encola.
"""
from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from email.message import EmailMessage

from .clientes import secreto
from .conectores.base import ClienteHttp, ErrorConector

log = logging.getLogger("responselab.avisos")

COLORES = {1: 0x6B7280, 2: 0x2563EB, 3: 0xF59E0B, 4: 0xDC2626}


def _canales(cliente: dict, tipo: str) -> list[tuple[str, dict]]:
    avisos = cliente.get("avisos") or {}
    nombres = (avisos.get("por_tipo") or {}).get(tipo) or avisos.get("canales") or []
    conectores = cliente.get("conectores") or {}
    return [(n, conectores.get(n) or {}) for n in nombres]


async def _discord(http, cfg, titulo, texto, severidad, campos, enlace):
    embed = {"title": titulo[:256], "description": texto[:3900], "color": COLORES.get(severidad, 0x2563EB),
             "fields": [{"name": k[:256], "value": str(v)[:1000] or "-", "inline": True} for k, v in campos.items()][:20]}
    if enlace:
        embed["url"] = enlace
    await http.peticion("POST", secreto(cfg, "webhook"), json_={"username": "ResponseLab", "embeds": [embed]},
                        esperado=(200, 204))


async def _slack(http, cfg, titulo, texto, severidad, campos, enlace):
    detalle = "\n".join(f"*{k}:* {v}" for k, v in campos.items())
    bloques = [{"type": "header", "text": {"type": "plain_text", "text": titulo[:150]}},
               {"type": "section", "text": {"type": "mrkdwn", "text": (texto + "\n" + detalle)[:2900]}}]
    if enlace:
        bloques.append({"type": "section", "text": {"type": "mrkdwn", "text": f"<{enlace}|Abrir en ResponseLab>"}})
    await http.peticion("POST", secreto(cfg, "webhook"), json_={"text": titulo, "blocks": bloques})


async def _teams(http, cfg, titulo, texto, severidad, campos, enlace):
    # Webhook de flujo de trabajo de Teams (Power Automate): tarjeta adaptable.
    cuerpo = [{"type": "TextBlock", "text": titulo, "weight": "Bolder", "size": "Medium", "wrap": True},
              {"type": "TextBlock", "text": texto[:2000], "wrap": True},
              {"type": "FactSet", "facts": [{"title": k, "value": str(v)[:500]} for k, v in campos.items()]}]
    tarjeta = {"type": "AdaptiveCard", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
               "version": "1.4", "body": cuerpo}
    if enlace:
        tarjeta["actions"] = [{"type": "Action.OpenUrl", "title": "Abrir en ResponseLab", "url": enlace}]
    await http.peticion("POST", secreto(cfg, "webhook"), json_={
        "type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive",
                                            "content": tarjeta}]}, esperado=(200, 202))


async def _webhook(http, cfg, titulo, texto, severidad, campos, enlace):
    await http.peticion("POST", secreto(cfg, "url") or cfg.get("url", ""), json_={
        "titulo": titulo, "texto": texto, "severidad": severidad, "campos": campos, "enlace": enlace})


def _correo_envio(cfg, titulo, texto, campos, enlace):
    msg = EmailMessage()
    msg["Subject"] = f"[ResponseLab] {titulo}"[:250]
    msg["From"] = cfg.get("remitente", "responselab@localhost")
    msg["To"] = ", ".join(cfg.get("destinatarios") or [])
    cuerpo = texto + "\n\n" + "\n".join(f"{k}: {v}" for k, v in campos.items())
    if enlace:
        cuerpo += f"\n\n{enlace}"
    msg.set_content(cuerpo)
    with smtplib.SMTP(cfg["servidor"], int(cfg.get("puerto", 587)), timeout=20) as s:
        s.starttls(context=ssl.create_default_context())
        if cfg.get("usuario_env"):
            s.login(secreto(cfg, "usuario"), secreto(cfg, "clave"))
        s.send_message(msg)


ENVIOS = {"discord": _discord, "slack": _slack, "teams": _teams, "webhook": _webhook}


async def enviar(cliente: dict, tipo: str, titulo: str, texto: str, severidad: int = 2,
                 campos: dict | None = None, enlace: str = "", simulacion: bool = False,
                 transporte=None) -> list[dict]:
    """Envia el aviso por los canales del cliente. Devuelve un registro por canal."""
    resultados = []
    for nombre, cfg in _canales(cliente, tipo):
        tipo_canal = cfg.get("tipo", nombre)
        registro = {"canal": nombre, "tipo": tipo_canal, "titulo": titulo}
        if simulacion:
            registro["estado"] = "simulada"
            registro["texto"] = texto[:500]
            resultados.append(registro)
            continue
        try:
            if tipo_canal == "correo":
                await asyncio.to_thread(_correo_envio, cfg, titulo, texto, campos or {}, enlace)
            elif tipo_canal in ENVIOS:
                if not (secreto(cfg, "webhook") or secreto(cfg, "url") or cfg.get("url")):
                    raise ErrorConector(f"canal {nombre} sin webhook configurado")
                http = ClienteHttp(False, verificar_tls=cfg.get("verificar_tls", True), transporte=transporte)
                await ENVIOS[tipo_canal](http, cfg, titulo, texto, severidad, campos or {}, enlace)
            else:
                raise ErrorConector(f"tipo de canal desconocido: {tipo_canal}")
            registro["estado"] = "ok"
        except Exception as e:  # un aviso que falla no para la respuesta
            registro["estado"] = "error"
            registro["error"] = str(e)[:300]
            log.warning("aviso %s fallido: %s", nombre, e)
        resultados.append(registro)
    return resultados
