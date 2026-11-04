"""
Firma del catalogo remoto: con RL_CATALOGO_CLAVE el motor solo acepta un
catalogo firmado por quien tiene la clave (la persona que revisa), no el que
el bot haya dejado en el repositorio.
"""
from __future__ import annotations

import hashlib
import hmac
import json

import httpx

from responselab.gestor_catalogo import GestorCatalogo

URL = "https://catalogo.example/catalogo.json"


def _transporte(cuerpo: bytes, firma: str | None):
    def responder(peticion: httpx.Request) -> httpx.Response:
        if str(peticion.url) == URL:
            return httpx.Response(200, content=cuerpo, headers={"content-type": "application/json"})
        if str(peticion.url) == URL + ".firma" and firma is not None:
            return httpx.Response(200, text=firma + "\n")
        return httpx.Response(404)
    return httpx.MockTransport(responder)


def _gestor(tmp_path, raiz, clave: str) -> tuple[GestorCatalogo, bytes]:
    local = raiz / "catalogo" / "catalogo.json"
    g = GestorCatalogo(local, tmp_path, URL, clave_firma=clave)
    g.cargar()
    datos = json.loads(local.read_text(encoding="utf-8"))
    datos["version"] = "9999.0.0-prueba"
    return g, json.dumps(datos).encode("utf-8")


async def test_sin_firma_se_rechaza_si_hay_clave(tmp_path, raiz):
    g, cuerpo = _gestor(tmp_path, raiz, "clave-de-quien-revisa")
    anterior = g.actual.version
    r = await g.actualizar_remoto(_transporte(cuerpo, None))
    assert r["estado"] == "error" and g.actual.version == anterior


async def test_firma_de_otra_clave_se_rechaza(tmp_path, raiz):
    g, cuerpo = _gestor(tmp_path, raiz, "clave-de-quien-revisa")
    falsa = hmac.new(b"clave-del-bot", cuerpo, hashlib.sha256).hexdigest()
    r = await g.actualizar_remoto(_transporte(cuerpo, falsa))
    assert r["estado"] == "rechazado" and "firma" in g.ultimo_error
    assert g.actual.version != "9999.0.0-prueba"


async def test_firma_correcta_se_acepta(tmp_path, raiz):
    g, cuerpo = _gestor(tmp_path, raiz, "clave-de-quien-revisa")
    buena = hmac.new(b"clave-de-quien-revisa", cuerpo, hashlib.sha256).hexdigest()
    r = await g.actualizar_remoto(_transporte(cuerpo, buena))
    assert r["estado"] == "actualizado" and g.actual.version == "9999.0.0-prueba"


async def test_sin_clave_no_se_acepta_ningun_catalogo_remoto(tmp_path, raiz, monkeypatch):
    """Antes, sin RL_CATALOGO_CLAVE se aceptaba cualquier catalogo de la URL: quien
    escribiera en main cambiaba la politica del motor. Ahora hay que pedirlo a sabiendas."""
    monkeypatch.delenv("RL_CATALOGO_SIN_FIRMA", raising=False)
    g, cuerpo = _gestor(tmp_path, raiz, "")
    anterior = g.actual.version
    r = await g.actualizar_remoto(_transporte(cuerpo, None))
    assert r["estado"] == "rechazado" and "RL_CATALOGO_CLAVE" in g.ultimo_error and g.actual.version == anterior
    monkeypatch.setenv("RL_CATALOGO_SIN_FIRMA", "1")
    r = await g.actualizar_remoto(_transporte(cuerpo, None))
    assert r["estado"] == "actualizado" and g.actual.version == "9999.0.0-prueba"


async def test_un_catalogo_no_puede_rebajar_el_radio_de_una_accion(tmp_path, raiz, monkeypatch):
    """El radio y la reversibilidad que fija el codigo mandan: un catalogo que diga que
    bloquear en el WAF es de radio equipo (y por tanto automatico) se rechaza."""
    monkeypatch.setenv("RL_CATALOGO_SIN_FIRMA", "1")
    local = raiz / "catalogo" / "catalogo.json"
    g = GestorCatalogo(local, tmp_path, URL, clave_firma="")
    g.cargar()
    datos = json.loads(local.read_text(encoding="utf-8"))
    datos["version"] = "9999.0.1-trampa"
    datos["acciones"]["waf.bloquear_origen"]["radio"] = "equipo"
    r = await g.actualizar_remoto(_transporte(json.dumps(datos).encode("utf-8"), None))
    assert r["estado"] != "actualizado" and g.actual.version != "9999.0.1-trampa"
    assert any("waf.bloquear_origen" in e and "MINIMOS_ACCION" in e for e in r.get("errores", []))


def test_el_radio_minimo_se_aplica_aunque_el_catalogo_mienta():
    from responselab import nucleo
    assert nucleo.radio_efectivo("equipo", nucleo.minimos_de("waf.bloquear_origen")[0]) == "organizacion"
    assert nucleo.reversible_efectivo("si", nucleo.minimos_de("cuenta.deshabilitar")[1]) == "si"
    assert nucleo.minimos_de("accion.inexistente") == (None, None)
