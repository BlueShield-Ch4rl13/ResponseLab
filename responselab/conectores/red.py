"""
Perimetro y WAF: Palo Alto (PAN-OS), Fortinet (FortiGate) y Cloudflare.

Todo lo que se hace aqui tiene radio organizacion o equipo-desde-la-red, asi
que solo llega a ejecutarse con aprobacion (salvo red.aislar_equipo, que aisla
un unico equipo). Aun asi, cada bloqueo nace con caducidad cuando la
herramienta lo permite: un bloqueo de emergencia olvidado acaba siendo la
causa de una incidencia que nadie relaciona con el incidente.

Ninguno bloquea direcciones internas: una IP privada en un bloqueo perimetral
corta trafico propio.
"""
from __future__ import annotations

import ipaddress
from xml.sax.saxutils import escape

from .base import Conector, ErrorConector, NoSoportada, Resultado


def _campo(objetivo, contexto, ruta):
    from ..nucleo import leer
    return objetivo.get(ruta) or leer(contexto.get("alerta") or {}, ruta)


def _ip_publica(valor) -> str:
    try:
        ip = ipaddress.ip_address(str(valor))
    except ValueError:
        raise NoSoportada(f"'{valor}' no es una IP") from None
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise NoSoportada(f"{ip} es interna: no se bloquea en el perimetro")
    return str(ip)


def _ip_interna(valor) -> str:
    try:
        return str(ipaddress.ip_address(str(valor)))
    except ValueError:
        raise NoSoportada(f"'{valor}' no es una IP") from None


class PaloAlto(Conector):
    """Etiquetas dinamicas (User-ID) que alimentan grupos de direcciones dinamicos.

    Preparacion en el cortafuegos (una vez): un grupo dinamico que case con la
    etiqueta `responselab-bloqueo` y una regla de denegacion hacia y desde el;
    y otro con `responselab-cuarentena` para red.aislar_equipo. El registro
    lleva tiempo de vida, asi que la etiqueta desaparece sola.
    """
    nombre = "paloalto"
    requiere_cfg = ("url",)
    requiere_secretos = ("api_key",)
    acciones = {
        "perimetro.bloquear_destino": "bloquear",
        "perimetro.desbloquear_destino": "desbloquear",
        "waf.bloquear_origen": "bloquear_origen",
        "waf.desbloquear_origen": "desbloquear_origen",
        "red.aislar_equipo": "cuarentena",
        "red.liberar_equipo": "liberar",
    }

    def _ttl(self) -> int:
        horas = int((self.cliente.get("politica") or {}).get("bloqueo_perimetro_horas", 72))
        return min(horas * 3600, 2592000)    # PAN-OS admite hasta 30 dias

    async def _uid(self, http, operacion: str, ip: str, etiqueta: str, ttl: int | None):
        tag = f'<member timeout="{ttl}">{escape(etiqueta)}</member>' if ttl else f"<member>{escape(etiqueta)}</member>"
        cmd = (f"<uid-message><version>2.0</version><type>update</type><payload><{operacion}>"
               f'<entry ip="{escape(ip)}"><tag>{tag}</tag></entry></{operacion}></payload></uid-message>')
        r = await http.peticion("POST", self.cfg["url"].rstrip("/") + "/api/",
                                datos={"type": "user-id", "key": self.secreto("api_key"), "cmd": cmd},
                                simulada={"texto": '<response status="success"/>'})
        texto = r.text if not http.simulacion else '<response status="success"/>'
        if 'status="success"' not in texto:
            raise ErrorConector(f"PAN-OS rechazo el registro: {texto[:300]}")

    async def bloquear(self, http, objetivo, parametros, contexto):
        ip = _campo(objetivo, contexto, "red.ip_destino")
        if not ip:
            raise NoSoportada("PAN-OS etiqueta IP; dominios y URL van por la EDL")
        ip = _ip_publica(ip)
        etiqueta = self.cfg.get("etiqueta_bloqueo", "responselab-bloqueo")
        await self._uid(http, "register", ip, etiqueta, self._ttl())
        return Resultado("ok", f"{ip} etiquetada {etiqueta} durante {self._ttl() // 3600} h", {"ip": ip, "etiqueta": etiqueta})

    async def desbloquear(self, http, objetivo, parametros, contexto):
        d = contexto.get("datos_deshacer") or {}
        ip = d.get("ip") or _ip_publica(_campo(objetivo, contexto, "red.ip_destino"))
        await self._uid(http, "unregister", ip, d.get("etiqueta", self.cfg.get("etiqueta_bloqueo", "responselab-bloqueo")), None)
        return Resultado("ok", f"etiqueta retirada de {ip}")

    async def bloquear_origen(self, http, objetivo, parametros, contexto):
        ip = _ip_publica(_campo(objetivo, contexto, "red.ip_origen"))
        etiqueta = self.cfg.get("etiqueta_bloqueo", "responselab-bloqueo")
        await self._uid(http, "register", ip, etiqueta, self._ttl())
        return Resultado("ok", f"origen {ip} etiquetado {etiqueta}", {"ip": ip, "etiqueta": etiqueta})

    async def desbloquear_origen(self, http, objetivo, parametros, contexto):
        d = contexto.get("datos_deshacer") or {}
        ip = d.get("ip") or _ip_publica(_campo(objetivo, contexto, "red.ip_origen"))
        await self._uid(http, "unregister", ip, d.get("etiqueta", "responselab-bloqueo"), None)
        return Resultado("ok", f"etiqueta retirada de {ip}")

    async def cuarentena(self, http, objetivo, parametros, contexto):
        ip = _ip_interna(_campo(objetivo, contexto, "equipo.ip"))
        etiqueta = self.cfg.get("etiqueta_cuarentena", "responselab-cuarentena")
        await self._uid(http, "register", ip, etiqueta, None)
        return Resultado("ok", f"equipo {ip} en el grupo de cuarentena del cortafuegos", {"ip": ip, "etiqueta": etiqueta})

    async def liberar(self, http, objetivo, parametros, contexto):
        d = contexto.get("datos_deshacer") or {}
        ip = d.get("ip") or _ip_interna(_campo(objetivo, contexto, "equipo.ip"))
        await self._uid(http, "unregister", ip, d.get("etiqueta", "responselab-cuarentena"), None)
        return Resultado("ok", f"equipo {ip} fuera de cuarentena")


class Fortinet(Conector):
    """Objetos de direccion en un grupo usado por una politica de denegacion."""
    nombre = "fortinet"
    requiere_cfg = ("url",)
    requiere_secretos = ("api_token",)
    acciones = {
        "perimetro.bloquear_destino": "bloquear",
        "perimetro.desbloquear_destino": "desbloquear",
        "waf.bloquear_origen": "bloquear_origen",
        "waf.desbloquear_origen": "desbloquear_origen",
        "red.aislar_equipo": "cuarentena",
        "red.liberar_equipo": "liberar",
    }

    def _cab(self):
        return {"Authorization": f"Bearer {self.secreto('api_token')}", "Content-Type": "application/json"}

    def _p(self):
        return {"vdom": self.cfg.get("vdom", "root")}

    async def _anadir(self, http, ip: str, grupo: str):
        base = self.cfg["url"].rstrip("/") + "/api/v2/cmdb/firewall"
        nombre = f"RL-{ip}"
        try:
            await http.peticion("POST", f"{base}/address", cabeceras=self._cab(), params=self._p(),
                                json_={"name": nombre, "subnet": f"{ip} 255.255.255.255", "comment": "ResponseLab"})
        except ErrorConector as e:
            # FortiOS contesta error -5 si el objeto ya existe (otro incidente
            # lo creo antes): no es un fallo, se reutiliza.
            if not ('"error": -5' in str(e) or '"error":-5' in str(e) or "already exist" in str(e).lower()):
                raise
        await http.peticion("POST", f"{base}/addrgrp/{grupo}/member", cabeceras=self._cab(), params=self._p(),
                            json_={"name": nombre})
        return nombre

    async def _quitar(self, http, ip: str, grupo: str):
        base = self.cfg["url"].rstrip("/") + "/api/v2/cmdb/firewall"
        nombre = f"RL-{ip}"
        await http.peticion("DELETE", f"{base}/addrgrp/{grupo}/member/{nombre}", cabeceras=self._cab(), params=self._p())
        await http.peticion("DELETE", f"{base}/address/{nombre}", cabeceras=self._cab(), params=self._p(), esperado=(200, 404))

    async def bloquear(self, http, objetivo, parametros, contexto):
        ip = _ip_publica(_campo(objetivo, contexto, "red.ip_destino"))
        grupo = self.cfg.get("grupo_bloqueo", "ResponseLab-Bloqueo")
        await self._anadir(http, ip, grupo)
        return Resultado("ok", f"{ip} anadida a {grupo}", {"ip": ip, "grupo": grupo})

    async def desbloquear(self, http, objetivo, parametros, contexto):
        d = contexto.get("datos_deshacer") or {}
        await self._quitar(http, d.get("ip") or _ip_publica(_campo(objetivo, contexto, "red.ip_destino")),
                           d.get("grupo", self.cfg.get("grupo_bloqueo", "ResponseLab-Bloqueo")))
        return Resultado("ok", "bloqueo retirado")

    async def bloquear_origen(self, http, objetivo, parametros, contexto):
        ip = _ip_publica(_campo(objetivo, contexto, "red.ip_origen"))
        grupo = self.cfg.get("grupo_bloqueo", "ResponseLab-Bloqueo")
        await self._anadir(http, ip, grupo)
        return Resultado("ok", f"origen {ip} anadido a {grupo}", {"ip": ip, "grupo": grupo})

    async def desbloquear_origen(self, http, objetivo, parametros, contexto):
        d = contexto.get("datos_deshacer") or {}
        await self._quitar(http, d.get("ip") or _ip_publica(_campo(objetivo, contexto, "red.ip_origen")),
                           d.get("grupo", "ResponseLab-Bloqueo"))
        return Resultado("ok", "bloqueo de origen retirado")

    async def cuarentena(self, http, objetivo, parametros, contexto):
        ip = _ip_interna(_campo(objetivo, contexto, "equipo.ip"))
        grupo = self.cfg.get("grupo_cuarentena", "ResponseLab-Cuarentena")
        await self._anadir(http, ip, grupo)
        return Resultado("ok", f"equipo {ip} en {grupo}", {"ip": ip, "grupo": grupo})

    async def liberar(self, http, objetivo, parametros, contexto):
        d = contexto.get("datos_deshacer") or {}
        await self._quitar(http, d.get("ip") or _ip_interna(_campo(objetivo, contexto, "equipo.ip")),
                           d.get("grupo", self.cfg.get("grupo_cuarentena", "ResponseLab-Cuarentena")))
        return Resultado("ok", "equipo fuera de cuarentena")


class Cloudflare(Conector):
    """Reglas de acceso por IP en la zona (o en la cuenta) de Cloudflare."""
    nombre = "cloudflare"
    requiere_secretos = ("api_token",)
    acciones = {
        "waf.bloquear_origen": "bloquear_origen",
        "waf.desbloquear_origen": "desbloquear",
        "perimetro.bloquear_destino": "no_aplica",
        "perimetro.desbloquear_destino": "no_aplica",
    }

    def configurado(self):
        ok, motivo = super().configurado()
        if ok and not (self.cfg.get("zona") or self.cfg.get("cuenta")):
            return False, "falta zona o cuenta de Cloudflare"
        return ok, motivo

    def _base(self):
        if self.cfg.get("zona"):
            return f"https://api.cloudflare.com/client/v4/zones/{self.cfg['zona']}/firewall/access_rules/rules"
        return f"https://api.cloudflare.com/client/v4/accounts/{self.cfg['cuenta']}/firewall/access_rules/rules"

    def _cab(self):
        return {"Authorization": f"Bearer {self.secreto('api_token')}", "Content-Type": "application/json"}

    async def bloquear_origen(self, http, objetivo, parametros, contexto):
        ip = _ip_publica(_campo(objetivo, contexto, "red.ip_origen"))
        r = await http.peticion("POST", self._base(), cabeceras=self._cab(), json_={
            "mode": "block", "configuration": {"target": "ip", "value": ip},
            "notes": f"ResponseLab {contexto.get('incidente_id', '')}"[:500]},
            simulada={"result": {"id": "regla-simulada"}})
        rid = (r.json().get("result") or {}).get("id")
        return Resultado("ok", f"{ip} bloqueada en el WAF de Cloudflare", {"regla": rid, "ip": ip})

    async def desbloquear(self, http, objetivo, parametros, contexto):
        rid = (contexto.get("datos_deshacer") or {}).get("regla")
        if not rid:
            raise NoSoportada("no se guardo el id de la regla")
        await http.peticion("DELETE", f"{self._base()}/{rid}", cabeceras=self._cab())
        return Resultado("ok", f"regla {rid} retirada")

    async def no_aplica(self, http, objetivo, parametros, contexto):
        raise NoSoportada("Cloudflare protege el trafico entrante de la zona; el bloqueo de salida va por la EDL o el cortafuegos")
