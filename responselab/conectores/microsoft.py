"""
Microsoft: Defender for Endpoint, Entra ID y Exchange Online (Graph).

Una aplicacion registrada en Entra con permisos de aplicacion (no delegados) y
credencial de cliente. Permisos minimos por accion, en docs/CONECTORES.md:
Machine.Isolate, Machine.StopAndQuarantine, Machine.CollectForensics,
Machine.Read.All, Ti.ReadWrite.All (Defender); User.RevokeSessions.All,
IdentityRiskyUser.ReadWrite.All, User.EnableDisableAccount.All,
DelegatedPermissionGrant.ReadWrite.All (Graph); Mail.ReadWrite,
MailboxSettings.ReadWrite (Exchange).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .base import Conector, ErrorConector, NoSoportada, Resultado, TokenCache


def _campo(objetivo, contexto, ruta):
    from ..nucleo import leer
    return objetivo.get(ruta) or leer(contexto.get("alerta") or {}, ruta)


def _comentario(contexto) -> str:
    a = contexto.get("alerta") or {}
    return f"ResponseLab {contexto.get('incidente_id', '')}: {a.get('titulo', '')}"[:900]


class _Microsoft(Conector):
    requiere_cfg = ("tenant_id",)
    requiere_secretos = ("client_id", "client_secret")
    ambito = ""

    async def _token(self, http) -> str:
        url = f"https://login.microsoftonline.com/{self.cfg['tenant_id']}/oauth2/v2.0/token"
        datos = {"client_id": self.secreto("client_id"), "client_secret": self.secreto("client_secret"),
                 "grant_type": "client_credentials", "scope": self.ambito}
        return await TokenCache.obtener(http, url, datos, (url, datos["client_id"], self.ambito))

    async def _cab(self, http) -> dict:
        return {"Authorization": f"Bearer {await self._token(http)}", "Content-Type": "application/json"}


class Defender(_Microsoft):
    nombre = "defender"
    acciones = {
        "endpoint.aislar": "aislar",
        "endpoint.liberar": "liberar",
        "fichero.cuarentena": "cuarentena",
        "evidencia.paquete_investigacion": "paquete",
        "flota.bloquear_hash": "bloquear_hash",
        "flota.desbloquear_hash": "borrar_indicador",
        "correo.bloquear_url": "bloquear_url",
        "correo.desbloquear_url": "borrar_indicador",
        "perimetro.bloquear_destino": "bloquear_destino",
        "perimetro.desbloquear_destino": "borrar_indicador",
    }

    @property
    def ambito(self):
        return self.cfg.get("ambito", "https://api.securitycenter.microsoft.com/.default")

    @property
    def base(self):
        # La API se publica en api.security.microsoft.com (o us./eu./uk.); el
        # token sigue pidiendose para api.securitycenter.microsoft.com: algunas
        # operaciones devuelven 403 con un token de otra audiencia.
        return self.cfg.get("api", "https://api.security.microsoft.com").rstrip("/")

    async def _maquina(self, http, cab, objetivo, contexto) -> str:
        ident = _campo(objetivo, contexto, "equipo.id_edr")
        if ident:
            return ident
        nombre = _campo(objetivo, contexto, "equipo.nombre")
        if not nombre:
            raise NoSoportada("sin id de Defender ni nombre de equipo")
        nombre = str(nombre).lower().replace("'", "")
        r = await http.peticion("GET", f"{self.base}/api/machines", cabeceras=cab,
                                params={"$filter": f"startswith(computerDnsName,'{nombre}')", "$top": "5"},
                                simulada={"value": [{"id": "maquina-simulada", "computerDnsName": nombre}]})
        maquinas = [m for m in r.json().get("value") or []
                    if str(m.get("computerDnsName", "")).lower().split(".")[0] == nombre.split(".")[0]]
        if len(maquinas) != 1:
            raise ErrorConector(f"'{nombre}' casa con {len(maquinas)} maquinas en Defender: objetivo ambiguo, no se actua")
        return maquinas[0]["id"]

    async def aislar(self, http, objetivo, parametros, contexto):
        cab = await self._cab(http)
        mid = await self._maquina(http, cab, objetivo, contexto)
        r = await http.peticion("POST", f"{self.base}/api/machines/{mid}/isolate", cabeceras=cab,
                                json_={"Comment": _comentario(contexto), "IsolationType": parametros.get("tipo", "Full")},
                                simulada={"id": "accion-simulada", "status": "Pending"})
        return Resultado("ok", f"aislamiento solicitado en Defender ({r.json().get('status', '')})",
                         {"maquina": mid, "accion_mde": r.json().get("id")})

    async def liberar(self, http, objetivo, parametros, contexto):
        cab = await self._cab(http)
        mid = (contexto.get("datos_deshacer") or {}).get("maquina") or await self._maquina(http, cab, objetivo, contexto)
        await http.peticion("POST", f"{self.base}/api/machines/{mid}/unisolate", cabeceras=cab,
                            json_={"Comment": _comentario(contexto)}, simulada={"status": "Pending"})
        return Resultado("ok", "fin del aislamiento solicitado en Defender", {"maquina": mid})

    async def cuarentena(self, http, objetivo, parametros, contexto):
        sha1 = _campo(objetivo, contexto, "fichero.sha1")
        if not sha1:
            raise NoSoportada("StopAndQuarantineFile de Defender necesita el SHA-1 del fichero")
        cab = await self._cab(http)
        mid = await self._maquina(http, cab, objetivo, contexto)
        r = await http.peticion("POST", f"{self.base}/api/machines/{mid}/StopAndQuarantineFile", cabeceras=cab,
                                json_={"Comment": _comentario(contexto), "Sha1": sha1},
                                simulada={"id": "accion-simulada"})
        return Resultado("ok", "parada y cuarentena solicitadas (se restaura desde el portal de Defender)",
                         {"maquina": mid, "sha1": sha1, "accion_mde": r.json().get("id")})

    async def paquete(self, http, objetivo, parametros, contexto):
        cab = await self._cab(http)
        mid = await self._maquina(http, cab, objetivo, contexto)
        r = await http.peticion("POST", f"{self.base}/api/machines/{mid}/collectInvestigationPackage", cabeceras=cab,
                                json_={"Comment": _comentario(contexto)}, simulada={"id": "accion-simulada"})
        return Resultado("ok", "paquete de investigacion solicitado", {"maquina": mid, "accion_mde": r.json().get("id")})

    async def _indicador(self, http, valor, tipo, accion, contexto) -> Resultado:
        cab = await self._cab(http)
        horas = int((self.cliente.get("politica") or {}).get("bloqueo_perimetro_horas", 72))
        caduca = (datetime.now(timezone.utc) + timedelta(hours=horas)).strftime("%Y-%m-%dT%H:%M:%SZ")
        r = await http.peticion("POST", f"{self.base}/api/indicators", cabeceras=cab, json_={
            "indicatorValue": valor, "indicatorType": tipo, "action": accion,
            "title": f"ResponseLab {contexto.get('incidente_id', '')}"[:100],
            "description": _comentario(contexto), "severity": "High", "expirationTime": caduca,
            "generateAlert": True}, simulada={"id": "indicador-simulado"})
        return Resultado("ok", f"indicador {tipo} {valor} con accion {accion} hasta {caduca}",
                         {"indicador": r.json().get("id"), "valor": valor})

    async def bloquear_hash(self, http, objetivo, parametros, contexto):
        sha256 = _campo(objetivo, contexto, "fichero.sha256")
        sha1 = _campo(objetivo, contexto, "fichero.sha1")
        if sha256:
            return await self._indicador(http, sha256, "FileSha256", "BlockAndRemediate", contexto)
        if sha1:
            return await self._indicador(http, sha1, "FileSha1", "BlockAndRemediate", contexto)
        raise NoSoportada("sin hash de fichero")

    async def bloquear_url(self, http, objetivo, parametros, contexto):
        url = _campo(objetivo, contexto, "red.url")
        if not url:
            raise NoSoportada("sin URL")
        return await self._indicador(http, url, "Url", "Block", contexto)

    async def bloquear_destino(self, http, objetivo, parametros, contexto):
        from ..nucleo import es_ip, ip_privada
        ip = _campo(objetivo, contexto, "red.ip_destino")
        if ip and es_ip(ip) and not ip_privada(ip):
            return await self._indicador(http, ip, "IpAddress", "Block", contexto)
        dominio = _campo(objetivo, contexto, "red.dominio")
        if dominio:
            return await self._indicador(http, dominio, "DomainName", "Block", contexto)
        url = _campo(objetivo, contexto, "red.url")
        if url:
            return await self._indicador(http, url, "Url", "Block", contexto)
        raise NoSoportada("sin destino publico que bloquear")

    async def borrar_indicador(self, http, objetivo, parametros, contexto):
        ind = (contexto.get("datos_deshacer") or {}).get("indicador")
        if not ind:
            raise NoSoportada("no se guardo el id del indicador: retiralo desde el portal")
        cab = await self._cab(http)
        await http.peticion("DELETE", f"{self.base}/api/indicators/{ind}", cabeceras=cab)
        return Resultado("ok", f"indicador {ind} retirado")


class Entra(_Microsoft):
    nombre = "entra"
    ambito = "https://graph.microsoft.com/.default"
    acciones = {
        "identidad.revocar_sesiones": "revocar",
        "identidad.marcar_riesgo": "marcar_riesgo",
        "identidad.descartar_riesgo": "descartar_riesgo",
        "identidad.retirar_consentimiento": "retirar_consentimiento",
        "identidad.restaurar_consentimiento": "restaurar_consentimiento",
        "cuenta.deshabilitar": "deshabilitar",
        "cuenta.habilitar": "habilitar",
    }
    G = "https://graph.microsoft.com/v1.0"

    def _usuario(self, objetivo, contexto) -> str:
        u = _campo(objetivo, contexto, "usuario.id_nube") or _campo(objetivo, contexto, "usuario.upn")
        if not u:
            raise NoSoportada("sin UPN ni id de objeto de la identidad")
        return str(u)

    async def _id_objeto(self, http, cab, usuario) -> str:
        if "@" not in usuario:
            return usuario
        r = await http.peticion("GET", f"{self.G}/users/{usuario}", cabeceras=cab, params={"$select": "id"},
                                simulada={"id": "00000000-0000-0000-0000-00000000aaaa"})
        return r.json()["id"]

    async def revocar(self, http, objetivo, parametros, contexto):
        cab = await self._cab(http)
        u = self._usuario(objetivo, contexto)
        await http.peticion("POST", f"{self.G}/users/{u}/revokeSignInSessions", cabeceras=cab, json_={},
                            esperado=(200, 204), simulada={"value": True})
        return Resultado("ok", f"sesiones y tokens de refresco de {u} revocados", {"usuario": u})

    async def marcar_riesgo(self, http, objetivo, parametros, contexto):
        cab = await self._cab(http)
        oid = await self._id_objeto(http, cab, self._usuario(objetivo, contexto))
        await http.peticion("POST", f"{self.G}/identityProtection/riskyUsers/confirmCompromised", cabeceras=cab,
                            json_={"userIds": [oid]}, esperado=(200, 204))
        return Resultado("ok", f"identidad {oid} confirmada como comprometida", {"id": oid})

    async def descartar_riesgo(self, http, objetivo, parametros, contexto):
        cab = await self._cab(http)
        oid = (contexto.get("datos_deshacer") or {}).get("id") or await self._id_objeto(http, cab, self._usuario(objetivo, contexto))
        await http.peticion("POST", f"{self.G}/identityProtection/riskyUsers/dismiss", cabeceras=cab,
                            json_={"userIds": [oid]}, esperado=(200, 204))
        return Resultado("ok", f"riesgo de {oid} descartado")

    async def deshabilitar(self, http, objetivo, parametros, contexto):
        cab = await self._cab(http)
        u = self._usuario(objetivo, contexto)
        await http.peticion("PATCH", f"{self.G}/users/{u}", cabeceras=cab, json_={"accountEnabled": False},
                            esperado=(200, 204))
        return Resultado("ok", f"cuenta {u} deshabilitada", {"usuario": u})

    async def habilitar(self, http, objetivo, parametros, contexto):
        cab = await self._cab(http)
        u = (contexto.get("datos_deshacer") or {}).get("usuario") or self._usuario(objetivo, contexto)
        await http.peticion("PATCH", f"{self.G}/users/{u}", cabeceras=cab, json_={"accountEnabled": True},
                            esperado=(200, 204))
        return Resultado("ok", f"cuenta {u} habilitada")

    async def retirar_consentimiento(self, http, objetivo, parametros, contexto):
        concesion = _campo(objetivo, contexto, "nube.consentimiento_id")
        if not concesion:
            raise NoSoportada("sin id de la concesion (oauth2PermissionGrant)")
        cab = await self._cab(http)
        r = await http.peticion("GET", f"{self.G}/oauth2PermissionGrants/{concesion}", cabeceras=cab,
                                simulada={"id": concesion, "clientId": "sp", "consentType": "Principal",
                                          "principalId": "u", "resourceId": "r", "scope": "Mail.Read"})
        copia = {k: r.json().get(k) for k in ("clientId", "consentType", "principalId", "resourceId", "scope")}
        await http.peticion("DELETE", f"{self.G}/oauth2PermissionGrants/{concesion}", cabeceras=cab, esperado=(204, 200))
        return Resultado("ok", f"concesion {concesion} retirada (permisos: {copia.get('scope')})", {"concesion": copia})

    async def restaurar_consentimiento(self, http, objetivo, parametros, contexto):
        copia = (contexto.get("datos_deshacer") or {}).get("concesion")
        if not copia:
            raise NoSoportada("no hay copia de la concesion retirada")
        cab = await self._cab(http)
        await http.peticion("POST", f"{self.G}/oauth2PermissionGrants", cabeceras=cab, json_=copia)
        return Resultado("ok", "concesion recreada")


class Exchange(_Microsoft):
    nombre = "exchange"
    ambito = "https://graph.microsoft.com/.default"
    acciones = {
        "correo.retirar_mensaje": "retirar",
        "correo.restaurar_mensaje": "restaurar",
        "correo.deshabilitar_regla": "deshabilitar_regla",
        "correo.habilitar_regla": "habilitar_regla",
    }
    G = "https://graph.microsoft.com/v1.0"

    def _buzones(self, objetivo, contexto) -> list[str]:
        from ..nucleo import leer
        principal = _campo(objetivo, contexto, "correo.buzon") or _campo(objetivo, contexto, "usuario.upn")
        otros = leer(contexto.get("alerta") or {}, "correo.destinatarios") or []
        buzones = [b for b in [principal] + list(otros if isinstance(otros, list) else [otros]) if b]
        if not buzones:
            raise NoSoportada("sin buzon")
        return list(dict.fromkeys(str(b).lower() for b in buzones))[:500]

    async def retirar(self, http, objetivo, parametros, contexto):
        mid = _campo(objetivo, contexto, "correo.message_id")
        if not mid:
            raise NoSoportada("sin internetMessageId")
        cab = await self._cab(http)
        movidos = []
        for buzon in self._buzones(objetivo, contexto):
            r = await http.peticion("GET", f"{self.G}/users/{buzon}/messages", cabeceras=cab,
                                    params={"$filter": f"internetMessageId eq '{mid}'", "$select": "id"},
                                    simulada={"value": [{"id": "mensaje-simulado"}]})
            for m in r.json().get("value") or []:
                r2 = await http.peticion("POST", f"{self.G}/users/{buzon}/messages/{m['id']}/move", cabeceras=cab,
                                         json_={"destinationId": "recoverableitemsdeletions"},
                                         simulada={"id": "mensaje-movido"})
                movidos.append({"buzon": buzon, "id": r2.json().get("id")})
        return Resultado("ok", f"mensaje retirado de {len(movidos)} buzon(es) a elementos recuperables",
                         {"movidos": movidos})

    async def restaurar(self, http, objetivo, parametros, contexto):
        movidos = (contexto.get("datos_deshacer") or {}).get("movidos") or []
        if not movidos:
            raise NoSoportada("no hay registro de los mensajes movidos")
        cab = await self._cab(http)
        for m in movidos:
            await http.peticion("POST", f"{self.G}/users/{m['buzon']}/messages/{m['id']}/move", cabeceras=cab,
                                json_={"destinationId": "inbox"})
        return Resultado("ok", f"{len(movidos)} mensaje(s) devueltos a la bandeja de entrada")

    async def deshabilitar_regla(self, http, objetivo, parametros, contexto):
        regla = str(_campo(objetivo, contexto, "correo.regla_buzon") or "")
        if not regla:
            raise NoSoportada("sin regla de buzon")
        buzon = self._buzones(objetivo, contexto)[0]
        cab = await self._cab(http)
        # La auditoria de Exchange trae el nombre de la regla; Graph la conoce por
        # un id opaco. Se busca por los dos y solo se actua si casa exactamente una.
        r = await http.peticion("GET", f"{self.G}/users/{buzon}/mailFolders/inbox/messageRules", cabeceras=cab,
                                simulada={"value": [{"id": "regla-simulada", "displayName": regla, "isEnabled": True}]})
        reglas = [x for x in r.json().get("value") or [] if regla in (x.get("id"), x.get("displayName"))]
        if len(reglas) != 1:
            raise ErrorConector(f"'{regla}' casa con {len(reglas)} reglas del buzon {buzon}: no se actua")
        copia = reglas[0]
        await http.peticion("PATCH", f"{self.G}/users/{buzon}/mailFolders/inbox/messageRules/{copia['id']}",
                            cabeceras=cab, json_={"isEnabled": False})
        return Resultado("ok", f"regla '{copia.get('displayName', regla)}' deshabilitada (definicion guardada)",
                         {"buzon": buzon, "regla": copia["id"], "definicion": copia})

    async def habilitar_regla(self, http, objetivo, parametros, contexto):
        d = contexto.get("datos_deshacer") or {}
        buzon = d.get("buzon") or self._buzones(objetivo, contexto)[0]
        regla = d.get("regla") or _campo(objetivo, contexto, "correo.regla_buzon")
        cab = await self._cab(http)
        await http.peticion("PATCH", f"{self.G}/users/{buzon}/mailFolders/inbox/messageRules/{regla}", cabeceras=cab,
                            json_={"isEnabled": True})
        return Resultado("ok", "regla habilitada de nuevo")
