"""
Conectores que ejecuta el propio motor: tareas del caso, marcas de inventario,
retencion de evidencia registrada y listas EDL para el perimetro.

EDL (External Dynamic List)
---------------------------
Palo Alto, Fortinet, Check Point, pfSense y OPNsense saben leer una lista de
IP, dominios o URL desde una URL y refrescarla cada pocos minutos. El motor
publica una por cliente y tipo en /v1/edl/<cliente>/<tipo>. Bloquear en el
perimetro pasa a ser anadir una linea con caducidad; desbloquear, quitarla.
Funciona con cualquier fabricante que lea EDL, sin credenciales del
cortafuegos en el motor, y cada entrada caduca sola (72 h por defecto): un
bloqueo olvidado no se queda para siempre.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone

from ..regulatorio import plazos_para
from .base import Conector, NoSoportada, Resultado


def _campo(objetivo: dict, contexto: dict, ruta: str):
    from ..nucleo import leer
    return objetivo.get(ruta) or leer(contexto.get("alerta") or {}, ruta)


class Interno(Conector):
    nombre = "interno"
    acciones = {
        "caso.nota": "nota",
        "caso.tarea_obligacion": "tarea_obligacion",
        "caso.tarea_desviacion": "tarea_desviacion",
        "itsm.ticket": "tarea_generica",
        "credenciales.marcar_rotacion": "marcar_rotacion",
        "inventario.marcar_no_fiable": "marcar_no_fiable",
        "evidencia.retener": "retener",
    }

    def _tarea(self, contexto, grupo, titulo, descripcion, plazo=""):
        almacen = self.motor.almacen if self.motor else None
        if almacen is None or self.simulacion and contexto.get("no_persistir"):
            return {}
        return almacen.crear_tarea(self.cliente["id"], contexto.get("incidente_id", ""), grupo, titulo, descripcion, plazo)

    async def nota(self, http, objetivo, parametros, contexto):
        paso = contexto.get("paso") or {}
        t = self._tarea(contexto, "Contencion", paso.get("nombre", "Nota"), paso.get("origen", ""))
        return Resultado("ok", "anotado en el caso", {"tarea": t.get("id")})

    async def tarea_generica(self, http, objetivo, parametros, contexto):
        paso = contexto.get("paso") or {}
        t = self._tarea(contexto, "Seguimiento", paso.get("nombre", "Tarea"), paso.get("origen", ""))
        return Resultado("ok", "tarea abierta", {"tarea": t.get("id")})

    async def tarea_obligacion(self, http, objetivo, parametros, contexto):
        plan = contexto.get("plan") or {}
        alerta = contexto.get("alerta") or {}
        from ..nucleo import activos_de, leer
        etiquetas = {e for a in activos_de(self.cliente, leer(alerta, "equipo.nombre"), leer(alerta, "equipo.ip"))
                     for e in a.get("etiquetas") or []}
        plazos = plazos_para(self.cliente, plan, datetime.now(timezone.utc), etiquetas=etiquetas)
        if not plazos:
            t = self._tarea(contexto, "Cumplimiento", "Evaluar si el hecho es notificable",
                            "El perfil del cliente no declara marcos regulatorios: decidir a mano si aplica NIS2, DORA o RGPD.")
            return Resultado("ok", "sin marcos declarados: tarea de evaluacion", {"tarea": t.get("id")})
        ids = []
        for p in plazos:
            t = self._tarea(contexto, "Cumplimiento", f"{p['marco']}: {p['hito']}",
                            f"{p['descripcion']} Vence: {p['vence']} ({p['horas_restantes']:.1f} h).", p["vence"])
            ids.append(t.get("id"))
        return Resultado("ok", f"{len(plazos)} plazo(s) regulatorio(s) abiertos", {"tareas": ids, "plazos": plazos})

    async def tarea_desviacion(self, http, objetivo, parametros, contexto):
        alerta = contexto.get("alerta") or {}
        t = self._tarea(contexto, "Remediacion", f"Desviacion: {alerta.get('titulo', '')[:120]}",
                        "Desviacion de arquitectura contra el propietario del activo, con la evidencia del caso.")
        return Resultado("ok", "tarea de desviacion abierta", {"tarea": t.get("id")})

    async def marcar_rotacion(self, http, objetivo, parametros, contexto):
        usuario = _campo(objetivo, contexto, "usuario.nombre")
        equipo = _campo(objetivo, contexto, "equipo.nombre")
        t = self._tarea(contexto, "Contencion", "Rotar credenciales",
                        f"Rotar la contrasena de {usuario or '-'} y las credenciales locales y de servicio de {equipo or '-'}.")
        return Resultado("ok", "credenciales marcadas para rotacion", {"tarea": t.get("id")})

    async def marcar_no_fiable(self, http, objetivo, parametros, contexto):
        equipo = _campo(objetivo, contexto, "equipo.nombre")
        if self.motor and not self.simulacion:
            self.motor.almacen.marcar(self.cliente["id"], equipo, "telemetria_no_fiable",
                                      (contexto.get("alerta") or {}).get("titulo", ""))
        return Resultado("ok", f"{equipo}: telemetria marcada como no fiable", {"equipo": equipo})

    async def retener(self, http, objetivo, parametros, contexto):
        alerta = contexto.get("alerta") or {}
        t = self._tarea(contexto, "Evidencia", "Fijar retencion extendida",
                        f"Conservar los registros de {(alerta.get('equipo') or {}).get('nombre', '-')} "
                        f"desde 24 h antes de {alerta.get('momento', '')}. Sin conector de SIEM configurado: hacerlo a mano.")
        return Resultado("ok", "retencion registrada como tarea", {"tarea": t.get("id")})


class Edl(Conector):
    nombre = "edl"
    acciones = {
        "perimetro.bloquear_destino": "bloquear",
        "perimetro.desbloquear_destino": "desbloquear",
        "waf.bloquear_origen": "bloquear_origen",
        "waf.desbloquear_origen": "desbloquear_origen",
        "correo.bloquear_url": "bloquear_url",
        "correo.desbloquear_url": "desbloquear_url",
    }

    def _ttl(self) -> datetime:
        horas = int((self.cliente.get("politica") or {}).get("bloqueo_perimetro_horas", 72))
        return datetime.now(timezone.utc) + timedelta(hours=horas)

    def _entradas(self, objetivo, contexto, campos):
        salida = []
        for campo in campos:
            v = _campo(objetivo, contexto, campo)
            if not v:
                continue
            if campo.endswith("ip_destino") or campo.endswith("ip_origen"):
                try:
                    ip = ipaddress.ip_address(str(v))
                except ValueError:
                    continue
                if ip.is_private or ip.is_loopback:
                    # Una IP interna en la lista de bloqueo del perimetro corta
                    # trafico propio. No se hace nunca, ni con aprobacion.
                    raise NoSoportada(f"{v} es una direccion interna: no se bloquea en el perimetro")
                salida.append(("ip", str(ip)))
            elif campo.endswith("dominio"):
                salida.append(("dominio", str(v).lower()))
            elif campo.endswith("url"):
                salida.append(("url", str(v)))
        if not salida:
            raise NoSoportada("sin IP, dominio ni URL que bloquear")
        return salida

    async def _poner(self, objetivo, contexto, campos):
        entradas = self._entradas(objetivo, contexto, campos)
        caduca = self._ttl()
        if self.motor and not self.simulacion:
            for tipo, valor in entradas:
                self.motor.almacen.edl_anadir(self.cliente["id"], tipo, valor,
                                              (contexto.get("alerta") or {}).get("titulo", "")[:200],
                                              caduca, contexto.get("ejecucion_id", ""))
        return Resultado("ok", "en la EDL hasta " + caduca.strftime("%Y-%m-%d %H:%M UTC") + ": "
                         + ", ".join(f"{t}:{v}" for t, v in entradas), {"entradas": entradas})

    async def _quitar(self, objetivo, contexto, campos):
        entradas = (contexto.get("datos_deshacer") or {}).get("entradas") or self._entradas(objetivo, contexto, campos)
        if self.motor and not self.simulacion:
            for tipo, valor in entradas:
                self.motor.almacen.edl_quitar(self.cliente["id"], tipo, valor)
        return Resultado("ok", "retirado de la EDL: " + ", ".join(f"{t}:{v}" for t, v in entradas))

    async def bloquear(self, http, objetivo, parametros, contexto):
        return await self._poner(objetivo, contexto, ["red.ip_destino", "red.dominio", "red.url"])

    async def desbloquear(self, http, objetivo, parametros, contexto):
        return await self._quitar(objetivo, contexto, ["red.ip_destino", "red.dominio", "red.url"])

    async def bloquear_origen(self, http, objetivo, parametros, contexto):
        return await self._poner(objetivo, contexto, ["red.ip_origen"])

    async def desbloquear_origen(self, http, objetivo, parametros, contexto):
        return await self._quitar(objetivo, contexto, ["red.ip_origen"])

    async def bloquear_url(self, http, objetivo, parametros, contexto):
        return await self._poner(objetivo, contexto, ["red.url"])

    async def desbloquear_url(self, http, objetivo, parametros, contexto):
        return await self._quitar(objetivo, contexto, ["red.url"])
