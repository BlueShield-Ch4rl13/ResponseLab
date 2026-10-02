"""
Estado del motor en SQLite: alertas, incidentes, ejecuciones, aprobaciones,
trabajos pendientes, listas EDL y auditoria.

Por que SQLite
--------------
Un solo nodo, modo WAL y escrituras cortas: aguanta con holgura el volumen de
un SOC mediano (miles de alertas al dia) sin otra pieza que mantener. Si hace
falta alta disponibilidad, docs/PRODUCCION.md explica el paso a PostgreSQL;
todo el acceso a datos esta en este fichero.

La auditoria es una cadena de huellas
-------------------------------------
Cada registro guarda la huella del anterior. Borrar o editar una fila rompe la
cadena a partir de ese punto, y /v1/auditoria/verificar lo detecta. No impide
manipular la base de datos; impide hacerlo sin que se note, que es lo que se
le pide a un registro de lo que una maquina ha hecho sola.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ESQUEMA = """
CREATE TABLE IF NOT EXISTS alertas (
    cliente TEXT NOT NULL, id TEXT NOT NULL, siem TEXT, recibida TEXT, momento TEXT,
    regla_clave TEXT, familia TEXT, clase TEXT, severidad INTEGER, estado TEXT,
    equipo TEXT, usuario TEXT, observables TEXT, cti TEXT, tecnicas TEXT,
    incidente_id TEXT, plan TEXT, alerta TEXT,
    PRIMARY KEY (cliente, id)
);
CREATE INDEX IF NOT EXISTS ix_alertas_momento ON alertas (cliente, momento);
CREATE INDEX IF NOT EXISTS ix_alertas_equipo ON alertas (cliente, equipo, momento);
CREATE INDEX IF NOT EXISTS ix_alertas_usuario ON alertas (cliente, usuario, momento);

CREATE TABLE IF NOT EXISTS vistos (
    cliente TEXT NOT NULL, campo TEXT NOT NULL, valor TEXT NOT NULL, primera_vez TEXT,
    PRIMARY KEY (cliente, campo, valor)
);

CREATE TABLE IF NOT EXISTS incidentes (
    id TEXT PRIMARY KEY, cliente TEXT, abierto TEXT, actualizado TEXT, estado TEXT,
    severidad INTEGER, titulo TEXT, entidad_tipo TEXT, entidad TEXT, familias TEXT,
    n_alertas INTEGER, escalado_a TEXT, plazo TEXT, asumido_por TEXT, caso_externo TEXT,
    secuencias TEXT, plazos_regulatorios TEXT, vencimiento_avisado INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_incidentes ON incidentes (cliente, estado, actualizado);

CREATE TABLE IF NOT EXISTS ejecuciones (
    id TEXT PRIMARY KEY, cliente TEXT, incidente_id TEXT, alerta_id TEXT, paso_id TEXT,
    accion TEXT, conector TEXT, origen TEXT, estado TEXT, objetivo TEXT, parametros TEXT,
    peticiones TEXT, resultado TEXT, datos_deshacer TEXT, deshace TEXT, actor TEXT,
    creada TEXT, terminada TEXT, confirmada TEXT
);
CREATE INDEX IF NOT EXISTS ix_ejecuciones ON ejecuciones (cliente, incidente_id);

CREATE TABLE IF NOT EXISTS aprobaciones (
    id TEXT PRIMARY KEY, cliente TEXT, incidente_id TEXT, alerta_id TEXT, paso TEXT,
    estado TEXT, motivo TEXT, creada TEXT, caduca TEXT, decidida TEXT, decidida_por TEXT,
    comentario TEXT, ejecuciones TEXT
);
CREATE INDEX IF NOT EXISTS ix_aprobaciones ON aprobaciones (cliente, estado);

CREATE TABLE IF NOT EXISTS tareas (
    id TEXT PRIMARY KEY, cliente TEXT, incidente_id TEXT, grupo TEXT, titulo TEXT,
    descripcion TEXT, estado TEXT, creada TEXT, plazo TEXT
);

CREATE TABLE IF NOT EXISTS trabajos (
    n INTEGER PRIMARY KEY AUTOINCREMENT, tipo TEXT, carga TEXT, estado TEXT,
    intentos INTEGER DEFAULT 0, creado TEXT, actualizado TEXT, error TEXT
);

CREATE TABLE IF NOT EXISTS edl (
    cliente TEXT, tipo TEXT, valor TEXT, motivo TEXT, creado TEXT, caduca TEXT, ejecucion_id TEXT,
    PRIMARY KEY (cliente, tipo, valor)
);

CREATE TABLE IF NOT EXISTS marcas (
    cliente TEXT, equipo TEXT, marca TEXT, desde TEXT, motivo TEXT,
    PRIMARY KEY (cliente, equipo, marca)
);

CREATE TABLE IF NOT EXISTS cti_historial (
    valor TEXT PRIMARY KEY, tipo TEXT, primera_vez TEXT, ultima_vez TEXT
);

CREATE TABLE IF NOT EXISTS auditoria (
    n INTEGER PRIMARY KEY AUTOINCREMENT, momento TEXT, cliente TEXT, actor TEXT,
    evento TEXT, detalle TEXT, previo TEXT, huella TEXT
);

CREATE TABLE IF NOT EXISTS kv (clave TEXT PRIMARY KEY, valor TEXT);
"""


def ahora() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    return (dt or ahora()).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def normalizar_momento(valor) -> str:
    """Todas las marcas de tiempo con el mismo formato, para compararlas como texto."""
    from .nucleo import a_fecha
    dt = a_fecha(valor)
    return iso(dt) if dt else iso()


def nuevo_id(prefijo: str) -> str:
    return f"{prefijo}-{uuid.uuid4().hex[:16]}"


def _j(valor) -> str:
    return json.dumps(valor, ensure_ascii=False, default=str, sort_keys=True)


def _dj(texto, defecto=None):
    if texto in (None, ""):
        return defecto
    try:
        return json.loads(texto)
    except (TypeError, ValueError):
        return defecto


class Almacen:
    def __init__(self, ruta: Path):
        ruta.parent.mkdir(parents=True, exist_ok=True)
        self.ruta = ruta
        self._cerrojo = threading.RLock()
        self.db = sqlite3.connect(str(ruta), check_same_thread=False, isolation_level=None, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(ESQUEMA)

    # ── utilidades ──
    def _uno(self, sql, args=()):
        with self._cerrojo:
            fila = self.db.execute(sql, args).fetchone()
        return dict(fila) if fila else None

    def _todos(self, sql, args=()):
        with self._cerrojo:
            return [dict(f) for f in self.db.execute(sql, args).fetchall()]

    def _exec(self, sql, args=()):
        with self._cerrojo:
            return self.db.execute(sql, args)

    def cerrar(self):
        with self._cerrojo:
            self.db.close()

    # ── auditoria ──
    def auditar(self, cliente: str, actor: str, evento: str, detalle: dict) -> str:
        with self._cerrojo:
            fila = self.db.execute("SELECT huella FROM auditoria ORDER BY n DESC LIMIT 1").fetchone()
            previo = fila["huella"] if fila else "0" * 64
            momento = iso()
            cuerpo = _j({"momento": momento, "cliente": cliente, "actor": actor, "evento": evento,
                         "detalle": detalle, "previo": previo})
            huella = hashlib.sha256(cuerpo.encode("utf-8")).hexdigest()
            self.db.execute("INSERT INTO auditoria (momento, cliente, actor, evento, detalle, previo, huella) "
                            "VALUES (?,?,?,?,?,?,?)", (momento, cliente, actor, evento, _j(detalle), previo, huella))
        return huella

    def verificar_auditoria(self) -> dict:
        previo = "0" * 64
        n = 0
        for f in self._todos("SELECT * FROM auditoria ORDER BY n"):
            cuerpo = _j({"momento": f["momento"], "cliente": f["cliente"], "actor": f["actor"],
                         "evento": f["evento"], "detalle": _dj(f["detalle"], {}), "previo": f["previo"]})
            if f["previo"] != previo or hashlib.sha256(cuerpo.encode("utf-8")).hexdigest() != f["huella"]:
                return {"integra": False, "registros": n, "rota_en": f["n"]}
            previo = f["huella"]
            n += 1
        return {"integra": True, "registros": n, "ultima_huella": previo}

    def auditoria(self, cliente: str | None = None, limite: int = 200) -> list:
        if cliente:
            filas = self._todos("SELECT * FROM auditoria WHERE cliente=? ORDER BY n DESC LIMIT ?", (cliente, limite))
        else:
            filas = self._todos("SELECT * FROM auditoria ORDER BY n DESC LIMIT ?", (limite,))
        for f in filas:
            f["detalle"] = _dj(f["detalle"], {})
        return filas

    # ── alertas ──
    def existe_alerta(self, cliente: str, alerta_id: str) -> bool:
        return self._uno("SELECT 1 AS x FROM alertas WHERE cliente=? AND id=?", (cliente, alerta_id)) is not None

    def guardar_alerta(self, alerta: dict, plan: dict, incidente_id: str, cti: list):
        a = alerta
        self._exec(
            "INSERT OR REPLACE INTO alertas (cliente, id, siem, recibida, momento, regla_clave, familia, clase, "
            "severidad, estado, equipo, usuario, observables, cti, tecnicas, incidente_id, plan, alerta) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (a["cliente"], a["id"], a["siem"], iso(), normalizar_momento(plan.get("momento")),
             plan["regla"]["clave"], plan["familia"], plan["clase"], plan["severidad"], plan["estado"],
             (a.get("equipo") or {}).get("nombre", ""), (a.get("usuario") or {}).get("nombre", ""),
             _j([o["valor"] for o in a.get("observables") or []]), _j([c["valor"] for c in cti]),
             _j(plan["regla"].get("tecnicas") or []), incidente_id, _j(plan),
             _j({k: v for k, v in a.items() if k != "bruto"})))

    def recientes(self, cliente: str, desde: datetime, limite: int = 5000) -> list:
        filas = self._todos(
            "SELECT id, momento, regla_clave, familia, equipo, usuario, observables, cti, tecnicas "
            "FROM alertas WHERE cliente=? AND momento>=? ORDER BY momento DESC LIMIT ?",
            (cliente, iso(desde), limite))
        for f in filas:
            f["observables"] = _dj(f["observables"], [])
            f["cti"] = _dj(f["cti"], [])
            f["tecnicas"] = _dj(f["tecnicas"], [])
        return filas

    def visto(self, cliente: str, campo: str, valor: str) -> bool:
        """True si el valor ya se habia visto antes; lo registra si no."""
        if not valor:
            return False
        with self._cerrojo:
            fila = self.db.execute("SELECT 1 FROM vistos WHERE cliente=? AND campo=? AND valor=?",
                                   (cliente, campo, str(valor).lower())).fetchone()
            if fila:
                return True
            self.db.execute("INSERT OR IGNORE INTO vistos (cliente, campo, valor, primera_vez) VALUES (?,?,?,?)",
                            (cliente, campo, str(valor).lower(), iso()))
            return False

    def alertas(self, cliente: str | None = None, incidente_id: str | None = None, limite: int = 200) -> list:
        sql, args = "SELECT cliente, id, siem, recibida, momento, regla_clave, familia, clase, severidad, estado, " \
                    "equipo, usuario, incidente_id, plan FROM alertas WHERE 1=1", []
        if cliente:
            sql += " AND cliente=?"
            args.append(cliente)
        if incidente_id:
            sql += " AND incidente_id=?"
            args.append(incidente_id)
        sql += " ORDER BY recibida DESC LIMIT ?"
        args.append(limite)
        filas = self._todos(sql, tuple(args))
        for f in filas:
            f["plan"] = _dj(f["plan"], {})
        return filas

    # ── incidentes ──
    def incidente_abierto(self, cliente: str, entidad_tipo: str, entidad: str, desde: datetime):
        f = self._uno(
            "SELECT * FROM incidentes WHERE cliente=? AND entidad_tipo=? AND lower(entidad)=lower(?) "
            "AND estado IN ('abierto','asumido') AND actualizado>=? ORDER BY actualizado DESC LIMIT 1",
            (cliente, entidad_tipo, entidad, iso(desde)))
        if f:
            for k in ("familias", "secuencias", "plazos_regulatorios"):
                f[k] = _dj(f[k], [])
        return f

    def crear_incidente(self, cliente: str, entidad_tipo: str, entidad: str, plan: dict) -> dict:
        inc = {
            "id": nuevo_id("inc"), "cliente": cliente, "abierto": iso(), "actualizado": iso(), "estado": "abierto",
            "severidad": plan["severidad"], "titulo": plan["regla"]["titulo"] or plan["titulo"],
            "entidad_tipo": entidad_tipo, "entidad": entidad, "familias": _j([plan["familia"]]),
            "n_alertas": 1, "escalado_a": plan["escalado"].get("a", "L2"),
            "plazo": iso(ahora() + timedelta(minutes=int(plan["escalado"].get("plazo_min", 30)))),
            "asumido_por": "", "caso_externo": "", "secuencias": _j([s["id"] for s in plan.get("secuencias") or []]),
            "plazos_regulatorios": _j([]), "vencimiento_avisado": 0,
        }
        self._exec("INSERT INTO incidentes (%s) VALUES (%s)" % (",".join(inc), ",".join("?" * len(inc))),
                   tuple(inc.values()))
        return self.incidente(inc["id"])

    def actualizar_incidente(self, inc_id: str, plan: dict):
        inc = self.incidente(inc_id)
        if not inc:
            return None
        familias = sorted(set(inc["familias"]) | {plan["familia"]})
        secuencias = sorted(set(inc["secuencias"]) | {s["id"] for s in plan.get("secuencias") or []})
        orden = ["L1", "L2", "L3", "guardia"]
        escalado = max([inc["escalado_a"], plan["escalado"].get("a", "L2")],
                       key=lambda x: orden.index(x) if x in orden else 1)
        plazo_nuevo = ahora() + timedelta(minutes=int(plan["escalado"].get("plazo_min", 30)))
        plazo = min(plazo_nuevo, datetime.fromisoformat(inc["plazo"].replace("Z", "+00:00"))) \
            if inc["estado"] == "abierto" else datetime.fromisoformat(inc["plazo"].replace("Z", "+00:00"))
        self._exec("UPDATE incidentes SET actualizado=?, severidad=max(severidad, ?), familias=?, n_alertas=n_alertas+1, "
                   "escalado_a=?, plazo=?, secuencias=? WHERE id=?",
                   (iso(), plan["severidad"], _j(familias), escalado, iso(plazo), _j(secuencias), inc_id))
        return self.incidente(inc_id)

    def incidente(self, inc_id: str):
        f = self._uno("SELECT * FROM incidentes WHERE id=?", (inc_id,))
        if f:
            for k in ("familias", "secuencias", "plazos_regulatorios"):
                f[k] = _dj(f[k], [])
        return f

    def incidentes(self, cliente: str | None = None, estado: str | None = None, limite: int = 100) -> list:
        sql, args = "SELECT * FROM incidentes WHERE 1=1", []
        if cliente:
            sql += " AND cliente=?"
            args.append(cliente)
        if estado:
            sql += " AND estado=?"
            args.append(estado)
        sql += " ORDER BY actualizado DESC LIMIT ?"
        args.append(limite)
        filas = self._todos(sql, tuple(args))
        for f in filas:
            for k in ("familias", "secuencias", "plazos_regulatorios"):
                f[k] = _dj(f[k], [])
        return filas

    def modificar_incidente(self, inc_id: str, **campos):
        if not campos:
            return
        for k in ("familias", "secuencias", "plazos_regulatorios"):
            if k in campos and not isinstance(campos[k], str):
                campos[k] = _j(campos[k])
        self._exec("UPDATE incidentes SET %s WHERE id=?" % ", ".join(f"{k}=?" for k in campos),
                   tuple(campos.values()) + (inc_id,))

    def incidentes_vencidos(self) -> list:
        return self._todos("SELECT * FROM incidentes WHERE estado='abierto' AND plazo<? AND vencimiento_avisado=0",
                           (iso(),))

    # ── ejecuciones ──
    def crear_ejecucion(self, **campos) -> dict:
        campos.setdefault("id", nuevo_id("ej"))
        campos.setdefault("creada", iso())
        for k in ("objetivo", "parametros", "peticiones", "resultado", "datos_deshacer"):
            if k in campos and not isinstance(campos[k], str):
                campos[k] = _j(campos[k])
        self._exec("INSERT INTO ejecuciones (%s) VALUES (%s)" % (",".join(campos), ",".join("?" * len(campos))),
                   tuple(campos.values()))
        return self.ejecucion(campos["id"])

    def terminar_ejecucion(self, ej_id: str, estado: str, resultado, peticiones, datos_deshacer=None):
        self._exec("UPDATE ejecuciones SET estado=?, resultado=?, peticiones=?, datos_deshacer=?, terminada=? WHERE id=?",
                   (estado, _j(resultado), _j(peticiones), _j(datos_deshacer or {}), iso(), ej_id))

    def confirmar_ejecucion(self, ej_id: str, estado: str, detalle: dict):
        ej = self.ejecucion(ej_id)
        if not ej:
            return None
        resultado = ej.get("resultado") or {}
        resultado["confirmacion"] = detalle
        self._exec("UPDATE ejecuciones SET estado=?, resultado=?, confirmada=? WHERE id=?",
                   (estado, _j(resultado), iso(), ej_id))
        return self.ejecucion(ej_id)

    def ejecucion(self, ej_id: str):
        f = self._uno("SELECT * FROM ejecuciones WHERE id=?", (ej_id,))
        if f:
            for k in ("objetivo", "parametros", "peticiones", "resultado", "datos_deshacer"):
                f[k] = _dj(f[k], {} if k != "peticiones" else [])
        return f

    def ejecuciones(self, cliente: str | None = None, incidente_id: str | None = None, limite: int = 200) -> list:
        sql, args = "SELECT * FROM ejecuciones WHERE 1=1", []
        if cliente:
            sql += " AND cliente=?"
            args.append(cliente)
        if incidente_id:
            sql += " AND incidente_id=?"
            args.append(incidente_id)
        sql += " ORDER BY creada DESC LIMIT ?"
        args.append(limite)
        filas = self._todos(sql, tuple(args))
        for f in filas:
            for k in ("objetivo", "parametros", "peticiones", "resultado", "datos_deshacer"):
                f[k] = _dj(f[k], {} if k != "peticiones" else [])
        return filas

    def ejecucion_previa(self, cliente: str, alerta_id: str, paso_id: str):
        """Idempotencia: la misma accion de la misma alerta no se ejecuta dos veces."""
        return self._uno("SELECT id, estado FROM ejecuciones WHERE cliente=? AND alerta_id=? AND paso_id=? "
                         "AND deshace IS NULL AND estado NOT IN ('error')", (cliente, alerta_id, paso_id))

    def accion_vigente(self, cliente: str, incidente_id: str, accion: str, objetivo: dict):
        """La misma accion sobre el mismo objetivo ya aplicada en el incidente y no
        deshecha: la segunda alerta de un ataque no vuelve a aislar el equipo."""
        if not incidente_id:
            return None
        return self._uno(
            "SELECT e.id, e.estado FROM ejecuciones e WHERE e.cliente=? AND e.incidente_id=? AND e.accion=? "
            "AND e.objetivo=? AND e.deshace IS NULL AND e.estado IN ('ok', 'simulada', 'en_curso', 'confirmada') "
            "AND NOT EXISTS (SELECT 1 FROM ejecuciones d WHERE d.deshace = e.id AND d.estado IN ('ok', 'simulada', 'confirmada'))",
            (cliente, incidente_id, accion, _j(objetivo or {})))

    def deshecha_por(self, ej_id: str):
        """La ejecucion que ya deshizo (o esta deshaciendo) a esta, si la hay."""
        return self._uno("SELECT id, estado FROM ejecuciones WHERE deshace=? "
                         "AND estado IN ('ok', 'simulada', 'en_curso', 'confirmada') LIMIT 1", (ej_id,))

    # ── aprobaciones ──
    def crear_aprobacion(self, cliente, incidente_id, alerta_id, paso, motivo, caduca) -> dict:
        ap = {"id": nuevo_id("ap"), "cliente": cliente, "incidente_id": incidente_id, "alerta_id": alerta_id,
              "paso": _j(paso), "estado": "pendiente", "motivo": motivo, "creada": iso(), "caduca": iso(caduca),
              "decidida": "", "decidida_por": "", "comentario": "", "ejecuciones": _j([])}
        self._exec("INSERT INTO aprobaciones (%s) VALUES (%s)" % (",".join(ap), ",".join("?" * len(ap))),
                   tuple(ap.values()))
        return self.aprobacion(ap["id"])

    def aprobacion(self, ap_id: str):
        f = self._uno("SELECT * FROM aprobaciones WHERE id=?", (ap_id,))
        if f:
            f["paso"] = _dj(f["paso"], {})
            f["ejecuciones"] = _dj(f["ejecuciones"], [])
        return f

    def aprobaciones(self, cliente: str | None = None, estado: str | None = None, limite: int = 200) -> list:
        sql, args = "SELECT * FROM aprobaciones WHERE 1=1", []
        if cliente:
            sql += " AND cliente=?"
            args.append(cliente)
        if estado:
            sql += " AND estado=?"
            args.append(estado)
        sql += " ORDER BY creada DESC LIMIT ?"
        args.append(limite)
        filas = self._todos(sql, tuple(args))
        for f in filas:
            f["paso"] = _dj(f["paso"], {})
            f["ejecuciones"] = _dj(f["ejecuciones"], [])
        return filas

    def decidir_aprobacion(self, ap_id: str, estado: str, quien: str, comentario: str) -> bool:
        """Solo cambia si sigue pendiente (dos aprobadores a la vez no ejecutan dos
        veces) y, para aprobar, si no ha caducado aunque la vigilancia aun no la
        haya marcado."""
        caducidad = " AND caduca>?" if estado == "aprobada" else ""
        args = (estado, iso(), quien, comentario, ap_id) + ((iso(),) if caducidad else ())
        with self._cerrojo:
            cur = self.db.execute("UPDATE aprobaciones SET estado=?, decidida=?, decidida_por=?, comentario=? "
                                  "WHERE id=? AND estado='pendiente'" + caducidad, args)
            return cur.rowcount == 1

    def anotar_ejecuciones_aprobacion(self, ap_id: str, ejecuciones: list, estado: str):
        self._exec("UPDATE aprobaciones SET ejecuciones=?, estado=? WHERE id=?", (_j(ejecuciones), estado, ap_id))

    def caducar_aprobaciones(self) -> list:
        vencidas = self._todos("SELECT id, cliente, incidente_id FROM aprobaciones WHERE estado='pendiente' AND caduca<?",
                               (iso(),))
        for v in vencidas:
            self._exec("UPDATE aprobaciones SET estado='caducada' WHERE id=? AND estado='pendiente'", (v["id"],))
        return vencidas

    # ── tareas del caso ──
    def crear_tarea(self, cliente, incidente_id, grupo, titulo, descripcion, plazo: str = "") -> dict:
        t = {"id": nuevo_id("t"), "cliente": cliente, "incidente_id": incidente_id, "grupo": grupo,
             "titulo": titulo, "descripcion": descripcion, "estado": "pendiente", "creada": iso(), "plazo": plazo}
        self._exec("INSERT INTO tareas (%s) VALUES (%s)" % (",".join(t), ",".join("?" * len(t))), tuple(t.values()))
        return t

    def tareas(self, incidente_id: str) -> list:
        return self._todos("SELECT * FROM tareas WHERE incidente_id=? ORDER BY creada", (incidente_id,))

    # ── trabajos (cola persistente) ──
    def encolar(self, tipo: str, carga: dict) -> int:
        cur = self._exec("INSERT INTO trabajos (tipo, carga, estado, creado, actualizado) VALUES (?,?,?,?,?)",
                         (tipo, _j(carga), "pendiente", iso(), iso()))
        return cur.lastrowid

    def tomar_trabajo(self):
        with self._cerrojo:
            f = self.db.execute("SELECT * FROM trabajos WHERE estado='pendiente' ORDER BY n LIMIT 1").fetchone()
            if not f:
                return None
            self.db.execute("UPDATE trabajos SET estado='en_curso', intentos=intentos+1, actualizado=? WHERE n=?",
                            (iso(), f["n"]))
            d = dict(f)
        d["carga"] = _dj(d["carga"], {})
        return d

    def terminar_trabajo(self, n: int, error: str = ""):
        self._exec("UPDATE trabajos SET estado=?, error=?, actualizado=? WHERE n=?",
                   ("error" if error else "hecho", error[:2000], iso(), n))

    def reencolar_huerfanos(self) -> int:
        """Al arrancar: lo que quedo 'en_curso' por una caida vuelve a la cola."""
        cur = self._exec("UPDATE trabajos SET estado='pendiente' WHERE estado='en_curso' AND intentos<3")
        return cur.rowcount

    def pendientes(self) -> int:
        f = self._uno("SELECT count(*) AS n FROM trabajos WHERE estado IN ('pendiente','en_curso')")
        return f["n"] if f else 0

    # ── EDL ──
    def edl_anadir(self, cliente, tipo, valor, motivo, caduca: datetime, ejecucion_id: str):
        self._exec("INSERT OR REPLACE INTO edl (cliente, tipo, valor, motivo, creado, caduca, ejecucion_id) "
                   "VALUES (?,?,?,?,?,?,?)", (cliente, tipo, valor.lower(), motivo, iso(), iso(caduca), ejecucion_id))

    def edl_quitar(self, cliente, tipo, valor) -> bool:
        cur = self._exec("DELETE FROM edl WHERE cliente=? AND tipo=? AND valor=?", (cliente, tipo, valor.lower()))
        return cur.rowcount > 0

    def edl(self, cliente, tipo) -> list:
        return [f["valor"] for f in self._todos(
            "SELECT valor FROM edl WHERE cliente=? AND tipo=? AND caduca>? ORDER BY valor", (cliente, tipo, iso()))]

    def edl_purgar(self) -> int:
        return self._exec("DELETE FROM edl WHERE caduca<?", (iso(),)).rowcount

    # ── marcas de inventario ──
    def marcar(self, cliente, equipo, marca, motivo):
        self._exec("INSERT OR REPLACE INTO marcas (cliente, equipo, marca, desde, motivo) VALUES (?,?,?,?,?)",
                   (cliente, equipo.lower(), marca, iso(), motivo))

    def desmarcar(self, cliente, equipo, marca):
        self._exec("DELETE FROM marcas WHERE cliente=? AND equipo=? AND marca=?", (cliente, equipo.lower(), marca))

    def marcas(self, cliente, equipo) -> list:
        return self._todos("SELECT * FROM marcas WHERE cliente=? AND equipo=?", (cliente, (equipo or "").lower()))

    # ── historial de inteligencia ──
    def cti_registrar(self, valores: list[tuple[str, str]]):
        momento = iso()
        with self._cerrojo:
            self.db.execute("BEGIN")
            try:
                for valor, tipo in valores:
                    self.db.execute("INSERT INTO cti_historial (valor, tipo, primera_vez, ultima_vez) VALUES (?,?,?,?) "
                                    "ON CONFLICT(valor) DO UPDATE SET ultima_vez=excluded.ultima_vez",
                                    (valor.lower(), tipo, momento, momento))
                self.db.execute("COMMIT")
            except Exception:
                self.db.execute("ROLLBACK")
                raise

    def cti_historial(self, valores: list[str]) -> list:
        if not valores:
            return []
        marcas = ",".join("?" * len(valores))
        return self._todos(f"SELECT * FROM cti_historial WHERE valor IN ({marcas})", tuple(v.lower() for v in valores))

    # ── kv ──
    def kv(self, clave, defecto=None):
        f = self._uno("SELECT valor FROM kv WHERE clave=?", (clave,))
        return _dj(f["valor"], defecto) if f else defecto

    def kv_poner(self, clave, valor):
        self._exec("INSERT OR REPLACE INTO kv (clave, valor) VALUES (?,?)", (clave, _j(valor)))

    # ── metricas ──
    def contar(self) -> dict:
        def n(sql, args=()):
            f = self._uno(sql, args)
            return f["n"] if f else 0
        return {
            "alertas": n("SELECT count(*) AS n FROM alertas"),
            "incidentes_abiertos": n("SELECT count(*) AS n FROM incidentes WHERE estado IN ('abierto','asumido')"),
            "aprobaciones_pendientes": n("SELECT count(*) AS n FROM aprobaciones WHERE estado='pendiente'"),
            "trabajos_pendientes": n("SELECT count(*) AS n FROM trabajos WHERE estado IN ('pendiente','en_curso')"),
            "ejecuciones_por_estado": {f["estado"]: f["n"] for f in self._todos(
                "SELECT estado, count(*) AS n FROM ejecuciones GROUP BY estado")},
            "alertas_por_clase": {f["clase"]: f["n"] for f in self._todos(
                "SELECT clase, count(*) AS n FROM alertas GROUP BY clase")},
        }
