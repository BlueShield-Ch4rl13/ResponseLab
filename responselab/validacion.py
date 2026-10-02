"""
Comprobaciones del catalogo compilado.

Errores: lo que haria que el motor decidiera mal o no pudiera leer algo.
Avisos: lo que es seguro pero conviene mirar (una accion nueva de DetectionLab
sin mapear queda como tarea manual: no se pierde, pero tampoco se automatiza).

La comprobacion que de verdad importa es la ultima: se simula una alerta de
cada una de las reglas del catalogo con un cliente que lo permite todo, y
ninguna accion automatica puede violar las invariantes de radio y
reversibilidad. Si un dia alguien cambia un radio en el catalogo o una
excepcion en un playbook y abre la puerta a algo peligroso, aqui se ve.
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict

from . import nucleo
from .util import RAIZ

CAPACIDADES = {"edr", "agente", "nac", "identidad", "correo", "pasarela_correo", "perimetro",
               "waf", "kubernetes", "siem", "casos", "itsm", "aplicacion", "interno"}
CONECTORES = {"wazuh", "defender", "crowdstrike", "sentinelone", "entra", "exchange", "paloalto",
              "fortinet", "cloudflare", "edl", "kubernetes", "splunk", "thehive", "interno",
              "declarativo"}

# Lo que el motor lee de cada proyecto vecino. Si desaparece, el motor deja
# de entender sus ficheros: es error, no aviso.
CONTRATOS = {
    "newscti": {
        "claves": ["iocs", "cisa_kev_recent", "generated_utc"],
        "claves_ioc": ["value", "type", "level", "score", "age_days", "sources", "threat"],
        "claves_kev": ["cve"],
    },
    "malpipe": {
        "Report": ["verdict", "score", "static", "dynamic", "attack"],
        "StaticResult": ["hashes", "indicators", "filename"],
        "Hashes": ["sha256", "sha1", "md5"],
        "Indicators": ["ips", "domains", "urls"],
        "AttackTechnique": ["id", "name", "tactic"],
        "DynamicResult": ["family", "score"],
    },
    "ftriagedfir": {
        "opciones_triage": ["--case", "--examiner", "--output", "--target-os"],
        "informe": ["case", "host", "assessment", "iocs", "findings"],
    },
}


def _evaluadores_de(spec, salida: list):
    if spec is None:
        return
    if isinstance(spec, list):
        for x in spec:
            _evaluadores_de(x, salida)
        return
    if not isinstance(spec, dict):
        return
    for k, v in spec.items():
        if k in ("todos", "alguno"):
            _evaluadores_de(v, salida)
        elif k == "negar":
            _evaluadores_de(v, salida)
        else:
            salida.append((k, v))


def alerta_completa(regla: dict) -> dict:
    """Alerta sintetica con todos los campos, para que toda accion tenga objetivo."""
    a = nucleo.alerta_vacia("generico", "validacion")
    a.update({
        "id": "val-" + regla["clave"], "titulo": regla["titulo"], "regla_id": (regla.get("wazuh_ids") or [""])[0],
        "regla_fichero": regla["fichero"] if regla["fichero"].endswith(".yml") else "",
        "siem": "wazuh" if regla.get("wazuh_ids") else "generico",
        "momento": "2026-10-01T10:00:00Z", "cve": ["CVE-2021-44228"],
        "equipo": {"nombre": "PC-VAL-01", "ip": "10.0.0.10", "id_agente": "001", "id_edr": "edr-001"},
        "usuario": {"nombre": "usuario", "upn": "usuario@ejemplo.test", "id_nube": "00000000-0000-0000-0000-000000000001"},
        "proceso": {"guid": "1f2e3d4c-0000-1111-2222-333344445555", "pid": 4242, "inicio": "2026-10-01T09:59:58Z",
                    "imagen": "C:\\Users\\Public\\m.exe", "sha256": "a" * 64, "sha1": "b" * 40},
        "fichero": {"ruta": "C:\\Users\\Public\\m.exe", "sha256": "a" * 64, "sha1": "b" * 40},
        "persistencia": {"tipo": "tarea", "nombre": "Actualizador", "ruta": "C:\\Users\\Public\\m.exe"},
        "red": {"ip_origen": "203.0.113.10", "ip_destino": "198.51.100.20", "dominio": "malo.example", "url": "http://malo.example/x"},
        "correo": {"message_id": "<id@ejemplo>", "buzon": "usuario@ejemplo.test", "regla_buzon": "regla-1", "remitente": "a@malo.example"},
        "nube": {"consentimiento_id": "grant-1", "sp_id": "sp-1"},
        "k8s": {"namespace": "ns", "pod": "pod-1", "nodo": "nodo-1", "rolebinding": "rolebindings/ns/rb", "workload": "deployment/app"},
        "objeto_ad": "CN=krbtgt,CN=Users,DC=ejemplo,DC=test", "clave_ssh": "ssh-ed25519 AAAA", "sesion": {"id": "s-1"},
    })
    return a


COMBINADORES = ("todos", "alguno", "negar")


def errores_evaluador(spec, donde: str) -> list[str]:
    """Nombres de evaluador que el nucleo no conoce y especificaciones mal formadas.

    Un catalogo descargado que usa un evaluador de una version mas nueva del
    motor se rechaza aqui con un mensaje, en vez de reventar en cada alerta.
    """
    if spec is None:
        return []
    if isinstance(spec, list):
        return [e for x in spec for e in errores_evaluador(x, donde)]
    if not isinstance(spec, dict) or len(spec) != 1:
        return [f"{donde}: evaluador mal formado {spec!r}"]
    nombre, arg = next(iter(spec.items()))
    if nombre in ("todos", "alguno"):
        if not isinstance(arg, list):
            return [f"{donde}: '{nombre}' necesita una lista"]
        return [e for x in arg for e in errores_evaluador(x, donde)]
    if nombre == "negar":
        return errores_evaluador(arg, donde)
    if nombre not in nucleo.EVALUADORES:
        return [f"{donde}: evaluador desconocido '{nombre}' (este motor conoce {len(nucleo.EVALUADORES)})"]
    return []


def validar(catalogo: dict, contratos: dict | None = None) -> tuple[list, list, dict]:
    errores, avisos = [], []
    acciones = catalogo.get("acciones", {})
    familias = catalogo.get("familias", {})
    reglas = catalogo.get("reglas", [])
    ids_regla = set()
    for r in reglas:
        ids_regla |= {r["clave"].lower(), nucleo.stem(r["clave"]).lower()} | {str(w) for w in r.get("wazuh_ids") or []}

    # ── Acciones ──
    for nombre, a in sorted(acciones.items()):
        if a.get("radio") not in nucleo.ORDEN_RADIO:
            errores.append(f"accion {nombre}: radio '{a.get('radio')}' no valido")
        if str(a.get("reversible")) not in ("si", "no"):
            errores.append(f"accion {nombre}: reversible={a.get('reversible')!r}; debe ir entrecomillado como \"si\" o \"no\"")
        if a.get("capacidad") not in CAPACIDADES:
            errores.append(f"accion {nombre}: capacidad '{a.get('capacidad')}' desconocida")
        for c in a.get("conectores") or []:
            if c not in CONECTORES:
                errores.append(f"accion {nombre}: conector '{c}' desconocido")
        if a.get("registro") and (a.get("radio") in nucleo.RADIOS_AMPLIOS or str(a.get("reversible")) != "si"):
            errores.append(f"INVARIANTE ROTA en la accion {nombre}: una accion de registro se ejecuta sola, asi que "
                           f"tiene que ser reversible y de radio estrecho (radio {a.get('radio')}, "
                           f"reversible {a.get('reversible')})")
        if a.get("deshacer") and a["deshacer"] not in acciones:
            errores.append(f"accion {nombre}: su inversa '{a['deshacer']}' no existe")
        if a.get("reversible") == "si" and not a.get("deshacer") and not a.get("inversa") and not a.get("registro") \
                and not nombre.startswith(("evidencia.", "identidad.revocar", "caso.", "itsm.")) \
                and a.get("radio") != "objeto":
            avisos.append(f"accion {nombre}: reversible pero sin accion inversa declarada")
        for req in a.get("requiere") or []:
            for alt in str(req).split("|"):
                for campo in alt.split("+"):
                    if not re.fullmatch(r"[a-z0-9_]+(\.[a-z0-9_]+)?", campo.strip()):
                        errores.append(f"accion {nombre}: campo requerido mal escrito '{campo}'")

    # ── Familias ──
    metricas_fam = {}
    for nombre, f in sorted(familias.items()):
        n_tri = len(f.get("triaje") or [])
        n_tri_auto = sum(1 for t in f.get("triaje") or [] if t.get("evaluador"))
        n_cie = len(f.get("cierre") or [])
        n_cie_auto = sum(1 for c in f.get("cierre") or [] if c.get("evaluador"))
        cont = f.get("contencion") or []
        for c in cont:
            if c.get("accion") and c["accion"] not in acciones:
                errores.append(f"{nombre}: accion '{c['accion']}' no esta en el catalogo")
            if c.get("radio") not in nucleo.ORDEN_RADIO:
                errores.append(f"{nombre}: radio '{c.get('radio')}' no valido en '{c.get('texto', '')[:50]}'")
            for campo in ("reversible", "requiere_aprobacion"):
                if str(c.get(campo)) not in ("si", "no"):
                    errores.append(f"{nombre}: {campo}={c.get(campo)!r} en '{c.get('texto', '')[:50]}'")
            if c.get("accion") in acciones:
                meta = acciones[c["accion"]]
                ef = nucleo.radio_efectivo(c.get("radio"), meta.get("radio"))
                if ef != c.get("radio"):
                    avisos.append(f"{nombre}: '{c['texto'][:60]}' declara radio {c.get('radio')} en DetectionLab; "
                                  f"el efecto de {c['accion']} es {meta.get('radio')} y se aplica {ef}")
            if c.get("radio") in nucleo.RADIOS_AMPLIOS and str(c.get("requiere_aprobacion")) == "no":
                avisos.append(f"{nombre}: DetectionLab marca sin aprobacion una accion de radio {c['radio']}; el motor la pide igualmente")
        usados = []
        for t in f.get("triaje") or []:
            _evaluadores_de(t.get("evaluador"), usados)
        for c in f.get("cierre") or []:
            _evaluadores_de(c.get("evaluador"), usados)
        for v in (f.get("escalado_evaluadores") or {}).values():
            _evaluadores_de(v, usados)
        for c in cont:
            for e in c.get("excepciones") or []:
                _evaluadores_de(e, usados)
        for ev, arg in usados:
            if ev not in nucleo.EVALUADORES:
                errores.append(f"{nombre}: evaluador desconocido '{ev}'")
            if ev in ("evento.regla_en",):
                for x in arg or []:
                    if str(x).lower() not in ids_regla:
                        avisos.append(f"{nombre}: {ev} cita '{x}', que no esta en el catalogo de reglas")
            if ev == "correlacion.regla_en_equipo":
                for x in arg.get("reglas") or []:
                    if str(x).lower() not in ids_regla:
                        avisos.append(f"{nombre}: {ev} cita '{x}', que no esta en el catalogo de reglas")
        metricas_fam[nombre] = {
            "reglas": sum(1 for r in reglas if r["familia"] == nombre),
            "triaje": n_tri, "triaje_auto": n_tri_auto, "cierre": n_cie, "cierre_auto": n_cie_auto,
            "contencion": len(cont), "contencion_mapeada": sum(1 for c in cont if c.get("accion")),
        }

    # ── Reglas ──
    vistos_wz = {}
    for r in reglas:
        for w in r.get("wazuh_ids") or []:
            if w in vistos_wz and vistos_wz[w] != r["clave"]:
                errores.append(f"id de Wazuh {w} repetido en {vistos_wz[w]} y {r['clave']}")
            vistos_wz[w] = r["clave"]
        if r.get("familia") not in familias:
            avisos.append(f"regla {r['clave']}: familia '{r['familia']}' sin playbook")
    titulos = Counter(nucleo.norm(r["titulo"]) for r in reglas)
    for t, n in titulos.items():
        if n > 1:
            avisos.append(f"titulo repetido en {n} reglas: '{t}' (en Sentinel y Elastic se busca por titulo)")

    # ── Secuencias ──
    for s in catalogo.get("secuencias") or []:
        for paso in s.get("pasos") or []:
            for item in paso:
                item = str(item)
                if item.startswith("familia:"):
                    if item.split(":", 1)[1] not in familias:
                        errores.append(f"secuencia {s['id']}: familia inexistente '{item}'")
                elif item.startswith("tecnica:"):
                    continue
                elif item.lower() not in ids_regla:
                    avisos.append(f"secuencia {s['id']}: '{item}' no esta en el catalogo de reglas")
        if s.get("efecto", {}).get("escalar_a") not in (None, "L2", "L3", "guardia"):
            errores.append(f"secuencia {s['id']}: escalar_a no valido")

    # ── Contratos con los proyectos vecinos ──
    if contratos is not None:
        for fuente, req in CONTRATOS.items():
            c = contratos.get(fuente)
            if c is None:
                errores.append(f"contrato {fuente}: no sincronizado")
                continue
            if fuente == "malpipe":
                for clase, campos in req.items():
                    faltan = set(campos) - set(c.get("modelos", {}).get(clase, []))
                    if faltan:
                        errores.append(f"Malpipe cambio su formato: {clase} ya no tiene {sorted(faltan)}")
            elif fuente == "ftriagedfir":
                faltan = set(req["opciones_triage"]) - set(c.get("opciones_triage", []))
                if faltan:
                    errores.append(f"FtriageDFIR cambio su CLI: faltan {sorted(faltan)} (los usa el script de active response)")
                faltan = set(req["informe"]) - set(c.get("informe", {}))
                if faltan:
                    errores.append(f"FtriageDFIR cambio su informe: faltan {sorted(faltan)}")
            else:
                for clave, campos in req.items():
                    faltan = set(campos) - set(c.get(clave, []))
                    if faltan:
                        errores.append(f"News CTI cambio su formato: {clave} sin {sorted(faltan)}")

    # ── Evaluadores que este nucleo sabe ejecutar ──
    for nombre, f in sorted(familias.items()):
        for e in f.get("evidencia_automatica") or []:
            meta = acciones.get(e.get("accion"), {})
            if e.get("accion") in nucleo.ACCIONES_SOBRE_FICHERO or meta.get("radio") in nucleo.RADIOS_AMPLIOS:
                errores.append(f"INVARIANTE ROTA en la familia {nombre}: {e.get('accion')} no es recogida de evidencia")
        for i, t in enumerate(f.get("triaje") or []):
            errores += errores_evaluador(t.get("evaluador"), f"familia {nombre}: triaje {i + 1}")
        for i, c in enumerate(f.get("cierre") or []):
            errores += errores_evaluador(c.get("evaluador"), f"familia {nombre}: cierre {i + 1}")
        for i, c in enumerate(f.get("contencion") or []):
            for exc in c.get("excepciones") or []:
                errores += errores_evaluador(exc, f"familia {nombre}: excepcion de la contencion {i + 1}")
        for clave, ev in (f.get("escalado_evaluadores") or {}).items():
            errores += errores_evaluador(ev, f"familia {nombre}: escalado {clave}")

    # ── Simulacion: ninguna regla puede producir una accion automatica peligrosa ──
    cat = nucleo.Catalogo(catalogo)
    permisivo = {"politica": {"contencion_automatica": True, "excepcion_sin_datos": "ignorar",
                              "escalado_por_correlacion": True},
                 "inventario": {"completo": True, "activos": []},
                 "listas": {"aplicaciones_negocio": []}}
    modos = defaultdict(Counter)
    for r in reglas:
        alerta = alerta_completa(r)
        for clase in ("auto_analisis", "auto_contener"):
            regla_sim = dict(r, clase=clase, nivel="critical" if clase == "auto_contener" else "high")
            datos = dict(catalogo)
            datos["reglas"] = [regla_sim]
            try:
                plan = nucleo.decidir(alerta, nucleo.Catalogo(datos), permisivo, {})
            except (ValueError, TypeError, KeyError, AttributeError, re.error) as e:
                errores.append(f"la decision falla con la regla {r['clave']} ({clase}): {e}")
                continue
            for fallo in nucleo.verificar_invariantes(plan, alerta):
                errores.append(f"INVARIANTE ROTA en {r['clave']} ({clase}): {fallo}")
            if clase == "auto_contener":
                for p in plan["acciones"]:
                    modos[r["familia"]][p["modo"]] += 1
    del cat

    metricas = {
        "reglas": len(reglas),
        "reglas_por_origen": dict(Counter(r["origen"] for r in reglas)),
        "familias": metricas_fam,
        "acciones_catalogo": len(acciones),
        "modos_critico": {k: dict(v) for k, v in sorted(modos.items())},
    }
    return sorted(set(errores)), sorted(set(avisos)), metricas


def cargar_contratos():
    ruta = RAIZ / "ecosistema" / "contratos.json"
    return json.loads(ruta.read_text(encoding="utf-8")) if ruta.exists() else None
