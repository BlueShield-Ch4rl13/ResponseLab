#!/usr/bin/env python3
"""
Trae del ecosistema lo que ResponseLab necesita y lo deja en ecosistema/.

    DetectionLab ──► playbooks de respuesta + catalogo de reglas (Sigma y Wazuh)
    Infra-SocAnalyst ──► reglas 110xxx del SOC, con su familia
    SplunkLab ──► las reglas DET-* del laboratorio de Splunk, con su familia
    News CTI, Malpipe, FtriageDFIR ──► contratos: el formato que el motor lee

Por que se copia en vez de leerse en caliente
---------------------------------------------
Porque asi cada cambio aguas arriba llega como un diff revisable. Si
DetectionLab cambia una accion de contencion, el commit de sincronizacion lo
muestra, el validador comprueba que esa accion sigue mapeada a algo ejecutable
y, si no lo esta, el CI se pone en rojo antes de que el motor la vea. Leer el
otro repositorio en caliente seria mas comodo y haria que un cambio de prosa en
otro proyecto cambiase lo que se ejecuta en produccion sin que nadie lo mirase.

Por que el estado guarda un hash de contenido y no solo el commit
-----------------------------------------------------------------
DetectionLab hace un commit al dia solo para refrescar indicadores. Si ESTADO
registrara el commit de cabecera, cada sincronizacion produciria un commit en
este repositorio sin que nada relevante hubiese cambiado. Se registra el hash
de lo que realmente se consume y el commit solo se actualiza cuando ese hash
cambia.

Uso:
    python tools/sincronizar.py                    clona cada fuente (git, --depth 1)
    python tools/sincronizar.py --local ../        usa clones ya presentes en ../<Repo>
    python tools/sincronizar.py --comprobar        no escribe; sale con 1 si hay cambios
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from responselab.util import (RAIZ, consola_utf8, escribir_si_cambia,  # noqa: E402
                              json_estable, sha256_texto)

consola_utf8()

ECOSISTEMA = RAIZ / "ecosistema"
FUENTES = ECOSISTEMA / "fuentes.yml"
ESTADO = ECOSISTEMA / "ESTADO.json"

# Mismo mapeo que usa DetectionLab (tools/sigma_to_wazuh.py). Se repite aqui a
# proposito y el validador comprueba que coincide con los grupos auto_* de las
# reglas de Wazuh generadas: si DetectionLab lo cambia, se sabe.
CLASE_POR_NIVEL = {
    "informational": "auto_cierre",
    "low": "auto_enriq",
    "medium": "auto_analisis",
    "high": "auto_analisis",
    "critical": "auto_contener",
}
NIVEL_POR_SEVERIDAD = {4: "critical", 3: "high", 2: "medium", 1: "low"}

RE_REGLA_XML = re.compile(r'<rule\s+id="(\d+)"\s+level="(\d+)"[^>]*>(.*?)</rule>', re.S)
RE_INFO = re.compile(r"playbook=([\w-]+);\s*severidad_thehive=(\d);\s*origen=(\S+?)\s*<")


# ─────────────────────────────────────────────────────────────────────────────
# Obtener los repositorios
# ─────────────────────────────────────────────────────────────────────────────

def nombre_repo(url: str) -> str:
    return url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")


def git(*args: str, cwd: Path | None = None) -> str:
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()}")
    return r.stdout.strip()


def obtener(fuente: dict, local: Path | None, tmp: Path) -> Path:
    nombre = nombre_repo(fuente["repo"])
    if local is not None:
        ruta = local / nombre
        if not ruta.is_dir():
            raise FileNotFoundError(f"no esta el clon local {ruta}")
        return ruta
    destino = tmp / nombre
    git("clone", "--quiet", "--depth", "1", "--branch", fuente.get("rama", "main"),
        fuente["repo"], str(destino))
    return destino


def commit_de(ruta: Path) -> tuple[str, str]:
    try:
        sha, fecha = git("log", "-1", "--format=%H %cI", cwd=ruta).split(" ", 1)
        return sha, fecha
    except Exception:
        return "desconocido", ""


# ─────────────────────────────────────────────────────────────────────────────
# DetectionLab
# ─────────────────────────────────────────────────────────────────────────────

def familia_por_carpeta(ruta_regla: Path) -> str:
    """Misma logica que DetectionLab: la familia sale de la carpeta.

    rules/windows/ mezcla tres familias; ahi decide el prefijo del fichero.
    Solo se usa si la regla no tiene version Wazuh con playbook= explicito.
    """
    dominio = ruta_regla.parent.name
    if dominio != "windows":
        return dominio
    n = ruta_regla.stem
    if n.startswith(("soc_ad_", "ad_")):
        return "ad"
    if n.startswith("cred_"):
        return "credenciales"
    return "endpoint"


def tecnicas_de(tags: list[str]) -> list[str]:
    return sorted({t.split(".", 1)[1].upper() for t in tags
                   if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)})


def tacticas_de(tags: list[str]) -> list[str]:
    return sorted({t.split(".", 1)[1] for t in tags
                   if t.startswith("attack.") and not re.fullmatch(r"attack\.[tgs]\d+(\.\d+)?", t)})


def leer_reglas_wazuh(texto: str) -> list[dict]:
    reglas = []
    for ident, nivel, cuerpo in RE_REGLA_XML.findall(texto):
        grupos = []
        for g in re.findall(r"<group>([^<]*)</group>", cuerpo):
            grupos += [x.strip() for x in g.split(",") if x.strip()]
        desc = re.search(r"<description>(.*?)</description>", cuerpo, re.S)
        info = RE_INFO.search(cuerpo)
        mitre = re.findall(r"<id>(T\d{4}(?:\.\d{3})?)</id>", cuerpo)
        reglas.append({
            "id": ident,
            "nivel_wazuh": int(nivel),
            "descripcion": " ".join(desc.group(1).split()) if desc else "",
            "grupos": grupos,
            "playbook": info.group(1) if info else None,
            "severidad": int(info.group(2)) if info else None,
            "origen": info.group(3) if info else None,
            "tecnicas": sorted(set(mitre)),
        })
    return reglas


def leer_stanzas_splunk(texto: str) -> dict[str, str]:
    """Nombre de la busqueda guardada -> fichero Sigma de origen."""
    salida, actual = {}, None
    for linea in texto.splitlines():
        m = re.match(r"^\[(.+)\]\s*$", linea)
        if m:
            actual = m.group(1)
            continue
        m = re.match(r"^#\s*Regla Sigma:\s*(\S+)", linea)
        if m and actual:
            salida[Path(m.group(1)).name] = actual
    return salida


def extraer_detectionlab(raiz: Path, cfg: dict) -> dict[str, str]:
    salidas: dict[str, str] = {}
    avisos: list[str] = []

    # 1. Playbooks: copia literal. Son la razon de cada decision y ResponseLab
    #    no los reescribe: les pone debajo la capa que los hace ejecutables.
    for f in sorted((raiz / cfg["playbooks"]).glob("*.yml")):
        salidas[f"detectionlab/playbooks/{f.name}"] = f.read_text(encoding="utf-8")

    # 2. Reglas de Wazuh: generadas (origen=*.yml) y escritas a mano.
    por_origen: dict[str, list[dict]] = {}
    manuales = []
    for x in sorted((raiz / cfg["reglas_wazuh"]).glob("*.xml")):
        for r in leer_reglas_wazuh(x.read_text(encoding="utf-8")):
            r["fichero_xml"] = f"{cfg['reglas_wazuh']}/{x.name}"
            if r["origen"] and r["origen"].endswith(".yml"):
                por_origen.setdefault(r["origen"], []).append(r)
            else:
                manuales.append(r)

    # 3. Nombres de las busquedas de Splunk generadas
    splunk = {}
    ruta_splunk = raiz / cfg["splunk"]
    if ruta_splunk.exists():
        splunk = leer_stanzas_splunk(ruta_splunk.read_text(encoding="utf-8"))

    reglas = []
    for f in sorted((raiz / cfg["reglas_sigma"]).rglob("*.yml")):
        try:
            # Una regla de correlacion Sigma son dos documentos en el mismo
            # fichero: la regla base (informational, no alerta sola) y la
            # correlacion, que es la que alerta. Se cataloga por la que alerta
            # y se guardan los dos titulos, porque cada SIEM nombra la alerta
            # con uno distinto (Splunk usa el de la base).
            docs = [x for x in yaml.safe_load_all(f.read_text(encoding="utf-8")) if x]
        except Exception as e:
            avisos.append(f"{f.name}: YAML invalido ({e})")
            continue
        d = next((x for x in docs if "correlation" in x), docs[0])
        es_correlacion = "correlation" in d
        tags = sorted({t for x in docs for t in (x.get("tags") or [])})
        wz = por_origen.get(f.name, [])
        familias_wz = {r["playbook"] for r in wz if r["playbook"]}
        familia = sorted(familias_wz)[0] if familias_wz else familia_por_carpeta(f)
        if len(familias_wz) > 1:
            avisos.append(f"{f.name}: sus reglas de Wazuh declaran familias distintas {sorted(familias_wz)}")
        clases_wz = {g for r in wz for g in r["grupos"] if g.startswith("auto_")}
        nivel = d.get("level", "medium")
        if clases_wz and not es_correlacion and clases_wz != {CLASE_POR_NIVEL.get(nivel)}:
            avisos.append(f"{f.name}: nivel {nivel} pero Wazuh lleva {sorted(clases_wz)}")
        base = docs[0]
        ls = base.get("logsource") or {}
        reglas.append({
            "clave": f"dl:{f.stem}",
            "origen": "detectionlab",
            "tipo": "sigma_correlacion" if es_correlacion else "sigma",
            "sigma_id": str(d.get("id", "")),
            "fichero": f.relative_to(raiz).as_posix(),
            "titulo": " ".join(str(d.get("title", f.stem)).split()),
            "titulos": sorted({" ".join(str(x.get("title", "")).split()) for x in docs if x.get("title")}),
            "nivel": nivel,
            "familia": familia,
            "tecnicas": tecnicas_de(tags),
            "tacticas": tacticas_de(tags),
            "wazuh_ids": sorted({r["id"] for r in wz}, key=int),
            "splunk": splunk.get(f.name, ""),
            "logsource": "/".join(str(ls[k]) for k in ("product", "category", "service") if ls.get(k)),
        })

    # Reglas de Wazuh escritas a mano (Zero Trust, cumplimiento, inteligencia)
    for r in manuales:
        if not r["playbook"]:
            avisos.append(f"wazuh {r['id']}: sin playbook= en <info>")
            continue
        clase = next((g for g in r["grupos"] if g.startswith("auto_")), None)
        nivel = ("informational" if clase == "auto_cierre"
                 else NIVEL_POR_SEVERIDAD.get(r["severidad"] or 2, "medium"))
        reglas.append({
            "clave": f"wazuh:{r['id']}",
            "origen": "detectionlab",
            "tipo": "wazuh",
            "sigma_id": "",
            "fichero": r["fichero_xml"],
            "titulo": r["descripcion"],
            "nivel": nivel,
            "clase": clase or CLASE_POR_NIVEL[nivel],
            "familia": r["playbook"],
            "tecnicas": r["tecnicas"],
            "tacticas": [],
            "wazuh_ids": [r["id"]],
            "splunk": "",
            "logsource": "wazuh",
        })

    reglas.sort(key=lambda r: r["clave"])
    salidas["detectionlab/reglas.json"] = json_estable({"reglas": reglas, "avisos": sorted(avisos)})
    return salidas


# ─────────────────────────────────────────────────────────────────────────────
# Infra-SocAnalyst
# ─────────────────────────────────────────────────────────────────────────────

def nivel_por_corte(nivel_wazuh: int, cortes: list[dict]) -> str:
    for c in sorted(cortes, key=lambda c: -c["desde"]):
        if nivel_wazuh >= c["desde"]:
            return c["nivel"]
    return "informational"


def extraer_infra(raiz: Path, cfg: dict) -> dict[str, str]:
    texto = (raiz / cfg["reglas_wazuh"]).read_text(encoding="utf-8")
    tabla = cfg["familias_por_grupo"]
    reglas, avisos = [], []
    for r in leer_reglas_wazuh(texto):
        familia = next((tabla[g] for g in r["grupos"] if g in tabla), None)
        nivel = nivel_por_corte(r["nivel_wazuh"], cfg["niveles"])
        if not familia:
            if nivel != "informational":
                avisos.append(f"{r['id']}: ningun grupo en familias_por_grupo {r['grupos']}")
            familia = "_generico"
        reglas.append({
            "clave": f"infra:{r['id']}",
            "origen": "infra-socanalyst",
            "tipo": "wazuh",
            "sigma_id": "",
            "fichero": cfg["reglas_wazuh"],
            "titulo": r["descripcion"],
            "nivel": nivel,
            "clase": CLASE_POR_NIVEL[nivel],
            "familia": familia,
            "tecnicas": r["tecnicas"],
            "tacticas": [],
            "wazuh_ids": [r["id"]],
            "splunk": "",
            "logsource": "wazuh",
        })
    reglas.sort(key=lambda r: r["clave"])
    return {"infra-socanalyst/reglas.json": json_estable({"reglas": reglas, "avisos": avisos})}


# ─────────────────────────────────────────────────────────────────────────────
# SplunkLab
# ─────────────────────────────────────────────────────────────────────────────

def extraer_splunklab(raiz: Path, cfg: dict) -> dict[str, str]:
    texto = (raiz / cfg["savedsearches"]).read_text(encoding="utf-8")
    stanzas: dict[str, dict[str, str]] = {}
    actual = None
    for linea in texto.splitlines():
        m = re.match(r"^\[(.+)\]\s*$", linea)
        if m:
            actual = m.group(1)
            stanzas[actual] = {}
            continue
        m = re.match(r"^([\w.]+)\s*=\s*(.*)$", linea)
        if m and actual:
            stanzas[actual][m.group(1)] = m.group(2)
    reglas, avisos = [], []
    for nombre, campos in stanzas.items():
        codigo = campos.get("action.summary_index.regla")
        if not codigo:
            continue                                    # paneles, no reglas
        fam_lab = campos.get("action.summary_index.familia", "")
        familia = cfg.get("reglas_familia", {}).get(codigo) or cfg["familias"].get(fam_lab)
        if not familia:
            avisos.append(f"{codigo}: familia '{fam_lab}' sin mapear")
            familia = "_generico"
        sev = int(campos.get("alert.severity", "3") or 3)
        nivel = cfg["niveles"].get(sev, "medium")
        tecnica = (campos.get("action.summary_index.tecnica", "").split() or [""])[0]
        reglas.append({
            "clave": f"splunklab:{codigo}",
            "origen": "splunklab",
            "tipo": "splunk",
            "sigma_id": "",
            "fichero": cfg["savedsearches"],
            "titulo": nombre,
            "nivel": nivel,
            "clase": CLASE_POR_NIVEL[nivel],
            "familia": familia,
            "tecnicas": [tecnica] if re.fullmatch(r"T\d{4}(\.\d{3})?", tecnica) else [],
            "tacticas": [],
            "wazuh_ids": [],
            "splunk": nombre,
            "logsource": "splunk",
        })
    reglas.sort(key=lambda r: r["clave"])
    return {"splunklab/reglas.json": json_estable({"reglas": reglas, "avisos": avisos})}


# ─────────────────────────────────────────────────────────────────────────────
# Contratos: News CTI, Malpipe, FtriageDFIR
# ─────────────────────────────────────────────────────────────────────────────
# El motor lee los ficheros que producen estos tres proyectos. Si uno cambia su
# formato, el motor dejaria de entenderlos en silencio. Aqui se extrae la forma
# (no los datos, que cambian cada seis horas) y validar.py exige los campos que
# el motor usa.

def contrato_newscti(raiz: Path, cfg: dict) -> dict:
    d = json.loads((raiz / cfg["feed"]).read_text(encoding="utf-8"))
    iocs = d.get("iocs") or []
    kev = d.get("cisa_kev_recent") or []
    return {
        "claves": sorted(d.keys()),
        "claves_ioc": sorted(set().union(*[set(i) for i in iocs[:200]])) if iocs else [],
        "claves_kev": sorted(set().union(*[set(k) for k in kev[:50]])) if kev else [],
        "tipos_ioc": sorted({i.get("type", "") for i in iocs}),
        "niveles": sorted({i.get("level", "") for i in iocs}),
    }


def campos_dataclass(fuente: str) -> dict[str, list[str]]:
    arbol = ast.parse(fuente)
    salida = {}
    for nodo in arbol.body:
        if isinstance(nodo, ast.ClassDef):
            campos = [s.target.id for s in nodo.body
                      if isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name)]
            if campos:
                salida[nodo.name] = sorted(campos)
    return salida


def contrato_malpipe(raiz: Path, cfg: dict) -> dict:
    return {"modelos": campos_dataclass((raiz / cfg["modelos"]).read_text(encoding="utf-8"))}


def contrato_ftriage(raiz: Path, cfg: dict) -> dict:
    cli = (raiz / cfg["cli"]).read_text(encoding="utf-8")
    bloque = cli.split('add_parser("triage"', 1)[-1].split("add_parser(", 1)[0]
    opciones = sorted(set(re.findall(r'add_argument\("(--[\w-]+)"', bloque)))
    ej = json.loads((raiz / cfg["ejemplo"]).read_text(encoding="utf-8"))

    def forma(o, prof=0):
        if prof > 2:
            return "..."
        if isinstance(o, dict):
            return {k: forma(v, prof + 1) for k, v in sorted(o.items())}
        if isinstance(o, list):
            return [forma(o[0], prof + 1)] if o and isinstance(o[0], dict) else []
        return type(o).__name__

    return {
        "opciones_triage": opciones,
        "informe": {k: forma(ej[k]) for k in ("case", "host", "assessment", "iocs", "findings") if k in ej},
    }


# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--local", type=Path, help="carpeta con los clones de cada repositorio")
    ap.add_argument("--comprobar", action="store_true",
                    help="no escribe; sale con 1 si la sincronizacion cambiaria algo")
    args = ap.parse_args()

    cfg = yaml.safe_load(FUENTES.read_text(encoding="utf-8"))
    estado = json.loads(ESTADO.read_text(encoding="utf-8")) if ESTADO.exists() else {}
    fuentes = cfg["fuentes"]

    extractores = {
        "detectionlab": extraer_detectionlab,
        "infra-socanalyst": extraer_infra,
        "splunklab": extraer_splunklab,
    }
    contratos_fn = {
        "newscti": contrato_newscti,
        "malpipe": contrato_malpipe,
        "ftriagedfir": contrato_ftriage,
    }

    cambios: list[str] = []
    contratos: dict[str, dict] = {}
    nuevo_estado = dict(estado)
    with tempfile.TemporaryDirectory() as tmp:
        for nombre, fuente in fuentes.items():
            try:
                ruta = obtener(fuente, args.local, Path(tmp))
            except Exception as e:
                print(f"  x {nombre}: no se pudo obtener ({e})")
                return 2
            sha, fecha = commit_de(ruta)

            if nombre in extractores:
                salidas = extractores[nombre](ruta, fuente)
            else:
                contratos[nombre] = contratos_fn[nombre](ruta, fuente)
                salidas = {}

            huella = sha256_texto("".join(f"{k}\n{v}" for k, v in sorted(salidas.items()))
                                  + json_estable(contratos.get(nombre, {})))
            previo = estado.get(nombre, {})
            if previo.get("contenido_sha256") != huella:
                nuevo_estado[nombre] = {
                    "repo": fuente["repo"], "rama": fuente.get("rama", "main"),
                    "commit": sha, "fecha_commit": fecha,
                    "contenido_sha256": huella,
                    "sincronizado": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
                cambios.append(nombre)

            # Playbooks que desaparecen aguas arriba: se borran tambien aqui
            if nombre == "detectionlab" and not args.comprobar:
                destino = ECOSISTEMA / "detectionlab" / "playbooks"
                vivos = {Path(k).name for k in salidas if k.startswith("detectionlab/playbooks/")}
                if destino.is_dir():
                    for viejo in destino.glob("*.yml"):
                        if viejo.name not in vivos:
                            viejo.unlink()
                            print(f"  - playbook retirado aguas arriba: {viejo.name}")

            for rel, contenido in salidas.items():
                destino = ECOSISTEMA / rel
                if args.comprobar:
                    if not destino.exists() or destino.read_text(encoding="utf-8") != contenido:
                        cambios.append(rel)
                elif escribir_si_cambia(destino, contenido):
                    print(f"  ~ {rel}")
            print(f"  · {nombre:17} {sha[:12]}  {len(salidas)} fichero(s)")

    texto_contratos = json_estable(contratos)
    if args.comprobar:
        destino = ECOSISTEMA / "contratos.json"
        if not destino.exists() or destino.read_text(encoding="utf-8") != texto_contratos:
            cambios.append("contratos.json")
        print(f"\n{'Hay cambios aguas arriba' if cambios else 'Sin cambios'}: {sorted(set(cambios))}")
        return 1 if cambios else 0

    escribir_si_cambia(ECOSISTEMA / "contratos.json", texto_contratos)
    escribir_si_cambia(ESTADO, json_estable(nuevo_estado))
    print(f"\nFuentes con contenido nuevo: {', '.join(cambios) if cambios else 'ninguna'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
