"""docs/COBERTURA.md: que automatiza ResponseLab, familia a familia (generado)."""
from __future__ import annotations

from collections import Counter

ORDEN_MODOS = ["automatica", "aprobacion", "manual", "no_aplicable", "prohibida"]


def generar(catalogo: dict, metricas: dict) -> str:
    fams = metricas["familias"]
    reglas = catalogo["reglas"]
    l = []
    l.append("# Cobertura de respuesta")
    l.append("")
    l.append("<!-- Generado por tools/compilar.py desde catalogo/catalogo.json - no editar a mano -->")
    l.append("")
    l.append(f"Catálogo `{catalogo['version']}` · **{len(reglas)} reglas** · "
             f"**{len(fams)} familias** · **{len(catalogo['acciones'])} acciones ejecutables** · "
             f"**{len(catalogo.get('secuencias') or [])} secuencias de ataque**")
    l.append("")
    por_origen = Counter(r["origen"] for r in reglas)
    l.append("| Origen | Reglas |")
    l.append("|---|---:|")
    for k, v in sorted(por_origen.items()):
        l.append(f"| {k} | {v} |")
    l.append("")
    l.append("## Qué sabe contestar la máquina")
    l.append("")
    l.append("Las preguntas de triaje y las condiciones de cierre vienen de los playbooks de")
    l.append("DetectionLab. Las que tienen evaluador las contesta el motor con datos de la")
    l.append("alerta, del perfil del cliente, de la inteligencia o del histórico; el resto")
    l.append("quedan como tarea del analista. Ninguna se contesta por defecto.")
    l.append("")
    l.append("| Familia | Reglas | Triaje automático | Cierre automático | Contención mapeada |")
    l.append("|---|---:|---:|---:|---:|")
    tot = Counter()
    for nombre, f in sorted(fams.items()):
        if nombre == "_generico" and not f["reglas"]:
            continue
        l.append(f"| `{nombre}` | {f['reglas']} | {f['triaje_auto']}/{f['triaje']} | "
                 f"{f['cierre_auto']}/{f['cierre']} | {f['contencion_mapeada']}/{f['contencion']} |")
        for k in ("reglas", "triaje", "triaje_auto", "cierre", "cierre_auto", "contencion", "contencion_mapeada"):
            tot[k] += f[k]
    l.append(f"| **Total** | **{tot['reglas']}** | **{tot['triaje_auto']}/{tot['triaje']}** | "
             f"**{tot['cierre_auto']}/{tot['cierre']}** | **{tot['contencion_mapeada']}/{tot['contencion']}** |")
    l.append("")
    l.append("## Qué se ejecuta sin persona en una alerta crítica")
    l.append("")
    l.append("Simulación de una alerta `critical` de cada regla, con todos los campos presentes")
    l.append("y un cliente que no restringe nada. Es el techo: en producción, el perfil del")
    l.append("cliente, el inventario y los datos que traiga la alerta solo pueden bajar estas")
    l.append("cifras, nunca subirlas.")
    l.append("")
    l.append("| Familia | Automática | Con aprobación | Manual | No aplica |")
    l.append("|---|---:|---:|---:|---:|")
    for fam, modos in sorted(metricas["modos_critico"].items()):
        l.append(f"| `{fam}` | {modos.get('automatica', 0)} | {modos.get('aprobacion', 0)} | "
                 f"{modos.get('manual', 0)} | {modos.get('no_aplicable', 0)} |")
    l.append("")
    l.append("## Acciones por radio")
    l.append("")
    l.append("| Acción | Radio | Reversible | Capacidad | Conectores |")
    l.append("|---|---|:---:|---|---|")
    for nombre, a in sorted(catalogo["acciones"].items()):
        if a.get("inversa"):
            continue
        l.append(f"| `{nombre}` | {a['radio']} | {a['reversible']} | {a.get('capacidad', '')} | "
                 f"{', '.join(a.get('conectores') or [])} |")
    l.append("")
    l.append("## Traducción a cada SOAR")
    l.append("")
    l.append("El motor ejecuta todas las acciones con sus conectores; Shuffle y n8n le")
    l.append("delegan la ejecución. Cuando el SOAR actúa por su cuenta, esto es lo que")
    l.append("tiene traducción nativa; lo demás se exporta como tarea manual.")
    l.append("")
    l.append("| Acción | Cortex XSOAR | Splunk SOAR | Sentinel (Logic Apps) |")
    l.append("|---|---|---|---|")
    for nombre, a in sorted(catalogo["acciones"].items()):
        s = a.get("soar") or {}
        x = s.get("xsoar") or {}
        xs = f"`{x['playbook']}`" if x.get("playbook") else (f"`!{x['comando']}`" if x.get("comando") else "tarea")
        sp = f"`{s['splunk_soar']['accion']}`" if (s.get("splunk_soar") or {}).get("accion") else "tarea"
        se = f"`{s['sentinel']['tipo']}`" if (s.get("sentinel") or {}).get("tipo") else "tarea"
        if xs == sp == se == "tarea":
            continue
        l.append(f"| `{nombre}` | {xs} | {sp} | {se} |")
    l.append("")
    return "\n".join(l) + "\n"
