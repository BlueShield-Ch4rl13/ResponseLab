#!/usr/bin/env python3
"""Ejemplo de conector de script: lee la orden por stdin y contesta por stdout.

Configuracion en el perfil del cliente:
    capacidades: {pasarela_correo: script}
    conectores:
      script:
        acciones: {correo.bloquear_remitente: ejemplo.py}
        timeout: 30
"""
import json
import sys

orden = json.load(sys.stdin)
remitente = (orden.get("objetivo") or {}).get("correo.remitente", "")
# Aqui iria la llamada a la herramienta (una CLI, un SDK...). Nunca a traves de
# una shell con cadenas construidas a partir de la alerta.
print(json.dumps({"ok": True, "detalle": f"remitente {remitente} bloqueado (ejemplo)", "datos": {"remitente": remitente}}))
