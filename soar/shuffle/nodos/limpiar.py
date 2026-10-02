# Nodo "LIMPIAR": deja el analisis del LLM en una linea segura para Discord.
import json

texto = """$ollama.body.response"""
texto = texto.replace("**", "").replace("*", "").replace("`", "")
texto = " ".join(texto.split())
if not texto or texto.startswith("$ollama"):
    texto = "Sin analisis del LLM."
print(json.dumps({"mensaje_json": json.dumps(texto[:900], ensure_ascii=False)[1:-1]}))
