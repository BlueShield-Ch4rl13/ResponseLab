#!/bin/sh
# Instala la integracion de ResponseLab en un manager de Wazuh 4.x.
#
#   sudo sh siem/wazuh/instalar-manager.sh            instala o actualiza
#   sudo sh siem/wazuh/instalar-manager.sh --prueba   solo dice que haria
#
# 1. integrations/custom-responselab(.py)       root:wazuh 750
# 2. etc/rules/responselab_rules.xml            reglas 109900-109903 (acuses)
# 3. etc/responselab.json                       si no existe, desde el ejemplo (root:wazuh 640)
# 4. ossec.conf: un bloque <ossec_config> con ossec-responselab.conf entre
#    marcas; si ya estaba, se sustituye (se puede ejecutar tras cada sincronizacion)
# 5. comprueba la configuracion con wazuh-analysisd -t y reinicia el manager
set -eu
WAZUH=${WAZUH:-/var/ossec}
AQUI=$(cd "$(dirname "$0")" && pwd -P)
PRUEBA=0
[ "${1:-}" = "--prueba" ] && PRUEBA=1
INICIO='<!-- ResponseLab: inicio (instalar-manager.sh) -->'
FIN='<!-- ResponseLab: fin -->'

hacer() { if [ "$PRUEBA" = 1 ]; then echo "  [prueba] $*"; else "$@"; fi; }

[ -d "$WAZUH/integrations" ] || { echo "No hay manager de Wazuh en $WAZUH (WAZUH=...)" >&2; exit 1; }
[ "$PRUEBA" = 1 ] || [ "$(id -u)" = 0 ] || { echo "Ejecutar como root" >&2; exit 1; }

echo "1. Integracion"
for f in custom-responselab custom-responselab.py; do
    hacer cp "$AQUI/integracion/$f" "$WAZUH/integrations/$f"
    hacer chown root:wazuh "$WAZUH/integrations/$f"
    hacer chmod 750 "$WAZUH/integrations/$f"
done

echo "2. Reglas de acuse"
hacer cp "$AQUI/reglas/responselab_rules.xml" "$WAZUH/etc/rules/responselab_rules.xml"
hacer chown wazuh:wazuh "$WAZUH/etc/rules/responselab_rules.xml"
hacer chmod 660 "$WAZUH/etc/rules/responselab_rules.xml"

echo "3. Configuracion"
if [ ! -f "$WAZUH/etc/responselab.json" ]; then
    hacer cp "$AQUI/responselab.json.ejemplo" "$WAZUH/etc/responselab.json"
    echo "   Edita $WAZUH/etc/responselab.json (motor, cliente, tokens) antes de reiniciar."
fi
hacer chown root:wazuh "$WAZUH/etc/responselab.json" 2>/dev/null || true
hacer chmod 640 "$WAZUH/etc/responselab.json" 2>/dev/null || true

echo "4. ossec.conf"
CONF="$WAZUH/etc/ossec.conf"
TMP=$(mktemp)
# Quita el bloque anterior (si lo hay) y anade el nuevo al final
awk -v ini="$INICIO" -v fin="$FIN" '
    index($0, ini) { fuera = 1; next }
    index($0, fin) { fuera = 0; next }
    !fuera { print }' "$CONF" > "$TMP"
{
    echo "$INICIO"
    echo "<ossec_config>"
    cat "$AQUI/ossec-responselab.conf"
    echo "</ossec_config>"
    echo "$FIN"
} >> "$TMP"
if [ "$PRUEBA" = 1 ]; then
    echo "  [prueba] ossec.conf quedaria asi (diferencias):"
    diff "$CONF" "$TMP" | head -40 || true
    rm -f "$TMP"
    exit 0
fi
cp "$CONF" "$CONF.antes-responselab"
cat "$TMP" > "$CONF"
rm -f "$TMP"

echo "5. Comprobacion y reinicio"
if ! "$WAZUH/bin/wazuh-analysisd" -t || { [ -x "$WAZUH/bin/wazuh-integratord" ] && ! "$WAZUH/bin/wazuh-integratord" -t; }; then
    echo "La configuracion no es valida: se restaura la anterior ($CONF.antes-responselab)" >&2
    cp "$CONF.antes-responselab" "$CONF"
    exit 1
fi
systemctl restart wazuh-manager
echo "Hecho. Prueba: tail -f $WAZUH/logs/integrations.log y $WAZUH/logs/ossec.log"
