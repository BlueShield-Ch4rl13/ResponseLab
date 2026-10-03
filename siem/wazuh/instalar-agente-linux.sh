#!/bin/sh
# Instala los scripts de active response de ResponseLab en un agente Linux de Wazuh 4.x.
#
#   sudo sh siem/wazuh/instalar-agente-linux.sh
#
# 1. active-response/bin/responselab_ar.py y los lanzadores responselab-<accion>
#    root:wazuh 750: se ejecutan como root y nadie mas debe poder cambiarlos
# 2. comprueba que el agente envia logs/active-responses.log al manager (por ahi
#    vuelven los acuses) y, si no, lo anade a ossec.conf y reinicia el agente
# 3. comprueba que hay python3 y nft o iptables
set -eu
WAZUH=${WAZUH:-/var/ossec}
AQUI=$(cd "$(dirname "$0")" && pwd -P)
ORIGEN="$AQUI/active-response/linux"
BIN="$WAZUH/active-response/bin"

[ -d "$BIN" ] || { echo "No hay agente de Wazuh en $WAZUH (WAZUH=...)" >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo "Ejecutar como root" >&2; exit 1; }

for f in "$ORIGEN"/responselab_ar.py "$ORIGEN"/responselab-*; do
    cp "$f" "$BIN/"
    chown root:wazuh "$BIN/$(basename "$f")"
    chmod 750 "$BIN/$(basename "$f")"
done
echo "Scripts instalados en $BIN"

mkdir -p "$WAZUH/var/responselab"
chmod 700 "$WAZUH/var/responselab"

CONF="$WAZUH/etc/ossec.conf"
if ! grep -q "active-responses.log" "$CONF"; then
    cp "$CONF" "$CONF.antes-responselab"
    cat >> "$CONF" <<'XML'
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>
</ossec_config>
XML
    systemctl restart wazuh-agent
    echo "Anadido active-responses.log a $CONF y reiniciado el agente"
fi

command -v python3 >/dev/null 2>&1 || [ -x /usr/libexec/platform-python ] || echo "AVISO: no hay python3: los scripts no funcionaran"
command -v nft >/dev/null 2>&1 || command -v iptables >/dev/null 2>&1 || echo "AVISO: ni nft ni iptables: no se podra aislar"
grep -q "<address>" "$CONF" && echo "Manager(es) que nunca se bloquean al aislar: $(grep -o '<address>[^<]*' "$CONF" | sed 's/<address>//' | tr '\n' ' ')"
