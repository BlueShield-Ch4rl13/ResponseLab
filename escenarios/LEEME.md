# Escenarios de ataque

Cada fichero de esta carpeta es un ataque completo contado en alertas reales,
con el formato nativo del SIEM que las emite, y con lo que ResponseLab tiene que
hacer con cada una. `tools/simular.py` las pasa por el motor de verdad (el
mismo código que corre en producción, en modo simulación y con una base de datos
temporal) y comprueba cada expectativa.

Es la prueba de extremo a extremo del proyecto. El CI la ejecuta en cada cambio
y en cada sincronización con el ecosistema: si una regla nueva de DetectionLab,
un cambio en el catálogo o un perfil de cliente hacen que el motor deje de
contener un ransomware, o que empiece a aislar un controlador de dominio, el CI
se pone en rojo antes de que llegue a producción.

```powershell
python tools/simular.py                        # todos
python tools/simular.py ransomware-puesto      # uno
python tools/simular.py --detalle              # con el plan de cada alerta y lo que se ejecutó
python tools/simular.py --json                 # para otra herramienta

# Purple team: enviar las alertas a un motor desplegado y ver la respuesta en su panel
python tools/simular.py --enviar https://motor:8443 --cliente lab --token $env:RL_LAB_TOKEN intrusion-ssh-dmz
```

## Qué demuestra cada escenario

| Escenario | Cliente y SIEM | Lo que se comprueba |
|---|---|---|
| `ransomware-puesto` | lab · Wazuh | La secuencia *ransomware* eleva a contención automática; el equipo se aísla **una vez** aunque sigan llegando alertas; `vssadmin.exe` (binario del sistema que usa el atacante) no se pone en cuarentena; corren los plazos de RGPD y NIS2 porque el equipo trata datos personales. |
| `intrusion-ssh-dmz` | lab · Wazuh, Falco, Tetragon | Dos alertas sueltas no contienen un servidor; a la tercera, la secuencia *intrusion_ssh* aísla y escala a L3. El crontab modificado se copia a custodia solo; `/etc/shadow` no, porque copiar un almacén de credenciales multiplica el secreto. |
| `controlador-dominio` | lab · Wazuh | DCShadow en el DC: ni el aislamiento ni la recogida de evidencia son automáticos en un activo protegido, aunque la regla sea de contención automática. |
| `explotacion-web-produccion` | lab · Wazuh | Inyección SQL y shell en un servidor de producción: escala a L3 y recoge evidencia sola, pero no mata procesos (excepción por inventario) ni bloquea en el WAF (radio organización) sin una persona. |
| `phishing-a-cuenta` | acme · Sentinel | El clic solo no revoca nada; el MFA nuevo de la misma persona en la misma hora completa *phishing_a_cuenta* y revoca las sesiones en Entra ID sin esperar. |
| `exfiltracion-tras-acceso` | acme · Sentinel + Splunk | La primera alerta llega de un SIEM y la segunda del otro; la correlación por usuario las une. Se deshabilita sola la regla de reenvío del buzón, se avisa al DPD y a la asesoría jurídica y corren RGPD, NIS2 y DORA. |
| `credenciales-movimiento-ot` | norte · Elastic | El puesto de ingeniería se aísla solo con el EDR del cliente (CrowdStrike); el HMI de la planta, protegido por inventario, no se toca sin una persona aunque la técnica sea la misma. |
| `sensor-edr-desinstalado` | lab · Wazuh | La parada del sensor seguida de persistencia en el mismo equipo completa *ceguera_y_actividad* y avisa a guardia. Bloquear un hash en toda la flota nunca es automático. |
| `regla-desconocida` | lab · Wazuh | Una regla que el catálogo no conoce no contiene sola, ni aunque se declare `auto_contener` o de una familia concreta. |
| `escaner-autorizado` | lab · Splunk | El escáner autorizado dentro de su ventana baja la severidad, pero **no** cierra la alerta: la condición de cierre de DetectionLab exige algo que no viaja en la alerta. El mismo escaneo desde Internet no recibe rebaja. |

## Formato

```yaml
id: nombre-del-escenario           # por defecto, el nombre del fichero
nombre: Texto para el informe
cliente: lab                       # perfil de clientes/ contra el que se decide
mitre: [T1486]                     # documental
inicio: "2026-10-01T20:30:00Z"     # opcional: hora fija de la primera alerta
cti:                               # opcional: IOCs que el motor "ya conoce"
  - {type: domain, value: update-check.example, level: alta, score: 90, sources: [threatfox], threat: C2 de prueba}
alertas:
  - minuto: 0                      # minutos desde el inicio del escenario
    siem: wazuh                    # wazuh | splunk | sentinel | elastic | generico
    descripcion: Qué está pasando
    carga: {...}                   # la alerta tal cual la envía ese SIEM
    esperado: {...}                # ver abajo
final: {...}                       # comprobaciones sobre el estado al acabar
```

El simulador pone a cada alerta un identificador único y la hora del escenario
en el campo que use su SIEM (`timestamp` en Wazuh, `result._time` en Splunk,
`firstActivityTimeUtc` en Sentinel, `@timestamp` en Elastic). Sin `inicio`, la
primera alerta es «ahora menos lo que dura el escenario»; con `inicio`, la hora
es fija, que es lo que necesitan las ventanas de escaneo o de mantenimiento.

Las direcciones de documentación (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`) no son públicas para el motor: nunca se tratan como observables
ni se bloquean en el perímetro. Para un IOC de CTI que tenga que casar, usa un
dominio `.example`.

### Expectativas por alerta (`esperado`)

| Clave | Ejemplo | Comprueba |
|---|---|---|
| `familia`, `clase`, `estado` | `clase: auto_contener` | Igualdad con el plan. |
| `regla_conocida` | `false` | Si la regla está en el catálogo. |
| `severidad_minima`, `severidad_maxima` | `4` | Severidad final (1-4) tras triaje y secuencias. |
| `escalado` | `guardia` | Destino del escalado: `L2`, `L3` o `guardia`. |
| `secuencias` | `[ransomware]` | Secuencias detectadas en esta alerta. |
| `sin_secuencias` | `true` | Ninguna secuencia. |
| `modos` | `{endpoint.aislar: automatica}` | Modo de la acción en el plan (si aparece varias veces, basta con uno). |
| `nunca_automatica` | `[flota.bloquear_hash]` | La acción no aparece como automática. |
| `sin_contencion_automatica` | `true` | Ninguna acción de contención automática (las de registro y evidencia no cuentan). |
| `ejecuciones` | `{endpoint.aislar: simulada}` | Estado de alguna ejecución de la acción: `simulada`, `omitida`, `ok`, `error`... |
| `conectores` | `{endpoint.aislar: crowdstrike}` | Conector con el que se ejecutó. |
| `sin_ejecucion` | `[proceso.matar]` | La acción no llegó a ejecutarse. |
| `aprobaciones` | `[endpoint.aislar]` | Se pidió aprobación para la acción. |
| `avisar_ademas` | `[dpd]` | Contactos adicionales del escalado. |
| `notificar` | `true` | Si el plan avisa por los canales del cliente. |
| `triaje` | `{escaner autorizado: si}` | Resultado (`si`, `no`, `pendiente`) de la pregunta que contiene ese texto. |
| `cierre_propuesto` | `[escaner de vulnerabilidades]` | Hay una condición de cierre que se deja a una persona. |

### Comprobaciones finales (`final`)

| Clave | Comprueba |
|---|---|
| `incidentes` | Número de incidentes abiertos para el cliente. |
| `aprobaciones_pendientes` | Número de aprobaciones esperando. |
| `plazos` | Marcos con plazos de notificación en curso (`rgpd`, `nis2`, `dora`). |
| `ejecuciones_ok` | Número de ejecuciones reales correctas (en simulación, 0). |
| `auditoria_integra` | La cadena de hashes de la auditoría está intacta. Se comprueba siempre salvo `false`. |

## Añadir un escenario

1. Copia el que más se parezca. Usa alertas reales: exporta el JSON de la
   alerta del SIEM y anonimízalo (direcciones de documentación como
   `203.0.113.0/24` o `198.51.100.0/24`, dominios `.example` o `.test`).
2. Escribe primero lo que **no** debe pasar (`nunca_automatica`,
   `sin_ejecucion`): es lo que protege a producción.
3. `python tools/simular.py --detalle mi-escenario` y revisa el motivo de cada
   modo. Si el motor hace algo distinto de lo esperado, la pregunta es quién
   tiene razón: a veces el escenario, a veces el playbook.
