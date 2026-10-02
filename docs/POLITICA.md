# Política: qué se ejecuta solo y qué espera a una persona

Automatizar la respuesta no es difícil. Lo difícil es saber qué no automatizar. Este
documento explica cómo decide ResponseLab, en orden, y por qué cada paso está donde
está.

## 1. La clase de la regla

Cada regla de DetectionLab trae una clase de automatización que sale de su nivel en
Sigma. ResponseLab la respeta:

| Nivel Sigma | Clase | Qué permite |
|---|---|---|
| informational | `auto_cierre` | Se registra y se descarta |
| low | `auto_enriq` | Enriquecer y abrir caso; nada de contención |
| medium, high | `auto_analisis` | Contención **preparada**: cada acción espera aprobación |
| critical | `auto_contener` | Contención automática, dentro de los límites de abajo |

Una regla que el catálogo no conoce nunca pasa de `auto_analisis`. No importa lo que
diga la propia alerta (un grupo `auto_contener` en Wazuh, un `playbook=` en la
descripción), ni que complete una secuencia de ataque: nadie la ha revisado.

## 2. Las secuencias elevan

Una alerta suelta rara vez es el incidente; la secuencia sí lo es.
[`playbooks/secuencias.yml`](../playbooks/secuencias.yml) define siete. Cada una
tiene:

- un objetivo común: el mismo equipo o la misma persona;
- una ventana de tiempo;
- unos pasos;
- un mínimo de pasos que se tienen que cumplir.

Si la alerta que llega completa una secuencia, su efecto se aplica a esa alerta:
subir la severidad, escalar a L3 o a guardia, avisar al DPD o a la asesoría
jurídica y, en algunas, elevar la clase a `auto_contener`. El cliente puede
desactivar la elevación con `politica.escalado_por_correlacion: false`.

## 3. Radio × reversibilidad

Cada acción del catálogo declara a quién afecta (su **radio**) y si se puede
deshacer:

```
proceso < objeto < sesion < equipo < cuenta < organizacion
```

| Radio | Ejemplos | ¿Automática en `auto_contener`? |
|---|---|---|
| proceso | matar un proceso identificado por PID y hora de arranque | Sí, aunque no se pueda deshacer |
| objeto | cuarentena de un fichero, deshabilitar una regla de buzón | Sí, si es reversible |
| sesion | revocar las sesiones de una identidad | Sí, si es reversible |
| equipo | aislar un equipo de la red | Sí, si es reversible |
| cuenta | deshabilitar una cuenta, retirar una clave SSH | **Nunca** |
| organizacion | bloquear un hash en toda la flota, un destino en el perímetro | **Nunca** |

Cuando DetectionLab y el catálogo declaran radios distintos para la misma acción,
manda el más amplio. Una acción sin radio declarado cuenta como `organizacion`. La
validación avisa de cada discrepancia.

## 4. Las invariantes

Tres reglas viven en el código y no dependen de ningún dato configurable. Ni un
catálogo ni un perfil de cliente pueden autorizar lo que prohíben:

1. **Nada de radio `cuenta` u `organizacion` se ejecuta solo.** Tampoco si el
   catálogo marca la acción como «de registro» o «de evidencia».
2. **Lo irreversible solo es automático con radio `proceso`**, y solo si el proceso
   está identificado sin ambigüedad: PID más hora de arranque, o GUID más PID.
3. **Ningún fichero del sistema operativo ni de configuración crítica se pone en
   cuarentena o se bloquea solo.** Eso incluye `C:\Windows\`, `/usr/bin`,
   `/usr/lib64`, `/etc/passwd`, `/etc/shadow`, etc. Con `vssadmin delete shadows` el
   proceso es `vssadmin.exe` de System32: ponerlo en cuarentena rompería el equipo y
   no tocaría al atacante, que es quien lo lanzó.

Hay dos comprobaciones más. `verificar_invariantes` revisa el plan otra vez antes de
ejecutar, y si encuentra algo baja la acción a aprobación y lo deja en la auditoría.
`tools/validar.py` simula una alerta crítica de cada regla del catálogo y falla si
alguna acaba en una acción automática de radio amplio.

## 5. El objetivo tiene que ser inequívoco

Cada acción declara los campos que necesita (`requiere`). Si la alerta no los trae,
la acción es `no_aplicable` y queda como tarea. Los conectores añaden su propia
comprobación: CrowdStrike, SentinelOne y Defender se niegan a actuar si el nombre del
equipo casa con cero o con más de un dispositivo, y Exchange hace lo mismo con una
regla de buzón cuyo nombre no es único. «Aislar el equipo que se llama PC-01» cuando
hay dos es justo lo que una máquina no tiene que hacer sola.

## 6. Lo que decide el cliente

Después de las invariantes, el perfil del cliente solo puede **restringir**:

| En el perfil | Efecto |
|---|---|
| `politica.contencion_automatica: false` | Toda la contención espera aprobación |
| `politica.acciones_prohibidas` | Esas acciones no se ejecutan nunca, ni con aprobación |
| `politica.acciones_siempre_aprobacion` | Esas acciones esperan siempre a una persona |
| `inventario.protegidos` | Sobre esos equipos nada es automático, tampoco la recogida de evidencia |
| `politica.excepcion_sin_datos: aprobacion` | Una excepción que no se puede comprobar por falta de datos lleva a aprobación |
| `modo: simulacion` | Decide y registra; no ejecuta nada |

Y un interruptor por encima de todos los perfiles: `RL_SIMULACION_GLOBAL=true`.

## 7. Las excepciones de DetectionLab

Cada acción de contención de DetectionLab trae su excepción en prosa. Por ejemplo:
«si el proceso es una aplicación de negocio, no se mata: se anota». La capa
ejecutable la traduce a evaluadores que contestan **sí**, **no** o **no lo sé**:

- **Sí:** se cumple la excepción y la acción pasa a aprobación, con el motivo.
- **No:** la excepción está descartada y sigue la decisión normal.
- **No lo sé:** faltan datos (por ejemplo, el cliente no ha declarado su lista de
  aplicaciones de negocio). Con `excepcion_sin_datos: aprobacion`, que es lo
  recomendado, la acción espera. «No lo sé» nunca se convierte en «no».

## 8. La evidencia

Recoger evidencia (triage forense, paquete de investigación, copia de un fichero)
es automático en `auto_contener`: en el peor caso ocupa disco. Hay tres excepciones:

- en un activo protegido la decide una persona, porque un colector en un sistema
  frágil también es tocarlo;
- un almacén de credenciales (`/etc/shadow`, SAM, `ntds.dit`) no se copia a
  custodia: multiplicaría el secreto, y que se leyó ya consta en la alerta;
- marcar una acción como evidencia no la libra de las invariantes del punto 4.

## 9. El cierre automático

Las condiciones de cierre de DetectionLab solo cierran solas cuando **todas** sus
partes se pueden comprobar con datos. El escáner autorizado es el ejemplo. La
condición exige tres cosas:
- que la IP esté en el rango del escáner;
- que el escaneo caiga dentro de su ventana;
- que ninguna ruta fuera del inventario de la aplicación haya devuelto 200.

La tercera no viaja en la alerta. Así que el triaje reconoce al escáner y baja la
severidad, pero el cierre se propone a una persona. El propio playbook explica por
qué rango y ventana no bastan: un escáner comprometido es el sitio ideal desde el
que atacar. Ninguna alerta que forme parte de una secuencia se cierra sola.

## 10. Después de actuar

- **Una vez por incidente.** La misma acción sobre el mismo objetivo no se repite
  mientras no se deshaga.
- **Deshacer.** Las acciones reversibles guardan lo necesario para su inversa (la
  regla de buzón exacta, la ruta y el hash del fichero, el grupo del cortafuegos) y
  se deshacen con el mismo conector que las ejecutó. Una acción ya deshecha no se
  deshace dos veces.
- **Aprobaciones.** Caducan, a las 4 h por defecto. Una caducada no se puede aprobar
  aunque la vigilancia periódica todavía no la haya marcado.
- **Acuses.** Lo que pasó de verdad en el equipo lo confirma el script del agente,
  no la petición a la API.
- **Auditoría.** Cada decisión, ejecución, aprobación y acuse va a una cadena de
  hashes que se puede verificar.
