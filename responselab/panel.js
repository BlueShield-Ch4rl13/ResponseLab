// Panel de aprobaciones de ResponseLab. Va en un fichero aparte (y no dentro de
// panel.html) para que la CSP solo permita scripts del propio motor.
"use strict";
const $ = (id) => document.getElementById(id);
const esc = (t) => String(t ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function guardado(k) { try { return sessionStorage.getItem(k) || ""; } catch (e) { return ""; } }
function guardar(k, v) { try { sessionStorage.setItem(k, v); } catch (e) {} }
$("cliente").value = guardado("rl_cliente") || (location.hash.slice(1).split("/")[0] || "");
$("token").value = guardado("rl_token");

async function api(ruta, metodo = "GET", cuerpo) {
  const r = await fetch(`/v1/${encodeURIComponent($("cliente").value)}${ruta}`, {
    method: metodo, headers: {"Authorization": "Bearer " + $("token").value, "Content-Type": "application/json"},
    body: cuerpo ? JSON.stringify(cuerpo) : undefined });
  const datos = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(datos.error || r.status);
  return datos;
}

async function cargar() {
  guardar("rl_cliente", $("cliente").value); guardar("rl_token", $("token").value);
  $("aviso").textContent = "";
  try {
    const [aps, incs] = await Promise.all([api("/aprobaciones?estado=pendiente"), api("/incidentes")]);
    $("aprobaciones").innerHTML = aps.map((a) => `<tr>
      <td><b>${esc(a.paso.nombre)}</b><br><span class="suave">${esc(JSON.stringify(a.paso.objetivo))}</span></td>
      <td>${esc(a.motivo)}<br><span class="suave">caduca ${esc(a.caduca.slice(0,16))} · ${esc(a.incidente_id)}</span></td>
      <td><button class="primario" data-ap="${esc(a.id)}" data-op="aprobar">Aprobar</button>
          <button class="peligro" data-ap="${esc(a.id)}" data-op="rechazar">Rechazar</button></td></tr>`).join("")
      || `<tr><td colspan="3" class="suave">Nada pendiente.</td></tr>`;
    $("incidentes").innerHTML = incs.map((i) => `<tr class="fila" data-inc="${esc(i.id)}">
      <td><span class="chip s${i.severidad}">${i.severidad}</span></td>
      <td><b>${esc(i.titulo)}</b><br><span class="suave">${esc(i.entidad_tipo)}: ${esc(i.entidad)} · ${esc(i.familias.join(", "))} · ${i.n_alertas} alerta(s)</span></td>
      <td>${esc(i.estado)}</td><td>${esc(i.escalado_a)}<br><span class="suave">${esc(i.plazo.slice(11,16))}</span></td></tr>`).join("")
      || `<tr><td colspan="4" class="suave">Sin incidentes.</td></tr>`;
    $("estado").textContent = "actualizado " + new Date().toLocaleTimeString();
    const inc = location.hash.slice(1).split("/")[1];
    if (inc) detalle(inc);
  } catch (e) { $("aviso").textContent = "No se pudo cargar: " + e.message; }
}

async function detalle(id) {
  location.hash = `${$("cliente").value}/${id}`;
  try {
    const d = await api(`/incidentes/${encodeURIComponent(id)}`);
    const i = d.incidente;
    $("detalle").innerHTML = `<h2>${esc(i.titulo)}</h2>
      <p><span class="chip s${i.severidad}">severidad ${i.severidad}</span> ${esc(i.estado)} · escalar a <b>${esc(i.escalado_a)}</b>
         · ${esc(i.entidad_tipo)} ${esc(i.entidad)} ${i.caso_externo ? "· caso " + esc(i.caso_externo) : ""}
         <button data-inc-op="asumir">Asumir</button> <button data-inc-op="cerrar">Cerrar</button></p>
      ${i.plazos_regulatorios.length ? `<p><b>Plazos regulatorios:</b> ${i.plazos_regulatorios.map((p) => esc(p.marco + " " + p.hito + " → " + p.vence)).join(" · ")}</p>` : ""}
      <h2>Alertas</h2><table>${d.alertas.map((a) => `<tr><td>${esc(a.momento.slice(0,19))}</td><td><b>${esc(a.plan.regla?.titulo || a.regla_clave)}</b>
         <br><span class="suave">${esc(a.familia)} · ${esc(a.clase)}</span><pre>${esc(a.plan.resumen || "")}</pre></td></tr>`).join("")}</table>
      <h2>Ejecuciones</h2><table>${d.ejecuciones.map((e) => `<tr><td><b>${esc(e.accion)}</b> via ${esc(e.conector)}<br>
         <span class="suave">${esc(e.origen)} · ${esc(e.actor)} · ${esc(e.creada.slice(0,19))}</span></td>
         <td class="${e.estado === "error" ? "error" : "ok"}">${esc(e.estado)}</td><td>${esc(e.resultado?.detalle || "")}</td>
         <td>${["ok","simulada","confirmada"].includes(e.estado) && !e.deshace ? `<button data-ej="${esc(e.id)}">Deshacer</button>` : ""}</td></tr>`).join("") || `<tr><td class="suave">Ninguna.</td></tr>`}</table>
      <h2>Tareas</h2><table>${d.tareas.map((t) => `<tr><td>${esc(t.grupo)}</td><td><b>${esc(t.titulo)}</b><br><span class="suave">${esc(t.descripcion)}</span></td></tr>`).join("") || `<tr><td class="suave">Ninguna.</td></tr>`}</table>`;
  } catch (e) { $("aviso").textContent = "No se pudo abrir el incidente: " + e.message; }
}

document.addEventListener("click", async (ev) => {
  const t = ev.target.closest("[data-ap],[data-inc],[data-ej],[data-inc-op]");
  if (!t) return;
  try {
    if (t.dataset.ap) {
      const comentario = prompt(t.dataset.op === "aprobar" ? "Comentario de la aprobación:" : "Motivo del rechazo:") ?? "";
      await api(`/aprobaciones/${encodeURIComponent(t.dataset.ap)}/${t.dataset.op}`, "POST", {comentario});
      await cargar();
    } else if (t.dataset.inc) { detalle(t.dataset.inc); }
    else if (t.dataset.ej) {
      if (confirm("¿Deshacer esta acción?")) { await api(`/ejecuciones/${encodeURIComponent(t.dataset.ej)}/deshacer`, "POST"); await cargar(); }
    } else if (t.dataset.incOp) {
      const id = location.hash.slice(1).split("/")[1];
      await api(`/incidentes/${encodeURIComponent(id)}/${t.dataset.incOp}`, "POST", {}); await cargar();
    }
  } catch (e) { $("aviso").textContent = e.message; }
});
$("cargar").addEventListener("click", cargar);
if ($("cliente").value && $("token").value) cargar();
setInterval(() => { if ($("cliente").value && $("token").value) cargar(); }, 30000);
