document.addEventListener("DOMContentLoaded", () => {
  const btnScan = document.getElementById("btn-escanear");

  const estadoVacio = document.getElementById("estado-vacio");
  const estadoResultado = document.getElementById("estado-resultado");

  const statTotal = document.getElementById("stat-total");
  const statVulnerables = document.getElementById("stat-vulnerables");
  const statNuevos = document.getElementById("stat-nuevos");

  const progresoTexto = document.getElementById("progreso-texto");
  const progresoPorcentaje = document.getElementById("progreso-porcentaje");
  const progresoBarra = document.getElementById("progreso-barra");

  const tablaBody = document.getElementById("tabla-dispositivos-body");
  const historialBody = document.getElementById("tabla-historial-body");

  function badgeEstado(estado) {
    const e = (estado || "").toLowerCase();
    if (e === "nuevo") {
      return `<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-500/10 text-amber-400">● Nuevo</span>`;
    }
    if (e === "bloqueado") {
      return `<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-500/10 text-red-400">● Bloqueado</span>`;
    }
    if (e === "sospechoso") {
      return `<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-500/10 text-red-400">● Sospechoso</span>`;
    }
    return `<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400">● Seguro</span>`;
  }

  function escapeHtml(str) {
    return String(str ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function renderDispositivos(dispositivos) {
    if (!tablaBody) return;
    tablaBody.innerHTML = "";

    dispositivos.forEach((d) => {
      const fabricante = d.fabricante || "Desconocido";
      const nombre = d.nombre || "Desconocido";
      const mac = d.mac || "MAC desconocida";

      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="px-6 py-3 text-sm text-gray-200">${escapeHtml(d.ip)}</td>
        <td class="px-6 py-3 text-sm text-gray-200">${escapeHtml(mac)}</td>
        <td class="px-6 py-3 text-sm text-gray-200 max-w-[180px] truncate" title="${escapeHtml(fabricante)}">${escapeHtml(fabricante)}</td>
        <td class="px-6 py-3 text-sm text-gray-200">${escapeHtml(nombre)}</td>
        <td class="px-6 py-3 text-sm">${badgeEstado(d.estado)}</td>
        <td class="px-6 py-3 text-sm">
          <a href="/dispositivo/${d.id}"
             class="inline-flex items-center rounded-lg bg-primary px-3 py-1 text-xs font-semibold text-white hover:bg-primary/90">
            Ver detalle
          </a>
        </td>
      `;
      tablaBody.appendChild(tr);
    });
  }

  function renderHistorial(escaneos) {
    if (!historialBody) return;
    historialBody.innerHTML = "";

    escaneos.forEach((e) => {
      const fecha = e.fecha ? new Date(e.fecha) : null;
      const fechaTxt = fecha ? fecha.toLocaleString() : "—";

      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="px-4 py-3 text-sm text-gray-200">${escapeHtml(fechaTxt)}</td>
        <td class="px-4 py-3 text-sm text-gray-200">${escapeHtml(e.total_dispositivos)}</td>
        <td class="px-4 py-3 text-sm text-gray-200">${escapeHtml(e.dispositivos_vulnerables)}</td>
      `;
      historialBody.appendChild(tr);
    });
  }

  async function refreshDashboard() {
    const res = await fetch("/api/dashboard-data", { headers: { "Accept": "application/json" } });
    if (!res.ok) throw new Error("No se pudo cargar /api/dashboard-data");

    const data = await res.json();

    const hay = (data.dispositivos || []).length > 0;
    if (estadoVacio) estadoVacio.classList.toggle("hidden", hay);
    if (estadoResultado) estadoResultado.classList.toggle("hidden", !hay);

    if (statTotal) statTotal.textContent = data.stats?.total ?? 0;
    if (statVulnerables) statVulnerables.textContent = data.stats?.vulnerables ?? 0;
    if (statNuevos) statNuevos.textContent = data.stats?.nuevos ?? 0;

    if (progresoTexto) progresoTexto.textContent = hay ? "Escaneo completado." : "Preparando escaneo...";
    if (progresoPorcentaje) progresoPorcentaje.textContent = hay ? "100%" : "0%";
    if (progresoBarra) progresoBarra.style.width = hay ? "100%" : "0%";

    renderDispositivos(data.dispositivos || []);
    renderHistorial(data.ultimos_escaneos || []);
  }

  async function ejecutarScan() {
    if (!btnScan) return;

    btnScan.disabled = true;
    btnScan.classList.add("opacity-60", "cursor-not-allowed");

    if (progresoTexto) progresoTexto.textContent = "Escaneando red...";
    if (progresoPorcentaje) progresoPorcentaje.textContent = "0%";
    if (progresoBarra) progresoBarra.style.width = "25%";

    try {
      const res = await fetch("/ejecutar-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });

      if (!res.ok) {
        const txt = await res.text();
        throw new Error(txt || "Error ejecutando escaneo");
      }

      if (progresoBarra) progresoBarra.style.width = "80%";
      await refreshDashboard();
      if (progresoBarra) progresoBarra.style.width = "100%";
      if (progresoPorcentaje) progresoPorcentaje.textContent = "100%";
      if (progresoTexto) progresoTexto.textContent = "Escaneo completado.";
    } catch (e) {
      console.error(e);
      alert("Error al ejecutar escaneo. Revisa la consola/terminal para más detalles.");
      if (progresoTexto) progresoTexto.textContent = "Error al escanear.";
      if (progresoPorcentaje) progresoPorcentaje.textContent = "0%";
      if (progresoBarra) progresoBarra.style.width = "0%";
    } finally {
      btnScan.disabled = false;
      btnScan.classList.remove("opacity-60", "cursor-not-allowed");
    }
  }

  if (btnScan) btnScan.addEventListener("click", ejecutarScan);

  refreshDashboard().catch(() => {
  });
});

