document.addEventListener('DOMContentLoaded', () => {
  const btnEscanear        = document.getElementById('btn-escanear');

  const totalDispEl        = document.getElementById('stat-total');
  const vulnerablesEl      = document.getElementById('stat-vulnerables');
  const nuevosEl           = document.getElementById('stat-nuevos');

  const bloqueProgreso     = document.getElementById('bloque-progreso');
  const progresoTextoEl    = document.getElementById('progreso-texto');
  const progresoPctEl      = document.getElementById('progreso-porcentaje');
  const progresoBarraEl    = document.getElementById('progreso-barra');

  const tablaDispBody      = document.getElementById('tabla-dispositivos-body');
  const tablaHistBody      = document.getElementById('tabla-historial-body');

  const estadoVacioEl      = document.getElementById('estado-vacio');
  const estadoResultadoEl  = document.getElementById('estado-resultado');


  function actualizarProgreso(porcentaje, texto) {
    if (!bloqueProgreso) return;

    const pct = Math.max(0, Math.min(100, porcentaje));

    progresoTextoEl.textContent = texto || '';
    progresoPctEl.textContent   = pct.toString() + '%';
    progresoBarraEl.style.width = pct + '%';
  }

  function mostrarPlaceholder(mostrar) {
    if (!estadoVacioEl || !estadoResultadoEl) return;

    if (mostrar) {
      estadoVacioEl.classList.remove('hidden');
      estadoResultadoEl.classList.add('hidden');
    } else {
      estadoVacioEl.classList.add('hidden');
      estadoResultadoEl.classList.remove('hidden');
    }
  }

  async function fetchJSON(url, options) {
    const resp = await fetch(url, options || {});
    if (!resp.ok) {
      throw new Error('Error HTTP ' + resp.status + ' al llamar ' + url);
    }
    return await resp.json();
  }

  function crearBadgeEstado(estadoCrudo) {
    const estado = (estadoCrudo || 'desconocido').toLowerCase();
    let bgClass   = 'bg-slate-600/20';
    let textClass = 'text-slate-200';
    let label     = 'Desconocido';

    if (estado === 'seguro') {
      bgClass   = 'bg-emerald-500/10';
      textClass = 'text-emerald-400';
      label     = 'Seguro';
    } else if (estado === 'nuevo') {
      bgClass   = 'bg-orange-500/10';
      textClass = 'text-orange-400';
      label     = 'Nuevo';
    } else if (
      estado === 'sospechoso' ||
      estado === 'vulnerable' ||
      estado === 'alto' ||
      estado === 'inseguro'
    ) {
      bgClass   = 'bg-red-500/10';
      textClass = 'text-red-400';
      label     = 'Sospechoso';
    }

    const span = document.createElement('span');
    span.className =
      'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ' +
      bgClass + ' ' + textClass;
    span.textContent = '● ' + label;
    return span;
  }


  async function cargarHistorial() {
    try {
      const datos = await fetchJSON('/historial');

      tablaHistBody.innerHTML = '';

      if (!Array.isArray(datos) || datos.length === 0) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td colspan="4" class="px-4 py-3 text-center text-sm text-slate-400">
            No hay escaneos registrados aún.
          </td>`;
        tablaHistBody.appendChild(tr);
        return;
      }

      datos.forEach(item => {
        const tr = document.createElement('tr');
        tr.className = 'border-b border-slate-800/40';

        tr.innerHTML = `
          <td class="px-4 py-3 text-sm text-slate-200">
            ${item.fecha_hora || ''}
          </td>
          <td class="px-4 py-3 text-sm text-slate-200 text-center">
            ${item.total_dispositivos ?? 0}
          </td>
          <td class="px-4 py-3 text-sm text-slate-200 text-center">
            ${item.vulnerables ?? 0}
          </td>
          <td class="px-4 py-3 text-sm text-right text-slate-400">
            ${item.id ? 'Escaneo #' + item.id : ''}
          </td>
        `;
        tablaHistBody.appendChild(tr);
      });
    } catch (err) {
      console.error('Error al cargar historial:', err);
    }
  }


  async function cargarDispositivos() {
    try {
      actualizarProgreso(10, 'Iniciando escaneo de la red...');

      const data = await fetchJSON('/dispositivos');

      actualizarProgreso(60, 'Analizando dispositivos encontrados...');

      const cantidad     = data.cantidad ?? 0;
      const dispositivos = Array.isArray(data.dispositivos) ? data.dispositivos : [];
      const vulnerables  = data.vulnerables ?? 0;
      const duracion     = data.duracion ?? 0;

      totalDispEl.textContent   = cantidad.toString();
      vulnerablesEl.textContent = vulnerables.toString();

      const nuevos = dispositivos.filter(d => {
        const est = (d.estado || '').toLowerCase();
        return est === 'nuevo';
      }).length;
      nuevosEl.textContent = nuevos.toString();

      tablaDispBody.innerHTML = '';

      if (dispositivos.length === 0) {
        mostrarPlaceholder(true);
        actualizarProgreso(
          100,
          'No se detectaron dispositivos en el último escaneo.'
        );
        return;
      }

      mostrarPlaceholder(false);

      dispositivos.forEach(d => {
        const tr = document.createElement('tr');
        tr.className = 'border-b border-slate-800/40 hover:bg-slate-800/40';

        const ip     = d.ip || '—';
        const mac    = d.mac || 'No registrada';
        const host   = d.hostname || d.nombre || 'Desconocido';
        const estado = d.estado || d.riesgo || 'Desconocido';

        const tdIp = document.createElement('td');
        tdIp.className = 'px-4 py-3 text-sm text-slate-200';
        tdIp.textContent = ip;

        const tdMac = document.createElement('td');
        tdMac.className = 'px-4 py-3 text-sm text-slate-400';
        tdMac.textContent = mac;

        const tdHost = document.createElement('td');
        tdHost.className =
          'px-4 py-3 text-sm text-slate-200 truncate max-w-[220px]';
        tdHost.title = host;
        tdHost.textContent = host;

        const tdEstado = document.createElement('td');
        tdEstado.className = 'px-4 py-3';
        tdEstado.appendChild(crearBadgeEstado(estado));

        const tdAccion = document.createElement('td');
        tdAccion.className = 'px-4 py-3 text-right';
        tdAccion.innerHTML = `
          <a href="/dispositivo/${d.id || ''}"
             class="inline-flex items-center rounded-lg bg-primary px-3 py-1.5 text-xs font-semibold text-white hover:bg-primary/90">
            Ver detalle
          </a>
        `;

        tr.appendChild(tdIp);
        tr.appendChild(tdMac);
        tr.appendChild(tdHost);
        tr.appendChild(tdEstado);
        tr.appendChild(tdAccion);

        tablaDispBody.appendChild(tr);
      });

      const duracionTexto =
        typeof duracion === 'number' && duracion.toFixed
          ? duracion.toFixed(1) + ' segundos.'
          : duracion + ' segundos.';

      actualizarProgreso(100, 'Escaneo completado en ' + duracionTexto);
    } catch (err) {
      console.error('Error al cargar dispositivos:', err);
      actualizarProgreso(
        0,
        'Error al realizar el escaneo. Intenta nuevamente.'
      );
      mostrarPlaceholder(true);
    }
  }


  async function manejarClickEscanear() {
    if (!btnEscanear) return;

    btnEscanear.disabled = true;
    btnEscanear.classList.add('opacity-60', 'cursor-not-allowed');

    try {
      await cargarDispositivos();
      await cargarHistorial();
    } finally {
      btnEscanear.disabled = false;
      btnEscanear.classList.remove('opacity-60', 'cursor-not-allowed');
    }
  }

  if (btnEscanear) {
    btnEscanear.addEventListener('click', ev => {
      ev.preventDefault();
      manejarClickEscanear();
    });
  }


  actualizarProgreso(0, 'Listo para iniciar un nuevo escaneo.');
  cargarDispositivos(); 
  cargarHistorial();    
});
