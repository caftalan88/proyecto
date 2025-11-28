let chartHistorial = null;

async function cargarDispositivos() {
    try {
        const res = await fetch("/dispositivos");
        const data = await res.json();

        document.getElementById("kpi-total-dispositivos").textContent = data.cantidad;

        const tbody = document.getElementById("tabla-dispositivos");
        tbody.innerHTML = "";

        data.dispositivos.forEach(d => {
            const tr = document.createElement("tr");

            const puertos = (d.puertos_abiertos || []).join(", ");
            const riesgo = d.riesgo || "Desconocido";
            const lat = d.latencia_ms !== null && d.latencia_ms !== undefined ? d.latencia_ms : "-";

            tr.innerHTML = `
                <td>${d.ip || "-"}</td>
                <td>${d.mac || "-"}</td>
                <td>${d.nombre || "-"}</td>
                <td class="riesgo-${riesgo}">${riesgo}</td>
                <td>${lat}</td>
                <td>${puertos}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Error al cargar dispositivos:", e);
    }
}

async function cargarHistorial() {
    try {
        const res = await fetch("/historial");
        const data = await res.json();

        const labels = data.map(r => r.fecha).reverse();
        const totales = data.map(r => r.total).reverse();
        const vulnerables = data.map(r => r.vulnerables).reverse();

        const ctx = document.getElementById("chartHistorial").getContext("2d");

        if (chartHistorial) {
            chartHistorial.destroy();
        }

        chartHistorial = new Chart(ctx, {
            type: "line",
            data: {
                labels: labels,
                datasets: [
                    {
                        label: "Total dispositivos",
                        data: totales,
                        borderWidth: 2,
                        fill: false
                    },
                    {
                        label: "En riesgo alto",
                        data: vulnerables,
                        borderWidth: 2,
                        borderDash: [4, 2],
                        fill: false
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        precision: 0
                    }
                }
            }
        });
    } catch (e) {
        console.error("Error al cargar historial:", e);
    }
}

async function cargarAlertas() {
    try {
        const res = await fetch("/alertas");
        const data = await res.json();

        const ul = document.getElementById("lista-alertas");
        ul.innerHTML = "";

        data.forEach(a => {
            const li = document.createElement("li");
            li.classList.add(a.tipo || "evento");
            li.textContent = `${a.fecha} - [${a.tipo}] ${a.descripcion} (${a.ip || "IP desconocida"})`;
            ul.appendChild(li);
        });
    } catch (e) {
        console.error("Error al cargar alertas:", e);
    }
}

async function cargarResumen() {
    try {
        const res = await fetch("/reporte");
        const data = await res.json();

        document.getElementById("kpi-riesgo-alto").textContent = data.riesgo_alto ?? "-";
        document.getElementById("kpi-riesgo-medio").textContent = data.riesgo_medio ?? "-";
        document.getElementById("kpi-ultimo-escaneo").textContent = data.fecha_ultimo_escaneo ?? "-";

        const div = document.getElementById("resumen-texto");
        const total = data.total_dispositivos || 0;
        const alto = data.riesgo_alto || 0;
        const medio = data.riesgo_medio || 0;

        let texto = "";
        texto += `<p>Total de dispositivos conocidos en la red: <strong>${total}</strong>.</p>`;
        texto += `<p>Dispositivos con riesgo alto: <strong>${alto}</strong>; con riesgo medio: <strong>${medio}</strong>.</p>`;

        if (alto > 0) {
            texto += `<p>⚠ Se recomienda revisar estos dispositivos, cambiar credenciales por defecto y desactivar servicios innecesarios (por ejemplo, SSH en puertos 22 abiertos).</p>`;
        } else if (medio > 0) {
            texto += `<p>ℹ La red presenta algunos servicios expuestos (HTTP/puertos web). Se aconseja validar que estos accesos sean intencionados.</p>`;
        } else if (total > 0) {
            texto += `<p>✓ No se detectan dispositivos de riesgo alto. Mantén tu red actualizada y revisa periódicamente este panel.</p>`;
        } else {
            texto += `<p>Aún no se han registrado dispositivos. Ejecuta un escaneo manual o espera al escaneo automático.</p>`;
        }

        div.innerHTML = texto;
    } catch (e) {
        console.error("Error al cargar resumen:", e);
    }
}

async function forzarEscaneo() {
    const estado = document.getElementById("estado-escaneo");
    estado.textContent = "Ejecutando escaneo en tiempo real...";

    await cargarDispositivos();
    await cargarHistorial();
    await cargarAlertas();
    await cargarResumen();

    estado.textContent = "Escaneo completado.";
    setTimeout(() => {
        estado.textContent = "";
    }, 4000);
}

document.addEventListener("DOMContentLoaded", () => {
    cargarDispositivos();
    cargarHistorial();
    cargarAlertas();
    cargarResumen();

    setInterval(cargarAlertas, 7000);
    setInterval(cargarResumen, 15000);

    const btn = document.getElementById("btn-escanear");
    btn.addEventListener("click", forzarEscaneo);
});
