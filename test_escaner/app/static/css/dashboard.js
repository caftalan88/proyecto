<!DOCTYPE html>
<html class="dark" lang="es">
<head>
    <meta charset="utf-8" />
    <meta content="width=device-width, initial-scale=1.0" name="viewport" />
    <title>Monitoreo de Seguridad IoT Doméstico</title>

    
    <script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet" />
    <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined" rel="stylesheet" />

    <script id="tailwind-config">
      tailwind.config = {
        darkMode: "class",
        theme: {
          extend: {
            colors: {
              "primary": "#1173d4",
              "background-light": "#f6f7f8",
              "background-dark": "#101922",
            },
            fontFamily: {
              "display": ["Inter", "sans-serif"]
            },
            borderRadius: {
              "DEFAULT": "0.25rem",
              "lg": "0.5rem",
              "xl": "0.75rem",
              "full": "9999px"
            },
          },
        },
      }
    </script>

    <style>
      .material-symbols-outlined {
          font-variation-settings: 'FILL' 0, 'wght' 400, 'GRAD' 0, 'opsz' 24;
      }
    </style>
</head>
<body class="bg-background-light dark:bg-background-dark font-display text-gray-800 dark:text-gray-200">
<div class="relative flex h-auto min-h-screen w-full flex-col">
  <div class="layout-container flex h-full grow flex-col">
    <div class="px-4 sm:px-6 lg:px-8 xl:px-40 flex flex-1 justify-center py-5">
      <div class="layout-content-container flex flex-col w-full max-w-6xl flex-1">
        
        <header class="flex items-center justify-between whitespace-nowrap border-b border-gray-200 dark:border-b-[#233648] px-6 py-4">
          <div class="flex items-center gap-3">
            <div class="size-6 text-primary">
              <span class="material-symbols-outlined text-3xl">security</span>
            </div>
            <h1 class="text-gray-900 dark:text-white text-xl font-bold leading-tight tracking-tight">
              Monitoreo de Seguridad IoT Doméstico
              <nav class="flex items-center gap-4 text-sm">
                <a href="{{ url_for('main.dashboard') }}" class="hover:text-primary">Dashboard</a>
                <a href="{{ url_for('main.resultado_escaneo') }}" class="hover:text-primary">Resultado de escaneo</a>
                <a href="{{ url_for('main.historial_escaneos') }}" class="hover:text-primary">Historial</a>
              </nav>
            </h1>
          </div>
          <button
            id="btn-escanear"
            class="flex min-w-[84px] max-w-[480px] cursor-pointer items-center justify-center overflow-hidden rounded-lg h-10 px-5 bg-primary text-white text-sm font-bold leading-normal tracking-wide gap-2 hover:bg-primary/90 transition-colors"
          >
            <span class="material-symbols-outlined">radar</span>
            <span class="truncate">Iniciar Escaneo</span>
          </button>
        </header>

        <main class="flex-grow p-4 sm:p-6">
          
          <div id="estado-vacio" class="flex flex-col p-4 {% if hay_resultados %}hidden{% endif %}">
            <div class="flex flex-col items-center gap-6 rounded-lg border-2 border-dashed border-gray-300 dark:border-[#324d67] px-6 py-14 text-center">
              <div class="flex max-w-[480px] flex-col items-center gap-2">
                <p class="text-gray-900 dark:text-white text-lg font-bold leading-tight tracking-[-0.015em]">
                  No hay dispositivos detectados
                </p>
                <p class="text-gray-600 dark:text-gray-400 text-sm font-normal leading-normal">
                  Presione "Iniciar Escaneo" para detectar dispositivos en su red.
                </p>
              </div>
            </div>
          </div>

          
          <div id="estado-resultado" class="flex flex-col gap-8 mt-4 {% if not hay_resultados %}hidden{% endif %}">

            
            <section id="resumen-estadistico" class="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div class="bg-white dark:bg-[#111a22] rounded-lg shadow p-4 flex flex-col gap-1">
                <p class="text-xs uppercase text-gray-500 dark:text-gray-400 font-semibold">
                  Total dispositivos
                </p>
                <p id="stat-total" class="text-2xl font-bold text-gray-900 dark:text-white">
                  {{ stats.total }}
                </p>
              </div>
              <div class="bg-white dark:bg-[#111a22] rounded-lg shadow p-4 flex flex-col gap-1">
                <p class="text-xs uppercase text-gray-500 dark:text-gray-400 font-semibold">
                  Vulnerables
                </p>
                <p id="stat-vulnerables" class="text-2xl font-bold text-red-500">
                  {{ stats.vulnerables }}
                </p>
              </div>
              <div class="bg-white dark:bg-[#111a22] rounded-lg shadow p-4 flex flex-col gap-1">
                <p class="text-xs uppercase text-gray-500 dark:text-gray-400 font-semibold">
                  Nuevos
                </p>
                <p id="stat-nuevos" class="text-2xl font-bold text-amber-400">
                  {{ stats.nuevos }}
                </p>
              </div>
            </section>

            
            <section id="bloque-progreso" 
                     class="flex flex-col gap-3 p-4 bg-white dark:bg-[#111a22] rounded-lg shadow">
              <div class="flex gap-6 justify-between items-center">
                <p class="text-gray-800 dark:text-white text-base font-medium leading-normal"
                   id="progreso-texto">
                  {% if hay_resultados %}
                    Escaneo completado.
                  {% else %}
                    Preparando escaneo...
                  {% endif %}
                </p>
                <p class="text-gray-700 dark:text-white text-sm font-normal leading-normal"
                   id="progreso-porcentaje">
                  {% if hay_resultados %}100%{% else %}0%{% endif %}
                </p>
              </div>
              {% set barra = '100%' if hay_resultados else '0%' %}
              <div class="h-2 rounded-full bg-gray-200 dark:bg-[#324d67] overflow-hidden">
                <div id="progreso-barra"
                     class="h-2 rounded-full bg-primary transition-all duration-300"
                     style="width: {{ barra }};">
                </div>
              </div>
            </section>

            
            <section class="px-0 sm:px-1 @container">
              <div class="flex overflow-hidden rounded-lg border border-gray-200 dark:border-[#324d67] bg-background-light dark:bg-[#111a22]">
                <table class="w-full text-left">
                  <thead class="bg-gray-50 dark:bg-[#192633]">
                    <tr>
                      <th class="px-6 py-4 text-xs font-semibold uppercase tracking-wider text-gray-600 dark:text-white">
                        Dirección IP
                      </th>
                      <th class="px-6 py-4 text-xs font-semibold uppercase tracking-wider text-gray-600 dark:text-white">
                        Dirección MAC
                      </th>
                      <th class="px-6 py-4 text-xs font-semibold uppercase tracking-wider text-gray-600 dark:text-white">
                        Hostname
                      </th>
                      <th class="px-6 py-4 text-xs font-semibold uppercase tracking-wider text-gray-600 dark:text-white">
                        Estado
                      </th>
                      <th class="px-6 py-4 text-xs font-semibold uppercase tracking-wider text-gray-600 dark:text-white">
                        Acción
                      </th>
                    </tr>
                  </thead>
                  <tbody id="tabla-dispositivos-body" 
                         class="divide-y divide-gray-200 dark:divide-[#324d67]">
                    {% for d in dispositivos %}
                      <tr>
                       <td class="px-6 py-3 text-sm text-gray-200">{{ d.ip }}</td>
                       <td class="px-6 py-3 text-sm text-gray-200">
                         {{ d.mac or 'MAC desconocida' }}
                       </td>
                       <td class="px-6 py-3 text-sm text-gray-200">
                         {{ d.nombre or 'Desconocido' }}
                       </td>
                       <td class="px-6 py-3 text-sm">
                         {% if d.estado == 'nuevo' %}
                           <span class="inline-flex items-center px-2.5 py-0.5 rounded-full
                                        text-xs font-medium bg-amber-500/10 text-amber-400">
                             ● Nuevo
                           </span>
                         {% elif d.estado == 'bloqueado' %}
                           <span class="inline-flex items-center px-2.5 py-0.5 rounded-full
                                        text-xs font-medium bg-red-500/10 text-red-400">
                             ● Bloqueado
                           </span>
                         {% else %}
                           <span class="inline-flex items-center px-2.5 py-0.5 rounded-full
                                        text-xs font-medium bg-emerald-500/10 text-emerald-400">
                             ● Seguro
                           </span>
                         {% endif %}
                       </td>
                       <td class="px-6 py-3 text-sm">
                         <a href="{{ url_for('main.detalle_dispositivo', dispositivo_id=d.id) }}"
                            class="inline-flex items-center rounded-lg bg-primary px-3 py-1
                                   text-xs font-semibold text-white hover:bg-primary/90">
                           Ver detalle
                         </a>
                       </td>
                     </tr>
                    {% endfor %}
                  </tbody>
                </table>
              </div>
            </section>

            
            <section class="px-0 sm:px-1">
              <div class="rounded-lg border border-gray-200 dark:border-[#324d67] bg-background-light dark:bg-[#111a22]">
                <div class="px-4 py-3 border-b border-gray-200 dark:border-[#324d67] flex items-center justify-between">
                  <h2 class="text-sm font-semibold text-gray-800 dark:text-white">
                    Historial de escaneos
                  </h2>
                  <span class="text-xs text-gray-500 dark:text-gray-400">
                    Últimos 10 escaneos
                  </span>
                </div>
                <div class="overflow-x-auto">
                  <table class="w-full text-left">
                    <thead class="bg-gray-50 dark:bg-[#192633]">
                      <tr>
                        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-gray-600 dark:text-white">
                          Fecha y hora
                        </th>
                        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-gray-600 dark:text-white">
                          Total disp.
                        </th>
                        <th class="px-4 py-3 text-xs font-semibold uppercase tracking-wider text-gray-600 dark:text-white">
                          Vulnerables
                        </th>
                      </tr>
                    </thead>
                    <tbody id="tabla-historial-body" 
                           class="divide-y divide-gray-200 dark:divide-[#324d67]">
                      {% for e in ultimos_escaneos %}
                        <tr>
                          <td class="px-4 py-3 text-sm text-gray-200">
                            {{ e.fecha.strftime("%d-%m-%Y %H:%M") }}
                          </td>
                          <td class="px-4 py-3 text-sm text-gray-200">
                            {{ e.total_dispositivos }}
                          </td>
                          <td class="px-4 py-3 text-sm text-gray-200">
                            {{ e.dispositivos_vulnerables }}
                          </td>
                        </tr>
                      {% endfor %}                      
                    </tbody>
                  </table>
                </div>
              </div>
            </section>

          </div>
        </main>

      </div>
    </div>
  </div>
</div>


<script src="{{ url_for('static', filename='js/dashboard.js') }}"></script>
</body>
</html>
