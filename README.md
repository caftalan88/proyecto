# IoT Security Monitor

Monitoreo y clasificación de dispositivos IoT en una red local. Escanea la red, detecta puertos básicos, clasifica dispositivos (seguro / nuevo / sospechoso), guarda historiales de escaneo y muestra detalles/estadísticas.

## Estado
Proyecto en desarrollo. Funcionalidad principal implementada (escaneo, clasificación, persistencia y vistas básicas).

## Estructura principal
- run.py — punto de entrada (inicia Flask).
- requirements.txt — dependencias.
- app/
  - __init__.py — inicializa la app y DB.
  - routes.py — rutas y capas de presentación.
  - scanner.py — lógica de descubrimiento y clasificación.
  - traffic_analyzer.py — análisis de tráfico (complementario).
  - models.py — modelos SQLAlchemy (Dispositivo, Escaneo, EstadoDispositivoLog).
  - templates/ — HTML (dashboard, resultados, detalle).
  - static/ — JS y CSS.

## Requisitos
- Python 3.8+
- Instalar dependencias:
```sh
pip install -r requirements.txt
```

## Configuración rápida (Windows)
1. Crear entorno virtual (opcional):
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
2. Iniciar:
```powershell
python run.py
```
3. Abrir: http://127.0.0.1:5000/

## Uso
- Escanear la red desde la interfaz web (Dashboard).
- Ver resultados, historial de escaneos y detalles por dispositivo.
- Marcar dispositivos como seguros o bloquearlos (acciones en la UI que registran logs).

## Endpoints relevantes
- GET /dashboard — panel principal.
- GET /resultado-escaneo — ver último escaneo.
- GET /dispositivo/<id> — detalle del dispositivo.
- POST /dispositivo/<id>/bloquear — bloquear dispositivo.
- POST /dispositivo/<id>/marcar_seguro — marcar como seguro.

## Notas de desarrollo
- scanner.escanear_red realiza el descubrimiento y crea/actualiza registros en DB.
- La clasificación se hace en scanner.clasificar_dispositivo (reglas configurables).
- Los logs de cambio de estado se guardan en EstadoDispositivoLog.
- Las visualizaciones usan Chart.js y utilidades en static/js.

## Tareas pendientes (sugeridas)
- Añadir autenticación y controles de acceso.
- Mejorar detección activa de puertos y fingerprinting.
- Soporte para escaneos programados y alertas.
- Tests unitarios para scanner y rutas críticas.

## Contribuir
1. Fork -> branch descriptiva -> PR con cambios y tests.
2. Mantener separación entre lógica (app/scanner.py) y presentación (routes/templates).

## Licencia
Añadir archivo LICENSE con la licencia deseada (por ejemplo MIT).
