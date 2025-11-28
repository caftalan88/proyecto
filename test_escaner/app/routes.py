from datetime import datetime

from flask import Blueprint, jsonify, render_template, request

from .scanner import escanear_red
from .models import Dispositivo, Escaneo, EventoRed
from . import db

main = Blueprint("main", __name__)


@main.route("/")
def dashboard():
    return render_template("dashboard.html")


@main.route("/dispositivos")
def listar_dispositivos():
    """Escaneo en tiempo real para el dashboard."""
    dispositivos = escanear_red()

    return jsonify({
        "cantidad": len(dispositivos),
        "dispositivos": dispositivos,
    })


@main.route("/historial")
def historial():
    """Últimos escaneos del hilo automático."""
    registros = Escaneo.query.order_by(Escaneo.fecha.desc()).limit(20).all()
    data = [
        {
            "fecha": e.fecha.strftime("%d-%m-%Y %H:%M"),
            "total": e.total_dispositivos,
            "vulnerables": e.dispositivos_vulnerables,
        } for e in registros
    ]
    return jsonify(data)


@main.route("/alertas")
def alertas():
    """Eventos relevantes en la red (nuevos, desconectados, IoT, etc.)."""
    eventos = EventoRed.query.order_by(EventoRed.fecha.desc()).limit(30).all()
    data = [
        {
            "tipo": e.tipo,
            "descripcion": e.descripcion,
            "ip": e.ip,
            "mac": e.mac,
            "riesgo": e.riesgo,
            "fecha": e.fecha.strftime("%d-%m-%Y %H:%M"),
        } for e in eventos
    ]
    return jsonify(data)


@main.route("/reporte")
def reporte():
    """Resumen general del estado de la red y riesgos."""
    total_dispositivos = Dispositivo.query.count()
    riesgos_altos = Dispositivo.query.filter_by(riesgo="Alto").count()
    riesgos_medios = Dispositivo.query.filter_by(riesgo="Medio").count()
    ult_escaneo = Escaneo.query.order_by(Escaneo.fecha.desc()).first()

    resumen = {
        "total_dispositivos": total_dispositivos,
        "riesgo_alto": riesgos_altos,
        "riesgo_medio": riesgos_medios,
        "fecha_ultimo_escaneo": ult_escaneo.fecha.strftime("%d-%m-%Y %H:%M") if ult_escaneo else None,
    }

    return jsonify(resumen)


@main.route("/api/iot_report", methods=["POST"])
def iot_report():
    """Punto para reportes desde dispositivos IoT (ej: ESP32/Wokwi)."""
    data = request.json or {}
    ip = data.get("ip")
    device = data.get("device", "IoT device")
    status = data.get("status", "desconocido")

    print("[IOT REPORT]", data)

    evento = EventoRed(
        tipo="iot",
        descripcion=f"Reporte IoT recibido desde {device} con estado {status}",
        ip=ip,
        mac=None,
        riesgo="Bajo",
    )
    db.session.add(evento)
    db.session.commit()

    return jsonify({"status": "ok", "received": data}), 200
