from datetime import datetime, timedelta
import time
import random

from flask import (
    Blueprint,
    jsonify,
    render_template,
    request,
    redirect,
    url_for,
    flash,
)

from sqlalchemy import desc

from . import db
from .scanner import escanear_red, escanear_puertos_basico, clasificar_dispositivo
from .models import Dispositivo, Escaneo, EventoRed, EstadoDispositivoLog


def inferir_tipo_dispositivo(nombre: str) -> str:
    n = (nombre or "").lower()

    if "cam" in n or "camera" in n or "cámara" in n:
        return "Cámara"
    if "tv" in n or "smart tv" in n:
        return "Televisión"
    if "phone" in n or "iphone" in n or "android" in n or "galaxy" in n:
        return "Smartphone"
    if "tablet" in n or "ipad" in n:
        return "Tableta"
    if "router" in n or "gateway" in n or "modem" in n:
        return "Router"
    if "printer" in n or "impresora" in n:
        return "Impresora"
    if "laptop" in n or "notebook" in n or "desktop" in n or "pc" in n:
        return "Computadora"
    if "upnp/ssdp" in n or "mdns device" in n:
        return "Dispositivo IoT"
    if "netbios device" in n:
        return "Equipo de red"

    return "Desconocido"


def procesar_resultados_scan(resultados_por_ip):
    for ip, info in resultados_por_ip.items():
        dispositivo = Dispositivo.query.filter_by(ip=ip).first()

        if dispositivo is None:
            dispositivo = Dispositivo(ip=ip)
            db.session.add(dispositivo)

        estado_anterior = dispositivo.estado or "desconocido"

        dispositivo.mac = info.get("mac") or dispositivo.mac
        dispositivo.nombre = info.get("nombre") or dispositivo.nombre
        dispositivo.tipo = info.get("tipo") or dispositivo.tipo
        dispositivo.fecha_ultima_visto = datetime.utcnow()

        estado_nuevo = clasificar_dispositivo(info, dispositivo_actual=dispositivo)
        dispositivo.estado = estado_nuevo

        if estado_nuevo != estado_anterior:
            if dispositivo.id is None:
                db.session.flush()

            log = EstadoDispositivoLog(
                dispositivo_id=dispositivo.id,
                estado_anterior=estado_anterior,
                estado_nuevo=estado_nuevo,
                motivo="clasificación automática",
            )
            db.session.add(log)

    db.session.commit()


main = Blueprint("main", __name__)


@main.route("/")
def index():
    return redirect(url_for("main.dashboard"))


@main.route("/dashboard")
def dashboard():
    ultimos_escaneos = (
        Escaneo.query.order_by(desc(Escaneo.fecha))
        .limit(10)
        .all()
    )

    ultimo_escaneo = ultimos_escaneos[0] if ultimos_escaneos else None

    dispositivos = Dispositivo.query.order_by(Dispositivo.ip).all()

    hay_resultados = bool(ultimo_escaneo and ultimo_escaneo.total_dispositivos > 0)

    if hay_resultados:
        total = ultimo_escaneo.total_dispositivos
        vulnerables = ultimo_escaneo.dispositivos_vulnerables or 0
        nuevos = Dispositivo.query.filter_by(estado="nuevo").count()
    else:
        total = 0
        vulnerables = 0
        nuevos = 0

    stats = {
        "total": total,
        "vulnerables": vulnerables,
        "nuevos": nuevos,
    }

    return render_template(
        "dashboard.html",
        hay_resultados=hay_resultados,
        stats=stats,
        dispositivos=dispositivos,
        ultimos_escaneos=ultimos_escaneos,
    )

@main.route("/historial")
def historial():
    registros = Escaneo.query.order_by(Escaneo.fecha.desc()).limit(10).all()

    data = []
    for esc in registros:
        data.append(
            {
                "fecha": esc.fecha.strftime("%d-%m-%Y %H:%M"),
                "total_dispositivos": esc.total_dispositivos,
                "vulnerables": esc.dispositivos_vulnerables or 0,
            }
        )

    return jsonify(data)


@main.route("/dispositivo/<int:dispositivo_id>/bloquear", methods=["POST"])
def bloquear_dispositivo(dispositivo_id):
    dispositivo = Dispositivo.query.get_or_404(dispositivo_id)
    estado_anterior = dispositivo.estado or "desconocido"

    dispositivo.estado = "bloqueado"

    log = EstadoDispositivoLog(
        dispositivo_id=dispositivo.id,
        estado_anterior=estado_anterior,
        estado_nuevo="bloqueado",
        motivo="bloqueo manual desde UI",
    )
    db.session.add(log)
    db.session.commit()

    return redirect(url_for("main.detalle_dispositivo", dispositivo_id=dispositivo.id))


@main.route("/dispositivo/<int:dispositivo_id>/marcar_seguro", methods=["POST"])
def marcar_seguro_dispositivo(dispositivo_id):
    dispositivo = Dispositivo.query.get_or_404(dispositivo_id)

    estado_anterior = dispositivo.estado or "desconocido"
    dispositivo.riesgo = "seguro"
    dispositivo.estado = "seguro"

    log = EstadoDispositivoLog(
        dispositivo_id=dispositivo.id,
        estado_anterior=estado_anterior,
        estado_nuevo="seguro",
        motivo="marcado manual como seguro desde UI",
    )
    db.session.add(log)

    db.session.commit()
    flash("Dispositivo marcado como seguro.", "success")
    return redirect(url_for("main.detalle_dispositivo", dispositivo_id=dispositivo.id))


@main.route("/dispositivos")
def listar_dispositivos():
    try:
        resultados_por_ip = escanear_red()  
    except Exception as e:
        return jsonify({"error": f"Error al escanear la red: {e}"}), 500

    if not isinstance(resultados_por_ip, dict):
        tmp = {}
        for item in resultados_por_ip:
            ip = item.get("ip")
            if ip:
                tmp[ip] = item
        resultados_por_ip = tmp

    ips = list(resultados_por_ip.keys())
    ahora = datetime.utcnow()

    existentes = {
        d.ip: d
        for d in Dispositivo.query.filter(Dispositivo.ip.in_(ips)).all()
    }

    dispositivos_actualizados = []
    dispositivos_sospechosos = []

    for ip, info in resultados_por_ip.items():
        disp = existentes.get(ip)
        if disp is None:
            disp = Dispositivo(ip=ip)
            db.session.add(disp)
            estado_anterior = "desconocido"
        else:
            estado_anterior = disp.estado or "desconocido"

        disp.mac = info.get("mac") or disp.mac
        disp.nombre = info.get("nombre") or disp.nombre
        disp.tipo = info.get("tipo") or disp.tipo or inferir_tipo_dispositivo(disp.nombre)

        disp.riesgo = clasificar_dispositivo(info)
        disp.ultimo_escaneo = ahora

        if disp.riesgo and str(disp.riesgo).lower() == "alto":
            disp.estado = "sospechoso"
        else:
            if estado_anterior == "desconocido":
                disp.estado = "nuevo"
            else:
                disp.estado = "seguro"

        if disp.estado == "sospechoso":
            dispositivos_sospechosos.append(disp)

        if disp.estado != estado_anterior:
            log = EstadoDispositivoLog(
                dispositivo=disp,
                estado_anterior=estado_anterior,
                estado_nuevo=disp.estado,
                motivo="clasificación automática",
                fecha_cambio=ahora,
            )
            db.session.add(log)

        dispositivos_actualizados.append(disp)

    total_dispositivos = len(dispositivos_actualizados)
    total_vulnerables = len(dispositivos_sospechosos)

    resumen = Escaneo(
        fecha=ahora,
        total_dispositivos=total_dispositivos,
        dispositivos_vulnerables=total_vulnerables,
    )
    db.session.add(resumen)

    db.session.commit()

    dispositivos_json = []
    for d in dispositivos_actualizados:
        dispositivos_json.append(
            {
                "id": d.id,
                "ip": d.ip,
                "mac": d.mac,
                "nombre": d.nombre or "Desconocido",
                "tipo": d.tipo or "Desconocido",
                "riesgo": d.riesgo or "Desconocido",
                "estado": d.estado or "desconocido",
            }
        )

    stats = {
        "total": total_dispositivos,
        "vulnerables": total_vulnerables,
    }

    return jsonify(
        {
            "dispositivos": dispositivos_json,
            "stats": stats,
        }
    )


@main.route("/resultado-escaneo")
def resultado_escaneo():
    dispositivos = Dispositivo.query.all()

    stats = {
        "seguro": sum(1 for d in dispositivos if d.estado == "seguro"),
        "nuevo": sum(1 for d in dispositivos if d.estado == "nuevo"),
        "sospechoso": sum(1 for d in dispositivos if d.estado == "sospechoso"),
    }

    total_dispositivos = len(dispositivos)

    return render_template(
        "scan_results.html",
        dispositivos=dispositivos,
        stats=stats,
        total_dispositivos=total_dispositivos,
    )


@main.route("/dispositivo/<int:dispositivo_id>")
def detalle_dispositivo(dispositivo_id):
    dispositivo = Dispositivo.query.get_or_404(dispositivo_id)

    try:
        puertos_abiertos = escanear_puertos_basico(dispositivo.ip, timeout=0.3)
    except Exception:
        puertos_abiertos = []

    puertos_info = []
    for port in puertos_abiertos:
        if port == 80:
            servicio = "HTTP (panel web)"
        elif port == 443:
            servicio = "HTTPS (panel seguro)"
        elif port == 554:
            servicio = "RTSP (streaming de cámara)"
        elif port == 22:
            servicio = "SSH (acceso remoto seguro)"
        elif port == 23:
            servicio = "Telnet (acceso remoto inseguro)"
        elif port == 445:
            servicio = "SMB (compartición de archivos)"
        elif port == 9100:
            servicio = "Impresión de red (JetDirect)"
        else:
            servicio = "Servicio desconocido"

        puertos_info.append(
            {
                "puerto": port,
                "servicio": servicio,
            }
        )

    labels = []
    upload_values = []
    download_values = []

    now = datetime.utcnow()
    for i in range(8):
        t = (now - timedelta(minutes=5 * (7 - i))).strftime("%H:%M")
        labels.append(t)

        upload_values.append(round(random.uniform(0.2, 2.5), 2))      
        download_values.append(round(random.uniform(1.5, 8.0), 2))    

    traffic_data = {
        "labels": labels,
        "upload": upload_values,
        "download": download_values,
        "upload_current": upload_values[-1] if upload_values else 0,
        "download_current": download_values[-1] if download_values else 0,
    }

    return render_template(
        "device_detail.html",
        dispositivo=dispositivo,
        puertos_info=puertos_info,
        traffic_data=traffic_data,
    )


@main.route("/historial-escaneos")
def historial_escaneos():
    registros = Escaneo.query.order_by(Escaneo.fecha.desc()).all()
    anterior = None
    for esc in registros:
        esc.variacion_texto = "Sin cambios"
        esc.variacion_tipo = "neutral"

        if anterior is not None:
            delta = esc.total_dispositivos - anterior.total_dispositivos

            if delta > 0:
                esc.variacion_texto = f"+{delta} nuevos"
                esc.variacion_tipo = "positivo"
            elif delta < 0:
                cantidad = -delta
                palabra = "desconectado" if cantidad == 1 else "desconectados"
                esc.variacion_texto = f"-{cantidad} {palabra}"
                esc.variacion_tipo = "negativo"

        anterior = esc

    registros = list(reversed(registros))

    return render_template("scan_history.html", registros=registros)
