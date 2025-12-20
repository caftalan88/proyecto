from __future__ import annotations

import platform
import subprocess
import re
import os
import csv
import socket
import pandas as pd
from flask import send_file
from io import BytesIO
from datetime import datetime
from functools import lru_cache
from typing import Any, Dict, List, Optional
from flask import Blueprint, jsonify, redirect, render_template, request, url_for, abort
from sqlalchemy import desc
from . import db
from .models import Dispositivo, Escaneo, EstadoDispositivoLog, DispositivoEscaneo
from .scanner import escanear_red  
try:
    from .scanner_utils import clasificar_dispositivo  
except Exception:
    def clasificar_dispositivo(data, previo):
        riesgo = (data.get("riesgo") or (getattr(previo, "riesgo", None)) or "").lower()
        if riesgo in ("alto", "medio"):
            return "sospechoso", "riesgo alto/medio"
        return "seguro", "sin indicadores críticos"



main = Blueprint("main", __name__)


def _normalizar_mac(mac: str) -> str:
    return mac.strip().upper().replace("-", ":").replace(".", ":")

def host_reachable(ip: str) -> bool:
    online, _, _ = ping_stats(ip, count=1, timeout_ms=500)
    if online:
        return True

    for port in (80, 443, 53, 22):
        try:
            with socket.create_connection((ip, port), timeout=0.6):
                return True
        except Exception:
            continue

    return False

@main.route("/informe/excel")
def exportar_informe_excel():
    dispositivos = Dispositivo.query.all()

    data = []
    for d in dispositivos:
        data.append({
            "Dirección IP": d.ip,
            "Dirección MAC": d.mac or "No registrada",
            "Fabricante": getattr(d, "fabricante", None) or "Desconocido",
            "Hostname": getattr(d, "hostname", None) or "Desconocido",
            "Fecha registro": d.fecha_registro.strftime("%d-%m-%Y %H:%M")
            if getattr(d, "fecha_registro", None) else ""
        })

    df = pd.DataFrame(data)

    output = BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Dispositivos NetGuard")

    output.seek(0)

    return send_file(
        output,
        download_name="netguard_informe_dispositivos.xlsx",
        as_attachment=True,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


@lru_cache(maxsize=1)
def cargar_oui_map() -> Dict[str, str]:
    posibles_rutas = [
        os.path.join(os.path.dirname(__file__), "oui.csv"),
        os.path.join(os.path.dirname(__file__), "data", "oui.csv"),
        os.path.join(os.getcwd(), "oui.csv"),
    ]

    ruta = next((p for p in posibles_rutas if os.path.exists(p)), None)
    if not ruta:
        return {}

    mapa: Dict[str, str] = {}
    with open(ruta, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            prefix = row[0].strip().upper()
            vendor = (row[1].strip() if len(row) > 1 else "").strip()
            if not prefix or not vendor:
                continue

            prefix = prefix.replace("-", "").replace(":", "").replace(".", "")
            if len(prefix) < 6:
                continue
            prefix = prefix[:6]
            oui = f"{prefix[0:2]}:{prefix[2:4]}:{prefix[4:6]}"
            if oui not in mapa:
                mapa[oui] = vendor

    return mapa


def fabricante_desde_mac(mac: Optional[str]) -> str:
    if not mac:
        return "Desconocido"
    mac = _normalizar_mac(mac)
    partes = mac.split(":")
    if len(partes) < 3:
        return "Desconocido"
    oui = ":".join(partes[:3])
    return cargar_oui_map().get(oui, "Desconocido")


def _registrar_cambio_estado(dispositivo: Dispositivo, anterior: str, nuevo: str, motivo: str) -> None:
    log = EstadoDispositivoLog(
        dispositivo_id=dispositivo.id,
        estado_anterior=anterior or "desconocido",
        estado_nuevo=nuevo or "desconocido",
        motivo=motivo or "",
        fecha_cambio=datetime.utcnow(),
    )
    db.session.add(log)


def _calcular_stats(dispositivos: List[Dispositivo]) -> Dict[str, int]:
    total = len(dispositivos)
    vulnerables = sum(1 for d in dispositivos if (d.riesgo or "").lower() in ("alto", "medio"))
    nuevos = sum(1 for d in dispositivos if (d.estado or "").lower() == "nuevo")
    return {"total": total, "vulnerables": vulnerables, "nuevos": nuevos}


def _dispositivo_to_dict(d: Dispositivo) -> Dict[str, Any]:
    return {
        "id": d.id,
        "ip": d.ip,
        "mac": d.mac,
        "fabricante": fabricante_desde_mac(d.mac),
        "nombre": d.nombre,
        "tipo": d.tipo,
        "riesgo": d.riesgo,
        "estado": d.estado,
        "ultimo_escaneo": d.ultimo_escaneo.isoformat() if d.ultimo_escaneo else None,
    }


@main.route("/", methods=["GET"])
def dashboard():
    dispositivos = Dispositivo.query.order_by(desc(Dispositivo.ultimo_escaneo)).all()
    stats = _calcular_stats(dispositivos)
    ultimos_escaneos = Escaneo.query.order_by(desc(Escaneo.fecha)).limit(10).all()
    hay_resultados = len(dispositivos) > 0

    for d in dispositivos:
        setattr(d, "fabricante", fabricante_desde_mac(d.mac))

    return render_template(
        "dashboard.html",
        hay_resultados=hay_resultados,
        dispositivos=dispositivos,
        stats=stats,
        ultimos_escaneos=ultimos_escaneos,
    )


@main.route("/api/dashboard-data", methods=["GET"])
def api_dashboard_data():
    dispositivos = Dispositivo.query.order_by(desc(Dispositivo.ultimo_escaneo)).all()
    stats = _calcular_stats(dispositivos)
    ultimos_escaneos = Escaneo.query.order_by(desc(Escaneo.fecha)).limit(10).all()

    return jsonify(
        {
            "stats": stats,
            "dispositivos": [_dispositivo_to_dict(d) for d in dispositivos],
            "ultimos_escaneos": [
                {
                    "id": e.id,
                    "fecha": e.fecha.isoformat(),
                    "total_dispositivos": e.total_dispositivos,
                    "dispositivos_vulnerables": e.dispositivos_vulnerables,
                }
                for e in ultimos_escaneos
            ],
        }
    )


@main.route("/dispositivos", methods=["GET"])
def listar_dispositivos():
    dispositivos = Dispositivo.query.order_by(desc(Dispositivo.ultimo_escaneo)).all()
    stats = _calcular_stats(dispositivos)
    total_dispositivos = len(dispositivos)

    for d in dispositivos:
        setattr(d, "fabricante", fabricante_desde_mac(d.mac))

    return render_template(
        "scan_results.html",
        dispositivos=dispositivos,
        stats={
            "seguro": sum(1 for d in dispositivos if (d.estado or "").lower() == "seguro"),
            "nuevo": sum(1 for d in dispositivos if (d.estado or "").lower() == "nuevo"),
            "sospechoso": sum(1 for d in dispositivos if (d.estado or "").lower() == "sospechoso"),
        },
        total_dispositivos=total_dispositivos,
    )


@main.route("/resultado-escaneo", methods=["GET"])
def resultado_escaneo():
    return redirect(url_for("main.listar_dispositivos"))


def ping_stats(ip: str, count: int = 2, timeout_ms: int = 700):
    is_win = platform.system().lower().startswith("win")
    if is_win:
        cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", str(count), "-W", str(max(1, timeout_ms // 1000)), ip]

    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=6).stdout.lower()
    except Exception:
        return False, None, None

    online = ("ttl=" in out) or ("bytes from" in out)

    times = re.findall(r"time[=<]\s*([\d\.]+)\s*ms", out)
    rtt = None
    if times:
        vals = []
        for t in times:
            try:
                vals.append(float(t))
            except Exception:
                pass
        if vals:
            rtt = sum(vals) / len(vals)

    loss = None
    m = re.search(r"(\d+)\s*%\s*(loss|perdidos)", out)
    if m:
        try:
            loss = float(m.group(1))
        except Exception:
            loss = None

    return online, rtt, loss


def calcular_actividad_score(online: bool, rtt_ms, loss_pct, puertos_abiertos: int) -> float:
    if not online:
        return 0.0

    score = 50.0

    if rtt_ms is None:
        score += 5.0
    else:
        try:
            rtt = float(rtt_ms)
            if rtt <= 20: score += 30
            elif rtt <= 50: score += 20
            elif rtt <= 100: score += 10
            else: score -= 5
        except Exception:
            score += 0.0

    if loss_pct is not None:
        try:
            loss = float(loss_pct)
            if loss >= 50: score -= 35
            elif loss >= 20: score -= 20
            elif loss >= 5: score -= 10
            else: score += 5
        except Exception:
            pass

    try:
        score += min(15.0, float(puertos_abiertos) * 3.0)
    except Exception:
        pass

    return float(max(0.0, min(100.0, score)))


def ejecutar_scan():
    resultados = escanear_red()  
    ahora = datetime.utcnow()

    ips = [r.get("ip") for r in resultados if r.get("ip")]
    existentes = {d.ip: d for d in Dispositivo.query.filter(Dispositivo.ip.in_(ips)).all()} if ips else {}

    dispositivos_guardados: List[Dispositivo] = []
    nuevos_count = 0
    vulnerables_count = 0

    for r in resultados:
        ip = r.get("ip")
        if not ip:
            continue

        mac = r.get("mac")
        nombre = r.get("nombre")
        tipo = r.get("tipo")
        riesgo = r.get("riesgo")  

        previo = existentes.get(ip)

        if previo is None:
            d = Dispositivo(
                ip=ip,
                mac=mac,
                nombre=(nombre if (nombre and str(nombre).strip().lower() not in ("desconocido","unknown")) else "Desconocido"),
                tipo=tipo,
                riesgo=riesgo,
                estado="nuevo",
                ultimo_escaneo=ahora,
            )
            db.session.add(d)
            db.session.flush()  
            _registrar_cambio_estado(d, "desconocido", "nuevo", "dispositivo nuevo detectado")
            nuevos_count += 1
        else:
            d = previo
            estado_anterior = (d.estado or "desconocido").lower()

            if mac:
                d.mac = mac
            if nombre and str(nombre).strip() and str(nombre).strip().lower() not in ("desconocido", "unknown"):
                d.nombre = nombre
            if tipo:
                d.tipo = tipo
            if riesgo is not None:
                d.riesgo = riesgo
            d.ultimo_escaneo = ahora

            try:
                estado_auto, motivo = clasificar_dispositivo(r, d)
            except Exception:
                estado_auto, motivo = (estado_anterior, "")

            if estado_anterior == "bloqueado":
                estado_nuevo = "bloqueado"
                motivo = "permanece bloqueado"
            else:
                estado_nuevo = (estado_auto or estado_anterior or "seguro").lower()

            if estado_nuevo != estado_anterior:
                d.estado = estado_nuevo
                _registrar_cambio_estado(d, estado_anterior, estado_nuevo, motivo or "clasificación automática")

        try:
            puertos = r.get("puertos") or []
            puertos_count = len(puertos) if isinstance(puertos, list) else int(puertos or 0)
        except Exception:
            puertos_count = 0
        online_ping, rtt_ms, loss_pct = ping_stats(ip)
        online = host_reachable(ip)  

        actividad = calcular_actividad_score(online, rtt_ms, loss_pct, puertos_count)
        estado_actual = (d.estado or "desconocido").lower()

        if estado_actual != "bloqueado":
            if online:
                if (d.riesgo or "").lower() in ("alto", "medio"):
                    estado_nuevo = "sospechoso"
                else:
                    estado_nuevo = "seguro"
            else:
                estado_nuevo = "desconocido"

            if estado_nuevo != estado_actual:
                d.estado = estado_nuevo
                _registrar_cambio_estado(d, estado_actual, estado_nuevo, "estado por reachability (ping/tcp)")

        db.session.add(
            DispositivoEscaneo(
                dispositivo_id=d.id,
                fecha=ahora,
                puertos_abiertos=puertos_count,
                actividad_score=float(actividad),
                rtt_ms=(float(rtt_ms) if rtt_ms is not None else None),
                packet_loss=(float(loss_pct) if loss_pct is not None else None),
                estado=(d.estado or "desconocido"),
                riesgo=(d.riesgo or "Desconocido"),
            )
        )

        dispositivos_guardados.append(d)
        if (d.riesgo or "").lower() in ("alto", "medio"):
            vulnerables_count += 1

    esc = Escaneo(
        fecha=ahora,
        total_dispositivos=len(dispositivos_guardados),
        dispositivos_vulnerables=vulnerables_count,
    )
    db.session.add(esc)
    db.session.commit()

    return jsonify(
        {
            "ok": True,
            "scan": {
                "fecha": esc.fecha.isoformat(),
                "total_dispositivos": esc.total_dispositivos,
                "dispositivos_vulnerables": esc.dispositivos_vulnerables,
            },
            "stats": _calcular_stats(Dispositivo.query.all()),
        }
    )


@main.route("/ejecutar-scan", methods=["POST"])
def ejecutar_scan_alias():
    return ejecutar_scan()


@main.route("/historial", methods=["GET"])
def historial():
    escaneos = Escaneo.query.order_by(desc(Escaneo.fecha)).limit(50).all()
    return render_template("scan_history.html", escaneos=escaneos)

@main.route("/sugerencias", methods=["GET"])
def sugerencias_ciberseguridad():
    return render_template("security_tips.html")


@main.route("/historial-escaneos", methods=["GET"])
def historial_escaneos():
    return redirect(url_for("main.historial"))

@main.route("/dispositivo/<int:dispositivo_id>", methods=["GET"])
def detalle_dispositivo(dispositivo_id: int):
    d = Dispositivo.query.get_or_404(dispositivo_id)

    traffic_data = []
    puertos_info = []

    return render_template(
        "device_detail.html",
        dispositivo=d,
        traffic_data=traffic_data,
        puertos_info=puertos_info,
    )

@main.route("/api/dispositivo/<int:dispositivo_id>/chart-data", methods=["GET"])
def api_dispositivo_chart_data(dispositivo_id: int):
    d = Dispositivo.query.get_or_404(dispositivo_id)

    logs = (
        DispositivoEscaneo.query
        .filter_by(dispositivo_id=d.id)
        .order_by(desc(DispositivoEscaneo.fecha))
        .limit(20)
        .all()
    )
    logs = list(reversed(logs))  # cronológico

    labels = [l.fecha.strftime("%d-%m %H:%M") for l in logs]
    actividad = [float(getattr(l, "actividad_score", 0.0) or 0.0) for l in logs]

    last = actividad[-1] if actividad else 0

    return jsonify({
        "ok": True,
        "labels": labels,
        "actividad_score": actividad,  
        "data": actividad,              
        "last_value": last              
    })

@main.route("/dispositivo/<int:dispositivo_id>/renombrar", methods=["POST"])
def renombrar_dispositivo(dispositivo_id: int):
    d = Dispositivo.query.get_or_404(dispositivo_id)
    nuevo = (request.form.get("nombre") or "").strip()
    if not nuevo:
        return redirect(url_for("main.detalle_dispositivo", dispositivo_id=d.id))

    d.nombre = nuevo
    d.ultimo_escaneo = datetime.utcnow()
    db.session.commit()
    return redirect(url_for("main.detalle_dispositivo", dispositivo_id=d.id))



@main.route("/dispositivo/<int:dispositivo_id>/bloquear", methods=["POST"])
def bloquear_dispositivo(dispositivo_id: int):
    d = Dispositivo.query.get_or_404(dispositivo_id)
    anterior = (d.estado or "desconocido").lower()
    if anterior != "bloqueado":
        d.estado = "bloqueado"
        _registrar_cambio_estado(d, anterior, "bloqueado", "bloqueado manualmente")
        db.session.commit()
    return redirect(url_for("main.detalle_dispositivo", dispositivo_id=d.id))


@main.route("/dispositivo/<int:dispositivo_id>/marcar-seguro", methods=["POST"])
def marcar_seguro_dispositivo(dispositivo_id: int):
    d = Dispositivo.query.get_or_404(dispositivo_id)
    anterior = (d.estado or "desconocido").lower()
    if anterior != "seguro":
        d.estado = "seguro"
        _registrar_cambio_estado(d, anterior, "seguro", "marcado como seguro manualmente")
        db.session.commit()
    return redirect(url_for("main.detalle_dispositivo", dispositivo_id=d.id))


@main.route("/favicon.ico")
def favicon():
    return ("", 204)
