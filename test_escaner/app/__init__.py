import threading
import time
from datetime import datetime

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

db = SQLAlchemy()


def create_app():
    app = Flask(__name__)
    CORS(app)

    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///iot_monitor.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["JSON_AS_ASCII"] = False

    db.init_app(app)

    from . import models  
    from .routes import main

    app.register_blueprint(main)

    with app.app_context():
        db.create_all()

    from .scanner import escanear_red
    from .models import Dispositivo, Escaneo, EventoRed

    def escaneo_continuo():
        """Hilo en segundo plano que escanea la red periódicamente."""
        while True:
            with app.app_context():
                dispositivos = escanear_red()

                
                prev_dispositivos = {d.ip: d for d in Dispositivo.query.all()}
                ips_actuales = {d["ip"] for d in dispositivos}

                vulnerables = 0

                
                for info in dispositivos:
                    ip = info.get("ip")
                    mac = info.get("mac")
                    nombre = info.get("nombre")
                    riesgo = info.get("riesgo", "Desconocido")

                    if riesgo == "Alto":
                        vulnerables += 1

                    if ip in prev_dispositivos:
                        disp = prev_dispositivos[ip]
                        disp.mac = mac
                        disp.nombre = nombre
                        disp.riesgo = riesgo
                        disp.fecha_ultima_visto = datetime.utcnow()
                    else:
                        disp = Dispositivo(
                            ip=ip,
                            mac=mac,
                            nombre=nombre,
                            riesgo=riesgo,
                        )
                        db.session.add(disp)
                        evento = EventoRed(
                            tipo="nuevo",
                            descripcion="Nuevo dispositivo detectado en la red",
                            ip=ip,
                            mac=mac,
                            riesgo=riesgo,
                        )
                        db.session.add(evento)

                
                for ip, disp in prev_dispositivos.items():
                    if ip not in ips_actuales:
                        evento = EventoRed(
                            tipo="desconectado",
                            descripcion="Dispositivo dejó de estar visible en la red",
                            ip=disp.ip,
                            mac=disp.mac,
                            riesgo=disp.riesgo,
                        )
                        db.session.add(evento)

                escaneo = Escaneo(
                    fecha=datetime.utcnow(),
                    total_dispositivos=len(dispositivos),
                    dispositivos_vulnerables=vulnerables,
                )
                db.session.add(escaneo)
                db.session.commit()

                print(f"[SCAN AUTO] {len(dispositivos)} dispositivos, {vulnerables} en riesgo alto.")

            time.sleep(60)  

    hilo = threading.Thread(target=escaneo_continuo, daemon=True)
    hilo.start()

    return app

