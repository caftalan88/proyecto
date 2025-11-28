from datetime import datetime
from . import db


class Dispositivo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), unique=True, nullable=False)
    mac = db.Column(db.String(50))
    nombre = db.Column(db.String(100))
    riesgo = db.Column(db.String(20), default="Desconocido")
    fecha_ultima_visto = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Dispositivo {self.ip} ({self.mac})>"


class Escaneo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fecha = db.Column(db.DateTime, default=datetime.utcnow)
    total_dispositivos = db.Column(db.Integer, default=0)
    dispositivos_vulnerables = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f"<Escaneo {self.fecha} - {self.total_dispositivos} dispositivos>"


class EventoRed(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(50))  
    descripcion = db.Column(db.String(255))
    ip = db.Column(db.String(50))
    mac = db.Column(db.String(50))
    riesgo = db.Column(db.String(20), default="Desconocido")
    fecha = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Evento {self.tipo} - {self.ip}>"
