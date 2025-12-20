from datetime import datetime
from . import db
from sqlalchemy.orm import synonym


class Dispositivo(db.Model):
    __tablename__ = "dispositivo"

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), unique=True, nullable=False)
    mac = db.Column(db.String(50))
    nombre = db.Column(db.String(100))
    tipo = db.Column(db.String(50), default="Desconocido")
    riesgo = db.Column(db.String(20), default="Desconocido")
    fecha_ultima_visto = db.Column(db.DateTime, default=datetime.utcnow)
    ultimo_escaneo = synonym("fecha_ultima_visto")

    estado = db.Column(db.String(20), default="activo")

    def __repr__(self):
        return f"<Dispositivo {self.ip} ({self.mac})>"

class EstadoDispositivoLog(db.Model):
    __tablename__ = "estado_dispositivo_log"

    id = db.Column(db.Integer, primary_key=True)
    dispositivo_id = db.Column(db.Integer, db.ForeignKey("dispositivo.id"), nullable=False)
    estado_anterior = db.Column(db.String(20))
    estado_nuevo = db.Column(db.String(20))
    motivo = db.Column(db.String(255))
    fecha_cambio = db.Column(db.DateTime, default=datetime.utcnow)

    dispositivo = db.relationship("Dispositivo", backref=db.backref("historial_estados", lazy=True))

class Escaneo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fecha = db.Column(db.DateTime, default=datetime.utcnow)
    total_dispositivos = db.Column(db.Integer, default=0)
    dispositivos_vulnerables = db.Column(db.Integer, default=0)
    duracion_segundos = db.Column(db.Float, nullable=True)

    def __repr__(self):
        return (
            f"<Escaneo {self.fecha} - "
            f"{self.total_dispositivos} dispositivos - "
            f"{self.duracion_segundos or 0}s>"
        )


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



class DispositivoEscaneo(db.Model):
    __tablename__ = "dispositivo_escaneo"

    id = db.Column(db.Integer, primary_key=True)
    dispositivo_id = db.Column(db.Integer, db.ForeignKey("dispositivo.id"), nullable=False)
    fecha = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    consumo_upload_mb = db.Column(db.Float, default=0.0)
    consumo_download_mb = db.Column(db.Float, default=0.0)
    consumo_total_mb = db.Column(db.Float, default=0.0)

    actividad_score = db.Column(db.Float, default=0.0)
    rtt_ms = db.Column(db.Float, nullable=True)
    packet_loss = db.Column(db.Float, nullable=True)

    puertos_abiertos = db.Column(db.Integer, default=0)

    estado = db.Column(db.String(20), default="desconocido")
    riesgo = db.Column(db.String(20), default="Desconocido")

    dispositivo = db.relationship("Dispositivo", backref=db.backref("escaneos_dispositivo", lazy=True))

    def __repr__(self):
        return f"<DispositivoEscaneo {self.dispositivo_id} {self.fecha} act={getattr(self,"actividad_score",None)} puertos={self.puertos_abiertos}>"
