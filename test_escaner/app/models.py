from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Dispositivo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50))
    mac = db.Column(db.String(50))
    nombre = db.Column(db.String(100))
    fecha = db.Column(db.DateTime, default=datetime.utcnow)
