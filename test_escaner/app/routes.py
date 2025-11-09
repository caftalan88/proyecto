from flask import Blueprint, jsonify
from .scanner import escanear_red
from .models import db, Dispositivo

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return jsonify({
        "mensaje": "Bienvenido al escáner de red IoT. Accede a /dispositivos para ver los equipos detectados."
    })

@main.route('/dispositivos')
def listar_dispositivos():
    try:
        dispositivos = escanear_red() 
        
        for d in dispositivos:
            existe = Dispositivo.query.filter_by(ip=d['ip']).first() 
            if not dispositivos:
                nuevo = Dispositivo(ip=d["ip"], mac=d["mac"], nombre=d["nombre"])
                db.session.add(nuevo)
        db.session.commit()        
        
        return jsonify({
            "cantidad": len(dispositivos),
            "dispositivos": dispositivos
        }), 200

    except Exception as e:
        
        print(f"[ERROR] Fallo al listar dispositivos: {e}")
        return jsonify({"error": "Ocurrió un problema al escanear la red."}), 500
