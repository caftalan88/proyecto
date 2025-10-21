from flask import Blueprint, jsonify
from .scanner import escanear_red

main = Blueprint('main', __name__)

@main.route('/dispositivos', methods=['GET'])
def listar_dispositivos():
    dispositivos = escanear_red()
    return jsonify(dispositivos)
