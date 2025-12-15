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


    return app
