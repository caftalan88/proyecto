from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from .routes import main
from .models import db

def create_app():
    app = Flask(__name__)
    CORS(app)
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///dispositivos.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    app.register_blueprint(main)

    with app.app_context():
        db.create_all()

    return app

