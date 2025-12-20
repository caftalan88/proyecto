import time
from datetime import datetime

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

db = SQLAlchemy()


def _ensure_sqlite_columns(app):
    try:
        import sqlite3
        from flask import current_app

        db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
        if not db_uri.startswith("sqlite:///"):
            return
        db_file = db_uri.replace("sqlite:///", "", 1)
        if not os.path.isabs(db_file):
            db_path = os.path.join(app.instance_path, os.path.basename(db_file))
        else:
            db_path = db_file

        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        def has_col(table, col):
            cur.execute(f"PRAGMA table_info({table})")
            cols = [r[1] for r in cur.fetchall()]
            return col in cols

        table = "dispositivo_escaneo"
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
        if cur.fetchone():
            for col, ddl in [
                ("consumo_upload_mb", "ALTER TABLE dispositivo_escaneo ADD COLUMN consumo_upload_mb REAL DEFAULT 0.0"),
                ("consumo_download_mb", "ALTER TABLE dispositivo_escaneo ADD COLUMN consumo_download_mb REAL DEFAULT 0.0"),
                ("consumo_total_mb", "ALTER TABLE dispositivo_escaneo ADD COLUMN consumo_total_mb REAL DEFAULT 0.0"),
            ]:
                if not has_col(table, col):
                    cur.execute(ddl)
                    conn.commit()

        conn.close()
    except Exception:
        pass


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
        _ensure_sqlite_columns(app)


    return app
